import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { WorkerConfig } from '../shared/config';
import type { Logger } from '../shared/logger';
import { PORT_SCOPE_LABELS, DEFAULT_USER_AGENT, MAX_STEP_TIMEOUT_MS, MODERATE_STEP_TIMEOUT_MS } from '../shared/constants';
import { expandProfile, expandModules, assertApprovedArgs } from '../shared/profiles';
import { buildExecutiveSummary, renderMarkdown } from '../shared/report';
import { parseTarget } from '../shared/targets';
import type {
  CustomScanOptions,
  DiscoveredPath,
  DiscoveredPort,
  DiscoveredSubdomain,
  DnsRecord,
  Job,
  ModuleId,
  NormalizedTarget,
  ReportModel,
  ScanProfile,
  TlsHardeningResult,
  ToolResultRecord,
  VulnerabilityFinding,
  WhoisInfo,
  CveContextFinding,
} from '../shared/types';
import { assertNoRebinding, defaultResolver, resolveAndValidate, type DnsResolver, type ResolveResult } from './dns';
import { buildFindings } from './findings';
import { httpCheck as defaultHttpCheck, tlsCheck as defaultTlsCheck } from './http';
import { formatHostForUrl } from '../shared/net';
import type { HttpObservation, TlsObservation } from '../shared/types';
import {
  parseNmapGrepable,
  parseWhatwebJson,
  parseWpscanJson,
  parseSubfinderJson,
  parseDnsxJson,
  parseNucleiJsonl,
  parseRetireJson,
  parseTestsslJson,
  parseFeroxJson,
  type WpscanResult,
} from './parsers';
import { renderPdf } from './pdf';
import { ScanQueue } from './queue';
import { rdapLookup } from './rdap';
import { osvLookup, mapTechnologyToOsv, type OsvPackageQuery } from './osv';
import { VERSION_PROBE_ARGS, captureToolVersion, runTool, type RunnerDeps } from './runner';

interface Observations {
  ports: DiscoveredPort[];
  http: HttpObservation | null;
  tls: TlsObservation | null;
  technologies: Array<{ name: string; version: string | null }>;
  wordpressDetected: boolean;
  wpscan: WpscanResult | null;
  wpscanRan: boolean;
  wpscanError: string | null;
  wpscanExitNote: string | null;
  subdomains: DiscoveredSubdomain[];
  dnsRecords: DnsRecord[];
  whois: WhoisInfo | null;
  vulnerabilities: VulnerabilityFinding[];
  tlsHardening: TlsHardeningResult | null;
  discoveredPaths: DiscoveredPath[];
  cveContext: CveContextFinding[];
}

/**
 * Escape-hatch read of cancellation state. The queue mutates `job.status`
 * asynchronously (via cancelJob), so TS control-flow narrowing on the property
 * is not valid here; reading through a function avoids bogus narrowing errors.
 */
function isJobCancelled(job: Job): boolean {
  return job.status === 'cancelled';
}

/** Map detected technologies to OSV package queries (deduplicated). */
function buildOsvQueries(technologies: Array<{ name: string; version: string | null }>): OsvPackageQuery[] {
  const queries: OsvPackageQuery[] = [];
  const seen = new Set<string>();
  for (const t of technologies) {
    const q = mapTechnologyToOsv(t.name, t.version);
    if (!q) continue;
    const key = `${q.ecosystem}:${q.name}@${q.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    queries.push(q);
  }
  return queries;
}

/** Extract same-origin `<script src>` URLs from a page's HTML. */
function extractScriptSrcs(html: string, baseUrl: string, host: string): string[] {
  const out: string[] = [];
  const re = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    try {
      const url = new URL(m[1], baseUrl);
      if (url.protocol === 'http:' || url.protocol === 'https:') {
        if (url.hostname === host) out.push(url.toString());
      }
    } catch {
      // ignore malformed src
    }
  }
  return out;
}

export class QueueFullError extends Error {
  constructor() {
    super('The scan queue is full. Please wait for a running scan to finish and try again.');
    this.name = 'QueueFullError';
  }
}

export class TargetRejectedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TargetRejectedError';
  }
}

export class JobNotFoundError extends Error {
  constructor(id: string) {
    super(`Job not found: ${id}`);
    this.name = 'JobNotFoundError';
  }
}

export class ModuleNotEnabledError extends Error {
  constructor(moduleId: ModuleId) {
    super(`The ${moduleId} module is not enabled on this deployment.`);
    this.name = 'ModuleNotEnabledError';
  }
}

export interface ScannerDeps {
  resolver?: DnsResolver;
  httpCheck?: typeof defaultHttpCheck;
  tlsCheck?: typeof defaultTlsCheck;
  rdap?: typeof rdapLookup;
  osv?: typeof osvLookup;
  downloadJs?: (job: Job, jsDir: string, controller: AbortController) => Promise<string | null>;
}

const LIMITATIONS = [
  'TCP-only scanning; UDP and all-port scans are not performed.',
  'Each scan is capped at the configured scan duration and port scope.',
  'CIDR/network-range scanning is not supported.',
  'Detection-oriented reconnaissance only; no exploitation or vulnerability confirmation is performed.',
  'No external vulnerability database lookups are performed.',
  'Severity ratings are inferred from observed evidence and should be verified against your environment.',
];

export class ScannerService {
  private readonly queue: ScanQueue;
  private readonly resolver: DnsResolver;
  private readonly httpCheckImpl: typeof defaultHttpCheck;
  private readonly tlsCheckImpl: typeof defaultTlsCheck;
  private readonly rdapImpl: typeof rdapLookup;
  private readonly osvImpl: typeof osvLookup;
  private readonly downloadJsImpl: NonNullable<ScannerDeps['downloadJs']>;
  private readonly aborts = new Map<string, AbortController>();
  private readonly validatedTargets = new Map<string, ResolveResult>();
  private ttlTimer: NodeJS.Timeout | null = null;

  constructor(
    private readonly config: WorkerConfig,
    private readonly log: Logger,
    deps: ScannerDeps = {},
  ) {
    this.resolver = deps.resolver ?? defaultResolver;
    this.httpCheckImpl = deps.httpCheck ?? defaultHttpCheck;
    this.tlsCheckImpl = deps.tlsCheck ?? defaultTlsCheck;
    this.rdapImpl = deps.rdap ?? rdapLookup;
    this.osvImpl = deps.osv ?? osvLookup;
    this.downloadJsImpl = deps.downloadJs ?? ((job, jsDir, controller) => this.downloadJsForRetire(job, jsDir, controller));

    const runnerDeps: RunnerDeps = {
      maxOutputBytes: config.maxToolOutputBytes,
      binDir: config.scannerBinDir,
    };

    this.queue = new ScanQueue(
      config.maxConcurrentScans,
      config.maxQueue,
      (job) => this.processJob(job, runnerDeps),
      {
        onStart: (job) => this.log.info('job_started', { jobId: job.id, profile: job.profile }),
        onFinish: (job) => this.log.info('job_finished', { jobId: job.id, status: job.status }),
        onReject: (job, reason) => this.log.warn('job_rejected', { jobId: job.id, reason }),
      },
    );
  }

  start(): void {
    fs.mkdirSync(this.config.artifactDir, { recursive: true });
    const intervalMs = Math.max(60_000, this.config.artifactTtlMinutes * 60_000);
    this.ttlTimer = setInterval(() => this.sweepArtifacts(), intervalMs);
    this.ttlTimer.unref?.();
    this.log.info('scanner_started', {
      maxConcurrent: this.config.maxConcurrentScans,
      maxQueue: this.config.maxQueue,
      timeoutMs: this.config.scanTimeoutMs,
      allowInternal: this.config.allowInternalTargets,
    });
  }

  stop(): void {
    if (this.ttlTimer) clearInterval(this.ttlTimer);
    this.log.info('scanner_stopping', {});
  }

  get queueStats() {
    return { pending: this.queue.pendingCount, active: this.queue.activeCount };
  }

  async createJob(input: { target: string; profile: ScanProfile; custom?: CustomScanOptions; modules?: ModuleId[] }): Promise<Job> {
    const target = parseTarget(input.target);

    // Gate paid modules against the deployment's enabled set.
    const requested = input.modules ?? [];
    const enabled = this.config.enabledModules;
    for (const m of requested) {
      if (!enabled.has(m)) {
        throw new ModuleNotEnabledError(m);
      }
    }
    const modules = Array.from(new Set(requested));

    if (!this.config.allowInternalTargets) {
      // Resolve + validate up front so we never enqueue a blocked target.
      let resolved: ResolveResult;
      try {
        resolved = await resolveAndValidate(target.host, this.resolver);
      } catch (e) {
        throw new TargetRejectedError((e as Error).message);
      }
      const jobId = crypto.randomUUID();
      this.validatedTargets.set(jobId, resolved);
      return this.enqueue(jobId, target, input.profile, input.custom, modules);
    }

    const jobId = crypto.randomUUID();
    return this.enqueue(jobId, target, input.profile, input.custom, modules);
  }

  private enqueue(jobId: string, target: NormalizedTarget, profile: ScanProfile, custom?: CustomScanOptions, modules: ModuleId[] = []): Job {
    const jobDir = path.join(this.config.artifactDir, jobId);
    fs.mkdirSync(jobDir, { recursive: true });

    const planOpts = {
      outputPath: (name: string) => path.join(jobDir, name),
      wpscanApiToken: this.config.wpscanApiToken || undefined,
      nucleiTemplates: this.config.nucleiTemplates,
      wordlistPath: this.config.wordlistPath,
    };
    const plan = expandProfile(profile, target, custom ?? null, planOpts);
    const moduleSteps = expandModules(modules, target, planOpts);

    // Assert the generated plan only contains approved arguments (defense-in-depth).
    for (const step of [...plan.steps, ...moduleSteps]) {
      assertApprovedArgs(step.tool, step.args);
    }

    const createdAt = new Date().toISOString();
    const job: Job = {
      id: jobId,
      status: 'queued',
      target,
      profile,
      custom: custom ?? null,
      modules,
      createdAt,
      startedAt: null,
      finishedAt: null,
      error: null,
      report: null,
      artifacts: null,
    };

    const added = this.queue.add(job);
    if (!added) {
      fs.rmSync(jobDir, { recursive: true, force: true });
      throw new QueueFullError();
    }
    this.log.info('job_queued', { jobId, profile, host: target.host, modules });
    return job;
  }

  getJob(id: string): Job | undefined {
    return this.queue.get(id);
  }

  cancelJob(id: string): Job {
    const job = this.queue.get(id);
    if (!job) throw new JobNotFoundError(id);
    if (job.status === 'queued') {
      this.queue.cancelQueued(id);
      this.log.info('job_cancelled', { jobId: id, phase: 'queued' });
      return job;
    }
    if (job.status === 'running') {
      const controller = this.aborts.get(id);
      job.status = 'cancelled';
      job.finishedAt = new Date().toISOString();
      job.error = 'Cancelled by user.';
      controller?.abort();
      this.log.info('job_cancelled', { jobId: id, phase: 'running' });
      return job;
    }
    return job;
  }

  getArtifactPath(job: Job, format: 'markdown' | 'pdf'): string | null {
    if (!job.artifacts) return null;
    return format === 'markdown' ? job.artifacts.markdownPath : job.artifacts.pdfPath;
  }

  /** Delete an artifact file after it has been delivered to the web service. */
  deleteArtifact(job: Job, format: 'markdown' | 'pdf'): void {
    const filePath = this.getArtifactPath(job, format);
    if (!filePath) return;
    try {
      fs.rmSync(filePath, { force: true });
      this.log.debug('artifact_deleted', { jobId: job.id, format });
    } catch (e) {
      this.log.warn('artifact_delete_failed', { jobId: job.id, format, error: (e as Error).message });
    }
  }

  /** Validate a target host; throws if blocked or unresolvable. */
  private async validateHost(host: string): Promise<ResolveResult> {
    return resolveAndValidate(host, this.resolver);
  }

  private async processJob(job: Job, runnerDeps: RunnerDeps): Promise<void> {
    const jobId = job.id;
    const controller = new AbortController();
    this.aborts.set(jobId, controller);
    const startedAt = Date.now();
    const jobDir = path.join(this.config.artifactDir, jobId);

    try {
      const effectiveTimeout = Math.min(
        this.config.scanTimeoutMs,
        job.custom?.timeoutMs ?? this.config.scanTimeoutMs,
      );
      const timeoutHandle = setTimeout(() => controller.abort(new Error('Scan exceeded the maximum allowed duration.')), effectiveTimeout);
      timeoutHandle.unref?.();

      this.log.info('job_running', { jobId, host: job.target.host, profile: job.profile });

      // Revalidate the target before running anything (DNS rebinding guard).
      // Also compare against the enqueue-time resolution to catch rebinding
      // that happened between acceptance and execution.
      const current = await this.validateHost(job.target.host);
      const prior = this.validatedTargets.get(jobId);
      if (prior) {
        assertNoRebinding(prior, current);
      }
      const initial = current;
      if (isJobCancelled(job)) return;

      const toolVersions = await this.captureVersions(job, runnerDeps);

      const planOpts = {
        outputPath: (name: string) => path.join(jobDir, name),
        wpscanApiToken: this.config.wpscanApiToken || undefined,
        nucleiTemplates: this.config.nucleiTemplates,
        wordlistPath: this.config.wordlistPath,
      };
      const plan = expandProfile(job.profile, job.target, job.custom, planOpts);
      const moduleSteps = expandModules(job.modules, job.target, planOpts);

      const observations: Observations = {
        ports: [],
        http: null,
        tls: null,
        technologies: [],
        wordpressDetected: false,
        wpscan: null,
        wpscanRan: false,
        wpscanError: null,
        wpscanExitNote: null,
        subdomains: [],
        dnsRecords: [],
        whois: null,
        vulnerabilities: [],
        tlsHardening: null,
        discoveredPaths: [],
        cveContext: [],
      };
      const toolResults: ToolResultRecord[] = [];
      const warnings: string[] = [];
      let fatalError: string | null = null;

      for (const step of [...plan.steps, ...moduleSteps]) {
        if (isJobCancelled(job)) {
          await this.cleanupDir(jobDir);
          return;
        }
        // Revalidate before EVERY tool execution (rebinding protection).
        let current: ResolveResult;
        try {
          current = await this.validateHost(job.target.host);
          assertNoRebinding(initial, current);
        } catch (e) {
          fatalError = `Target validation failed before ${step.label}: ${(e as Error).message}`;
          this.log.warn('job_aborted_rebinding', { jobId, error: fatalError });
          break;
        }

        const stepStart = Date.now();
        const record: ToolResultRecord = {
          tool: step.tool,
          label: step.label,
          ok: false,
          timedOut: false,
          exitCode: null,
          error: null,
          startedAt: new Date(stepStart).toISOString(),
          finishedAt: '',
          durationMs: 0,
        };

        try {
          if (step.tool === 'http') {
            const http = await this.httpCheckImpl(job.target, {
              userAgent: job.custom?.userAgent ?? undefined,
              followRedirects: job.custom?.followRedirects ?? true,
              resolver: this.resolver,
            });
            observations.http = http;
            record.ok = !http.error;
            record.error = http.error;
          } else if (step.tool === 'tls') {
            const tls = await this.tlsCheckImpl(job.target);
            observations.tls = tls;
            record.ok = !tls.error;
            record.error = tls.error;
          } else if (step.tool === 'rdap') {
            const whois = await this.rdapImpl(job.target.host);
            observations.whois = whois;
            record.ok = !whois.error;
            record.error = whois.error;
          } else if (step.tool === 'osv') {
            const packages = buildOsvQueries(observations.technologies);
            const cve = await this.osvImpl(packages);
            observations.cveContext = cve;
            record.ok = true;
          } else if (step.tool === 'retire') {
            // Download the target's JavaScript into a temp dir first (bounded).
            const jsDir = path.join(jobDir, 'js');
            const downloadErr = await this.downloadJsImpl(job, jsDir, controller);
            if (downloadErr) {
              record.error = downloadErr;
              record.ok = false;
            } else {
              const stepTimeout = Math.max(10_000, Math.min(60_000, effectiveTimeout - (Date.now() - startedAt)));
              const result = await runTool(step.tool, step.args, runnerDeps, { timeoutMs: stepTimeout, signal: controller.signal });
              record.exitCode = result.exitCode;
              record.timedOut = result.timedOut;
              const outFile = path.join(jobDir, 'retire.json');
              const raw = fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf8') : result.output;
              const parsed = parseRetireJson(raw);
              observations.vulnerabilities.push(...parsed);
              // retire.js uses a semantic exit code when findings are found;
              // parseable output means the scan succeeded.
              if (parsed.length > 0 || result.exitCode === 0) {
                record.ok = true;
                record.error = null;
              } else {
                record.error = this.redactError(
                  result.error ??
                    (result.exitCode != null && result.exitCode !== 0
                      ? `exited with code ${result.exitCode}`
                      : result.signal
                        ? `killed by signal ${result.signal}`
                        : 'produced no parseable output'),
                );
              }
            }
          } else {
            // Heavy module tools (nuclei/testssl) get the largest step budget,
            // dnsx/feroxbuster a moderate one, everything else 60s. All bounded
            // by the job cap.
            const isHeavy = step.tool === 'nuclei' || step.tool === 'testssl';
            const isModerate = step.tool === 'dnsx' || step.tool === 'feroxbuster';
            const stepCap = isHeavy ? MAX_STEP_TIMEOUT_MS : isModerate ? MODERATE_STEP_TIMEOUT_MS : 60_000;
            const stepTimeout = Math.max(10_000, Math.min(stepCap, effectiveTimeout - (Date.now() - startedAt)));
            if (step.tool === 'dnsx') {
              // dnsx `-l` list file containing the target host.
              fs.writeFileSync(path.join(jobDir, 'domains.txt'), `${job.target.host}\n`);
            }
            const result = await runTool(step.tool, step.args, runnerDeps, {
              timeoutMs: stepTimeout,
              signal: controller.signal,
            });
            record.exitCode = result.exitCode;
            record.timedOut = result.timedOut;
            record.error = this.redactError(
              result.error ??
                (result.exitCode != null && result.exitCode !== 0
                  ? `exited with code ${result.exitCode}`
                  : result.signal
                    ? `killed by signal ${result.signal}`
                    : null),
            );
            if (record.error) {
              // Troubleshooting only: never expose raw output in reports/UI.
              this.log.warn('tool_failed', {
                jobId,
                tool: step.tool,
                exitCode: result.exitCode,
                timedOut: result.timedOut,
                outputTail: result.output.slice(-2000),
                truncated: result.truncated,
              });
            }

            if (step.tool === 'nmap') {
              const outFile = path.join(jobDir, 'nmap.grepable');
              const raw = fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf8') : result.output;
              observations.ports = parseNmapGrepable(raw);
            } else if (step.tool === 'whatweb') {
              const outFile = path.join(jobDir, 'whatweb.json');
              const raw = fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf8') : result.output;
              const parsed = parseWhatwebJson(raw);
              if (parsed) {
                observations.technologies = parsed.plugins;
                observations.wordpressDetected = parsed.wordpressDetected;
              }
            } else if (step.tool === 'wpscan') {
              const outFile = path.join(jobDir, 'wpscan.json');
              const raw = fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf8') : result.output;
              const parsed = parseWpscanJson(raw);
              observations.wpscan = parsed;
              // WPScan uses semantic exit codes (e.g. 3 = post-run exception).
              // If we got parseable results, the scan succeeded; surface the
              // non-zero code as an informational note rather than a failure.
              if (parsed) {
                record.ok = true;
                record.error = null;
                if (result.exitCode !== 0) {
                  observations.wpscanExitNote = `WPScan exited with code ${result.exitCode}; findings were still collected.`;
                }
              }
            } else if (step.tool === 'nuclei') {
              const outFile = path.join(jobDir, 'nuclei.jsonl');
              const raw = fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf8') : result.output;
              const parsed = parseNucleiJsonl(raw);
              observations.vulnerabilities.push(...parsed);
              // Nuclei may exit 1 when some templates error, but if findings
              // were collected the scan still produced value — treat as success.
              if (parsed.length > 0) {
                record.ok = true;
                record.error = null;
              }
            } else if (step.tool === 'subfinder') {
              const outFile = path.join(jobDir, 'subfinder.json');
              const raw = fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf8') : result.output;
              observations.subdomains = parseSubfinderJson(raw);
            } else if (step.tool === 'dnsx') {
              const outFile = path.join(jobDir, 'dnsx.json');
              const raw = fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf8') : result.output;
              observations.dnsRecords = parseDnsxJson(raw);
            } else if (step.tool === 'testssl') {
              const outFile = path.join(jobDir, 'testssl.json');
              const raw = fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf8') : result.output;
              const parsed = parseTestsslJson(raw);
              observations.tlsHardening = parsed;
              // testssl.sh uses non-zero exit codes for findings; parseable
              // output still means the audit produced results.
              if (parsed.finished) {
                record.ok = true;
                record.error = null;
              }
            } else if (step.tool === 'feroxbuster') {
              const outFile = path.join(jobDir, 'ferox.json');
              const raw = fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf8') : result.output;
              observations.discoveredPaths = parseFeroxJson(raw);
            }
            record.ok = !record.error;
          }
        } catch (e) {
          if (controller.signal.aborted) {
            record.error = (e as Error).message;
            record.timedOut = true;
          } else if (isJobCancelled(job)) {
            record.error = 'Cancelled';
          } else {
            record.error = (e as Error).message;
          }
        }
        record.finishedAt = new Date().toISOString();
        record.durationMs = Date.now() - stepStart;
        toolResults.push(record);

        if (!record.ok && record.error) {
          warnings.push(`${step.label}: ${record.error}`);
        }
      }

      if (isJobCancelled(job)) {
        await this.cleanupDir(jobDir);
        return;
      }

      if (fatalError) {
        job.status = 'failed';
        job.error = fatalError;
        job.finishedAt = new Date().toISOString();
        this.log.warn('job_failed', { jobId, error: fatalError });
        await this.cleanupDir(jobDir);
        return;
      }

      // Conditional WPScan: run local WPScan when WordPress is detected and the
      // plan did not already include it. A failure here is non-fatal: the scan
      // still completes and the report notes the WPScan error.
      if (observations.wordpressDetected && !plan.steps.some((s) => s.tool === 'wpscan')) {
        observations.wpscanRan = true;
        const wpscanResult = await this.runConditionalWpscan(job, runnerDeps, controller, effectiveTimeout, startedAt, jobDir);
        if (wpscanResult) {
          observations.wpscan = wpscanResult.parsed;
          observations.wpscanExitNote = wpscanResult.exitNote;
          toolResults.push(wpscanResult.record);
          if (!wpscanResult.record.ok && wpscanResult.record.error) {
            observations.wpscanError = wpscanResult.record.error;
            warnings.push(`WPScan: ${wpscanResult.record.error}`);
          }
        }
      }

      const findings = buildFindings({
        ports: observations.ports,
        http: observations.http,
        tls: observations.tls,
        technologies: observations.technologies,
        wordpressDetected: observations.wordpressDetected,
        wpscan: observations.wpscan,
        wpscanRan: observations.wpscanRan,
        wpscanError: observations.wpscanError,
        wpscanExitNote: observations.wpscanExitNote,
        vulnerabilities: observations.vulnerabilities,
        discoveredPaths: observations.discoveredPaths,
        cveContext: observations.cveContext,
        host: job.target.host,
        path: job.target.path,
      });

      const finishedAt = new Date();
      const meta = {
        target: job.target.display,
        host: job.target.host,
        path: job.target.path,
        profile: job.profile,
        portScope: plan.portScope,
        startedAt: new Date(startedAt).toISOString(),
        finishedAt: finishedAt.toISOString(),
        durationMs: finishedAt.getTime() - startedAt,
        toolVersions,
        status: 'completed' as const,
        warnings,
      };

      const executiveSummary = buildExecutiveSummary(meta, findings, observations.ports.length);
      const report: ReportModel = {
        meta,
        executiveSummary,
        findings,
        ports: observations.ports,
        http: observations.http,
        tls: observations.tls,
        technologies: observations.technologies,
        wordpress: {
          detected: observations.wordpressDetected,
          wpscanRan: observations.wpscanRan,
          notes: [
            ...(observations.wpscan?.notes ?? []),
            ...(observations.wpscanExitNote ? [observations.wpscanExitNote] : []),
            ...(observations.wpscanError ? [`Local WPScan checks failed: ${observations.wpscanError}`] : []),
          ],
        },
        subdomains: observations.subdomains,
        dnsRecords: observations.dnsRecords,
        whois: observations.whois,
        vulnerabilities: observations.vulnerabilities,
        tlsHardening: observations.tlsHardening,
        discoveredPaths: observations.discoveredPaths,
        cveContext: observations.cveContext,
        toolResults,
        limitations: LIMITATIONS,
      };

      clearTimeout(timeoutHandle);

      const markdownPath = path.join(jobDir, 'report.md');
      const pdfPath = path.join(jobDir, 'report.pdf');
      fs.writeFileSync(markdownPath, renderMarkdown(report), 'utf8');
      await renderPdf(report, pdfPath);

      job.report = report;
      job.artifacts = {
        markdownBytes: fs.statSync(markdownPath).size,
        pdfBytes: fs.statSync(pdfPath).size,
        markdownPath,
        pdfPath,
      };
      job.status = 'completed';
      job.finishedAt = new Date().toISOString();
      this.log.info('job_completed', { jobId, findings: findings.length, ports: observations.ports.length });
    } catch (e) {
      const message = (e as Error).message;
      if (!isJobCancelled(job)) {
        job.status = 'failed';
        job.error = message;
        job.finishedAt = new Date().toISOString();
      }
      this.log.error('job_failed', { jobId, error: message });
      await this.cleanupDir(jobDir);
    } finally {
      this.aborts.delete(jobId);
    }
  }

  private async runConditionalWpscan(
    job: Job,
    runnerDeps: RunnerDeps,
    controller: AbortController,
    effectiveTimeout: number,
    startedAt: number,
    jobDir: string,
  ): Promise<{ record: ToolResultRecord; parsed: ReturnType<typeof parseWpscanJson>; exitNote: string | null } | null> {
    const step = {
      tool: 'wpscan' as const,
      label: 'WPScan (local-only, auto-detected WordPress)',
      args: [
        '--url',
        `${job.target.scheme}://${formatHostForUrl(job.target.host)}${job.target.path}`,
        ...(this.config.wpscanApiToken ? ['--api-token', this.config.wpscanApiToken] : []),
        '--no-banner',
        '--disable-tls-checks',
        '--format',
        'json',
        '--output',
        path.join(jobDir, 'wpscan.json'),
      ],
    };
    try {
      assertApprovedArgs(step.tool, step.args);
      const stepTimeout = Math.max(10_000, Math.min(60_000, effectiveTimeout - (Date.now() - startedAt)));
      const stepStart = Date.now();
      const outFile = path.join(jobDir, 'wpscan.json');
      const result = await runTool(step.tool, step.args, runnerDeps, { timeoutMs: stepTimeout, signal: controller.signal });
      const raw = fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf8') : result.output;
      const parsed = parseWpscanJson(raw);
      // WPScan uses semantic exit codes (0/1/2/3/4/5); a non-zero code after
      // producing parseable JSON is not a hard failure. Treat it as success
      // and surface the code as an informational note.
      const ok = parsed !== null;
      const record: ToolResultRecord = {
        tool: 'wpscan',
        label: step.label,
        ok,
        timedOut: result.timedOut,
        exitCode: result.exitCode,
        error: ok
          ? null
          : this.redactError(
              result.error ??
                (result.exitCode != null && result.exitCode !== 0
                  ? `exited with code ${result.exitCode}`
                  : result.signal
                    ? `killed by signal ${result.signal}`
                    : 'produced no parseable output'),
            ),
        startedAt: new Date(stepStart).toISOString(),
        finishedAt: new Date().toISOString(),
        durationMs: Date.now() - stepStart,
      };
      const exitNote = ok && result.exitCode !== 0 ? `WPScan exited with code ${result.exitCode}; findings were still collected.` : null;
      return { record, parsed, exitNote };
    } catch (e) {
      return null;
    }
  }

  private async captureVersions(job: Job, runnerDeps: RunnerDeps) {
    const tools = ['nmap', 'whatweb', 'wpscan', 'subfinder', 'dnsx', 'nuclei', 'feroxbuster'] as const;
    const versions: Array<{ tool: string; version: string | null }> = [];
    for (const tool of tools) {
      if (tool === 'wpscan') {
        versions.push({ tool, version: await this.captureWpscanVersion(runnerDeps) });
        continue;
      }
      if (tool === 'dnsx') {
        versions.push({ tool, version: await this.captureDnsxVersion(runnerDeps) });
        continue;
      }
      const args = VERSION_PROBE_ARGS[tool];
      if (!args) continue;
      const version = await captureToolVersion(tool, runnerDeps, args);
      versions.push({ tool, version });
    }
    return versions;
  }

  /** dnsx -version prints an ASCII banner; extract the real version line. */
  private async captureDnsxVersion(runnerDeps: RunnerDeps): Promise<string | null> {
    try {
      const res = await runTool('dnsx', ['-version'], runnerDeps, { timeoutMs: 15_000 });
      const match = res.output.match(/Current Version:\s*([\d.]+)/);
      return match ? `dnsx ${match[1]}` : null;
    } catch {
      return null;
    }
  }

  /** Never surface the WPScan API token in reports/logs (it can appear in execa error messages). */
  private redactError(msg: string | null): string | null {
    if (!msg || !this.config.wpscanApiToken) return msg;
    return msg.split(this.config.wpscanApiToken).join('***');
  }

  /**
   * Download a bounded set of same-origin JavaScript files so retire.js can
   * fingerprint vulnerable libraries. Returns an error string or null on success.
   */
  private async downloadJsForRetire(job: Job, jsDir: string, controller: AbortController): Promise<string | null> {
    try {
      fs.mkdirSync(jsDir, { recursive: true });
      const baseUrl = `${job.target.scheme}://${formatHostForUrl(job.target.host)}${job.target.path}`;
      const res = await fetch(baseUrl, {
        signal: controller.signal,
        headers: { 'user-agent': DEFAULT_USER_AGENT, accept: 'text/html' },
      });
      if (!res.ok) return `Could not fetch ${baseUrl} (HTTP ${res.status}).`;
      const html = await res.text();
      const srcs = extractScriptSrcs(html, baseUrl, job.target.host);
      if (srcs.length === 0) return 'No same-origin JavaScript files found to scan.';
      let downloaded = 0;
      for (const src of srcs.slice(0, 10)) {
        try {
          const r = await fetch(src, { signal: controller.signal, headers: { 'user-agent': DEFAULT_USER_AGENT } });
          if (!r.ok) continue;
          const buf = Buffer.from(await r.arrayBuffer());
          fs.writeFileSync(path.join(jsDir, `js-${downloaded}.js`), buf);
          downloaded += 1;
        } catch {
          // skip failed script downloads
        }
      }
      return downloaded === 0 ? 'Could not download any JavaScript files.' : null;
    } catch (e) {
      if (controller.signal.aborted) return 'JavaScript download interrupted.';
      return (e as Error).message;
    }
  }

  /** `wpscan --version` prints a large ASCII banner first; extract the real version. */
  private async captureWpscanVersion(runnerDeps: RunnerDeps): Promise<string | null> {
    try {
      const res = await runTool('wpscan', ['--version'], runnerDeps, { timeoutMs: 15_000 });
      const match = res.output.match(/Version\s+(\d+\.\d+(?:\.\d+)?)/);
      return match ? `WPScan ${match[1]}` : null;
    } catch {
      return null;
    }
  }

  private async sweepArtifacts(): Promise<void> {
    const ttlMs = this.config.artifactTtlMinutes * 60_000;
    let dir: fs.Dirent[];
    try {
      dir = fs.readdirSync(this.config.artifactDir, { withFileTypes: true });
    } catch {
      return;
    }
    const now = Date.now();
    for (const entry of dir) {
      if (!entry.isDirectory()) continue;
      const full = path.join(this.config.artifactDir, entry.name);
      try {
        const stat = fs.statSync(full);
        if (now - stat.mtimeMs > ttlMs) {
          fs.rmSync(full, { recursive: true, force: true });
          this.log.debug('artifact_swept', { dir: entry.name });
        }
      } catch {
        // ignore
      }
    }
  }

  private async cleanupDir(dir: string): Promise<void> {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  }
}

export { PORT_SCOPE_LABELS };
