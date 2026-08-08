import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { WorkerConfig } from '../shared/config';
import type { Logger } from '../shared/logger';
import { PORT_SCOPE_LABELS } from '../shared/constants';
import { expandProfile, assertApprovedArgs } from '../shared/profiles';
import { buildExecutiveSummary, renderMarkdown } from '../shared/report';
import { parseTarget } from '../shared/targets';
import type { CustomScanOptions, DiscoveredPort, Job, NormalizedTarget, ReportModel, ScanProfile, ToolResultRecord } from '../shared/types';
import { assertNoRebinding, defaultResolver, resolveAndValidate, type DnsResolver, type ResolveResult } from './dns';
import { buildFindings } from './findings';
import { httpCheck as defaultHttpCheck, tlsCheck as defaultTlsCheck } from './http';
import { formatHostForUrl } from '../shared/net';
import type { HttpObservation, TlsObservation } from '../shared/types';
import { parseNmapGrepable, parseWhatwebJson, parseWpscanJson, type WpscanResult } from './parsers';
import { renderPdf } from './pdf';
import { ScanQueue } from './queue';
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
}

/**
 * Escape-hatch read of cancellation state. The queue mutates `job.status`
 * asynchronously (via cancelJob), so TS control-flow narrowing on the property
 * is not valid here; reading through a function avoids bogus narrowing errors.
 */
function isJobCancelled(job: Job): boolean {
  return job.status === 'cancelled';
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

export interface ScannerDeps {
  resolver?: DnsResolver;
  httpCheck?: typeof defaultHttpCheck;
  tlsCheck?: typeof defaultTlsCheck;
}

const LIMITATIONS = [
  'TCP-only scanning; UDP and all-port scans are not performed.',
  'Each scan is capped at 5 minutes and the configured port scope.',
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

  async createJob(input: { target: string; profile: ScanProfile; custom?: CustomScanOptions }): Promise<Job> {
    const target = parseTarget(input.target);
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
      return this.enqueue(jobId, target, input.profile, input.custom);
    }

    const jobId = crypto.randomUUID();
    return this.enqueue(jobId, target, input.profile, input.custom);
  }

  private enqueue(jobId: string, target: NormalizedTarget, profile: ScanProfile, custom?: CustomScanOptions): Job {
    const jobDir = path.join(this.config.artifactDir, jobId);
    fs.mkdirSync(jobDir, { recursive: true });

    const plan = expandProfile(profile, target, custom ?? null, {
      outputPath: (name) => path.join(jobDir, name),
    });

    // Assert the generated plan only contains approved arguments (defense-in-depth).
    for (const step of plan.steps) {
      assertApprovedArgs(step.tool, step.args);
    }

    const createdAt = new Date().toISOString();
    const job: Job = {
      id: jobId,
      status: 'queued',
      target,
      profile,
      custom: custom ?? null,
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
    this.log.info('job_queued', { jobId, profile, host: target.host });
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

      const plan = expandProfile(job.profile, job.target, job.custom, {
        outputPath: (name) => path.join(jobDir, name),
      });

      const observations: Observations = {
        ports: [],
        http: null,
        tls: null,
        technologies: [],
        wordpressDetected: false,
        wpscan: null,
        wpscanRan: false,
        wpscanError: null,
      };
      const toolResults: ToolResultRecord[] = [];
      const warnings: string[] = [];
      let fatalError: string | null = null;

      for (const step of plan.steps) {
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
          } else {
            const stepTimeout = Math.max(10_000, Math.min(60_000, effectiveTimeout - (Date.now() - startedAt)));
            const result = await runTool(step.tool, step.args, runnerDeps, {
              timeoutMs: stepTimeout,
              signal: controller.signal,
            });
            record.exitCode = result.exitCode;
            record.timedOut = result.timedOut;
            record.error = result.error ?? (result.exitCode !== 0 ? `exited with code ${result.exitCode}` : null);
            record.ok = !record.error;
            if (!record.ok) {
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
              observations.wpscan = parseWpscanJson(raw);
            }
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
          notes: [...(observations.wpscan?.notes ?? []), ...(observations.wpscanError ? [`Local WPScan checks failed: ${observations.wpscanError}`] : [])],
        },
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
  ): Promise<{ record: ToolResultRecord; parsed: ReturnType<typeof parseWpscanJson> } | null> {
    const step = {
      tool: 'wpscan' as const,
      label: 'WPScan (local-only, auto-detected WordPress)',
      args: [
        '--url',
        `${job.target.scheme}://${formatHostForUrl(job.target.host)}${job.target.path}`,
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
      const record: ToolResultRecord = {
        tool: 'wpscan',
        label: step.label,
        ok: result.exitCode === 0,
        timedOut: result.timedOut,
        exitCode: result.exitCode,
        error: result.error ?? (result.exitCode !== 0 ? `exited with code ${result.exitCode}` : null),
        startedAt: new Date(stepStart).toISOString(),
        finishedAt: new Date().toISOString(),
        durationMs: Date.now() - stepStart,
      };
      const raw = fs.existsSync(outFile) ? fs.readFileSync(outFile, 'utf8') : result.output;
      return { record, parsed: parseWpscanJson(raw) };
    } catch (e) {
      return null;
    }
  }

  private async captureVersions(job: Job, runnerDeps: RunnerDeps) {
    const tools = ['nmap', 'whatweb', 'wpscan'] as const;
    const versions: Array<{ tool: string; version: string | null }> = [];
    for (const tool of tools) {
      const args = VERSION_PROBE_ARGS[tool];
      if (!args) continue;
      const version = await captureToolVersion(tool, runnerDeps, args);
      versions.push({ tool, version });
    }
    return versions;
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
