import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { WorkerConfig } from '../src/shared/config';
import type { ModuleId } from '../src/shared/types';
import { createLogger } from '../src/shared/logger';
import { QueueFullError, ScannerService, TargetRejectedError, ModuleNotEnabledError } from '../src/worker/scanner';
import type { DnsResolver } from '../src/worker/dns';
import type { HttpObservation, TlsObservation, WhoisInfo, CveContextFinding } from '../src/shared/types';

const BIN = path.join(__dirname, 'fixtures', 'stub-bin');

function makeConfig(overrides: Partial<WorkerConfig> = {}): WorkerConfig {
  return {
    port: 0,
    serviceToken: '',
    maxConcurrentScans: 1,
    maxQueue: 2,
    scanTimeoutMs: 30_000,
    maxToolOutputBytes: 1_000_000,
    logLevel: 'silent',
    allowInternalTargets: true,
    artifactDir: fs.mkdtempSync(path.join(os.tmpdir(), 'sitedig-test-')),
    artifactTtlMinutes: 30,
    scannerBinDir: BIN,
    enabledModules: new Set<ModuleId>(),
    wpscanApiToken: '',
    nucleiTemplates: [],
    wordlistPath: '/opt/sitedig/wordlists/common.txt',
    ...overrides,
  };
}

function publicResolver(): DnsResolver {
  return { resolve: async () => ['93.184.216.34'] };
}

function fakeHttp(): Promise<HttpObservation> {
  return Promise.resolve({ status: 200, finalUrl: 'https://example.com/', server: 'nginx', poweredBy: null, headers: { server: 'nginx' }, redirects: [], error: null });
}

function fakeTls(): Promise<TlsObservation> {
  return Promise.resolve({ connected: true, protocol: 'TLSv1.3', subjectCn: 'example.com', issuerCn: 'CA', validFrom: 'x', validTo: 'y', daysRemaining: 100, selfSigned: false, error: null });
}

function fakeRda(): Promise<WhoisInfo> {
  return Promise.resolve({ registrar: 'Test Registrar', creationDate: '2020-01-01', updateDate: null, expiryDate: '2030-01-01', status: [], nameservers: ['ns1.example.com'], error: null });
}

function fakeOsv(): Promise<CveContextFinding[]> {
  return Promise.resolve([{ id: 'jquery@2.2.4', ecosystem: 'npm', name: 'jquery', version: '2.2.4', cveCount: 3, severities: { critical: 0, high: 1, medium: 2, low: 0 } }]);
}

function makeService(config: WorkerConfig) {
  return new ScannerService(config, createLogger({ LOG_LEVEL: config.logLevel }), {
    resolver: publicResolver(),
    httpCheck: fakeHttp,
    tlsCheck: fakeTls,
  });
}

const waitFor = async (fn: () => boolean, timeoutMs = 15_000) => {
  const start = Date.now();
  for (;;) {
    if (fn()) return;
    if (Date.now() - start > timeoutMs) throw new Error('Timed out waiting for condition');
    await new Promise((r) => setTimeout(r, 50));
  }
};

describe('ScannerService integration', () => {
  let config: WorkerConfig;
  let service: ScannerService;
  let artifactDir: string;

  beforeEach(() => {
    artifactDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sitedig-test-'));
    config = makeConfig({ artifactDir });
    service = makeService(config, null as never);
    service.start();
  });

  afterEach(() => {
    service.stop();
    fs.rmSync(artifactDir, { recursive: true, force: true });
  });

  it('runs a quick scan end-to-end and produces artifacts', async () => {
    const job = await service.createJob({ target: 'https://example.com/shop', profile: 'quick' });
    await waitFor(() => service.getJob(job.id)?.status === 'completed');

    const done = service.getJob(job.id)!;
    expect(done.status).toBe('completed');
    expect(done.artifacts).not.toBeNull();
    expect(fs.existsSync(done.artifacts!.pdfPath)).toBe(true);
    expect(fs.existsSync(done.artifacts!.markdownPath)).toBe(true);

    const report = done.report!;
    expect(report.ports.some((p) => p.port === 80 || p.port === 443)).toBe(true);
    expect(report.wordpress?.detected).toBe(true);
    expect(report.wordpress?.wpscanRan).toBe(true);
    expect(report.findings.some((f) => f.category === 'wordpress')).toBe(true);
    expect(report.meta.path).toBe('/shop');
  });

  it('rejects blocked targets at creation time', async () => {
    const resolver: DnsResolver = { resolve: async () => ['10.0.0.5'] };
    const svc = new ScannerService(makeConfig({ allowInternalTargets: false }), createLogger({ LOG_LEVEL: 'silent' }), {
      resolver,
      httpCheck: fakeHttp,
      tlsCheck: fakeTls,
    });
    await expect(svc.createJob({ target: 'internal.local', profile: 'quick' })).rejects.toThrow(TargetRejectedError);
  });

  it('fails a job when DNS rebinds after enqueue', async () => {
    let calls = 0;
    const resolver: DnsResolver = {
      resolve: async () => {
        calls += 1;
        // First resolution (enqueue) is public; afterwards it points internal.
        return calls === 1 ? ['93.184.216.34'] : ['10.0.0.5'];
      },
    };
    const svc = new ScannerService(makeConfig({ allowInternalTargets: false }), createLogger({ LOG_LEVEL: 'silent' }), {
      resolver,
      httpCheck: fakeHttp,
      tlsCheck: fakeTls,
    });
    svc.start();
    const job = await svc.createJob({ target: 'example.com', profile: 'quick' });
    await waitFor(() => svc.getJob(job.id)?.status === 'failed');
    const done = svc.getJob(job.id)!;
    expect(done.error).toMatch(/blocked|rebinding/i);
    svc.stop();
  });

  it('marks wpscan as run (with error) when the local wpscan fails', async () => {
    const svc = new ScannerService(makeConfig({ scannerBinDir: path.join(__dirname, 'fixtures', 'stub-bin-failwpscan') }), createLogger({ LOG_LEVEL: 'silent' }), {
      resolver: publicResolver(),
      httpCheck: fakeHttp,
      tlsCheck: fakeTls,
    });
    svc.start();
    const job = await svc.createJob({ target: 'example.com', profile: 'quick' });
    await waitFor(() => svc.getJob(job.id)?.status === 'completed');
    const done = svc.getJob(job.id)!;
    expect(done.status).toBe('completed');
    const wp = done.report?.wordpress!;
    expect(wp.detected).toBe(true);
    expect(wp.wpscanRan).toBe(true);
    expect(wp.notes.some((n) => n.includes('WPScan checks failed'))).toBe(true);
    const finding = done.report?.findings.find((f) => f.category === 'wordpress')!;
    expect(finding.evidence.some((e) => e.includes('wpscan_error'))).toBe(true);
    svc.stop();
  });

  it('treats a non-zero wpscan exit as success when results are collected', async () => {
    const svc = new ScannerService(makeConfig({ scannerBinDir: path.join(__dirname, 'fixtures', 'stub-bin-partialwpscan') }), createLogger({ LOG_LEVEL: 'silent' }), {
      resolver: publicResolver(),
      httpCheck: fakeHttp,
      tlsCheck: fakeTls,
    });
    svc.start();
    const job = await svc.createJob({ target: 'example.com', profile: 'quick' });
    await waitFor(() => svc.getJob(job.id)?.status === 'completed');
    const done = svc.getJob(job.id)!;
    expect(done.status).toBe('completed');
    expect(done.report?.meta.warnings.some((w) => w.includes('WPScan'))).toBe(false);

    const wp = done.report?.wordpress!;
    expect(wp.wpscanRan).toBe(true);
    expect(wp.notes.some((n) => n.includes('exited with code 3'))).toBe(true);
    expect(wp.notes.some((n) => n.includes('failed'))).toBe(false);

    const toolResult = done.report?.toolResults.find((t) => t.tool === 'wpscan')!;
    expect(toolResult.ok).toBe(true);
    expect(toolResult.exitCode).toBe(3);

    const finding = done.report?.findings.find((f) => f.category === 'wordpress')!;
    expect(finding.description).toContain('exited with code 3');
    expect(finding.description).not.toContain('failed');
    expect(finding.evidence.some((e) => e.includes('wpscan_error'))).toBe(false);
    svc.stop();
  });

  it('rejects a paid module that is not enabled', async () => {
    const svc = makeService(config); // enabledModules is empty by default
    await expect(svc.createJob({ target: 'example.com', profile: 'quick', modules: ['asset-discovery'] })).rejects.toThrow(ModuleNotEnabledError);
  });

  it('runs an asset-discovery module end-to-end', async () => {
    const cfg = makeConfig({ enabledModules: new Set<ModuleId>(['asset-discovery']) });
    const svc = new ScannerService(cfg, createLogger({ LOG_LEVEL: 'silent' }), {
      resolver: publicResolver(),
      httpCheck: fakeHttp,
      tlsCheck: fakeTls,
      rdap: fakeRda,
      osv: fakeOsv,
      downloadJs: async () => null,
    });
    svc.start();
    const job = await svc.createJob({ target: 'example.com', profile: 'quick', modules: ['asset-discovery'] });
    await waitFor(() => svc.getJob(job.id)?.status === 'completed');
    const done = svc.getJob(job.id)!;
    expect(done.status).toBe('completed');
    expect(done.report?.subdomains.length).toBeGreaterThan(0);
    expect(done.report?.dnsRecords.length).toBeGreaterThan(0);
    expect(done.report?.whois?.registrar).toBe('Test Registrar');
    expect(done.report?.toolResults.some((t) => t.tool === 'subfinder')).toBe(true);
    expect(done.report?.toolResults.some((t) => t.tool === 'dnsx')).toBe(true);
    expect(done.report?.toolResults.some((t) => t.tool === 'rdap')).toBe(true);
    svc.stop();
  });

  it('runs vuln-scan and cve-context modules end-to-end', async () => {
    const cfg = makeConfig({ enabledModules: new Set<ModuleId>(['vuln-scan', 'cve-context']), nucleiTemplates: [path.join(__dirname, 'fixtures', 'templates', 'fixture.yaml')] });
    const svc = new ScannerService(cfg, createLogger({ LOG_LEVEL: 'silent' }), {
      resolver: publicResolver(),
      httpCheck: fakeHttp,
      tlsCheck: fakeTls,
      rdap: fakeRda,
      osv: fakeOsv,
      downloadJs: async () => null,
    });
    svc.start();
    const job = await svc.createJob({ target: 'example.com', profile: 'quick', modules: ['vuln-scan', 'cve-context'] });
    await waitFor(() => svc.getJob(job.id)?.status === 'completed');
    const done = svc.getJob(job.id)!;
    expect(done.status).toBe('completed');
    expect(done.report?.vulnerabilities.some((v) => v.source === 'nuclei')).toBe(true);
    expect(done.report?.vulnerabilities.some((v) => v.source === 'retire')).toBe(true);
    expect(done.report?.cveContext.length).toBeGreaterThan(0);
    const vulnFindings = done.report?.findings.filter((f) => f.category === 'vulnerability') ?? [];
    expect(vulnFindings.length).toBeGreaterThan(0);
    svc.stop();
  });

  it('runs tls-hardening and content-discovery modules end-to-end', async () => {
    const cfg = makeConfig({
      enabledModules: new Set<ModuleId>(['tls-hardening', 'content-discovery']),
      wordlistPath: path.join(__dirname, 'fixtures', 'wordlists', 'common.txt'),
    });
    const svc = new ScannerService(cfg, createLogger({ LOG_LEVEL: 'silent' }), {
      resolver: publicResolver(),
      httpCheck: fakeHttp,
      tlsCheck: fakeTls,
      rdap: fakeRda,
      osv: fakeOsv,
      downloadJs: async () => null,
    });
    svc.start();
    const job = await svc.createJob({ target: 'example.com', profile: 'quick', modules: ['tls-hardening', 'content-discovery'] });
    await waitFor(() => svc.getJob(job.id)?.status === 'completed');
    const done = svc.getJob(job.id)!;
    expect(done.status).toBe('completed');
    expect(done.report?.tlsHardening?.weaknesses.length).toBeGreaterThan(0);
    expect(done.report?.discoveredPaths.length).toBeGreaterThan(0);
    svc.stop();
  });

  it('redacts the WPScan API token from report errors', async () => {
    const token = 'super-secret-wpscan-token';
    const svc = new ScannerService(makeConfig({ scannerBinDir: path.join(__dirname, 'fixtures', 'stub-bin-failwpscan'), wpscanApiToken: token }), createLogger({ LOG_LEVEL: 'silent' }), {
      resolver: publicResolver(),
      httpCheck: fakeHttp,
      tlsCheck: fakeTls,
      rdap: fakeRda,
      osv: fakeOsv,
      downloadJs: async () => null,
    });
    svc.start();
    const job = await svc.createJob({ target: 'example.com', profile: 'quick' });
    await waitFor(() => svc.getJob(job.id)?.status === 'completed');
    const done = svc.getJob(job.id)!;
    const reportText = JSON.stringify(done.report);
    expect(reportText).not.toContain(token);
    expect(reportText).toContain('***');
    svc.stop();
  });

  it('returns a queue-full error when the queue is saturated', async () => {
    const slowHttp: typeof fakeHttp = async () => {
      await new Promise((r) => setTimeout(r, 3000));
      return fakeHttp();
    };
    const slowSvc = new ScannerService(config, createLogger({ LOG_LEVEL: 'silent' }), { resolver: publicResolver(), httpCheck: slowHttp, tlsCheck: fakeTls });
    slowSvc.start();
    await slowSvc.createJob({ target: 'example.com', profile: 'quick' });
    await slowSvc.createJob({ target: 'example.com', profile: 'quick' });
    await slowSvc.createJob({ target: 'example.com', profile: 'quick' });
    await expect(slowSvc.createJob({ target: 'example.com', profile: 'quick' })).rejects.toThrow(QueueFullError);
    slowSvc.stop();
  });
});
