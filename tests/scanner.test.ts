import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { WorkerConfig } from '../src/shared/config';
import { createLogger } from '../src/shared/logger';
import { QueueFullError, ScannerService, TargetRejectedError } from '../src/worker/scanner';
import type { DnsResolver } from '../src/worker/dns';
import type { HttpObservation, TlsObservation } from '../src/shared/types';

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
