import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { AddressInfo } from 'node:net';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { WorkerConfig } from '../src/shared/config';
import type { ModuleId } from '../src/shared/types';
import { createLogger } from '../src/shared/logger';
import { ScannerService } from '../src/worker/scanner';
import { startWorkerServer } from '../src/worker/index';
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
    enabledModules: new Set<ModuleId>(),
    wpscanApiToken: '',
    nucleiTemplates: [],
    wordlistPath: '/opt/sitedig/wordlists/common.txt',
    ...overrides,
  };
}

function fakeHttp(): Promise<HttpObservation> {
  return Promise.resolve({ status: 200, finalUrl: 'https://example.com/', server: 'nginx', poweredBy: null, headers: {}, redirects: [], error: null });
}
function fakeTls(): Promise<TlsObservation> {
  return Promise.resolve({ connected: true, protocol: 'TLSv1.3', subjectCn: 'example.com', issuerCn: 'CA', validFrom: 'x', validTo: 'y', daysRemaining: 100, selfSigned: false, error: null });
}
function publicResolver(): DnsResolver {
  return { resolve: async () => ['93.184.216.34'] };
}

const waitFor = async (fn: () => boolean | Promise<boolean>, timeoutMs = 15_000) => {
  const start = Date.now();
  for (;;) {
    if (await Promise.resolve(fn())) return;
    if (Date.now() - start > timeoutMs) throw new Error('Timed out waiting for condition');
    await new Promise((r) => setTimeout(r, 50));
  }
};

describe('worker HTTP server', () => {
  let config: WorkerConfig;
  let server: http.Server;
  let baseUrl: string;

  const setup = (overrides: Partial<WorkerConfig> = {}) => {
    config = makeConfig(overrides);
    const service = new ScannerService(config, createLogger({ LOG_LEVEL: 'silent' }), {
      resolver: publicResolver(),
      httpCheck: fakeHttp,
      tlsCheck: fakeTls,
    });
    service.start();
    server = startWorkerServer({ config, service });
    return new Promise<http.Server>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const { port } = server.address() as AddressInfo;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve(server);
      });
    });
  };

  beforeEach(async () => {
    await setup();
  });

  afterEach(() => {
    server.close();
  });

  const json = async (pathName: string, init?: RequestInit) => {
    const res = await fetch(`${baseUrl}${pathName}`, init);
    const body = await res.json();
    return { status: res.status, body: body as Record<string, unknown> };
  };

  it('serves unauthenticated health', async () => {
    const res = await fetch(`${baseUrl}/health`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; service: string };
    expect(body.ok).toBe(true);
    expect(body.service).toBe('worker');
  });

  it('rejects scans without consent', async () => {
    const { status } = await json('/jobs', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target: 'example.com', profile: 'quick', consent: false }),
    });
    expect(status).toBe(400);
  });

  it('rejects scans with a blocked target', async () => {
    const blockedConfig = makeConfig({ allowInternalTargets: false });
    server.close();
    const service = new ScannerService(blockedConfig, createLogger({ LOG_LEVEL: 'silent' }), {
      resolver: { resolve: async () => ['10.0.0.5'] },
      httpCheck: fakeHttp,
      tlsCheck: fakeTls,
    });
    service.start();
    server = startWorkerServer({ config: blockedConfig, service });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    const { port } = server.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${port}`;

    const { status } = await json('/jobs', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target: 'internal.local', profile: 'quick', consent: true }),
    });
    expect(status).toBe(422);
  });

  it('creates, polls, and downloads a completed scan', async () => {
    const created = await json('/jobs', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target: 'https://example.com/app', profile: 'quick', consent: true }),
    });
    expect(created.status).toBe(201);
    const jobId = (created.body as { jobId: string }).jobId;

    await waitFor(async () => {
      const s = await json(`/jobs/${jobId}`);
      const job = (s.body as { job: { status: string } }).job;
      return job.status === 'completed';
    });

    const statusRes = await json(`/jobs/${jobId}`);
    const view = (statusRes.body as { job: { status: string; hasArtifacts: boolean; summaryCounts: unknown } }).job;
    expect(view.status).toBe('completed');
    expect(view.hasArtifacts).toBe(true);
    expect(view.summaryCounts).not.toBeNull();

    const pdfRes = await fetch(`${baseUrl}/jobs/${jobId}/artifacts/pdf`);
    expect(pdfRes.status).toBe(200);
    const bytes = Buffer.from(await pdfRes.arrayBuffer());
    expect(bytes.length).toBeGreaterThan(100);
    expect(bytes.subarray(0, 4).toString()).toBe('%PDF');

    const mdRes = await fetch(`${baseUrl}/jobs/${jobId}/artifacts/markdown`);
    expect(mdRes.status).toBe(200);
    const md = await mdRes.text();
    expect(md).toContain('# SiteDig Scan Report');

    // Artifacts are deleted after delivery.
    const secondPdf = await fetch(`${baseUrl}/jobs/${jobId}/artifacts/pdf`);
    expect([404, 409]).toContain(secondPdf.status);
  });

  it('requires a token when configured', async () => {
    server.close();
    const securedConfig = makeConfig({ serviceToken: 'secret' });
    const service = new ScannerService(securedConfig, createLogger({ LOG_LEVEL: 'silent' }), {
      resolver: publicResolver(),
      httpCheck: fakeHttp,
      tlsCheck: fakeTls,
    });
    service.start();
    server = startWorkerServer({ config: securedConfig, service });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    const { port } = server.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${port}`;

    const noAuth = await fetch(`${baseUrl}/jobs/whatever`);
    expect(noAuth.status).toBe(401);

    const withAuth = await fetch(`${baseUrl}/jobs/whatever`, { headers: { authorization: 'Bearer secret' } });
    expect(withAuth.status).toBe(404);
  });

  it('reports an unknown job as not found', async () => {
    const { status } = await json('/jobs/does-not-exist');
    expect(status).toBe(404);
  });

  it('lists modules with enabled flags', async () => {
    const res = await fetch(`${baseUrl}/modules`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { modules: Array<{ id: string; enabled: boolean }> };
    expect(body.modules.some((m) => m.id === 'asset-discovery')).toBe(true);
    expect(body.modules.every((m) => m.enabled === false)).toBe(true);
  });

  it('rejects scans requesting a disabled paid module', async () => {
    const { status, body } = await json('/jobs', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target: 'example.com', profile: 'quick', consent: true, modules: ['asset-discovery'] }),
    });
    expect(status).toBe(403);
    expect((body as { error?: { code?: string } }).error?.code).toBe('module_not_enabled');
  });
});
