import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getDb, resetDbForTests } from '../src/server/db';
import { createUser } from '../src/server/users';
import { applyScanEvent, recordScanQueued } from '../src/server/scans';
import { computeScanDiff } from '../src/server/scan-diffs';
import type { ScanEventPayload, ScanFindingSummary } from '../src/shared/types';

let dbPath: string;

beforeAll(() => {
  dbPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sitedig-diffs-')), 'test.sqlite');
  process.env.DB_PATH = dbPath;
  process.env.DEPLOYMENT_MODE = 'self-hosted';
  process.env.APP_BASE_URL = 'http://localhost:3000';
});

beforeEach(() => {
  resetDbForTests();
  getDb().exec('DELETE FROM scan_findings; DELETE FROM scan_tools; DELETE FROM scans; DELETE FROM users;');
});

afterAll(() => {
  resetDbForTests();
  fs.rmSync(path.dirname(dbPath), { recursive: true, force: true });
});

function finding(fingerprint: string, title: string, severity: ScanFindingSummary['severity'], sourceTools: ScanFindingSummary['sourceTools']): ScanFindingSummary {
  return { fingerprint, title, severity, category: 'misconfiguration', affected: 'example.com', sourceTools };
}

function event(id: string, host: string, findingsDetail: ScanFindingSummary[], tools: ScanEventPayload['tools']): ScanEventPayload {
  const findings = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const f of findingsDetail) findings[f.severity] += 1;
  return {
    scanId: id,
    status: 'completed',
    targetRaw: `https://${host}`,
    host,
    path: '/',
    scheme: 'https',
    profile: 'quick',
    portScope: 'common',
    modules: [],
    resolvedIps: ['93.184.216.34'],
    ipVersion: 'ipv4',
    startedAt: new Date(Date.now() - 5000).toISOString(),
    finishedAt: new Date().toISOString(),
    durationMs: 5000,
    portCount: 0,
    findings,
    findingsDetail,
    tools,
    toolOk: tools.filter((t) => t.ok).length,
    toolTotal: tools.length,
    error: null,
  };
}

describe('scan diffs', () => {
  it('reports new, resolved, severity changes, and risk delta', () => {
    const user = createUser({ email: 'diff@example.com', passwordHash: 'x', verified: true });
    recordScanQueued({ id: 'scan-1', userId: user.id, userEmail: user.email, targetRaw: 'https://example.com', host: 'example.com', path: '/', scheme: 'https', profile: 'quick', modules: [] });
    applyScanEvent(
      event('scan-1', 'example.com', [finding('a', 'Missing HSTS', 'high', ['header-posture']), finding('b', 'Weak CSP', 'medium', ['http'])], [{ tool: 'header-posture', ok: true, timedOut: false, exitCode: null, durationMs: 10 }, { tool: 'http', ok: true, timedOut: false, exitCode: null, durationMs: 10 }]),
    );
    recordScanQueued({ id: 'scan-2', userId: user.id, userEmail: user.email, targetRaw: 'https://example.com', host: 'example.com', path: '/', scheme: 'https', profile: 'quick', modules: [] });
    applyScanEvent(
      event('scan-2', 'example.com', [finding('a', 'Missing HSTS', 'critical', ['header-posture']), finding('c', 'Missing SRI', 'low', ['page-recon'])], [{ tool: 'header-posture', ok: true, timedOut: false, exitCode: null, durationMs: 10 }, { tool: 'page-recon', ok: true, timedOut: false, exitCode: null, durationMs: 10 }, { tool: 'http', ok: true, timedOut: false, exitCode: null, durationMs: 10 }]),
    );

    const diff = computeScanDiff('scan-2')!;
    expect(diff.previousScanId).toBe('scan-1');
    expect(diff.newFindings.map((f) => f.title)).toEqual(['Missing SRI']);
    expect(diff.resolvedFindings.map((f) => f.title)).toEqual(['Weak CSP']);
    expect(diff.severityChanges).toHaveLength(1);
    expect(diff.severityChanges[0]).toMatchObject({ from: 'high', to: 'critical' });
    expect(diff.riskDelta).not.toBeNull();
  });

  it('marks missing findings as not assessed when a source tool failed', () => {
    const user = createUser({ email: 'notassessed@example.com', passwordHash: 'x', verified: true });
    recordScanQueued({ id: 'scan-a', userId: user.id, userEmail: user.email, targetRaw: 'https://example.com', host: 'example.com', path: '/', scheme: 'https', profile: 'quick', modules: [] });
    applyScanEvent(event('scan-a', 'example.com', [finding('a', 'Weak CSP', 'medium', ['http'])], [{ tool: 'http', ok: true, timedOut: false, exitCode: null, durationMs: 10 }]));
    recordScanQueued({ id: 'scan-b', userId: user.id, userEmail: user.email, targetRaw: 'https://example.com', host: 'example.com', path: '/', scheme: 'https', profile: 'quick', modules: [] });
    applyScanEvent(event('scan-b', 'example.com', [], [{ tool: 'http', ok: false, timedOut: true, exitCode: null, durationMs: 10 }]));

    const diff = computeScanDiff('scan-b')!;
    expect(diff.resolvedFindings).toHaveLength(0);
    expect(diff.notAssessed.map((f) => f.title)).toEqual(['Weak CSP']);
  });

  it('returns an empty diff when there is no previous scan', () => {
    const user = createUser({ email: 'first@example.com', passwordHash: 'x', verified: true });
    recordScanQueued({ id: 'scan-first', userId: user.id, userEmail: user.email, targetRaw: 'https://example.com', host: 'example.com', path: '/', scheme: 'https', profile: 'quick', modules: [] });
    applyScanEvent(event('scan-first', 'example.com', [finding('a', 'Weak CSP', 'medium', ['http'])], [{ tool: 'http', ok: true, timedOut: false, exitCode: null, durationMs: 10 }]));
    const diff = computeScanDiff('scan-first')!;
    expect(diff.previousScanId).toBeNull();
    expect(diff.newFindings).toHaveLength(0);
    expect(diff.previousRisk).toBeNull();
  });
});
