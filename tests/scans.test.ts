import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getDb, resetDbForTests } from '../src/server/db';
import { createUser } from '../src/server/users';
import {
  applyScanEvent,
  countActiveScans,
  getScan,
  getScanFindings,
  getScanForUser,
  getScanStats,
  listAdminScans,
  listUserScans,
  recordScanQueued,
  sweepScanHistory,
  toScanView,
} from '../src/server/scans';
import { buildDigestData } from '../src/server/digest';
import type { ScanEventPayload } from '../src/shared/types';

let dbPath: string;

beforeAll(() => {
  dbPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sitedig-scans-')), 'test.sqlite');
  process.env.DB_PATH = dbPath;
  process.env.DEPLOYMENT_MODE = 'self-hosted';
  process.env.APP_BASE_URL = 'http://localhost:3000';
});

beforeEach(() => {
  resetDbForTests();
  // The temp DB file persists across tests; clear tables for isolation.
  getDb().exec('DELETE FROM scan_tools; DELETE FROM scans; DELETE FROM recovery_codes; DELETE FROM mfa_challenges; DELETE FROM users; DELETE FROM app_settings;');
});

afterAll(() => {
  resetDbForTests();
  fs.rmSync(path.dirname(dbPath), { recursive: true, force: true });
});

function queued(userId: number, id: string, host: string, profile = 'quick', modules: string[] = []): void {
  recordScanQueued({
    id,
    userId,
    userEmail: 'user@example.com',
    targetRaw: `https://${host}`,
    host,
    path: '/',
    scheme: 'https',
    profile,
    modules,
  });
}

function event(id: string, host: string, overrides: Partial<ScanEventPayload> = {}): ScanEventPayload {
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
    portCount: 2,
    findings: { critical: 1, high: 0, medium: 2, low: 0, informational: 1 },
    tools: [
      { tool: 'nmap', ok: true, timedOut: false, exitCode: 0, durationMs: 3000 },
      { tool: 'whatweb', ok: false, timedOut: true, exitCode: null, durationMs: 2000 },
    ],
    toolOk: 1,
    toolTotal: 2,
    error: null,
    ...overrides,
  };
}

describe('scan history', () => {
  it('records a queued scan then applies the completion event', () => {
    const user = createUser({ email: 'u1@example.com', passwordHash: 'x', verified: true });
    queued(user.id, 'scan-1', 'example.com');
    expect(getScan('scan-1')?.status).toBe('queued');

    applyScanEvent(event('scan-1', 'example.com'));

    const row = getScan('scan-1')!;
    expect(row.status).toBe('completed');
    expect(row.duration_ms).toBe(5000);
    const view = toScanView(row);
    expect(view.resolvedIps).toEqual(['93.184.216.34']);
    expect(view.findings).toEqual({ critical: 1, high: 0, medium: 2, low: 0, informational: 1 });
    expect(view.toolTotal).toBe(2);
    expect(view.toolOk).toBe(1);
  });

  it('persists finding summaries and replaces them on re-apply', () => {
    const user = createUser({ email: 'summaries@example.com', passwordHash: 'x', verified: true });
    queued(user.id, 'scan-summary', 'example.com');
    const detail = [
      { fingerprint: 'fp-1', title: 'Weak CSP', severity: 'medium' as const, category: 'misconfiguration' as const, affected: 'example.com', sourceTools: ['header-posture' as const] },
    ];
    applyScanEvent(event('scan-summary', 'example.com', { findingsDetail: detail }));
    expect(getScanFindings('scan-summary')).toEqual(detail);
    applyScanEvent(
      event('scan-summary', 'example.com', {
        findingsDetail: [{ ...detail[0], severity: 'high' }],
      }),
    );
    expect(getScanFindings('scan-summary')).toHaveLength(1);
    expect(getScanFindings('scan-summary')[0].severity).toBe('high');
  });

  it('is idempotent and keeps user attribution across re-applies', () => {
    const user = createUser({ email: 'u2@example.com', passwordHash: 'x', verified: true });
    queued(user.id, 'scan-2', 'example.com');
    applyScanEvent(event('scan-2', 'example.com'));
    applyScanEvent(event('scan-2', 'example.com'));
    const rows = listUserScans(user.id);
    expect(rows).toHaveLength(1);
    expect(rows[0].user_id).toBe(user.id);
    expect(rows[0].user_email).toBe('user@example.com');
  });

  it('inserts a standalone record when the queued row is missing', () => {
    applyScanEvent(event('orphan', 'orphan.example'));
    const row = getScan('orphan')!;
    expect(row.status).toBe('completed');
    expect(row.host).toBe('orphan.example');
    expect(row.user_id).toBeNull();
  });

  it('aggregates stats across a range', () => {
    const user = createUser({ email: 'u3@example.com', passwordHash: 'x', verified: true });
    queued(user.id, 'a', 'a.example', 'quick');
    queued(user.id, 'b', 'b.example', 'deep', ['vuln-scan']);
    queued(user.id, 'c', 'a.example', 'quick');
    applyScanEvent(event('a', 'a.example'));
    applyScanEvent(event('b', 'b.example', { profile: 'deep', modules: ['vuln-scan'], status: 'failed', durationMs: 9000 }));
    applyScanEvent(event('c', 'a.example', { durationMs: 1000 }));

    const stats = getScanStats(new Date(Date.now() - 86400000).toISOString(), new Date(Date.now() + 86400000).toISOString());
    expect(stats.total).toBe(3);
    expect(stats.completed).toBe(2);
    expect(stats.failed).toBe(1);
    expect(stats.uniqueHosts).toBe(2);
    expect(stats.byProfile.find((p) => p.profile === 'quick')?.count).toBe(2);
    expect(stats.byModule).toEqual([{ module: 'vuln-scan', count: 1 }]);
    expect(stats.topTargets[0]).toEqual({ host: 'a.example', count: 2 });
    expect(stats.toolDurations.find((t) => t.tool === 'whatweb')?.failures).toBe(3);
    expect(stats.avgDurationMs).toBeGreaterThan(0);
  });

  it('filters admin listing by host and status', () => {
    const user = createUser({ email: 'u4@example.com', passwordHash: 'x', verified: true });
    queued(user.id, 'x', 'x.example');
    queued(user.id, 'y', 'y.example');
    applyScanEvent(event('x', 'x.example'));
    applyScanEvent(event('y', 'y.example', { status: 'failed' }));

    expect(listAdminScans({ host: 'x.example' })).toHaveLength(1);
    expect(listAdminScans({ status: 'failed' })).toHaveLength(1);
    expect(listAdminScans({ host: 'x.example' })[0].id).toBe('x');
  });

  it('sweeps history past the retention window', () => {
    const user = createUser({ email: 'u5@example.com', passwordHash: 'x', verified: true });
    queued(user.id, 'old', 'old.example');
    applyScanEvent(event('old', 'old.example', { finishedAt: new Date(Date.now() - 400 * 86400000).toISOString() }));
    // Force created_at into the past to simulate age.
    getDb().prepare('UPDATE scans SET created_at = ? WHERE id = ?').run(new Date(Date.now() - 400 * 86400000).toISOString(), 'old');

    const removed = sweepScanHistory(365);
    expect(removed).toBe(1);
    expect(getScan('old')).toBeNull();
  });
});

describe('scan access and quotas', () => {
  it('only resolves scans for their owner or an admin', () => {
    const owner = createUser({ email: 'owner@example.com', passwordHash: 'x', verified: true });
    const other = createUser({ email: 'other@example.com', passwordHash: 'x', verified: true });
    queued(owner.id, 'owned-scan', 'owned.example');
    expect(getScanForUser('owned-scan', owner.id, false)?.id).toBe('owned-scan');
    expect(getScanForUser('owned-scan', other.id, false)).toBeNull();
    expect(getScanForUser('owned-scan', other.id, true)?.id).toBe('owned-scan');
    expect(getScanForUser('missing', owner.id, false)).toBeNull();
  });

  it('counts only queued and running scans', () => {
    const user = createUser({ email: 'quota@example.com', passwordHash: 'x', verified: true });
    queued(user.id, 'queued-scan', 'q.example');
    queued(user.id, 'running-scan', 'r.example');
    getDb().prepare(`UPDATE scans SET status = 'running' WHERE id = ?`).run('running-scan');
    expect(countActiveScans(user.id)).toBe(2);
    applyScanEvent(event('queued-scan', 'q.example'));
    expect(countActiveScans(user.id)).toBe(1);
  });
});

describe('digest data', () => {
  it('summarizes signups and scan activity', () => {
    const user = createUser({ email: 'newbie@example.com', passwordHash: 'x', verified: true });
    queued(user.id, 'd1', 'digest.example', 'quick');
    applyScanEvent(event('d1', 'digest.example'));

    const data = buildDigestData(new Date(Date.now() - 86400000).toISOString(), new Date(Date.now() + 86400000).toISOString());
    expect(data.newUsers.some((u) => u.email === 'newbie@example.com')).toBe(true);
    expect(data.scans.total).toBe(1);
    expect(data.scans.completed).toBe(1);
    expect(data.topTargets[0].host).toBe('digest.example');
    expect(data.adminUrl).toContain('/admin/scans');
  });
});
