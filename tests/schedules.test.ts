import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getDb, resetDbForTests } from '../src/server/db';
import { createUser } from '../src/server/users';
import { PREMIUM_KEY, grantEntitlement } from '../src/server/entitlements';
import { getWebConfig } from '../src/shared/config';
import {
  claimDueSchedule,
  computeNextRun,
  createSchedule,
  deleteSchedule,
  getSchedule,
  listSchedules,
  updateSchedule,
} from '../src/server/schedules';
import { runDueScheduledScans } from '../src/server/scheduler';
import { getScan } from '../src/server/scans';

let dbPath: string;

beforeAll(() => {
  dbPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sitedig-schedules-')), 'test.sqlite');
  process.env.DB_PATH = dbPath;
  process.env.DEPLOYMENT_MODE = 'self-hosted';
  process.env.APP_BASE_URL = 'http://localhost:3000';
});

beforeEach(() => {
  resetDbForTests();
  getDb().exec(
    'DELETE FROM scan_findings; DELETE FROM scan_tools; DELETE FROM scans; DELETE FROM scheduled_scans; DELETE FROM entitlements; DELETE FROM users; DELETE FROM app_settings;',
  );
});

afterAll(() => {
  resetDbForTests();
  fs.rmSync(path.dirname(dbPath), { recursive: true, force: true });
});

function scheduleInput(userId: number, userEmail: string) {
  return {
    userId,
    userEmail,
    target: 'https://example.com/',
    profile: 'quick' as const,
    custom: null,
    modules: [],
    frequency: 'daily' as const,
    hourUtc: 8,
    minuteUtc: 0,
    dayOfWeek: null,
    alertMinSeverity: 'high' as const,
    alertOnFailure: true,
  };
}

describe('schedule next-run math', () => {
  it('schedules daily runs in the future', () => {
    const from = new Date('2026-01-01T09:00:00.000Z');
    expect(computeNextRun({ frequency: 'daily', hourUtc: 8, minuteUtc: 0, dayOfWeek: null }, from).toISOString()).toBe('2026-01-02T08:00:00.000Z');
    const before = new Date('2026-01-01T07:30:00.000Z');
    expect(computeNextRun({ frequency: 'daily', hourUtc: 8, minuteUtc: 0, dayOfWeek: null }, before).toISOString()).toBe('2026-01-01T08:00:00.000Z');
  });

  it('schedules weekly runs on the requested weekday', () => {
    const from = new Date('2026-01-01T09:00:00.000Z'); // Thursday
    expect(computeNextRun({ frequency: 'weekly', hourUtc: 8, minuteUtc: 0, dayOfWeek: 1 }, from).toISOString()).toBe('2026-01-05T08:00:00.000Z');
    expect(() => computeNextRun({ frequency: 'weekly', hourUtc: 8, minuteUtc: 0, dayOfWeek: null }, from)).toThrow(/day of week/i);
  });
});

describe('schedule CRUD', () => {
  it('creates, updates, lists, and deletes a schedule', () => {
    const user = createUser({ email: 'sched@example.com', passwordHash: 'x', verified: true });
    const schedule = createSchedule(scheduleInput(user.id, user.email));
    expect(schedule.id).toBeGreaterThan(0);
    expect(schedule.target).toBe('https://example.com/');
    expect(listSchedules(user.id)).toHaveLength(1);

    const updated = updateSchedule(schedule.id, user.id, { frequency: 'weekly', dayOfWeek: 3, alertMinSeverity: 'medium' });
    expect(updated?.frequency).toBe('weekly');
    expect(updated?.dayOfWeek).toBe(3);
    expect(updated?.alertMinSeverity).toBe('medium');
    expect(updated?.nextRunAt).toBeTruthy();

    expect(deleteSchedule(schedule.id, user.id)).toBe(true);
    expect(getSchedule(schedule.id)).toBeNull();
  });

  it('claims a due schedule only once', () => {
    const user = createUser({ email: 'claim@example.com', passwordHash: 'x', verified: true });
    const schedule = createSchedule(scheduleInput(user.id, user.email));
    getDb().prepare('UPDATE scheduled_scans SET next_run_at = ? WHERE id = ?').run('2020-01-01T00:00:00.000Z', schedule.id);
    const now = new Date('2026-01-01T00:00:00.000Z');
    expect(claimDueSchedule(schedule.id, now, new Date(now.getTime() + 60_000))).toBe(true);
    expect(claimDueSchedule(schedule.id, now, new Date(now.getTime() + 60_000))).toBe(false);
  });
});

describe('scheduled dispatch', () => {
  it('dispatches a due schedule and records scan history', async () => {
    const user = createUser({ email: 'dispatch@example.com', passwordHash: 'x', verified: true });
    grantEntitlement({ userId: user.id, key: PREMIUM_KEY, source: 'admin' });
    const schedule = createSchedule(scheduleInput(user.id, user.email));
    getDb().prepare('UPDATE scheduled_scans SET next_run_at = ? WHERE id = ?').run('2020-01-01T00:00:00.000Z', schedule.id);

    const now = new Date('2026-01-01T00:00:00.000Z');
    const dispatched = await runDueScheduledScans({
      now,
      config: getWebConfig(),
      createScan: async () => ({ jobId: 'scheduled-scan-1', status: 'queued' }),
    });
    expect(dispatched).toBe(1);
    const scan = getScan('scheduled-scan-1')!;
    expect(scan.schedule_id).toBe(schedule.id);
    expect(scan.status).toBe('queued');
    const updated = getSchedule(schedule.id)!;
    expect(updated.lastScanId).toBe('scheduled-scan-1');
    expect(updated.lastError).toBeNull();
    expect(new Date(updated.nextRunAt).getTime()).toBeGreaterThan(now.getTime());
  });

  it('pauses a schedule when Premium is no longer active', async () => {
    const user = createUser({ email: 'free@example.com', passwordHash: 'x', verified: true });
    const schedule = createSchedule(scheduleInput(user.id, user.email));
    getDb().prepare('UPDATE scheduled_scans SET next_run_at = ? WHERE id = ?').run('2020-01-01T00:00:00.000Z', schedule.id);
    const dispatched = await runDueScheduledScans({
      now: new Date('2026-01-01T00:00:00.000Z'),
      config: getWebConfig(),
      createScan: async () => ({ jobId: 'should-not-run', status: 'queued' }),
    });
    expect(dispatched).toBe(0);
    const updated = getSchedule(schedule.id)!;
    expect(updated.enabled).toBe(false);
    expect(updated.lastError).toMatch(/Premium/i);
  });
});
