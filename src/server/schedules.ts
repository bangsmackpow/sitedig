import { parseTarget } from '../shared/targets';
import type { CustomScanOptions, ModuleId, ScheduledScan, ScanProfile, ScheduleAlertThreshold, ScheduleFrequency } from '../shared/types';
import { getDb } from './db';

interface ScheduleRow {
  id: number;
  user_id: number;
  user_email: string | null;
  target_raw: string;
  host: string;
  path: string;
  scheme: string | null;
  profile: string;
  custom_json: string | null;
  modules_json: string;
  frequency: ScheduleFrequency;
  hour_utc: number;
  minute_utc: number;
  day_of_week: number | null;
  alert_min_severity: ScheduleAlertThreshold;
  alert_on_failure: number;
  enabled: number;
  consent_at: string;
  next_run_at: string;
  last_attempt_at: string | null;
  last_run_at: string | null;
  last_scan_id: string | null;
  last_alert_scan_id: string | null;
  last_alert_at: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

function parseJson<T>(value: string | null): T | null {
  if (!value) return null;
  try {
    return JSON.parse(value) as T;
  } catch {
    return null;
  }
}

function parseArray<T>(value: string | null): T[] {
  const parsed = parseJson<unknown>(value);
  return Array.isArray(parsed) ? (parsed as T[]) : [];
}

function toSchedule(row: ScheduleRow): ScheduledScan {
  return {
    id: row.id,
    userId: row.user_id,
    userEmail: row.user_email,
    target: row.target_raw,
    host: row.host,
    path: row.path,
    scheme: row.scheme === 'http' ? 'http' : 'https',
    profile: row.profile as ScanProfile,
    custom: parseJson<CustomScanOptions>(row.custom_json),
    modules: parseArray<ModuleId>(row.modules_json),
    frequency: row.frequency,
    hourUtc: row.hour_utc,
    minuteUtc: row.minute_utc,
    dayOfWeek: row.day_of_week,
    alertMinSeverity: row.alert_min_severity,
    alertOnFailure: Boolean(row.alert_on_failure),
    enabled: Boolean(row.enabled),
    consentAt: row.consent_at,
    nextRunAt: row.next_run_at,
    lastAttemptAt: row.last_attempt_at,
    lastRunAt: row.last_run_at,
    lastScanId: row.last_scan_id,
    lastAlertScanId: row.last_alert_scan_id,
    lastAlertAt: row.last_alert_at,
    lastError: row.last_error,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export interface NextRunInput {
  frequency: ScheduleFrequency;
  hourUtc: number;
  minuteUtc: number;
  dayOfWeek: number | null;
}

/** Pure UTC next-run calculation for daily/weekly schedules. */
export function computeNextRun(input: NextRunInput, from: Date = new Date()): Date {
  const candidate = new Date(from);
  candidate.setUTCHours(input.hourUtc, input.minuteUtc, 0, 0);
  if (input.frequency === 'daily') {
    if (candidate.getTime() <= from.getTime()) candidate.setUTCDate(candidate.getUTCDate() + 1);
    return candidate;
  }
  if (input.dayOfWeek === null || input.dayOfWeek === undefined) {
    throw new Error('A day of week is required for weekly schedules.');
  }
  const delta = (input.dayOfWeek - candidate.getUTCDay() + 7) % 7;
  candidate.setUTCDate(candidate.getUTCDate() + delta);
  if (candidate.getTime() <= from.getTime()) candidate.setUTCDate(candidate.getUTCDate() + 7);
  return candidate;
}

export function countSchedules(userId: number): number {
  return (getDb().prepare('SELECT COUNT(*) AS c FROM scheduled_scans WHERE user_id = ?').get(userId) as { c: number }).c;
}

export function listSchedules(userId: number): ScheduledScan[] {
  return (getDb().prepare('SELECT * FROM scheduled_scans WHERE user_id = ? ORDER BY created_at DESC').all(userId) as ScheduleRow[]).map(toSchedule);
}

export function getSchedule(id: number): ScheduledScan | null {
  const row = getDb().prepare('SELECT * FROM scheduled_scans WHERE id = ?').get(id) as ScheduleRow | undefined;
  return row ? toSchedule(row) : null;
}

export function getScheduleForUser(id: number, userId: number): ScheduledScan | null {
  const row = getDb().prepare('SELECT * FROM scheduled_scans WHERE id = ? AND user_id = ?').get(id, userId) as ScheduleRow | undefined;
  return row ? toSchedule(row) : null;
}

export function getScheduleByLastScan(scanId: string): ScheduledScan | null {
  const row = getDb().prepare('SELECT * FROM scheduled_scans WHERE last_scan_id = ?').get(scanId) as ScheduleRow | undefined;
  return row ? toSchedule(row) : null;
}

export interface CreateScheduleServiceInput {
  userId: number;
  userEmail: string | null;
  target: string;
  profile: ScanProfile;
  custom: CustomScanOptions | null;
  modules: ModuleId[];
  frequency: ScheduleFrequency;
  hourUtc: number;
  minuteUtc: number;
  dayOfWeek: number | null;
  alertMinSeverity: ScheduleAlertThreshold;
  alertOnFailure: boolean;
}

export function createSchedule(input: CreateScheduleServiceInput): ScheduledScan {
  const target = parseTarget(input.target);
  const now = new Date();
  const nextRunAt = computeNextRun(
    { frequency: input.frequency, hourUtc: input.hourUtc, minuteUtc: input.minuteUtc, dayOfWeek: input.dayOfWeek },
    now,
  );
  const nowIso = now.toISOString();
  const result = getDb()
    .prepare(
      `INSERT INTO scheduled_scans (
         user_id, user_email, target_raw, host, path, scheme, profile, custom_json, modules_json,
         frequency, hour_utc, minute_utc, day_of_week, alert_min_severity, alert_on_failure, enabled,
         consent_at, next_run_at, created_at, updated_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`,
    )
    .run(
      input.userId,
      input.userEmail,
      input.target,
      target.host,
      target.path,
      target.scheme,
      input.profile,
      input.custom ? JSON.stringify(input.custom) : null,
      JSON.stringify(input.modules),
      input.frequency,
      input.hourUtc,
      input.minuteUtc,
      input.frequency === 'weekly' ? input.dayOfWeek : null,
      input.alertMinSeverity,
      input.alertOnFailure ? 1 : 0,
      nowIso,
      nextRunAt.toISOString(),
      nowIso,
      nowIso,
    );
  return getSchedule(Number(result.lastInsertRowid))!;
}

export interface UpdateScheduleServiceInput {
  frequency?: ScheduleFrequency;
  hourUtc?: number;
  minuteUtc?: number;
  dayOfWeek?: number | null;
  alertMinSeverity?: ScheduleAlertThreshold;
  alertOnFailure?: boolean;
  enabled?: boolean;
}

export function updateSchedule(id: number, userId: number, patch: UpdateScheduleServiceInput): ScheduledScan | null {
  const existing = getScheduleForUser(id, userId);
  if (!existing) return null;
  const frequency = patch.frequency ?? existing.frequency;
  const hourUtc = patch.hourUtc ?? existing.hourUtc;
  const minuteUtc = patch.minuteUtc ?? existing.minuteUtc;
  const dayOfWeek = frequency === 'weekly' ? (patch.dayOfWeek ?? existing.dayOfWeek) : null;
  if (frequency === 'weekly' && dayOfWeek === null) throw new Error('A day of week is required for weekly schedules.');
  const enabled = patch.enabled ?? existing.enabled;
  const timingChanged =
    frequency !== existing.frequency ||
    hourUtc !== existing.hourUtc ||
    minuteUtc !== existing.minuteUtc ||
    dayOfWeek !== existing.dayOfWeek ||
    (enabled && !existing.enabled);
  const nextRunAt =
    enabled && timingChanged
      ? computeNextRun({ frequency, hourUtc, minuteUtc, dayOfWeek }, new Date()).toISOString()
      : existing.nextRunAt;
  const now = new Date().toISOString();
  getDb()
    .prepare(
      `UPDATE scheduled_scans SET
         frequency = ?, hour_utc = ?, minute_utc = ?, day_of_week = ?,
         alert_min_severity = ?, alert_on_failure = ?, enabled = ?,
         next_run_at = ?, last_error = CASE WHEN ? = 1 THEN NULL ELSE last_error END,
         updated_at = ?
       WHERE id = ? AND user_id = ?`,
    )
    .run(
      frequency,
      hourUtc,
      minuteUtc,
      dayOfWeek,
      patch.alertMinSeverity ?? existing.alertMinSeverity,
      (patch.alertOnFailure ?? existing.alertOnFailure) ? 1 : 0,
      enabled ? 1 : 0,
      nextRunAt,
      enabled ? 1 : 0,
      now,
      id,
      userId,
    );
  return getScheduleForUser(id, userId);
}

export function deleteSchedule(id: number, userId: number): boolean {
  return getDb().prepare('DELETE FROM scheduled_scans WHERE id = ? AND user_id = ?').run(id, userId).changes > 0;
}

export function setScheduleEnabled(id: number, enabled: boolean, error: string | null = null): void {
  const now = new Date().toISOString();
  getDb()
    .prepare('UPDATE scheduled_scans SET enabled = ?, last_error = ?, updated_at = ? WHERE id = ?')
    .run(enabled ? 1 : 0, error, now, id);
}

export function listDueScheduleIds(now: Date, limit = 10): number[] {
  const rows = getDb()
    .prepare(
      `SELECT id FROM scheduled_scans
       WHERE enabled = 1 AND next_run_at <= ?
       ORDER BY next_run_at ASC LIMIT ?`,
    )
    .all(now.toISOString(), limit) as Array<{ id: number }>;
  return rows.map((r) => r.id);
}

/** Atomically take ownership of a due schedule and set a short retry lease. */
export function claimDueSchedule(id: number, now: Date, leaseUntil: Date): boolean {
  const nowIso = now.toISOString();
  return (
    getDb()
      .prepare(
        `UPDATE scheduled_scans SET last_attempt_at = ?, next_run_at = ?, updated_at = ?
         WHERE id = ? AND enabled = 1 AND next_run_at <= ?`,
      )
      .run(nowIso, leaseUntil.toISOString(), nowIso, id, nowIso).changes > 0
  );
}

export function markScheduleRun(id: number, scanId: string, ranAt: Date, nextRunAt: Date): void {
  const now = new Date().toISOString();
  getDb()
    .prepare(
      `UPDATE scheduled_scans SET last_run_at = ?, last_scan_id = ?, next_run_at = ?,
         last_error = NULL, updated_at = ? WHERE id = ?`,
    )
    .run(ranAt.toISOString(), scanId, nextRunAt.toISOString(), now, id);
}

export function markScheduleError(id: number, error: string, nextRunAt?: Date): void {
  const now = new Date().toISOString();
  if (nextRunAt) {
    getDb()
      .prepare('UPDATE scheduled_scans SET last_error = ?, next_run_at = ?, updated_at = ? WHERE id = ?')
      .run(error.slice(0, 2000), nextRunAt.toISOString(), now, id);
  } else {
    getDb().prepare('UPDATE scheduled_scans SET last_error = ?, updated_at = ? WHERE id = ?').run(error.slice(0, 2000), now, id);
  }
}

export function recordScheduleAlert(id: number, scanId: string): void {
  const now = new Date().toISOString();
  getDb()
    .prepare('UPDATE scheduled_scans SET last_alert_scan_id = ?, last_alert_at = ?, updated_at = ? WHERE id = ?')
    .run(scanId, now, now, id);
}
