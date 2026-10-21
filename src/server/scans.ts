import { getDb } from './db';
import { riskGrade, riskScore } from '../shared/risk';
import type { FindingCounts, ScanEventPayload, ScanFindingSummary, ScanRisk, ScanToolTiming } from '../shared/types';

export interface ScanRow {
  id: string;
  user_id: number | null;
  user_email: string | null;
  target_raw: string;
  host: string;
  path: string;
  scheme: string | null;
  resolved_ips: string | null;
  ip_version: string | null;
  profile: string;
  port_scope: string | null;
  modules_json: string;
  status: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  port_count: number;
  findings_critical: number;
  findings_high: number;
  findings_medium: number;
  findings_low: number;
  findings_informational: number;
  tool_ok: number;
  tool_total: number;
  error: string | null;
  schedule_id: number | null;
}

export interface ScanView {
  id: string;
  target: string;
  host: string;
  resolvedIps: string[];
  ipVersion: string | null;
  profile: string;
  portScope: string | null;
  modules: string[];
  status: string;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  portCount: number;
  findings: FindingCounts;
  toolOk: number;
  toolTotal: number;
  error: string | null;
  scheduleId: number | null;
  risk: ScanRisk;
  userEmail?: string | null;
}

function parseJsonArray(value: string | null): string[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? (parsed as string[]) : [];
  } catch {
    return [];
  }
}

export function toScanView(row: ScanRow, withUser = false): ScanView {
  const findings: FindingCounts = {
    critical: row.findings_critical,
    high: row.findings_high,
    medium: row.findings_medium,
    low: row.findings_low,
    informational: row.findings_informational,
  };
  const score = riskScore(findings);
  return {
    id: row.id,
    target: row.target_raw,
    host: row.host,
    resolvedIps: parseJsonArray(row.resolved_ips),
    ipVersion: row.ip_version,
    profile: row.profile,
    portScope: row.port_scope,
    modules: parseJsonArray(row.modules_json),
    status: row.status,
    createdAt: row.created_at,
    startedAt: row.started_at,
    finishedAt: row.finished_at,
    durationMs: row.duration_ms,
    portCount: row.port_count,
    findings,
    toolOk: row.tool_ok,
    toolTotal: row.tool_total,
    error: row.error,
    scheduleId: row.schedule_id ?? null,
    risk: { score, grade: riskGrade(score) },
    ...(withUser ? { userEmail: row.user_email } : {}),
  };
}

/** Insert a placeholder row when a scan is queued (called from the web API). */
export function recordScanQueued(input: {
  id: string;
  userId: number;
  userEmail: string | null;
  targetRaw: string;
  host: string;
  path: string;
  scheme: string;
  profile: string;
  modules: string[];
  scheduleId?: number | null;
}): void {
  getDb()
    .prepare(
      `INSERT INTO scans (id, user_id, user_email, target_raw, host, path, scheme, profile, modules_json, status, schedule_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         user_id = excluded.user_id,
         user_email = excluded.user_email,
         target_raw = excluded.target_raw,
         host = excluded.host,
         path = excluded.path,
         scheme = excluded.scheme,
         profile = excluded.profile,
         modules_json = excluded.modules_json,
         schedule_id = excluded.schedule_id`,
    )
    .run(
      input.id,
      input.userId,
      input.userEmail,
      input.targetRaw,
      input.host,
      input.path,
      input.scheme,
      input.profile,
      JSON.stringify(input.modules),
      input.scheduleId ?? null,
      new Date().toISOString(),
    );
}

function insertTools(scanId: string, tools: ScanToolTiming[]): void {
  const stmt = getDb().prepare('INSERT INTO scan_tools (scan_id, tool, ok, timed_out, exit_code, duration_ms) VALUES (?, ?, ?, ?, ?, ?)');
  for (const t of tools) {
    stmt.run(scanId, t.tool, t.ok ? 1 : 0, t.timedOut ? 1 : 0, t.exitCode, Math.max(0, Math.round(t.durationMs)));
  }
}

function insertFindings(scanId: string, findings: ScanFindingSummary[]): void {
  getDb().prepare('DELETE FROM scan_findings WHERE scan_id = ?').run(scanId);
  const stmt = getDb().prepare(
    'INSERT INTO scan_findings (scan_id, fingerprint, title, severity, category, affected, source_tools_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
  );
  const now = new Date().toISOString();
  for (const f of findings.slice(0, 500)) {
    stmt.run(scanId, f.fingerprint, f.title, f.severity, f.category, f.affected, JSON.stringify(f.sourceTools ?? []), now);
  }
}

/** Apply a completion/failure summary from the worker (idempotent). */
export function applyScanEvent(payload: ScanEventPayload): void {
  const db = getDb();
  const run = db.transaction(() => {
    const res = db
      .prepare(
        `UPDATE scans SET
           status = ?, started_at = ?, finished_at = ?, duration_ms = ?,
           resolved_ips = ?, ip_version = ?, port_scope = ?, modules_json = ?,
           port_count = ?, findings_critical = ?, findings_high = ?, findings_medium = ?,
           findings_low = ?, findings_informational = ?, tool_ok = ?, tool_total = ?, error = ?
         WHERE id = ?`,
      )
      .run(
        payload.status,
        payload.startedAt,
        payload.finishedAt,
        payload.durationMs,
        JSON.stringify(payload.resolvedIps),
        payload.ipVersion,
        payload.portScope,
        JSON.stringify(payload.modules),
        payload.portCount,
        payload.findings.critical,
        payload.findings.high,
        payload.findings.medium,
        payload.findings.low,
        payload.findings.informational,
        payload.toolOk,
        payload.toolTotal,
        payload.error,
        payload.scanId,
      );

    // The queued row is normally present; if it was lost (e.g. cleanup between
    // create and completion) insert a standalone record so history is complete.
    if (res.changes === 0) {
      db.prepare(
        `INSERT INTO scans (id, user_id, target_raw, host, path, scheme, profile, port_scope, modules_json, status, created_at,
           started_at, finished_at, duration_ms, resolved_ips, ip_version, port_count,
           findings_critical, findings_high, findings_medium, findings_low, findings_informational, tool_ok, tool_total, error)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        payload.scanId,
        payload.userId ?? null,
        payload.targetRaw,
        payload.host,
        payload.path,
        payload.scheme,
        payload.profile,
        payload.portScope,
        JSON.stringify(payload.modules),
        payload.status,
        payload.finishedAt ?? new Date().toISOString(),
        payload.startedAt,
        payload.finishedAt,
        payload.durationMs,
        JSON.stringify(payload.resolvedIps),
        payload.ipVersion,
        payload.portCount,
        payload.findings.critical,
        payload.findings.high,
        payload.findings.medium,
        payload.findings.low,
        payload.findings.informational,
        payload.toolOk,
        payload.toolTotal,
        payload.error,
      );
    }

    db.prepare('DELETE FROM scan_tools WHERE scan_id = ?').run(payload.scanId);
    insertTools(payload.scanId, payload.tools);
    insertFindings(payload.scanId, payload.findingsDetail ?? []);
  });
  run();
}

export function getScan(id: string): ScanRow | null {
  return (getDb().prepare('SELECT * FROM scans WHERE id = ?').get(id) as ScanRow | undefined) ?? null;
}

/** Resolve a scan only when it belongs to the user (admins may access all). */
export function getScanForUser(id: string, userId: number, isAdmin: boolean): ScanRow | null {
  const scan = getScan(id);
  if (!scan) return null;
  if (isAdmin || scan.user_id === userId) return scan;
  return null;
}

/** Count scans currently queued or running for a user. */
export function countActiveScans(userId: number): number {
  return (
    getDb()
      .prepare(`SELECT COUNT(*) AS c FROM scans WHERE user_id = ? AND status IN ('queued','running')`)
      .get(userId) as { c: number }
  ).c;
}

export function getScanFindings(scanId: string): ScanFindingSummary[] {
  const rows = getDb()
    .prepare('SELECT fingerprint, title, severity, category, affected, source_tools_json FROM scan_findings WHERE scan_id = ? ORDER BY id')
    .all(scanId) as Array<{
    fingerprint: string;
    title: string;
    severity: ScanFindingSummary['severity'];
    category: ScanFindingSummary['category'];
    affected: string | null;
    source_tools_json: string;
  }>;
  return rows.map((r) => ({
    fingerprint: r.fingerprint,
    title: r.title,
    severity: r.severity,
    category: r.category,
    affected: r.affected,
    sourceTools: parseJsonArray(r.source_tools_json) as ScanFindingSummary['sourceTools'],
  }));
}

/** Previous completed scan for the same schedule, or same user/host/path. */
export function getPreviousScan(current: ScanRow): ScanRow | null {
  if (current.schedule_id !== null) {
    const scheduled = getDb()
      .prepare(
        `SELECT * FROM scans
         WHERE schedule_id = ? AND status = 'completed'
           AND rowid < (SELECT rowid FROM scans WHERE id = ?)
         ORDER BY rowid DESC LIMIT 1`,
      )
      .get(current.schedule_id, current.id) as ScanRow | undefined;
    if (scheduled) return scheduled;
  }
  if (current.user_id === null) return null;
  return (
    (getDb()
      .prepare(
        `SELECT * FROM scans
         WHERE user_id = ? AND host = ? AND path = ? AND status = 'completed'
           AND rowid < (SELECT rowid FROM scans WHERE id = ?)
         ORDER BY rowid DESC LIMIT 1`,
      )
      .get(current.user_id, current.host, current.path, current.id) as ScanRow | undefined) ?? null
  );
}

export function getScanToolStatus(scanId: string): Map<string, boolean> {
  const rows = getDb().prepare('SELECT tool, ok FROM scan_tools WHERE scan_id = ?').all(scanId) as Array<{ tool: string; ok: number }>;
  return new Map(rows.map((r) => [r.tool, Boolean(r.ok)]));
}

const DAY_MS = 24 * 60 * 60 * 1000;

/** Resolve a half-open [from, to) ISO range from query params (default: last 30 days). */
export function resolveRange(sp: URLSearchParams, defaultDays = 30): { from: string; to: string } {
  const to = sp.get('to') ? new Date(sp.get('to')!) : new Date();
  const from = sp.get('from') ? new Date(sp.get('from')!) : new Date(to.getTime() - defaultDays * DAY_MS);
  return { from: from.toISOString(), to: new Date(to.getTime() + DAY_MS).toISOString() };
}

export function listUserScans(userId: number, limit = 100): ScanRow[] {
  return getDb().prepare('SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ?').all(userId, limit) as ScanRow[];
}

export interface AdminScanFilters {
  from?: string;
  to?: string;
  host?: string;
  profile?: string;
  status?: string;
  user?: string;
  limit?: number;
}

export function listAdminScans(filters: AdminScanFilters = {}): ScanRow[] {
  const clauses: string[] = [];
  const params: unknown[] = [];
  if (filters.from) {
    clauses.push('created_at >= ?');
    params.push(filters.from);
  }
  if (filters.to) {
    clauses.push('created_at < ?');
    params.push(filters.to);
  }
  if (filters.host) {
    clauses.push('host LIKE ?');
    params.push(`%${filters.host}%`);
  }
  if (filters.profile) {
    clauses.push('profile = ?');
    params.push(filters.profile);
  }
  if (filters.status) {
    clauses.push('status = ?');
    params.push(filters.status);
  }
  if (filters.user) {
    clauses.push('user_email LIKE ?');
    params.push(`%${filters.user.toLowerCase()}%`);
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  const requested = filters.limit !== undefined && Number.isFinite(filters.limit) ? Math.floor(filters.limit) : 200;
  const limit = Math.min(Math.max(requested, 1), 2000);
  return getDb().prepare(`SELECT * FROM scans ${where} ORDER BY created_at DESC LIMIT ?`).all(...params, limit) as ScanRow[];
}

export interface ScanStats {
  range: { from: string; to: string };
  total: number;
  completed: number;
  failed: number;
  cancelled: number;
  running: number;
  successRate: number;
  avgDurationMs: number;
  p95DurationMs: number;
  totalDurationMs: number;
  uniqueHosts: number;
  findings: FindingCounts;
  byProfile: Array<{ profile: string; count: number }>;
  byModule: Array<{ module: string; count: number }>;
  byDay: Array<{ date: string; count: number; avgDurationMs: number }>;
  topTargets: Array<{ host: string; count: number }>;
  toolDurations: Array<{ tool: string; runs: number; failures: number; avgMs: number; p95Ms: number }>;
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

export function getScanStats(fromIso: string, toIso: string): ScanStats {
  const db = getDb();
  const range = [fromIso, toIso];

  const totals = db
    .prepare(
      `SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed,
        SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
        SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) AS cancelled,
        SUM(CASE WHEN status IN ('queued','running') THEN 1 ELSE 0 END) AS running,
        COUNT(DISTINCT host) AS uniqueHosts,
        SUM(findings_critical) AS fCrit, SUM(findings_high) AS fHigh, SUM(findings_medium) AS fMed,
        SUM(findings_low) AS fLow, SUM(findings_informational) AS fInfo
       FROM scans WHERE created_at >= ? AND created_at < ?`,
    )
    .get(...range) as Record<string, number | null>;

  const total = totals.total ?? 0;
  const completed = totals.completed ?? 0;
  const failed = totals.failed ?? 0;
  const cancelled = totals.cancelled ?? 0;

  const durations = (db.prepare('SELECT duration_ms AS d FROM scans WHERE created_at >= ? AND created_at < ? AND duration_ms IS NOT NULL').all(...range) as Array<{ d: number }>)
    .map((r) => r.d)
    .sort((a, b) => a - b);
  const avgDurationMs = durations.length ? Math.round(durations.reduce((a, b) => a + b, 0) / durations.length) : 0;
  const totalDurationMs = durations.reduce((a, b) => a + b, 0);

  const byProfile = db.prepare('SELECT profile, COUNT(*) AS count FROM scans WHERE created_at >= ? AND created_at < ? GROUP BY profile ORDER BY count DESC').all(...range) as Array<{ profile: string; count: number }>;
  const byDay = db
    .prepare(
      `SELECT substr(created_at, 1, 10) AS date, COUNT(*) AS count, AVG(duration_ms) AS avgDurationMs
       FROM scans WHERE created_at >= ? AND created_at < ? GROUP BY date ORDER BY date ASC`,
    )
    .all(...range) as Array<{ date: string; count: number; avgDurationMs: number | null }>;
  const topTargets = db.prepare('SELECT host, COUNT(*) AS count FROM scans WHERE created_at >= ? AND created_at < ? GROUP BY host ORDER BY count DESC LIMIT 10').all(...range) as Array<{ host: string; count: number }>;

  // Module usage requires parsing JSON (SQLite has no json_each dependency assumption).
  const moduleCounts = new Map<string, number>();
  for (const row of db.prepare('SELECT modules_json AS m FROM scans WHERE created_at >= ? AND created_at < ?').all(...range) as Array<{ m: string }>) {
    for (const mod of parseJsonArray(row.m)) moduleCounts.set(mod, (moduleCounts.get(mod) ?? 0) + 1);
  }
  const byModule = [...moduleCounts.entries()].map(([module, count]) => ({ module, count })).sort((a, b) => b.count - a.count);

  // Per-tool timing across the range.
  const toolRows = db
    .prepare(
      `SELECT st.tool AS tool, st.duration_ms AS durationMs, st.ok AS ok
       FROM scan_tools st JOIN scans s ON s.id = st.scan_id
       WHERE s.created_at >= ? AND s.created_at < ?`,
    )
    .all(...range) as Array<{ tool: string; durationMs: number; ok: number }>;
  const toolMap = new Map<string, { durations: number[]; failures: number }>();
  for (const r of toolRows) {
    const entry = toolMap.get(r.tool) ?? { durations: [], failures: 0 };
    entry.durations.push(r.durationMs);
    if (!r.ok) entry.failures += 1;
    toolMap.set(r.tool, entry);
  }
  const toolDurations = [...toolMap.entries()]
    .map(([tool, e]) => {
      const sorted = [...e.durations].sort((a, b) => a - b);
      return {
        tool,
        runs: sorted.length,
        failures: e.failures,
        avgMs: sorted.length ? Math.round(sorted.reduce((a, b) => a + b, 0) / sorted.length) : 0,
        p95Ms: percentile(sorted, 95),
      };
    })
    .sort((a, b) => b.avgMs - a.avgMs);

  return {
    range: { from: fromIso, to: toIso },
    total,
    completed,
    failed,
    cancelled,
    running: totals.running ?? 0,
    successRate: total ? completed / total : 0,
    avgDurationMs,
    p95DurationMs: percentile(durations, 95),
    totalDurationMs,
    uniqueHosts: totals.uniqueHosts ?? 0,
    findings: {
      critical: totals.fCrit ?? 0,
      high: totals.fHigh ?? 0,
      medium: totals.fMed ?? 0,
      low: totals.fLow ?? 0,
      informational: totals.fInfo ?? 0,
    },
    byProfile,
    byModule,
    byDay: byDay.map((d) => ({ date: d.date, count: d.count, avgDurationMs: Math.round(d.avgDurationMs ?? 0) })),
    topTargets,
    toolDurations,
  };
}

/** Delete scan history older than the retention window. Returns rows removed. */
export function sweepScanHistory(retentionDays: number): number {
  if (!Number.isFinite(retentionDays) || retentionDays <= 0) return 0;
  const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
  const db = getDb();
  const run = db.transaction(() => {
    db.prepare('UPDATE scheduled_scans SET last_scan_id = NULL WHERE last_scan_id IN (SELECT id FROM scans WHERE created_at < ?)').run(cutoff);
    return db.prepare('DELETE FROM scans WHERE created_at < ?').run(cutoff).changes;
  });
  return run();
}

export function deleteUserScans(userId: number): void {
  getDb().prepare('DELETE FROM scans WHERE user_id = ?').run(userId);
}
