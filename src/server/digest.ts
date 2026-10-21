import { getWebConfig, type WebConfig } from '../shared/config';
import { MODULE_DEFINITIONS } from '../shared/modules';
import { createLogger } from '../shared/logger';
import { getDb } from './db';
import { createMailer } from './email/mailer';
import { digestEmail, type DigestEmailData } from './email/templates';
import { sweepExpiredAuthData } from './maintenance';
import { getScanStats, sweepScanHistory } from './scans';
import { getSetting, setSetting } from './settings';

const log = createLogger();
const DAY_MS = 24 * 60 * 60 * 1000;
const LAST_RUN_KEY = 'digest_last_run_at';

/** Configured recipients, or every admin account when none are configured. */
export function resolveRecipients(config: WebConfig = getWebConfig()): string[] {
  if (config.digest.recipients.length > 0) return config.digest.recipients;
  const admins = getDb()
    .prepare(`SELECT email FROM users WHERE role = 'admin' AND deleted_at IS NULL AND status = 'active'`)
    .all() as Array<{ email: string }>;
  return admins.map((a) => a.email);
}

interface NewUserRow {
  email: string;
  created_at: string;
  email_verified_at: string | null;
}

export function buildDigestData(fromIso: string, toIso: string, config: WebConfig = getWebConfig()): DigestEmailData {
  const stats = getScanStats(fromIso, toIso);
  const newUsers = (getDb()
    .prepare(`SELECT email, created_at, email_verified_at FROM users WHERE created_at >= ? AND created_at < ? AND deleted_at IS NULL ORDER BY created_at DESC`)
    .all(fromIso, toIso) as NewUserRow[]).map((u) => ({ email: u.email, createdAt: u.created_at, verified: Boolean(u.email_verified_at) }));

  return {
    date: new Date(fromIso).toISOString().slice(0, 10),
    newUsers,
    scans: {
      total: stats.total,
      completed: stats.completed,
      failed: stats.failed,
      cancelled: stats.cancelled,
      totalDurationMs: stats.totalDurationMs,
      avgDurationMs: stats.avgDurationMs,
      p95DurationMs: stats.p95DurationMs,
    },
    byProfile: stats.byProfile,
    byModule: stats.byModule.map((m) => ({ module: MODULE_DEFINITIONS[m.module as keyof typeof MODULE_DEFINITIONS]?.name ?? m.module, count: m.count })),
    topTargets: stats.topTargets,
    findings: stats.findings,
    adminUrl: `${config.appBaseUrl}/admin/scans`,
  };
}

export interface DigestResult {
  sent: boolean;
  recipients: string[];
  reason?: string;
}

/** Render and send the admin digest for a window (defaults to the last 24h). */
export async function sendAdminDigest(range?: { from: string; to: string }, config: WebConfig = getWebConfig()): Promise<DigestResult> {
  if (!config.email.configured) return { sent: false, recipients: [], reason: 'email_not_configured' };
  const recipients = resolveRecipients(config);
  if (recipients.length === 0) return { sent: false, recipients: [], reason: 'no_recipients' };

  const to = range?.to ?? new Date().toISOString();
  const from = range?.from ?? new Date(Date.now() - DAY_MS).toISOString();
  const data = buildDigestData(from, to, config);
  const rendered = digestEmail(data);
  const mailer = createMailer(config);

  let sentAny = false;
  for (const recipient of recipients) {
    try {
      await mailer.send({ to: recipient, ...rendered });
      sentAny = true;
    } catch (e) {
      log.warn('digest_send_failed', { to: recipient, error: (e as Error).message });
    }
  }
  setSetting(LAST_RUN_KEY, new Date().toISOString());
  log.info('digest_sent', { recipients: recipients.length, sentAny });
  return { sent: sentAny, recipients };
}

/**
 * Called on an hourly tick: send the digest once per UTC day at/after the
 * configured hour, and sweep scan history daily.
 */
export async function runScheduledMaintenance(): Promise<void> {
  const config = getWebConfig();
  const now = new Date();

  // Retention sweep (at most once per day).
  const lastSweep = getSetting('retention_last_sweep_at');
  const sweptToday = lastSweep && new Date(lastSweep).toISOString().slice(0, 10) === now.toISOString().slice(0, 10);
  if (!sweptToday && config.scanHistoryRetentionDays > 0) {
    try {
      const removed = sweepScanHistory(config.scanHistoryRetentionDays);
      setSetting('retention_last_sweep_at', now.toISOString());
      if (removed > 0) log.info('scan_history_swept', { removed, retentionDays: config.scanHistoryRetentionDays });
    } catch (e) {
      log.warn('scan_history_sweep_failed', { error: (e as Error).message });
    }
  }

  const lastAuthCleanup = getSetting('auth_cleanup_last_sweep_at');
  const authCleanedToday = lastAuthCleanup && new Date(lastAuthCleanup).toISOString().slice(0, 10) === now.toISOString().slice(0, 10);
  if (!authCleanedToday) {
    try {
      const removed = sweepExpiredAuthData(now);
      setSetting('auth_cleanup_last_sweep_at', now.toISOString());
      log.info('auth_artifacts_swept', { ...removed });
    } catch (e) {
      log.warn('auth_artifacts_sweep_failed', { error: (e as Error).message });
    }
  }

  if (!config.digest.enabled) return;
  if (now.getUTCHours() < config.digest.hourUtc) return;

  const lastRun = getSetting(LAST_RUN_KEY);
  if (lastRun && new Date(lastRun).toISOString().slice(0, 10) === now.toISOString().slice(0, 10)) return;

  await sendAdminDigest(undefined, config);
}
