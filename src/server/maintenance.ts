import { getDb } from './db';

const DAY_MS = 24 * 60 * 60 * 1000;

export interface CleanupCounts {
  sessions: number;
  emailTokens: number;
  mfaChallenges: number;
  recoveryCodes: number;
  webhookEvents: number;
  auditRows: number;
}

/**
 * Remove expired or long-used authentication artifacts. Kept separate from scan
 * history retention so the database does not grow indefinitely from sessions,
 * tokens, challenges, webhook bookkeeping, and audit rows.
 */
export function sweepExpiredAuthData(now = new Date()): CleanupCounts {
  const db = getDb();
  const nowIso = now.toISOString();
  const usedCutoff = new Date(now.getTime() - 30 * DAY_MS).toISOString();
  const webhookCutoff = new Date(now.getTime() - 90 * DAY_MS).toISOString();
  const auditCutoff = new Date(now.getTime() - 365 * DAY_MS).toISOString();

  const cleanup = db.transaction(() => {
    const sessions = db
      .prepare('DELETE FROM sessions WHERE expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)')
      .run(nowIso, usedCutoff).changes;
    const emailTokens = db
      .prepare('DELETE FROM email_tokens WHERE expires_at < ? OR (used_at IS NOT NULL AND used_at < ?)')
      .run(nowIso, usedCutoff).changes;
    const mfaChallenges = db
      .prepare('DELETE FROM mfa_challenges WHERE expires_at < ? OR (used_at IS NOT NULL AND used_at < ?)')
      .run(nowIso, usedCutoff).changes;
    const recoveryCodes = db
      .prepare('DELETE FROM recovery_codes WHERE used_at IS NOT NULL AND used_at < ?')
      .run(usedCutoff).changes;
    const webhookEvents = db
      .prepare('DELETE FROM webhook_events WHERE processed_at < ?')
      .run(webhookCutoff).changes;
    const auditRows = db.prepare('DELETE FROM audit_log WHERE created_at < ?').run(auditCutoff).changes;

    return { sessions, emailTokens, mfaChallenges, recoveryCodes, webhookEvents, auditRows };
  });

  return cleanup();
}
