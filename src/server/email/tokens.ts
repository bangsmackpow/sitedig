import { randomBytes, createHash } from 'node:crypto';
import { getDb } from '../db';

export type EmailTokenPurpose = 'email_verify' | 'password_reset';

export const EMAIL_TOKEN_TTL_MS = 45 * 60 * 1000;

export function hashEmailToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function createEmailToken(userId: number, purpose: EmailTokenPurpose, ttlMs = EMAIL_TOKEN_TTL_MS): string {
  const token = randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + ttlMs).toISOString();
  getDb()
    .prepare(`INSERT INTO email_tokens (user_id, token_hash, purpose, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`)
    .run(userId, hashEmailToken(token), purpose, expiresAt, new Date().toISOString());
  return token;
}

/** Consume a token; returns true only for a valid, unused, unexpired token. */
export function consumeEmailToken(userId: number, purpose: EmailTokenPurpose, token: string): boolean {
  const now = new Date().toISOString();
  const result = getDb()
    .prepare(
      `UPDATE email_tokens SET used_at = ?
       WHERE user_id = ? AND purpose = ? AND token_hash = ? AND used_at IS NULL AND expires_at > ?`,
    )
    .run(now, userId, purpose, hashEmailToken(token), now);
  return result.changes > 0;
}

export function invalidateEmailTokens(userId: number, purpose: EmailTokenPurpose): void {
  getDb()
    .prepare(`UPDATE email_tokens SET used_at = ? WHERE user_id = ? AND purpose = ? AND used_at IS NULL`)
    .run(new Date().toISOString(), userId, purpose);
}
