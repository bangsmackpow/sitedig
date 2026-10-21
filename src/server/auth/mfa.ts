import { createHmac, randomBytes, randomInt, timingSafeEqual, createHash } from 'node:crypto';
import { APP_NAME } from '../../shared/constants';
import { getDb } from '../db';
import type { UserRow } from '../users';

// --- TOTP (RFC 6238, SHA-1, 6 digits, 30s step) ----------------------------

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;
export const TOTP_WINDOW = 1; // accept ±1 step for clock skew

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

export function base32Decode(input: string): Buffer {
  const clean = input.replace(/=+$/, '').toUpperCase().replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error('Invalid base32 input.');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function hotp(key: Buffer, counter: number, digits: number): string {
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const hmac = createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin =
    ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return (bin % 10 ** digits).toString().padStart(digits, '0');
}

/** Generate a new base32 TOTP secret (160-bit, the RFC-recommended size). */
export function generateTotpSecret(bytes = 20): string {
  return base32Encode(randomBytes(bytes));
}

/** Compute the TOTP code for a given time-step counter. */
export function totpCode(secret: string, counter: number, digits = TOTP_DIGITS): string {
  return hotp(base32Decode(secret), counter, digits);
}

export function totpCounter(atMs: number, stepSeconds = TOTP_STEP_SECONDS): number {
  return Math.floor(atMs / 1000 / stepSeconds);
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

/** Verify a submitted TOTP code within a ±window of the current step. */
export function verifyTotp(secret: string, code: string, atMs = Date.now(), window = TOTP_WINDOW): boolean {
  const clean = (code ?? '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(clean)) return false;
  const counter = totpCounter(atMs);
  for (let i = -window; i <= window; i++) {
    if (safeEqual(totpCode(secret, counter + i), clean)) return true;
  }
  return false;
}

/** otpauth:// URI for authenticator apps. */
export function otpauthUri(secret: string, account: string, issuer = APP_NAME): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({ secret, issuer, algorithm: 'SHA1', digits: String(TOTP_DIGITS), period: String(TOTP_STEP_SECONDS) });
  return `otpauth://totp/${label}?${params.toString()}`;
}

// --- Email OTP + recovery codes --------------------------------------------

const CODE_TTL_MS = 10 * 60 * 1000;
const PENDING_TOTP_TTL_MS = 10 * 60 * 1000;
export const MFA_MAX_ATTEMPTS = 5;

export function generateEmailOtp(): string {
  return String(randomInt(0, 1_000_000)).padStart(6, '0');
}

/** Recovery codes: 10 codes, 8 chars each, unambiguous base32 alphabet. */
export function generateRecoveryCodes(count = 10): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const raw = base32Encode(randomBytes(5)); // 8 chars
    codes.push(`${raw.slice(0, 4)}-${raw.slice(4, 8)}`);
  }
  return codes;
}

function hashSecret(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

// --- User MFA state --------------------------------------------------------

export interface MfaState {
  emailEnabled: boolean;
  totpEnabled: boolean;
}

export function getMfaState(user: UserRow): MfaState {
  return { emailEnabled: Boolean(user.mfa_email_enabled), totpEnabled: Boolean(user.totp_enabled_at && user.totp_secret) };
}

export function isMfaEnabled(user: UserRow): boolean {
  const s = getMfaState(user);
  return s.emailEnabled || s.totpEnabled;
}

export function setEmailMfaEnabled(userId: number, enabled: boolean): void {
  getDb().prepare('UPDATE users SET mfa_email_enabled = ?, updated_at = ? WHERE id = ?').run(enabled ? 1 : 0, new Date().toISOString(), userId);
}

/** Store an unconfirmed TOTP secret without touching the active factor. */
export function setPendingTotpSecret(userId: number, secret: string): void {
  const now = new Date().toISOString();
  getDb()
    .prepare('UPDATE users SET totp_pending_secret = ?, totp_pending_created_at = ?, updated_at = ? WHERE id = ?')
    .run(secret, now, now, userId);
}

/** Return a pending secret only while its enrollment window is still valid. */
export function getPendingTotpSecret(userId: number): string | null {
  const row = getDb()
    .prepare('SELECT totp_pending_secret AS secret, totp_pending_created_at AS createdAt FROM users WHERE id = ?')
    .get(userId) as { secret: string | null; createdAt: string | null } | undefined;
  if (!row?.secret || !row.createdAt) return null;
  const createdAt = Date.parse(row.createdAt);
  if (!Number.isFinite(createdAt) || Date.now() - createdAt > PENDING_TOTP_TTL_MS) return null;
  return row.secret;
}

/** Promote a confirmed pending secret, replacing any previous active secret. */
export function enableTotp(userId: number, secret: string): void {
  const now = new Date().toISOString();
  getDb()
    .prepare(
      `UPDATE users SET totp_secret = ?, totp_enabled_at = ?, totp_pending_secret = NULL,
         totp_pending_created_at = NULL, updated_at = ? WHERE id = ?`,
    )
    .run(secret, now, now, userId);
}

export function disableTotp(userId: number): void {
  getDb()
    .prepare(
      `UPDATE users SET totp_secret = NULL, totp_enabled_at = NULL,
         totp_pending_secret = NULL, totp_pending_created_at = NULL, updated_at = ? WHERE id = ?`,
    )
    .run(new Date().toISOString(), userId);
}

export function disableAllMfa(userId: number): void {
  getDb()
    .prepare(
      `UPDATE users SET mfa_email_enabled = 0, totp_secret = NULL, totp_enabled_at = NULL,
         totp_pending_secret = NULL, totp_pending_created_at = NULL, updated_at = ? WHERE id = ?`,
    )
    .run(new Date().toISOString(), userId);
  getDb().prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(userId);
}

/** Invalidate any pre-session MFA tickets, e.g. after a password reset. */
export function invalidateMfaChallenges(userId: number): void {
  getDb()
    .prepare('UPDATE mfa_challenges SET used_at = ? WHERE user_id = ? AND used_at IS NULL')
    .run(new Date().toISOString(), userId);
}

export function countUnusedRecoveryCodes(userId: number): number {
  const row = getDb().prepare('SELECT COUNT(*) AS c FROM recovery_codes WHERE user_id = ? AND used_at IS NULL').get(userId) as { c: number };
  return row.c;
}

/** Replace all recovery codes; returns the plaintext codes once (never stored raw). */
export function replaceRecoveryCodes(userId: number): string[] {
  const codes = generateRecoveryCodes();
  const db = getDb();
  const now = new Date().toISOString();
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(userId);
    const stmt = db.prepare('INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)');
    for (const code of codes) stmt.run(userId, hashSecret(code.toUpperCase()), now);
  });
  tx();
  return codes;
}

export function consumeRecoveryCode(userId: number, code: string): boolean {
  const normalized = (code ?? '').trim().toUpperCase();
  const row = getDb()
    .prepare('SELECT id FROM recovery_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL')
    .get(userId, hashSecret(normalized)) as { id: number } | undefined;
  if (!row) return false;
  const result = getDb()
    .prepare('UPDATE recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL')
    .run(new Date().toISOString(), row.id);
  return result.changes > 0;
}

// --- Login challenges ------------------------------------------------------

export type MfaMethod = 'totp' | 'email' | 'recovery';

export interface MfaChallengeRow {
  id: number;
  user_id: number;
  ticket_hash: string;
  methods_json: string;
  code_hash: string | null;
  expires_at: string;
  attempts: number;
  used_at: string | null;
  created_at: string;
}

export function availableMethods(user: UserRow): MfaMethod[] {
  const methods: MfaMethod[] = [];
  if (user.totp_enabled_at && user.totp_secret) methods.push('totp');
  if (user.mfa_email_enabled) methods.push('email');
  const recovery = countUnusedRecoveryCodes(user.id);
  if (recovery > 0) methods.push('recovery');
  return methods;
}

export interface CreatedChallenge {
  ticket: string;
  methods: MfaMethod[];
  /** Present only when the email method is available. */
  emailCode: string | null;
}

/** Create a login challenge after a correct password, when MFA is enabled. */
export function createLoginChallenge(user: UserRow): CreatedChallenge {
  const methods = availableMethods(user);
  const ticket = randomBytes(32).toString('base64url');
  const emailCode = methods.includes('email') ? generateEmailOtp() : null;
  const now = new Date().toISOString();
  getDb()
    .prepare('UPDATE mfa_challenges SET used_at = ? WHERE user_id = ? AND used_at IS NULL')
    .run(now, user.id);
  getDb()
    .prepare(
      `INSERT INTO mfa_challenges (user_id, ticket_hash, methods_json, code_hash, expires_at, attempts, created_at)
       VALUES (?, ?, ?, ?, ?, 0, ?)`,
    )
    .run(user.id, hashSecret(ticket), JSON.stringify(methods), emailCode ? hashSecret(emailCode) : null, new Date(Date.now() + CODE_TTL_MS).toISOString(), now);
  return { ticket, methods, emailCode };
}

export function findChallenge(ticket: string): MfaChallengeRow | null {
  const row = getDb()
    .prepare('SELECT * FROM mfa_challenges WHERE ticket_hash = ? AND used_at IS NULL')
    .get(hashSecret(ticket)) as MfaChallengeRow | undefined;
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) return null;
  return row;
}

/** Issue a fresh email code for an existing challenge (resend). */
export function refreshEmailCode(challengeId: number): string | null {
  const code = generateEmailOtp();
  // Do not reset attempts: a resend must not bypass the challenge lockout.
  getDb()
    .prepare('UPDATE mfa_challenges SET code_hash = ?, expires_at = ? WHERE id = ?')
    .run(hashSecret(code), new Date(Date.now() + CODE_TTL_MS).toISOString(), challengeId);
  return code;
}

export type VerifyOutcome =
  | { ok: true; userId: number; method: MfaMethod }
  | { ok: false; reason: 'expired' | 'too_many_attempts' | 'method_not_allowed' | 'invalid_code' };

/**
 * Verify a submitted code against a login challenge. Consumes the challenge on
 * success; locks it out after MFA_MAX_ATTEMPTS failed attempts.
 */
export function verifyChallenge(challenge: MfaChallengeRow, user: UserRow, method: MfaMethod, code: string): VerifyOutcome {
  const methods = JSON.parse(challenge.methods_json) as MfaMethod[];
  if (!methods.includes(method)) return { ok: false, reason: 'method_not_allowed' };

  const attempts = challenge.attempts + 1;
  if (attempts > MFA_MAX_ATTEMPTS) {
    getDb().prepare('UPDATE mfa_challenges SET used_at = ? WHERE id = ?').run(new Date().toISOString(), challenge.id);
    return { ok: false, reason: 'too_many_attempts' };
  }
  getDb().prepare('UPDATE mfa_challenges SET attempts = ? WHERE id = ?').run(attempts, challenge.id);

  let valid = false;
  if (method === 'totp' && user.totp_secret) {
    valid = verifyTotp(user.totp_secret, code);
  } else if (method === 'email') {
    valid = Boolean(challenge.code_hash) && safeEqual(challenge.code_hash!, hashSecret((code ?? '').replace(/\s+/g, '')));
  } else if (method === 'recovery') {
    valid = consumeRecoveryCode(user.id, code);
  }

  if (!valid) return { ok: false, reason: 'invalid_code' };
  getDb().prepare('UPDATE mfa_challenges SET used_at = ? WHERE id = ?').run(new Date().toISOString(), challenge.id);
  return { ok: true, userId: user.id, method };
}
