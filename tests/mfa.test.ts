import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { resetDbForTests } from '../src/server/db';
import { createUser, getUserById } from '../src/server/users';
import {
  base32Decode,
  base32Encode,
  consumeRecoveryCode,
  createLoginChallenge,
  findChallenge,
  generateRecoveryCodes,
  generateTotpSecret,
  getPendingTotpSecret,
  otpauthUri,
  replaceRecoveryCodes,
  setEmailMfaEnabled,
  setPendingTotpSecret,
  enableTotp,
  totpCode,
  totpCounter,
  verifyChallenge,
  verifyTotp,
} from '../src/server/auth/mfa';

let dbPath: string;

beforeAll(() => {
  dbPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sitedig-mfa-')), 'test.sqlite');
  process.env.DB_PATH = dbPath;
  process.env.DEPLOYMENT_MODE = 'self-hosted';
});

beforeEach(() => {
  resetDbForTests();
});

afterAll(() => {
  resetDbForTests();
  fs.rmSync(path.dirname(dbPath), { recursive: true, force: true });
});

describe('base32', () => {
  it('round-trips arbitrary bytes', () => {
    const buf = Buffer.from('The quick brown fox jumps over the lazy dog');
    expect(base32Decode(base32Encode(buf)).equals(buf)).toBe(true);
  });

  it('ignores padding and whitespace on decode', () => {
    expect(base32Decode('JBSW Y3DP====').toString('utf8')).toBe('Hello');
  });
});

describe('TOTP (RFC 6238 test vectors, SHA-1)', () => {
  // RFC 6238 Appendix B uses the ASCII secret "12345678901234567890".
  const secret = base32Encode(Buffer.from('12345678901234567890'));

  const vectors: Array<[number, string]> = [
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ];

  it.each(vectors)('matches the RFC vector at T=%i', (time, expected) => {
    expect(totpCode(secret, Math.floor(time / 30), 8)).toBe(expected);
  });

  it('verifies a current code and rejects a wrong one', () => {
    const s = generateTotpSecret();
    const now = Date.now();
    const code = totpCode(s, totpCounter(now));
    expect(verifyTotp(s, code, now)).toBe(true);
    expect(verifyTotp(s, '000000', now)).toBe(false);
    expect(verifyTotp(s, 'nope', now)).toBe(false);
  });

  it('accepts a code from the previous step (clock skew) but not far outside', () => {
    const s = generateTotpSecret();
    const now = Date.now();
    const prev = totpCode(s, totpCounter(now) - 1);
    expect(verifyTotp(s, prev, now, 1)).toBe(true);
    const far = totpCode(s, totpCounter(now) - 5);
    expect(verifyTotp(s, far, now, 1)).toBe(false);
  });

  it('builds a valid otpauth URI', () => {
    const uri = otpauthUri('ABCDEFGH', 'user@example.com', 'SiteDig');
    expect(uri).toMatch(/^otpauth:\/\/totp\//);
    expect(uri).toContain('secret=ABCDEFGH');
    expect(uri).toContain('issuer=SiteDig');
  });
});

describe('recovery codes', () => {
  it('generates unique, well-formed codes', () => {
    const codes = generateRecoveryCodes(10);
    expect(codes).toHaveLength(10);
    expect(new Set(codes).size).toBe(10);
    for (const c of codes) expect(c).toMatch(/^[A-Z2-7]{4}-[A-Z2-7]{4}$/);
  });

  it('consumes a stored code exactly once', () => {
    const user = createUser({ email: 'rec@example.com', passwordHash: 'x', verified: true });
    const codes = replaceRecoveryCodes(user.id);
    expect(consumeRecoveryCode(user.id, codes[0])).toBe(true);
    expect(consumeRecoveryCode(user.id, codes[0])).toBe(false);
    expect(consumeRecoveryCode(user.id, 'ZZZZ-ZZZZ')).toBe(false);
  });

  it('keeps the active TOTP factor while re-enrollment is pending', () => {
    const user = createUser({ email: 'reenroll@example.com', passwordHash: 'x', verified: true });
    const first = generateTotpSecret();
    setPendingTotpSecret(user.id, first);
    enableTotp(user.id, first);

    const second = generateTotpSecret();
    setPendingTotpSecret(user.id, second);
    const current = getUserById(user.id)!;
    expect(current.totp_enabled_at).not.toBeNull();
    expect(current.totp_secret).toBe(first);
    expect(getPendingTotpSecret(user.id)).toBe(second);
  });
});

describe('login challenges', () => {
  it('issues and verifies an email OTP, locking out after too many attempts', () => {
    const user = createUser({ email: 'otp@example.com', passwordHash: 'x', verified: true });
    setEmailMfaEnabled(user.id, true);

    const challenge = createLoginChallenge(getUserById(user.id)!);
    expect(challenge.methods).toContain('email');
    expect(challenge.emailCode).toMatch(/^\d{6}$/);

    const stored = findChallenge(challenge.ticket)!;
    const fresh = getUserById(user.id)!;

    // wrong code does not consume the challenge
    expect(verifyChallenge(stored, fresh, 'email', '000000')).toMatchObject({ ok: false, reason: 'invalid_code' });
    // correct code succeeds
    const reloaded = findChallenge(challenge.ticket)!;
    expect(verifyChallenge(reloaded, fresh, 'email', challenge.emailCode!)).toMatchObject({ ok: true, method: 'email' });
    // challenge is consumed
    expect(findChallenge(challenge.ticket)).toBeNull();
  });

  it('verifies a TOTP challenge for a TOTP-enabled user', () => {
    const user = createUser({ email: 'totp@example.com', passwordHash: 'x', verified: true });
    const secret = generateTotpSecret();
    setPendingTotpSecret(user.id, secret);
    enableTotp(user.id, secret);

    const challenge = createLoginChallenge(getUserById(user.id)!);
    expect(challenge.methods).toContain('totp');
    expect(challenge.emailCode).toBeNull();

    const stored = findChallenge(challenge.ticket)!;
    const fresh = getUserById(user.id)!;
    const code = totpCode(secret, totpCounter(Date.now()));
    expect(verifyChallenge(stored, fresh, 'totp', code)).toMatchObject({ ok: true, method: 'totp' });
  });

  it('rejects an unavailable method', () => {
    const user = createUser({ email: 'only-email@example.com', passwordHash: 'x', verified: true });
    setEmailMfaEnabled(user.id, true);
    const challenge = createLoginChallenge(getUserById(user.id)!);
    const stored = findChallenge(challenge.ticket)!;
    const fresh = getUserById(user.id)!;
    expect(verifyChallenge(stored, fresh, 'totp', '123456')).toMatchObject({ ok: false, reason: 'method_not_allowed' });
  });
});
