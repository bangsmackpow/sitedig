import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getDb, resetDbForTests } from '../src/server/db';
import { hashPassword, verifyPassword, validatePasswordStrength } from '../src/server/auth/passwords';
import { createSession, getSessionUser, revokeAllUserSessions, sessionCookieName } from '../src/server/auth/sessions';
import { createUser, getUserByEmail, getUserById, setStripeCustomerId, updateUserStatus } from '../src/server/users';
import { grantEntitlement, revokeEntitlement, isPremium, canUseModule, hasEntitlement, PREMIUM_KEY } from '../src/server/entitlements';
import { register, login, requestPasswordReset, resetPassword } from '../src/server/auth/service';
import { createEmailToken, consumeEmailToken } from '../src/server/email/tokens';
import { applySubscriptionState, hasActiveSubscription } from '../src/server/billing/stripe';
import { requestAccountDeletion } from '../src/server/account';
import { createMailer } from '../src/server/email/mailer';
import { newCsrfToken } from '../src/server/auth/sessions';
import { auditLog, listAuditLog } from '../src/server/audit';

vi.mock('nodemailer', () => {
  const sendMail = vi.fn().mockResolvedValue({ messageId: 'test' });
  return {
    default: {
      createTransport: () => ({ sendMail }),
    },
  };
});

vi.mock('stripe', () => {
  const subscriptions = {
    update: vi.fn().mockResolvedValue({ id: 'sub_mock', status: 'canceled' }),
    retrieve: vi.fn(),
  };
  return {
    default: class {
      subscriptions = subscriptions;
      checkout = { sessions: { create: vi.fn() } };
      billingPortal = { sessions: { create: vi.fn() } };
    },
  };
});

let dbPath: string;

beforeAll(() => {
  dbPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sitedig-test-')), 'test.sqlite');
  process.env.DB_PATH = dbPath;
  process.env.DEPLOYMENT_MODE = 'self-hosted';
  // SMTP configured so self-hosted registration/password-reset paths are exercised;
  // nodemailer is mocked so nothing is actually sent.
  process.env.SMTP_HOST = 'smtp.example.test';
  process.env.SMTP_FROM = 'noreply@example.test';
  process.env.APP_BASE_URL = 'http://localhost:3000';
  // Stripe "configured" for account-deletion subscription cancel path (client is mocked).
  process.env.STRIPE_SECRET_KEY = 'sk_test_123';
  process.env.STRIPE_WEBHOOK_SECRET = 'whsec_test_123';
  process.env.STRIPE_PRICE_ID = 'price_test_123';
});

beforeEach(() => {
  resetDbForTests();
});

afterAll(() => {
  resetDbForTests();
  fs.rmSync(path.dirname(dbPath), { recursive: true, force: true });
});

describe('passwords', () => {
  it('hashes and verifies a password', async () => {
    const hash = await hashPassword('correct horse battery staple');
    expect(hash).toMatch(/^scrypt\$1\$/);
    expect(hash).not.toContain('correct horse');
    await expect(verifyPassword('correct horse battery staple', hash)).resolves.toBe(true);
    await expect(verifyPassword('wrong password 123', hash)).resolves.toBe(false);
  });

  it('rejects malformed stored hashes', async () => {
    await expect(verifyPassword('anything', 'garbage')).resolves.toBe(false);
    await expect(verifyPassword('anything', '')).resolves.toBe(false);
  });

  it('enforces a minimum password length', () => {
    expect(validatePasswordStrength('short')).not.toBeNull();
    expect(validatePasswordStrength('this is at least 12 chars')).toBeNull();
  });
});

describe('users', () => {
  it('creates, finds, and normalizes emails', async () => {
    const user = createUser({ email: '  Alice@Example.COM ', passwordHash: 'x', verified: true });
    expect(user.email_normalized).toBe('alice@example.com');
    expect(getUserByEmail('ALICE@example.com')).toBeTruthy();
    expect(getUserById(user.id)?.email).toBe('  Alice@Example.COM ');
  });

  it('returns null for unknown users', () => {
    expect(getUserByEmail('nobody@example.com')).toBeNull();
    expect(getUserById(9999)).toBeNull();
  });
});

describe('sessions', () => {
  it('creates a session that resolves to the user and revokes', () => {
    const user = createUser({ email: 'bob@example.com', passwordHash: 'x', verified: true });
    const { token } = createSession(user.id);
    const session = getSessionUser(token);
    expect(session?.user.id).toBe(user.id);
    expect(session?.sessionId).toBeGreaterThan(0);
    revokeAllUserSessions(user.id);
    expect(getSessionUser(token)).toBeNull();
  });

  it('rejects disabled users', () => {
    const user = createUser({ email: 'carol@example.com', passwordHash: 'x', verified: true });
    const { token } = createSession(user.id);
    updateUserStatus(user.id, 'disabled');
    expect(getSessionUser(token)).toBeNull();
  });

  it('names the cookie with the __Host- prefix for secure contexts', () => {
    expect(sessionCookieName(true)).toBe('__Host-sitedig_session');
    expect(sessionCookieName(false)).toBe('sitedig_session');
  });
});

describe('auth service', () => {
  it('registers, logs in, verifies email, resets password', async () => {
    const { user, needsVerification } = await register('dave@example.com', 'super secret password 1');
    expect(needsVerification).toBe(false); // self-hosted, no SMTP

    const loginUser = await login('dave@example.com', 'super secret password 1');
    expect(loginUser.id).toBe(user.id);

    await expect(login('dave@example.com', 'wrong password 999')).rejects.toMatchObject({ status: 401 });

    // email verification token flow (hosted-style)
    const token = createEmailToken(user.id, 'email_verify');
    expect(consumeEmailToken(user.id, 'email_verify', token)).toBe(true);
    expect(consumeEmailToken(user.id, 'email_verify', token)).toBe(false); // one-time use

    // password reset flow (token issued directly; SMTP path is tested separately)
    const resetToken = createEmailToken(user.id, 'password_reset');
    await resetPassword(user.id, resetToken, 'a new much longer password');
    await expect(login('dave@example.com', 'a new much longer password')).resolves.toBeTruthy();
    await expect(login('dave@example.com', 'super secret password 1')).rejects.toMatchObject({ status: 401 });
  });

  it('rejects duplicate emails', async () => {
    await register('dup@example.com', 'first password 1234');
    await expect(register('DUP@example.com', 'second password 1234')).rejects.toMatchObject({ status: 409 });
  });

  it('rejects weak passwords at registration', async () => {
    await expect(register('weak@example.com', 'short')).rejects.toMatchObject({ status: 400 });
  });

  it('does not reveal account existence on password reset (anti-enumeration)', async () => {
    await expect(requestPasswordReset('ghost@example.com')).resolves.toBeUndefined();
  });

  it('rejects an invalid reset token', async () => {
    const user = createUser({ email: 'tokenbad@example.com', passwordHash: 'x', verified: true });
    await expect(resetPassword(user.id, 'not-a-real-token', 'a new much longer password')).rejects.toMatchObject({ status: 400 });
  });
});

describe('entitlements', () => {
  it('grants and revokes premium', async () => {
    const user = createUser({ email: 'ent@example.com', passwordHash: 'x', verified: true });
    expect(isPremium(user)).toBe(false);

    grantEntitlement({ userId: user.id, key: PREMIUM_KEY, source: 'admin', createdByUserId: user.id });
    expect(isPremium(getUserById(user.id)!)).toBe(true);
    expect(hasEntitlement(user.id, PREMIUM_KEY)).toBe(true);

    revokeEntitlement({ userId: user.id, key: PREMIUM_KEY, source: 'admin' });
    expect(isPremium(getUserById(user.id)!)).toBe(false);
  });

  it('treats admins as premium', async () => {
    const admin = createUser({ email: 'admin-ent@example.com', passwordHash: 'x', role: 'admin', verified: true });
    expect(isPremium(admin)).toBe(true);
  });

  it('canUseModule respects deployment ceiling and premium', async () => {
    const user = createUser({ email: 'mod@example.com', passwordHash: 'x', verified: true });
    const deployed = new Set(['asset-discovery', 'vuln-scan'] as const);

    expect(canUseModule(user.id, user, 'asset-discovery', deployed)).toBe(false);
    expect(canUseModule(user.id, user, 'cve-context', deployed)).toBe(false); // not in ceiling

    grantEntitlement({ userId: user.id, key: PREMIUM_KEY, source: 'admin' });
    expect(canUseModule(user.id, getUserById(user.id)!, 'asset-discovery', deployed)).toBe(true);
    expect(canUseModule(user.id, getUserById(user.id)!, 'cve-context', deployed)).toBe(false);
  });
});

describe('billing sync', () => {
  it('synchronizes subscription state to entitlements', () => {
    const user = createUser({ email: 'bill@example.com', passwordHash: 'x', verified: true });
    setStripeCustomerId(user.id, 'cus_test_1');

    applySubscriptionState({
      id: 'sub_test_1',
      customer: 'cus_test_1',
      status: 'active',
      current_period_start: Math.floor(Date.now() / 1000) - 1000,
      current_period_end: Math.floor(Date.now() / 1000) + 1000,
      cancel_at_period_end: false,
      items: { data: [{ price: { id: 'price_test_1' } }] },
    });

    expect(hasActiveSubscription(user.id)).toBe(true);
    expect(isPremium(getUserById(user.id)!)).toBe(true);
    expect(getUserById(user.id)?.stripe_customer_id).toBe('cus_test_1');

    applySubscriptionState({
      id: 'sub_test_1',
      customer: 'cus_test_1',
      status: 'unpaid',
      items: { data: [{ price: { id: 'price_test_1' } }] },
    });

    expect(hasActiveSubscription(user.id)).toBe(false);
    expect(isPremium(getUserById(user.id)!)).toBe(false);
  });

  it('keeps premium during past_due but revokes on incomplete_expired', () => {
    const user = createUser({ email: 'bill2@example.com', passwordHash: 'x', verified: true });
    setStripeCustomerId(user.id, 'cus_test_2');

    applySubscriptionState({ id: 'sub_test_2', customer: 'cus_test_2', status: 'past_due', items: { data: [] } });
    expect(isPremium(getUserById(user.id)!)).toBe(true);

    applySubscriptionState({ id: 'sub_test_2', customer: 'cus_test_2', status: 'incomplete_expired', items: { data: [] } });
    expect(isPremium(getUserById(user.id)!)).toBe(false);
  });
});

describe('account deletion', () => {
  it('hard-deletes users without an active subscription', async () => {
    const user = createUser({ email: 'del@example.com', passwordHash: 'x', verified: true });
    await requestAccountDeletion(user.id);
    expect(getUserById(user.id)).toBeNull();
  });

  it('marks deletion_pending when a subscription is active, then deletes after it lapses', async () => {
    const user = createUser({ email: 'del2@example.com', passwordHash: 'x', verified: true });
    setStripeCustomerId(user.id, 'cus_test_3');
    applySubscriptionState({ id: 'sub_test_3', customer: 'cus_test_3', status: 'active', items: { data: [] } });
    await requestAccountDeletion(user.id);
    expect(getUserById(user.id)?.status).toBe('deletion_pending');

    applySubscriptionState({ id: 'sub_test_3', customer: 'cus_test_3', status: 'canceled', items: { data: [] } });
    const { completeDeletionIfDue } = await import('../src/server/account');
    completeDeletionIfDue(user.id);
    expect(getUserById(user.id)).toBeNull();
  });
});

describe('mailer', () => {
  it('raises a clear error when SMTP is not configured', async () => {
    const savedHost = process.env.SMTP_HOST;
    const savedFrom = process.env.SMTP_FROM;
    delete process.env.SMTP_HOST;
    delete process.env.SMTP_FROM;
    try {
      const mailer = createMailer();
      await expect(mailer.send({ to: 'x@example.com', subject: 'hi', text: 'hi' })).rejects.toThrow('SMTP is not configured');
    } finally {
      process.env.SMTP_HOST = savedHost;
      process.env.SMTP_FROM = savedFrom;
    }
  });
});

describe('csrf', () => {
  it('creates random tokens', () => {
    const a = newCsrfToken();
    const b = newCsrfToken();
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(a).not.toEqual(b);
  });
});

describe('audit log', () => {
  it('records and lists events', () => {
    const user = createUser({ email: 'audit@example.com', passwordHash: 'x', verified: true });
    auditLog({ actorUserId: user.id, action: 'test.event', targetUserId: user.id, metadata: { k: 'v' } });
    const events = listAuditLog(10);
    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events[0].action).toBe('test.event');
  });
});
