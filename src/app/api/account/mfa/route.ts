import type { NextRequest } from 'next/server';
import { z } from 'zod';
import QRCode from 'qrcode';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json } from '@/server/http';
import { guardUser } from '@/server/http';
import { getDb } from '@/server/db';
import { verifyCsrfOrOrigin } from '@/server/auth/csrf';
import { verifyPassword } from '@/server/auth/passwords';
import { rateLimit } from '@/server/auth/rate-limit';
import {
  countUnusedRecoveryCodes,
  disableTotp,
  enableTotp,
  generateTotpSecret,
  otpauthUri,
  replaceRecoveryCodes,
  setEmailMfaEnabled,
  setPendingTotpSecret,
  verifyTotp,
} from '@/server/auth/mfa';
import { auditLog } from '@/server/audit';

export const dynamic = 'force-dynamic';

const schema = z.discriminatedUnion('action', [
  z.object({ action: z.literal('email'), enabled: z.boolean(), password: z.string().min(1).max(256) }).strict(),
  z.object({ action: z.literal('totp-begin'), password: z.string().min(1).max(256) }).strict(),
  z.object({ action: z.literal('totp-confirm'), code: z.string().min(6).max(8) }).strict(),
  z.object({ action: z.literal('totp-disable'), password: z.string().min(1).max(256) }).strict(),
  z.object({ action: z.literal('recovery-regenerate'), password: z.string().min(1).max(256) }).strict(),
]);

interface MfaStateView {
  emailEnabled: boolean;
  totpEnabled: boolean;
  recoveryCodesRemaining: number;
}

/** Read current MFA flags straight from the DB (the guard row may be stale). */
function stateFor(userId: number): MfaStateView {
  const row = getDb()
    .prepare('SELECT mfa_email_enabled, totp_secret, totp_enabled_at FROM users WHERE id = ?')
    .get(userId) as { mfa_email_enabled: number; totp_secret: string | null; totp_enabled_at: string | null } | undefined;
  return {
    emailEnabled: Boolean(row?.mfa_email_enabled),
    totpEnabled: Boolean(row?.totp_enabled_at && row?.totp_secret),
    recoveryCodesRemaining: countUnusedRecoveryCodes(userId),
  };
}

export async function POST(req: NextRequest) {
  await ensureInitialized();
  if (!verifyCsrfOrOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');
  const guard = await guardUser(req);
  if (!guard.ok) return guard.response;
  const user = guard.value.user;

  if (!rateLimit(`mfa-manage:${user.id}`, 20, 15 * 60 * 1000)) {
    return errorJson('Too many attempts. Try again later.', 429, 'rate_limited');
  }

  const parsed = schema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return errorJson('Invalid request.', 400, 'validation_error');
  const input = parsed.data;

  const checkPassword = async (): Promise<boolean> => {
    if (!('password' in input)) return true;
    return verifyPassword(input.password, user.password_hash);
  };

  switch (input.action) {
    case 'email': {
      if (!(await checkPassword())) return errorJson('Incorrect password.', 401, 'invalid_password');
      if (input.enabled && !user.email_verified_at) {
        return errorJson('Verify your email address before enabling email MFA.', 400, 'email_not_verified');
      }
      setEmailMfaEnabled(user.id, input.enabled);
      auditLog({ actorUserId: user.id, action: input.enabled ? 'mfa.email_enabled' : 'mfa.email_disabled', targetUserId: user.id });
      return json({ mfa: stateFor(user.id) });
    }
    case 'totp-begin': {
      if (!(await checkPassword())) return errorJson('Incorrect password.', 401, 'invalid_password');
      const secret = generateTotpSecret();
      setPendingTotpSecret(user.id, secret);
      const uri = otpauthUri(secret, user.email);
      const qrDataUrl = await QRCode.toDataURL(uri, { margin: 1, width: 220, color: { dark: '#0f172a', light: '#ffffff' } });
      return json({ totp: { secret, otpauthUri: uri, qrDataUrl } });
    }
    case 'totp-confirm': {
      if (!user.totp_secret) return errorJson('Start TOTP setup first.', 400, 'no_pending_secret');
      if (!verifyTotp(user.totp_secret, input.code)) return errorJson('That code is incorrect. Check your authenticator clock.', 400, 'invalid_code');
      enableTotp(user.id);
      const recoveryCodes = replaceRecoveryCodes(user.id);
      auditLog({ actorUserId: user.id, action: 'mfa.totp_enabled', targetUserId: user.id });
      return json({ mfa: stateFor(user.id), recoveryCodes });
    }
    case 'totp-disable': {
      if (!(await checkPassword())) return errorJson('Incorrect password.', 401, 'invalid_password');
      disableTotp(user.id);
      auditLog({ actorUserId: user.id, action: 'mfa.totp_disabled', targetUserId: user.id });
      return json({ mfa: stateFor(user.id) });
    }
    case 'recovery-regenerate': {
      if (!(await checkPassword())) return errorJson('Incorrect password.', 401, 'invalid_password');
      const recoveryCodes = replaceRecoveryCodes(user.id);
      auditLog({ actorUserId: user.id, action: 'mfa.recovery_regenerated', targetUserId: user.id });
      return json({ mfa: stateFor(user.id), recoveryCodes });
    }
    default:
      return errorJson('Unsupported action.', 400, 'validation_error');
  }
}

export async function GET(req: NextRequest) {
  await ensureInitialized();
  const guard = await guardUser(req);
  if (!guard.ok) return guard.response;
  return json({ mfa: stateFor(guard.value.user.id) });
}
