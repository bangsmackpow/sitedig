import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { z } from 'zod';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson } from '@/server/http';
import { getUserById } from '@/server/users';
import { toPublicUser } from '@/server/auth/service';
import { isPremium } from '@/server/entitlements';
import { clientIp, rateLimit, sha256 } from '@/server/auth/rate-limit';
import { createSession, setSessionCookie, setCsrfCookie, newCsrfToken, secureRequest } from '@/server/auth/sessions';
import { verifyOrigin } from '@/server/auth/csrf';
import { findChallenge, verifyChallenge, type MfaMethod } from '@/server/auth/mfa';

export const dynamic = 'force-dynamic';

const verifySchema = z
  .object({
    ticket: z.string().min(10).max(512),
    code: z.string().min(1).max(32),
    method: z.enum(['totp', 'email', 'recovery']),
  })
  .strict();

export async function POST(req: NextRequest): Promise<NextResponse> {
  await ensureInitialized();
  if (!verifyOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');

  const body = await req.json().catch(() => null);
  const parsed = verifySchema.safeParse(body);
  if (!parsed.success) return errorJson('Enter the code from your authenticator or email.', 400, 'validation_error');

  const ip = clientIp(req);
  if (!rateLimit(`mfa-verify:${ip}`, 20, 15 * 60 * 1000)) {
    return errorJson('Too many attempts. Try again later.', 429, 'rate_limited');
  }

  const challenge = findChallenge(parsed.data.ticket);
  if (!challenge) return errorJson('This sign-in session has expired. Please sign in again.', 401, 'mfa_expired');

  const user = getUserById(challenge.user_id);
  if (!user || user.status === 'disabled') return errorJson('This account is unavailable.', 401, 'unauthorized');

  const outcome = verifyChallenge(challenge, user, parsed.data.method as MfaMethod, parsed.data.code);
  if (!outcome.ok) {
    if (outcome.reason === 'too_many_attempts') {
      return errorJson('Too many incorrect codes. Please sign in again.', 429, 'too_many_attempts');
    }
    if (outcome.reason === 'method_not_allowed') {
      return errorJson('That verification method is not available for this account.', 400, 'method_not_allowed');
    }
    return errorJson('That code is incorrect.', 401, 'invalid_code');
  }

  const session = createSession(user.id, sha256(ip), req.headers.get('user-agent') ? sha256(req.headers.get('user-agent')!) : undefined);
  const secure = secureRequest(req);
  const res = NextResponse.json({ user: toPublicUser(user, isPremium(user)) });
  setSessionCookie(res, session.token, secure);
  setCsrfCookie(res, newCsrfToken(), secure);
  return res;
}
