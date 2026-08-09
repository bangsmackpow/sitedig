import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { z } from 'zod';
import { getWebConfig } from '@/shared/config';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json } from '@/server/http';
import { AuthError, login, register, toPublicUser } from '@/server/auth/service';
import { isPremium } from '@/server/entitlements';
import { clientIp, rateLimit, sha256 } from '@/server/auth/rate-limit';
import { createSession, sessionCookieOptions, setSessionCookie, setCsrfCookie, newCsrfToken, getRequestToken } from '@/server/auth/sessions';
import { verifyOrigin } from '@/server/auth/csrf';
import { getUserById } from '@/server/users';

export const dynamic = 'force-dynamic';

const registerSchema = z.object({ email: z.string().email().max(254), password: z.string().min(1).max(256) }).strict();
const loginSchema = z.object({ email: z.string().email().max(254), password: z.string().min(1).max(256) }).strict();

function secureCookies(): boolean {
  return getWebConfig().deploymentMode === 'hosted';
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  await ensureInitialized();
  if (!verifyOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');

  const body = await req.json().catch(() => null);
  const parsed = registerSchema.safeParse(body);
  if (!parsed.success) return errorJson(parsed.error.issues[0]?.message ?? 'Invalid input.', 400, 'validation_error');

  const ip = clientIp(req);
  if (!rateLimit(`register:${ip}`, 10, 60 * 60 * 1000)) {
    return errorJson('Too many registration attempts. Try again later.', 429, 'rate_limited');
  }

  try {
    const { user, needsVerification } = await register(parsed.data.email, parsed.data.password);
    const session = createSession(user.id, sha256(ip), req.headers.get('user-agent') ? sha256(req.headers.get('user-agent')!) : undefined);
    const secure = secureCookies();
    const res = NextResponse.json({ user: toPublicUser(user, isPremium(user)), needsVerification }, { status: 201 });
    setSessionCookie(res, session.token, secure);
    setCsrfCookie(res, newCsrfToken(), secure);
    return res;
  } catch (e) {
    if (e instanceof AuthError) return errorJson(e.message, e.status, 'auth_error');
    throw e;
  }
}
