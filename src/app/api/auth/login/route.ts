import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { z } from 'zod';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, readJsonLimited } from '@/server/http';
import { AuthError, login, toPublicUser } from '@/server/auth/service';
import { isPremium } from '@/server/entitlements';
import { clientIp, rateLimit, sha256 } from '@/server/auth/rate-limit';
import { createSession, setSessionCookie, setCsrfCookie, newCsrfToken, secureRequest } from '@/server/auth/sessions';
import { verifyOrigin } from '@/server/auth/csrf';
import { createLoginChallenge, isMfaEnabled } from '@/server/auth/mfa';
import { createMailer } from '@/server/email/mailer';
import { mfaCodeEmail } from '@/server/email/templates';
import { getWebConfig } from '@/shared/config';
import { createLogger } from '@/shared/logger';

export const dynamic = 'force-dynamic';

const loginSchema = z.object({ email: z.string().email().max(254), password: z.string().min(1).max(256) }).strict();
const log = createLogger();

export async function POST(req: NextRequest): Promise<NextResponse> {
  await ensureInitialized();
  if (!verifyOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');

  const body = await readJsonLimited(req, 16 * 1024).catch(() => null);
  const parsed = loginSchema.safeParse(body);
  if (!parsed.success) return errorJson('Invalid email or password.', 401, 'invalid_credentials');

  const ip = clientIp(req);
  if (!rateLimit(`login:${ip}:${parsed.data.email}`, 10, 15 * 60 * 1000)) {
    return errorJson('Too many login attempts. Try again later.', 429, 'rate_limited');
  }

  try {
    const user = await login(parsed.data.email, parsed.data.password);

    // Second factor: passwords alone do not create a session when MFA is on.
    if (isMfaEnabled(user)) {
      const challenge = createLoginChallenge(user);
      if (challenge.emailCode) {
        try {
          const cfg = getWebConfig();
          await createMailer(cfg).send({ to: user.email, ...mfaCodeEmail(challenge.emailCode, 10) });
        } catch (e) {
          // TOTP/recovery users can still proceed; email users can request a new code.
          log.warn('mfa_email_send_failed', { userId: user.id, error: (e as Error).message });
        }
      }
      return NextResponse.json({ mfaRequired: true, ticket: challenge.ticket, methods: challenge.methods });
    }

    const session = createSession(user.id, sha256(ip), req.headers.get('user-agent') ? sha256(req.headers.get('user-agent')!) : undefined);
    const secure = secureRequest(req);
    const res = NextResponse.json({ user: toPublicUser(user, isPremium(user)) });
    setSessionCookie(res, session.token, secure);
    setCsrfCookie(res, newCsrfToken(), secure);
    return res;
  } catch (e) {
    if (e instanceof AuthError) return errorJson(e.message, e.status, 'auth_error');
    throw e;
  }
}
