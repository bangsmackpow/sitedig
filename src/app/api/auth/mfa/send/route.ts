import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { z } from 'zod';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson } from '@/server/http';
import { getWebConfig } from '@/shared/config';
import { getUserById } from '@/server/users';
import { findChallenge, refreshEmailCode, type MfaMethod } from '@/server/auth/mfa';
import { createMailer } from '@/server/email/mailer';
import { mfaCodeEmail } from '@/server/email/templates';
import { rateLimit, sha256 } from '@/server/auth/rate-limit';
import { verifyOrigin } from '@/server/auth/csrf';

export const dynamic = 'force-dynamic';

const sendSchema = z.object({ ticket: z.string().min(10).max(512) }).strict();

export async function POST(req: NextRequest): Promise<NextResponse> {
  await ensureInitialized();
  if (!verifyOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');

  const body = await req.json().catch(() => null);
  const parsed = sendSchema.safeParse(body);
  if (!parsed.success) return errorJson('Invalid request.', 400, 'validation_error');

  // Bound resends per sign-in attempt.
  if (!rateLimit(`mfa-send:${sha256(parsed.data.ticket)}`, 5, 10 * 60 * 1000)) {
    return errorJson('A code was sent recently. Please wait before requesting another.', 429, 'rate_limited');
  }

  const challenge = findChallenge(parsed.data.ticket);
  if (!challenge) return errorJson('This sign-in session has expired. Please sign in again.', 401, 'mfa_expired');

  const methods = JSON.parse(challenge.methods_json) as MfaMethod[];
  if (!methods.includes('email')) return errorJson('Email codes are not available for this account.', 400, 'method_not_allowed');

  const user = getUserById(challenge.user_id);
  if (!user || user.status === 'disabled') return errorJson('This account is unavailable.', 401, 'unauthorized');

  const code = refreshEmailCode(challenge.id);
  if (!code) return errorJson('Could not issue a code.', 500, 'internal');

  try {
    await createMailer(getWebConfig()).send({ to: user.email, ...mfaCodeEmail(code, 10) });
  } catch (e) {
    return errorJson(`Could not send the email: ${(e as Error).message}`, 502, 'email_delivery_failed');
  }
  return NextResponse.json({ ok: true });
}
