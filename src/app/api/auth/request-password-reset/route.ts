import type { NextRequest } from 'next/server';
import { z } from 'zod';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json, readJsonLimited } from '@/server/http';
import { AuthError, requestPasswordReset } from '@/server/auth/service';
import { verifyOrigin } from '@/server/auth/csrf';
import { clientIp, rateLimit, sha256 } from '@/server/auth/rate-limit';
import { normalizeEmail } from '@/server/users';

export const dynamic = 'force-dynamic';

const schema = z.object({ email: z.string().email().max(254) }).strict();

export async function POST(req: NextRequest) {
  await ensureInitialized();
  if (!verifyOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');
  const body = await readJsonLimited(req, 16 * 1024).catch(() => null);
  const parsed = schema.safeParse(body);
  if (!parsed.success) return errorJson('Invalid input.', 400, 'validation_error');

  const ip = clientIp(req);
  const emailKey = sha256(normalizeEmail(parsed.data.email));
  if (!rateLimit(`pwreset:ip:${ip}`, 10, 15 * 60 * 1000) || !rateLimit(`pwreset:email:${emailKey}`, 3, 60 * 60 * 1000)) {
    return errorJson('Too many password reset requests. Try again later.', 429, 'rate_limited');
  }

  try {
    await requestPasswordReset(parsed.data.email);
  } catch (e) {
    if (e instanceof AuthError) return errorJson(e.message, e.status, 'auth_error');
    throw e;
  }
  // Always succeed (avoid account enumeration).
  return json({ ok: true });
}
