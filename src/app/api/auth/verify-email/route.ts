import type { NextRequest } from 'next/server';
import { z } from 'zod';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json, readJsonLimited } from '@/server/http';
import { verifyEmail } from '@/server/auth/service';
import { clientIp, rateLimit } from '@/server/auth/rate-limit';
import { verifyOrigin } from '@/server/auth/csrf';
import { getUserById } from '@/server/users';

export const dynamic = 'force-dynamic';

const schema = z.object({ userId: z.number().int().positive(), token: z.string().min(1).max(512) }).strict();

export async function POST(req: NextRequest) {
  await ensureInitialized();
  if (!verifyOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');
  if (!rateLimit(`verify-email:${clientIp(req)}`, 30, 15 * 60 * 1000)) {
    return errorJson('Too many verification attempts. Try again later.', 429, 'rate_limited');
  }
  const body = await readJsonLimited(req, 16 * 1024).catch(() => null);
  const parsed = schema.safeParse(body);
  if (!parsed.success) return errorJson('Invalid input.', 400, 'validation_error');

  if (!getUserById(parsed.data.userId)) return errorJson('Account not found.', 404, 'not_found');
  const ok = await verifyEmail(parsed.data.userId, parsed.data.token);
  if (!ok) return errorJson('This verification link is invalid or has expired.', 400, 'invalid_token');
  return json({ ok: true });
}
