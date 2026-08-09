import type { NextRequest } from 'next/server';
import { z } from 'zod';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json } from '@/server/http';
import { AuthError, requestPasswordReset } from '@/server/auth/service';
import { verifyOrigin } from '@/server/auth/csrf';

export const dynamic = 'force-dynamic';

const schema = z.object({ email: z.string().email().max(254) }).strict();

export async function POST(req: NextRequest) {
  await ensureInitialized();
  if (!verifyOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');
  const body = await req.json().catch(() => null);
  const parsed = schema.safeParse(body);
  if (!parsed.success) return errorJson('Invalid input.', 400, 'validation_error');

  try {
    await requestPasswordReset(parsed.data.email);
  } catch (e) {
    if (e instanceof AuthError) return errorJson(e.message, e.status, 'auth_error');
    throw e;
  }
  // Always succeed (avoid account enumeration).
  return json({ ok: true });
}
