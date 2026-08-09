import type { NextRequest } from 'next/server';
import { z } from 'zod';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json } from '@/server/http';
import { AuthError, resetPassword } from '@/server/auth/service';
import { verifyOrigin } from '@/server/auth/csrf';
import { getUserById } from '@/server/users';

export const dynamic = 'force-dynamic';

const schema = z
  .object({
    userId: z.number().int().positive(),
    token: z.string().min(1).max(512),
    password: z.string().min(1).max(256),
  })
  .strict();

export async function POST(req: NextRequest) {
  await ensureInitialized();
  if (!verifyOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');
  const body = await req.json().catch(() => null);
  const parsed = schema.safeParse(body);
  if (!parsed.success) return errorJson('Invalid input.', 400, 'validation_error');

  try {
    await resetPassword(parsed.data.userId, parsed.data.token, parsed.data.password);
  } catch (e) {
    if (e instanceof AuthError) return errorJson(e.message, e.status, 'auth_error');
    throw e;
  }
  return json({ ok: true });
}
