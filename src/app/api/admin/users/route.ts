import type { NextRequest } from 'next/server';
import { z } from 'zod';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json } from '@/server/http';
import { guardAdmin } from '@/server/http';
import { verifyCsrfOrOrigin } from '@/server/auth/csrf';
import { createUser, listUsers, type UserRow } from '@/server/users';
import { hashPassword, validatePasswordStrength } from '@/server/auth/passwords';
import { isPremium } from '@/server/entitlements';
import { auditLog } from '@/server/audit';

export const dynamic = 'force-dynamic';

const createSchema = z
  .object({
    email: z.string().email().max(254),
    password: z.string().min(1).max(256),
    role: z.enum(['admin', 'user']).optional(),
  })
  .strict();

function view(user: UserRow) {
  return { id: user.id, email: user.email, role: user.role, status: user.status, emailVerified: Boolean(user.email_verified_at), premium: isPremium(user), createdAt: user.created_at };
}

export async function GET(req: NextRequest) {
  await ensureInitialized();
  const guard = await guardAdmin(req);
  if (!guard.ok) return guard.response;
  const q = new URL(req.url).searchParams.get('q') ?? undefined;
  return json({ users: listUsers(q).map(view) });
}

export async function POST(req: NextRequest) {
  await ensureInitialized();
  if (!verifyCsrfOrOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');
  const guard = await guardAdmin(req);
  if (!guard.ok) return guard.response;

  const body = await req.json().catch(() => null);
  const parsed = createSchema.safeParse(body);
  if (!parsed.success) return errorJson(parsed.error.issues[0]?.message ?? 'Invalid input.', 400, 'validation_error');

  const passwordError = validatePasswordStrength(parsed.data.password);
  if (passwordError) return errorJson(passwordError, 400, 'weak_password');

  try {
    const user = createUser({ email: parsed.data.email, passwordHash: await hashPassword(parsed.data.password), role: parsed.data.role ?? 'user', verified: true });
    auditLog({ actorUserId: guard.value.user.id, action: 'admin.user_created', targetUserId: user.id, metadata: { role: user.role } });
    return json({ user: view(user) }, 201);
  } catch {
    return errorJson('An account with this email already exists.', 409, 'email_exists');
  }
}
