import type { NextRequest } from 'next/server';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json } from '@/server/http';
import { guardAdmin } from '@/server/http';
import { verifyCsrfOrOrigin } from '@/server/auth/csrf';
import { getUserById } from '@/server/users';
import { revokeEntitlement, PREMIUM_KEY } from '@/server/entitlements';
import { auditLog } from '@/server/audit';

export const dynamic = 'force-dynamic';

interface Ctx {
  params: Promise<{ id: string }>;
}

export async function POST(req: NextRequest, ctx: Ctx) {
  await ensureInitialized();
  if (!verifyCsrfOrOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');
  const guard = await guardAdmin(req);
  if (!guard.ok) return guard.response;

  const id = Number((await ctx.params).id);
  if (!Number.isInteger(id) || id <= 0) return errorJson('Invalid user id.', 400, 'bad_id');
  const user = getUserById(id);
  if (!user) return errorJson('User not found.', 404, 'not_found');

  revokeEntitlement({ userId: id, key: PREMIUM_KEY, source: 'admin' });
  auditLog({ actorUserId: guard.value.user.id, action: 'admin.premium_revoked', targetUserId: id });
  return json({ ok: true });
}
