import type { NextRequest } from 'next/server';
import { z } from 'zod';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json, readJsonLimited } from '@/server/http';
import { guardAdmin } from '@/server/http';
import { verifyCsrfOrOrigin } from '@/server/auth/csrf';
import { countActiveAdmins, getUserById, updateUserStatus } from '@/server/users';
import { requestAccountDeletion } from '@/server/account';
import { revokeAllUserSessions } from '@/server/auth/sessions';
import { auditLog } from '@/server/audit';

export const dynamic = 'force-dynamic';

interface Ctx {
  params: Promise<{ id: string }>;
}

const patchSchema = z.object({ status: z.enum(['active', 'disabled']).optional(), role: z.enum(['admin', 'user']).optional() }).strict();

function parseId(id: string): number | null {
  const n = Number(id);
  return Number.isInteger(n) && n > 0 ? n : null;
}

export async function PATCH(req: NextRequest, ctx: Ctx) {
  await ensureInitialized();
  if (!verifyCsrfOrOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');
  const guard = await guardAdmin(req);
  if (!guard.ok) return guard.response;

  const id = parseId((await ctx.params).id);
  if (!id) return errorJson('Invalid user id.', 400, 'bad_id');
  const user = getUserById(id);
  if (!user) return errorJson('User not found.', 404, 'not_found');

  const body = await readJsonLimited(req, 16 * 1024).catch(() => null);
  const parsed = patchSchema.safeParse(body);
  if (!parsed.success) return errorJson('Invalid input.', 400, 'validation_error');

  const removesAdmin =
    user.role === 'admin' && (parsed.data.status === 'disabled' || parsed.data.role === 'user');
  if (removesAdmin && countActiveAdmins(id) === 0) {
    return errorJson('Cannot remove the last active admin.', 409, 'last_admin');
  }
  const privilegeChanged = Boolean(parsed.data.status === 'disabled' || (parsed.data.role && parsed.data.role !== user.role));

  if (parsed.data.status) {
    updateUserStatus(id, parsed.data.status);
    auditLog({ actorUserId: guard.value.user.id, action: 'admin.user_status', targetUserId: id, metadata: { status: parsed.data.status } });
  }
  if (parsed.data.role) {
    const { getDb } = await import('@/server/db');
    getDb().prepare('UPDATE users SET role = ?, updated_at = ? WHERE id = ?').run(parsed.data.role, new Date().toISOString(), id);
    auditLog({ actorUserId: guard.value.user.id, action: 'admin.user_role', targetUserId: id, metadata: { role: parsed.data.role } });
  }
  if (privilegeChanged) revokeAllUserSessions(id);
  return json({ ok: true });
}

export async function DELETE(req: NextRequest, ctx: Ctx) {
  await ensureInitialized();
  if (!verifyCsrfOrOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');
  const guard = await guardAdmin(req);
  if (!guard.ok) return guard.response;

  const id = parseId((await ctx.params).id);
  if (!id) return errorJson('Invalid user id.', 400, 'bad_id');
  const user = getUserById(id);
  if (!user) return errorJson('User not found.', 404, 'not_found');
  if (user.role === 'admin' && id === guard.value.user.id) {
    return errorJson('Admins cannot delete their own account here.', 400, 'cannot_delete_self');
  }
  if (user.role === 'admin' && countActiveAdmins(id) === 0) {
    return errorJson('Cannot delete the last active admin.', 409, 'last_admin');
  }

  revokeAllUserSessions(id);
  await requestAccountDeletion(id);
  auditLog({ actorUserId: guard.value.user.id, action: 'admin.user_deleted', targetUserId: id });
  return json({ ok: true });
}
