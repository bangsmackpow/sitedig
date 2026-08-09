import type { NextRequest } from 'next/server';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json } from '@/server/http';
import { guardUser } from '@/server/http';
import { buildMePayload } from '@/server/me';
import { isDeletionPending } from '@/server/account';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  await ensureInitialized();
  const guard = await guardUser(req);
  if (!guard.ok) return guard.response;
  const payload = buildMePayload(guard.value.user.id);
  if (!payload) return errorJson('Account not found.', 404, 'not_found');
  return json({ ...payload, deletionPending: isDeletionPending(guard.value.user.id) });
}
