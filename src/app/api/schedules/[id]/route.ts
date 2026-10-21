import type { NextRequest } from 'next/server';
import { updateScheduleSchema } from '@/shared/schemas';
import { auditLog } from '@/server/audit';
import { verifyCsrfOrOrigin } from '@/server/auth/csrf';
import { ensureInitialized } from '@/server/bootstrap';
import { isPremium } from '@/server/entitlements';
import { errorJson, guardUser, json, readJsonLimited } from '@/server/http';
import { deleteSchedule, getScheduleForUser, updateSchedule } from '@/server/schedules';

export const dynamic = 'force-dynamic';

interface Ctx {
  params: Promise<{ id: string }>;
}

function parseId(raw: string): number | null {
  const id = Number(raw);
  return Number.isInteger(id) && id > 0 ? id : null;
}

export async function GET(req: NextRequest, ctx: Ctx): Promise<Response> {
  await ensureInitialized();
  const guard = await guardUser(req);
  if (!guard.ok) return guard.response;
  if (!isPremium(guard.value.user)) return errorJson('Scheduled scans require Premium.', 403, 'premium_required');
  const { id } = await ctx.params;
  const scheduleId = parseId(id);
  if (!scheduleId) return errorJson('Invalid schedule id.', 400, 'invalid_id');
  const schedule = getScheduleForUser(scheduleId, guard.value.user.id);
  if (!schedule) return errorJson('Schedule not found.', 404, 'not_found');
  return json({ schedule });
}

export async function PATCH(req: NextRequest, ctx: Ctx): Promise<Response> {
  await ensureInitialized();
  if (!verifyCsrfOrOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');
  const guard = await guardUser(req);
  if (!guard.ok) return guard.response;
  const user = guard.value.user;
  if (!isPremium(user)) return errorJson('Scheduled scans require Premium.', 403, 'premium_required');
  const { id } = await ctx.params;
  const scheduleId = parseId(id);
  if (!scheduleId) return errorJson('Invalid schedule id.', 400, 'invalid_id');

  let body: unknown;
  try {
    body = await readJsonLimited(req, 64 * 1024);
  } catch {
    return errorJson('Invalid JSON body.', 400, 'invalid_json');
  }
  const parsed = updateScheduleSchema.safeParse(body);
  if (!parsed.success) return errorJson(parsed.error.issues[0]?.message ?? 'Invalid schedule update.', 400, 'validation_error');
  try {
    const schedule = updateSchedule(scheduleId, user.id, parsed.data);
    if (!schedule) return errorJson('Schedule not found.', 404, 'not_found');
    auditLog({ actorUserId: user.id, action: 'schedule.updated', targetUserId: user.id, metadata: { scheduleId, enabled: schedule.enabled } });
    return json({ schedule });
  } catch (e) {
    return errorJson((e as Error).message || 'Failed to update the schedule.', 400, 'invalid_schedule');
  }
}

export async function DELETE(req: NextRequest, ctx: Ctx): Promise<Response> {
  await ensureInitialized();
  if (!verifyCsrfOrOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');
  const guard = await guardUser(req);
  if (!guard.ok) return guard.response;
  const user = guard.value.user;
  if (!isPremium(user)) return errorJson('Scheduled scans require Premium.', 403, 'premium_required');
  const { id } = await ctx.params;
  const scheduleId = parseId(id);
  if (!scheduleId) return errorJson('Invalid schedule id.', 400, 'invalid_id');
  if (!deleteSchedule(scheduleId, user.id)) return errorJson('Schedule not found.', 404, 'not_found');
  auditLog({ actorUserId: user.id, action: 'schedule.deleted', targetUserId: user.id, metadata: { scheduleId } });
  return json({ ok: true });
}
