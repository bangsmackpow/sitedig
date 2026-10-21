import type { NextRequest } from 'next/server';
import { createScheduleSchema } from '@/shared/schemas';
import { getWebConfig } from '@/shared/config';
import { DEFAULT_USER_AGENT } from '@/shared/constants';
import { parseTarget } from '@/shared/targets';
import type { ModuleId } from '@/shared/types';
import { auditLog } from '@/server/audit';
import { verifyCsrfOrOrigin } from '@/server/auth/csrf';
import { ensureInitialized } from '@/server/bootstrap';
import { canUseModule, isPremium } from '@/server/entitlements';
import { errorJson, guardUser, json, readJsonLimited } from '@/server/http';
import { countSchedules, createSchedule, listSchedules } from '@/server/schedules';
import { isUserVerified } from '@/server/users';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  await ensureInitialized();
  const guard = await guardUser(req);
  if (!guard.ok) return guard.response;
  if (!isPremium(guard.value.user)) return errorJson('Scheduled scans require Premium.', 403, 'premium_required');
  return json({ schedules: listSchedules(guard.value.user.id) });
}

export async function POST(req: NextRequest): Promise<Response> {
  await ensureInitialized();
  if (!verifyCsrfOrOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');
  const guard = await guardUser(req);
  if (!guard.ok) return guard.response;
  const user = guard.value.user;
  if (!isUserVerified(user)) return errorJson('Verify your email before creating schedules.', 403, 'email_not_verified');
  if (!isPremium(user)) return errorJson('Scheduled scans require Premium.', 403, 'premium_required');

  let body: unknown;
  try {
    body = await readJsonLimited(req, 64 * 1024);
  } catch {
    return errorJson('Invalid JSON body.', 400, 'invalid_json');
  }
  const parsed = createScheduleSchema.safeParse(body);
  if (!parsed.success) return errorJson(parsed.error.issues[0]?.message ?? 'Invalid schedule.', 400, 'validation_error');

  const config = getWebConfig();
  if (countSchedules(user.id) >= config.maxSchedulesPerUser) {
    return errorJson(`You can create at most ${config.maxSchedulesPerUser} scheduled scans.`, 409, 'schedule_limit');
  }
  for (const moduleId of parsed.data.modules ?? []) {
    if (!canUseModule(user.id, user, moduleId as ModuleId, config.enabledModules)) {
      return errorJson(`The ${moduleId} module is not available to your account.`, 403, 'module_locked');
    }
  }

  try {
    parseTarget(parsed.data.target);
    const custom = parsed.data.custom
      ? {
          ...parsed.data.custom,
          path: parsed.data.custom.path ?? '/',
          followRedirects: parsed.data.custom.followRedirects ?? true,
          userAgent: parsed.data.custom.userAgent ?? DEFAULT_USER_AGENT,
          timeoutMs: parsed.data.custom.timeoutMs ?? 300_000,
        }
      : null;
    const schedule = createSchedule({
      userId: user.id,
      userEmail: user.email,
      target: parsed.data.target,
      profile: parsed.data.profile,
      custom,
      modules: (parsed.data.modules ?? []) as ModuleId[],
      frequency: parsed.data.frequency,
      hourUtc: parsed.data.hourUtc,
      minuteUtc: parsed.data.minuteUtc,
      dayOfWeek: parsed.data.dayOfWeek ?? null,
      alertMinSeverity: parsed.data.alertMinSeverity,
      alertOnFailure: parsed.data.alertOnFailure,
      maxSchedules: config.maxSchedulesPerUser,
    });
    auditLog({ actorUserId: user.id, action: 'schedule.created', targetUserId: user.id, metadata: { scheduleId: schedule.id, target: schedule.target } });
    return json({ schedule }, 201);
  } catch (e) {
    return errorJson((e as Error).message || 'Failed to create the schedule.', 400, 'invalid_schedule');
  }
}
