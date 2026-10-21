import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { createJobSchema } from '@/shared/schemas';
import { createScan, getJobStatus, WorkerClientError, WorkerUnavailableError } from '@/app/lib/worker-client';
import { ensureInitialized } from '@/server/bootstrap';
import { guardUser } from '@/server/http';
import { errorJson, readJsonLimited } from '@/server/http';
import { verifyCsrfOrOrigin } from '@/server/auth/csrf';
import { canUseModule } from '@/server/entitlements';
import { isUserVerified } from '@/server/users';
import { countActiveScans, failStaleScans, listActiveScans, markScanFailed, recordScanQueued } from '@/server/scans';
import { rateLimit } from '@/server/auth/rate-limit';
import { MAX_ACTIVE_SCANS_PER_USER } from '@/shared/constants';
import { parseTarget } from '@/shared/targets';
import { getWebConfig } from '@/shared/config';
import type { ModuleId } from '@/shared/types';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest): Promise<NextResponse> {
  await ensureInitialized();
  if (!verifyCsrfOrOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');
  const guard = await guardUser(req);
  if (!guard.ok) return guard.response;

  if (!isUserVerified(guard.value.user)) {
    return errorJson('Verify your email before scanning.', 403, 'email_not_verified');
  }

  const userId = guard.value.user.id;
  if (!rateLimit(`scan:${userId}`, 10, 15 * 60 * 1000)) {
    return errorJson('Too many scan requests. Try again later.', 429, 'rate_limited');
  }
  failStaleScans();
  let activeScans = countActiveScans(userId);
  if (activeScans >= MAX_ACTIVE_SCANS_PER_USER) {
    // The worker may have restarted and lost these jobs. Reconcile before
    // turning the user away so abandoned rows do not block new scans.
    for (const scan of listActiveScans(userId)) {
      try {
        await getJobStatus(scan.id);
      } catch (e) {
        if (e instanceof WorkerClientError && e.status === 404) {
          markScanFailed(scan.id, 'The scan was no longer present in the worker and has been marked failed.');
        }
      }
    }
    activeScans = countActiveScans(userId);
  }
  if (activeScans >= MAX_ACTIVE_SCANS_PER_USER) {
    return errorJson(`You already have ${MAX_ACTIVE_SCANS_PER_USER} scans queued or running.`, 429, 'scan_limit');
  }

  let body: unknown;
  try {
    body = await readJsonLimited(req, 64 * 1024);
  } catch {
    return errorJson('Invalid JSON body.', 400, 'invalid_json');
  }

  const parsed = createJobSchema.safeParse(body);
  if (!parsed.success) {
    return errorJson(parsed.error.issues[0]?.message ?? 'Invalid scan request.', 400, 'validation_error');
  }

  // Entitlement gating: a requested paid module must be deployment-enabled AND
  // the user must be Premium (or have the module entitlement).
  const enabledModules = getWebConfig().enabledModules;
  const requestedModules = parsed.data.modules ?? [];
  for (const moduleId of requestedModules) {
    if (!canUseModule(guard.value.user.id, guard.value.user, moduleId as ModuleId, enabledModules)) {
      return errorJson(`The ${moduleId} module is not available to your account.`, 403, 'module_locked');
    }
  }

  try {
    const result = await createScan({
      target: parsed.data.target,
      profile: parsed.data.profile,
      consent: parsed.data.consent,
      custom: parsed.data.custom,
      modules: parsed.data.modules,
      userId,
    });
    // Record the scan in long-term history (best-effort; never blocks a scan).
    try {
      const target = parseTarget(parsed.data.target);
      recordScanQueued({
        id: result.jobId,
        userId: guard.value.user.id,
        userEmail: guard.value.user.email,
        targetRaw: parsed.data.target,
        host: target.host,
        path: target.path,
        scheme: target.scheme,
        profile: parsed.data.profile,
        modules: parsed.data.modules ?? [],
      });
    } catch {
      // ignore history write failures
    }
    return NextResponse.json(result, { status: 201 });
  } catch (e) {
    if (e instanceof WorkerClientError) {
      return errorJson(e.message, e.status, e.code);
    }
    if (e instanceof WorkerUnavailableError) {
      return errorJson(e.message, 503, 'worker_unavailable');
    }
    return errorJson('Failed to start the scan.', 500, 'internal');
  }
}
