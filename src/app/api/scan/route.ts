import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { createJobSchema } from '@/shared/schemas';
import { createScan, WorkerClientError, WorkerUnavailableError } from '@/app/lib/worker-client';
import { ensureInitialized } from '@/server/bootstrap';
import { guardUser } from '@/server/http';
import { errorJson } from '@/server/http';
import { verifyCsrfOrOrigin } from '@/server/auth/csrf';
import { canUseModule } from '@/server/entitlements';
import { isUserVerified } from '@/server/users';
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

  let body: unknown;
  try {
    body = await req.json();
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
    });
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
