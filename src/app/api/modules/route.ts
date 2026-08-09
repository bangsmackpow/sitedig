import type { NextRequest } from 'next/server';
import { getWebConfig } from '@/shared/config';
import { getModules, WorkerClientError, type ModuleView } from '@/app/lib/worker-client';
import { ensureInitialized } from '@/server/bootstrap';
import { guardUser } from '@/server/http';
import { errorJson } from '@/server/http';
import { canUseModule } from '@/server/entitlements';

export const dynamic = 'force-dynamic';

export interface ModuleViewWithAccess extends ModuleView {
  accessible: boolean;
}

export async function GET(req: NextRequest) {
  await ensureInitialized();
  const guard = await guardUser(req);
  if (!guard.ok) return guard.response;

  let modules: ModuleView[];
  try {
    modules = await getModules();
  } catch (e) {
    if (e instanceof WorkerClientError) {
      return errorJson(e.message, e.status, e.code);
    }
    return errorJson('Failed to load modules.', 500, 'internal');
  }

  const enabledModules = getWebConfig().enabledModules;
  const withAccess: ModuleViewWithAccess[] = modules.map((m) => ({
    ...m,
    accessible: canUseModule(guard.value.user.id, guard.value.user, m.id, enabledModules),
  }));
  return Response.json({ modules: withAccess });
}
