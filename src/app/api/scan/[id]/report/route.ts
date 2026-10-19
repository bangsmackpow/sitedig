import type { NextRequest } from 'next/server';
import { getJobReport, WorkerClientError, WorkerUnavailableError } from '@/app/lib/worker-client';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, guardUser } from '@/server/http';
import { getScan } from '@/server/scans';

export const dynamic = 'force-dynamic';

interface Ctx {
  params: Promise<{ id: string }>;
}

export async function GET(req: NextRequest, ctx: Ctx): Promise<Response> {
  await ensureInitialized();
  const guard = await guardUser(req);
  if (!guard.ok) return guard.response;

  const { id } = await ctx.params;
  const scan = getScan(id);
  const isOwner = scan?.user_id === guard.value.user.id;
  const isAdmin = guard.value.user.role === 'admin';
  if (!scan || (!isOwner && !isAdmin)) {
    return errorJson('Scan not found.', 404, 'not_found');
  }

  try {
    const { report, expiresAt } = await getJobReport(id);
    return new Response(JSON.stringify({ report, expiresAt }), {
      status: 200,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        'x-robots-tag': 'noindex',
      },
    });
  } catch (e) {
    if (e instanceof WorkerClientError) {
      return errorJson(e.message, e.status, e.code);
    }
    if (e instanceof WorkerUnavailableError) {
      return errorJson(e.message, 503, 'worker_unavailable');
    }
    return errorJson('Failed to load the report.', 500, 'internal');
  }
}
