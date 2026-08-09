import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { cancelScan, WorkerClientError, WorkerUnavailableError } from '@/app/lib/worker-client';
import { ensureInitialized } from '@/server/bootstrap';
import { guardUser } from '@/server/http';
import { errorJson } from '@/server/http';
import { verifyCsrfOrOrigin } from '@/server/auth/csrf';

export const dynamic = 'force-dynamic';

interface Ctx {
  params: Promise<{ id: string }>;
}

export async function POST(req: NextRequest, ctx: Ctx): Promise<NextResponse> {
  await ensureInitialized();
  if (!verifyCsrfOrOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');
  const guard = await guardUser(req);
  if (!guard.ok) return guard.response;
  const { id } = await ctx.params;
  try {
    const job = await cancelScan(id);
    return NextResponse.json({ job });
  } catch (e) {
    if (e instanceof WorkerClientError) {
      return NextResponse.json({ error: { code: e.code, message: e.message } }, { status: e.status });
    }
    if (e instanceof WorkerUnavailableError) {
      return NextResponse.json({ error: { code: 'worker_unavailable', message: e.message } }, { status: 503 });
    }
    return NextResponse.json({ error: { code: 'internal', message: 'Failed to cancel the scan.' } }, { status: 500 });
  }
}
