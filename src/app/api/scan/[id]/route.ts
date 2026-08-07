import { NextResponse } from 'next/server';
import type { PublicJobView } from '@/shared/types';
import { getJobStatus, WorkerClientError, WorkerUnavailableError } from '@/app/lib/worker-client';

export const dynamic = 'force-dynamic';

interface Ctx {
  params: Promise<{ id: string }>;
}

export async function GET(_req: Request, ctx: Ctx): Promise<NextResponse> {
  const { id } = await ctx.params;
  try {
    const job = await getJobStatus(id);
    return NextResponse.json({ job });
  } catch (e) {
    if (e instanceof WorkerClientError && e.status === 404) {
      // The worker has no record of this job (e.g. it restarted). Surface it
      // as interrupted rather than pretending it completed.
      const interrupted: PublicJobView = {
        id,
        status: 'failed',
        profile: 'quick',
        target: id,
        createdAt: new Date().toISOString(),
        startedAt: null,
        finishedAt: new Date().toISOString(),
        error: 'The scan was interrupted because the scanner worker restarted. No report is available.',
        hasArtifacts: false,
        summaryCounts: null,
      };
      return NextResponse.json({ job: interrupted });
    }
    if (e instanceof WorkerClientError) {
      return NextResponse.json({ error: { code: e.code, message: e.message } }, { status: e.status });
    }
    if (e instanceof WorkerUnavailableError) {
      return NextResponse.json({ error: { code: 'worker_unavailable', message: e.message } }, { status: 503 });
    }
    return NextResponse.json({ error: { code: 'internal', message: 'Failed to read scan status.' } }, { status: 500 });
  }
}
