import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { downloadArtifact, WorkerClientError, WorkerUnavailableError } from '@/app/lib/worker-client';
import { ensureInitialized } from '@/server/bootstrap';
import { guardUser } from '@/server/http';
import { getScanForUser } from '@/server/scans';

export const dynamic = 'force-dynamic';

interface Ctx {
  params: Promise<{ id: string; format: string }>;
}

const MIME: Record<string, string> = {
  pdf: 'application/pdf',
  markdown: 'text/markdown; charset=utf-8',
};

export async function GET(req: NextRequest, ctx: Ctx): Promise<NextResponse> {
  await ensureInitialized();
  const guard = await guardUser(req);
  if (!guard.ok) return guard.response;
  const { id, format } = await ctx.params;
  if (format !== 'pdf' && format !== 'markdown') {
    return NextResponse.json({ error: { code: 'bad_format', message: 'Unsupported report format.' } }, { status: 400 });
  }
  const scan = getScanForUser(id, guard.value.user.id, guard.value.user.role === 'admin');
  if (!scan) {
    return NextResponse.json({ error: { code: 'not_found', message: 'Scan not found.' } }, { status: 404 });
  }
  const mime = MIME[format];

  try {
    const res = await downloadArtifact(id, format);
    const declared = Number(res.headers.get('content-length') ?? '');
    if (Number.isFinite(declared) && declared > 50 * 1024 * 1024) {
      return NextResponse.json({ error: { code: 'payload_too_large', message: 'Report artifact is too large.' } }, { status: 413 });
    }
    const safeId = id.replace(/[^a-zA-Z0-9-]/g, '');
    const filename = `sitedig-report-${safeId}.${format === 'pdf' ? 'pdf' : 'md'}`;
    const headers: Record<string, string> = {
      'content-type': mime,
      'content-disposition': `attachment; filename="${filename}"`,
      'cache-control': 'no-store',
      'x-robots-tag': 'noindex',
    };
    if (Number.isFinite(declared) && declared > 0) headers['content-length'] = String(declared);
    return new NextResponse(res.body, { status: 200, headers });
  } catch (e) {
    if (e instanceof WorkerClientError) {
      return NextResponse.json({ error: { code: e.code, message: e.message } }, { status: e.status });
    }
    if (e instanceof WorkerUnavailableError) {
      return NextResponse.json({ error: { code: 'worker_unavailable', message: e.message } }, { status: 503 });
    }
    return NextResponse.json({ error: { code: 'internal', message: 'Failed to download the report.' } }, { status: 500 });
  }
}
