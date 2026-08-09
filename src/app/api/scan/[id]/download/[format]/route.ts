import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { downloadArtifact, WorkerClientError, WorkerUnavailableError } from '@/app/lib/worker-client';
import { ensureInitialized } from '@/server/bootstrap';
import { guardUser } from '@/server/http';
import { errorJson } from '@/server/http';

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
  const mime = MIME[format];

  try {
    const res = await downloadArtifact(id, format);
    const buffer = Buffer.from(await res.arrayBuffer());
    const filename = `sitedig-report-${id}.${format === 'pdf' ? 'pdf' : 'md'}`;
    return new NextResponse(new Uint8Array(buffer), {
      status: 200,
      headers: {
        'content-type': mime,
        'content-disposition': `attachment; filename="${filename}"`,
        'content-length': String(buffer.byteLength),
        'cache-control': 'no-store',
        'x-robots-tag': 'noindex',
      },
    });
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
