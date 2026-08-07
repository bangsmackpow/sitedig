import { NextResponse } from 'next/server';
import { createJobSchema } from '@/shared/schemas';
import { createScan, WorkerClientError, WorkerUnavailableError } from '@/app/lib/worker-client';

export const dynamic = 'force-dynamic';

export async function POST(req: Request): Promise<NextResponse> {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: { code: 'invalid_json', message: 'Invalid JSON body.' } }, { status: 400 });
  }

  const parsed = createJobSchema.safeParse(body);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    return NextResponse.json({ error: { code: 'validation_error', message: first?.message ?? 'Invalid scan request.' } }, { status: 400 });
  }

  try {
    const result = await createScan({
      target: parsed.data.target,
      profile: parsed.data.profile,
      consent: parsed.data.consent,
      custom: parsed.data.custom,
    });
    return NextResponse.json(result, { status: 201 });
  } catch (e) {
    if (e instanceof WorkerClientError) {
      return NextResponse.json({ error: { code: e.code, message: e.message } }, { status: e.status });
    }
    if (e instanceof WorkerUnavailableError) {
      return NextResponse.json({ error: { code: 'worker_unavailable', message: e.message } }, { status: 503 });
    }
    return NextResponse.json({ error: { code: 'internal', message: 'Failed to start the scan.' } }, { status: 500 });
  }
}
