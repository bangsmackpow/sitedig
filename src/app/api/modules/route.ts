import { NextResponse } from 'next/server';
import { getModules, WorkerClientError, WorkerUnavailableError, type ModuleView } from '@/app/lib/worker-client';

export const dynamic = 'force-dynamic';

export async function GET(): Promise<NextResponse> {
  try {
    const modules = await getModules();
    return NextResponse.json({ modules });
  } catch (e) {
    if (e instanceof WorkerClientError) {
      return NextResponse.json({ error: { code: e.code, message: e.message } }, { status: e.status });
    }
    if (e instanceof WorkerUnavailableError) {
      return NextResponse.json({ modules: [] as ModuleView[] });
    }
    return NextResponse.json({ error: { code: 'internal', message: 'Failed to load modules.' } }, { status: 500 });
  }
}
