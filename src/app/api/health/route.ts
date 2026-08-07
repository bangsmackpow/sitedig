import { NextResponse } from 'next/server';
import { getWebConfig } from '@/shared/config';
import { workerHealth } from '@/app/lib/worker-client';

export const dynamic = 'force-dynamic';

export async function GET(): Promise<NextResponse> {
  const cfg = getWebConfig();
  let workerOk = false;
  try {
    const health = await workerHealth();
    workerOk = health.ok;
  } catch {
    workerOk = false;
  }
  return NextResponse.json({ ok: true, service: 'web', workerOk, workerUrl: cfg.workerUrl });
}
