import { NextResponse } from 'next/server';
import { getWebConfig } from '@/shared/config';
import { APP_VERSION } from '@/shared/constants';
import { workerHealth, type WorkerHealth } from '@/app/lib/worker-client';

export const dynamic = 'force-dynamic';

export async function GET(): Promise<NextResponse> {
  const cfg = getWebConfig();
  let worker: WorkerHealth = { ok: false };
  try {
    worker = await workerHealth();
  } catch {
    worker = { ok: false };
  }
  return NextResponse.json({
    ok: true,
    service: 'web',
    version: APP_VERSION,
    workerOk: worker.ok,
    workerUrl: cfg.workerUrl,
    enabledModules: [...cfg.enabledModules].sort(),
    rawEnabledModules: process.env.ENABLED_MODULES ?? '',
    worker,
  });
}
