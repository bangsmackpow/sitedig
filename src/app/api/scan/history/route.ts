import type { NextRequest } from 'next/server';
import { ensureInitialized } from '@/server/bootstrap';
import { json } from '@/server/http';
import { guardUser } from '@/server/http';
import { listUserScans, toScanView } from '@/server/scans';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  await ensureInitialized();
  const guard = await guardUser(req);
  if (!guard.ok) return guard.response;

  const limitParam = Number(new URL(req.url).searchParams.get('limit') ?? '');
  const limit = Number.isFinite(limitParam) && limitParam > 0 ? Math.min(limitParam, 500) : 100;
  const scans = listUserScans(guard.value.user.id, limit).map((row) => toScanView(row));
  return json({ scans });
}
