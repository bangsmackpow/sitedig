import type { NextRequest } from 'next/server';
import { ensureInitialized } from '@/server/bootstrap';
import { json } from '@/server/http';
import { guardAdmin } from '@/server/http';
import { getScanStats, resolveRange } from '@/server/scans';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  await ensureInitialized();
  const guard = await guardAdmin(req);
  if (!guard.ok) return guard.response;

  const { from, to } = resolveRange(new URL(req.url).searchParams);
  return json({ stats: getScanStats(from, to) });
}
