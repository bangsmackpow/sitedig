import type { NextRequest } from 'next/server';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json } from '@/server/http';
import { guardAdmin } from '@/server/http';
import { getScanStats, resolveRange } from '@/server/scans';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  await ensureInitialized();
  const guard = await guardAdmin(req);
  if (!guard.ok) return guard.response;

  const sp = new URL(req.url).searchParams;
  for (const key of ['from', 'to']) {
    const value = sp.get(key);
    if (value && Number.isNaN(Date.parse(value))) return errorJson(`Invalid ${key} date.`, 400, 'invalid_date');
  }
  const { from, to } = resolveRange(sp);
  if (Date.parse(to) - Date.parse(from) > 366 * 24 * 60 * 60 * 1000) {
    return errorJson('Date range cannot exceed 366 days.', 400, 'range_too_large');
  }
  return json({ stats: getScanStats(from, to) });
}
