import type { NextRequest } from 'next/server';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, guardUser, json } from '@/server/http';
import { computeScanDiff } from '@/server/scan-diffs';
import { getScan } from '@/server/scans';

export const dynamic = 'force-dynamic';

interface Ctx {
  params: Promise<{ id: string }>;
}

export async function GET(req: NextRequest, ctx: Ctx): Promise<Response> {
  await ensureInitialized();
  const guard = await guardUser(req);
  if (!guard.ok) return guard.response;
  const { id } = await ctx.params;
  const scan = getScan(id);
  const isOwner = scan?.user_id === guard.value.user.id;
  const isAdmin = guard.value.user.role === 'admin';
  if (!scan || (!isOwner && !isAdmin)) return errorJson('Scan not found.', 404, 'not_found');
  const diff = computeScanDiff(id);
  if (!diff) return errorJson('Scan not found.', 404, 'not_found');
  return json({ diff });
}
