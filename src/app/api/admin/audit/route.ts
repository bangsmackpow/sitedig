import type { NextRequest } from 'next/server';
import { ensureInitialized } from '@/server/bootstrap';
import { json } from '@/server/http';
import { guardAdmin } from '@/server/http';
import { listAuditLog } from '@/server/audit';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  await ensureInitialized();
  const guard = await guardAdmin(req);
  if (!guard.ok) return guard.response;
  return json({ events: listAuditLog(100) });
}
