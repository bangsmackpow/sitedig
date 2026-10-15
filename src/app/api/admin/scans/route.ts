import type { NextRequest } from 'next/server';
import { ensureInitialized } from '@/server/bootstrap';
import { json } from '@/server/http';
import { guardAdmin } from '@/server/http';
import { listAdminScans, toScanView, type AdminScanFilters } from '@/server/scans';

export const dynamic = 'force-dynamic';

function csvEscape(value: unknown): string {
  const s = value === null || value === undefined ? '' : String(value);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export async function GET(req: NextRequest) {
  await ensureInitialized();
  const guard = await guardAdmin(req);
  if (!guard.ok) return guard.response;

  const sp = new URL(req.url).searchParams;
  const filters: AdminScanFilters = {
    from: sp.get('from') ?? undefined,
    to: sp.get('to') ?? undefined,
    host: sp.get('host') ?? undefined,
    profile: sp.get('profile') ?? undefined,
    status: sp.get('status') ?? undefined,
    user: sp.get('user') ?? undefined,
    limit: sp.get('limit') ? Number(sp.get('limit')) : undefined,
  };

  const rows = listAdminScans(filters);

  if (sp.get('format') === 'csv') {
    const header = [
      'id',
      'created_at',
      'user_email',
      'host',
      'resolved_ips',
      'profile',
      'port_scope',
      'modules',
      'status',
      'duration_ms',
      'port_count',
      'critical',
      'high',
      'medium',
      'low',
      'informational',
      'tool_ok',
      'tool_total',
      'error',
    ];
    const lines = [header.join(',')];
    for (const r of rows) {
      const view = toScanView(r, true);
      lines.push(
        [
          view.id,
          view.createdAt,
          view.userEmail ?? '',
          view.host,
          view.resolvedIps.join(' '),
          view.profile,
          view.portScope ?? '',
          view.modules.join(' '),
          view.status,
          view.durationMs ?? '',
          view.portCount,
          view.findings.critical,
          view.findings.high,
          view.findings.medium,
          view.findings.low,
          view.findings.informational,
          view.toolOk,
          view.toolTotal,
          view.error ?? '',
        ]
          .map(csvEscape)
          .join(','),
      );
    }
    return new Response(lines.join('\r\n'), {
      status: 200,
      headers: {
        'content-type': 'text/csv; charset=utf-8',
        'content-disposition': `attachment; filename="sitedig-scans.csv"`,
        'cache-control': 'no-store',
      },
    });
  }

  return json({ scans: rows.map((row) => toScanView(row, true)) });
}
