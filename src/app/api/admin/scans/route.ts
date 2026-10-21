import type { NextRequest } from 'next/server';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json } from '@/server/http';
import { guardAdmin } from '@/server/http';
import { listAdminScans, toScanView, type AdminScanFilters } from '@/server/scans';

export const dynamic = 'force-dynamic';

function csvEscape(value: unknown): string {
  const raw = value === null || value === undefined ? '' : String(value);
  // Neutralize spreadsheet formula injection before CSV quoting.
  const s = /^[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export async function GET(req: NextRequest) {
  await ensureInitialized();
  const guard = await guardAdmin(req);
  if (!guard.ok) return guard.response;

  const sp = new URL(req.url).searchParams;
  for (const key of ['from', 'to']) {
    const value = sp.get(key);
    if (value && Number.isNaN(Date.parse(value))) return errorJson(`Invalid ${key} date.`, 400, 'invalid_date');
  }
  const limitRaw = sp.get('limit');
  const limit = limitRaw ? Number(limitRaw) : undefined;
  if (limit !== undefined && (!Number.isFinite(limit) || limit <= 0)) {
    return errorJson('Invalid limit.', 400, 'invalid_limit');
  }
  const filters: AdminScanFilters = {
    from: sp.get('from') ?? undefined,
    to: sp.get('to') ?? undefined,
    host: sp.get('host')?.slice(0, 255) ?? undefined,
    profile: sp.get('profile')?.slice(0, 32) ?? undefined,
    status: sp.get('status')?.slice(0, 32) ?? undefined,
    user: sp.get('user')?.slice(0, 254) ?? undefined,
    limit,
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
