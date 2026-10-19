'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { apiFetch } from '@/app/lib/api';

interface ScanView {
  id: string;
  target: string;
  host: string;
  resolvedIps: string[];
  ipVersion: string | null;
  profile: string;
  portScope: string | null;
  modules: string[];
  status: string;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  portCount: number;
  findings: { critical: number; high: number; medium: number; low: number; informational: number };
  toolOk: number;
  toolTotal: number;
  error: string | null;
}

function statusClass(status: string): string {
  if (status === 'completed') return 'active';
  if (status === 'failed') return 'disabled';
  return 'info';
}

function duration(ms: number | null): string {
  if (ms === null || ms === undefined) return '—';
  return `${(ms / 1000).toFixed(1)}s`;
}

export default function HistoryPage() {
  const router = useRouter();
  const [scans, setScans] = useState<ScanView[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const data = await apiFetch<{ scans: ScanView[] }>('/api/scan/history?limit=200');
      setScans(data.scans);
    } catch (e) {
      if ((e as { status?: number }).status === 401) {
        router.replace('/login');
        return;
      }
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [router]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="card">
      <h1>Scan history</h1>
      <p className="text-muted">
        Metadata and finding counts for your past scans. Reports are generated on demand and are not archived here — re-run a
        scan to produce a fresh report. <Link className="link" href="/">New scan</Link>
      </p>
      {error && <div className="error-box">{error}</div>}
      {loading && <div className="info-box">Loading…</div>}

      {!loading && scans.length === 0 && <div className="info-box">No scans yet. Run your first scan from the home page.</div>}

      {scans.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>When</th>
              <th>Target</th>
              <th>Profile</th>
              <th>Status</th>
              <th>Duration</th>
              <th>Ports</th>
              <th>Findings</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id}>
                <td style={{ whiteSpace: 'nowrap' }}>{new Date(s.createdAt).toLocaleString()}</td>
                <td>
                  <div>{s.host}</div>
                  {s.resolvedIps.length > 0 && <div className="meta-line">{s.resolvedIps.join(', ')}</div>}
                </td>
                <td>{s.profile}</td>
                <td>
                  <span className={`pill ${statusClass(s.status)}`}>{s.status}</span>
                </td>
                <td>{duration(s.durationMs)}</td>
                <td>{s.portCount}</td>
                <td className="meta-line" style={{ whiteSpace: 'nowrap' }}>
                  {s.findings.critical > 0 && <span className="pill disabled" style={{ marginRight: 4 }}>{s.findings.critical} crit</span>}
                  {s.findings.high > 0 && <span className="pill info" style={{ marginRight: 4 }}>{s.findings.high} high</span>}
                  {s.findings.medium + s.findings.low + s.findings.informational > 0 && (
                    <span>
                      {s.findings.medium}M · {s.findings.low}L · {s.findings.informational}I
                    </span>
                  )}
                  {s.findings.critical + s.findings.high + s.findings.medium + s.findings.low + s.findings.informational === 0 && '—'}
                </td>
                <td style={{ whiteSpace: 'nowrap' }}>
                  {s.status === 'completed' && (
                    <>
                      <Link className="link" href={`/scan/${encodeURIComponent(s.id)}`}>
                        View
                      </Link>
                      {' | '}
                    </>
                  )}
                  <Link className="link" href={`/?target=${encodeURIComponent(s.target)}`}>
                    Re-run
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
