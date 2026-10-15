'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { apiFetch } from '@/app/lib/api';

interface FindingCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

interface ScanStats {
  range: { from: string; to: string };
  total: number;
  completed: number;
  failed: number;
  cancelled: number;
  running: number;
  successRate: number;
  avgDurationMs: number;
  p95DurationMs: number;
  uniqueHosts: number;
  findings: FindingCounts;
  byProfile: Array<{ profile: string; count: number }>;
  byModule: Array<{ module: string; count: number }>;
  byDay: Array<{ date: string; count: number; avgDurationMs: number }>;
  topTargets: Array<{ host: string; count: number }>;
  toolDurations: Array<{ tool: string; runs: number; failures: number; avgMs: number; p95Ms: number }>;
}

interface ScanView {
  id: string;
  target: string;
  host: string;
  resolvedIps: string[];
  profile: string;
  portScope: string | null;
  modules: string[];
  status: string;
  createdAt: string;
  durationMs: number | null;
  portCount: number;
  findings: FindingCounts;
  toolOk: number;
  toolTotal: number;
  error: string | null;
  userEmail?: string | null;
}

const day = 24 * 60 * 60 * 1000;
const isoDate = (d: Date) => d.toISOString().slice(0, 10);
const secs = (ms: number) => `${(ms / 1000).toFixed(1)}s`;

export default function AdminScansPage() {
  const router = useRouter();
  const [stats, setStats] = useState<ScanStats | null>(null);
  const [scans, setScans] = useState<ScanView[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [filters, setFilters] = useState({
    from: isoDate(new Date(Date.now() - 30 * day)),
    to: isoDate(new Date()),
    host: '',
    profile: '',
    status: '',
    user: '',
  });

  const query = useCallback(() => {
    const sp = new URLSearchParams();
    if (filters.from) sp.set('from', filters.from);
    if (filters.to) sp.set('to', filters.to);
    if (filters.host) sp.set('host', filters.host);
    if (filters.profile) sp.set('profile', filters.profile);
    if (filters.status) sp.set('status', filters.status);
    if (filters.user) sp.set('user', filters.user);
    return sp;
  }, [filters]);

  const load = useCallback(async () => {
    setError(null);
    try {
      const sp = query();
      const [s, l] = await Promise.all([
        apiFetch<{ stats: ScanStats }>(`/api/admin/stats?${sp.toString()}`),
        apiFetch<{ scans: ScanView[] }>(`/api/admin/scans?${sp.toString()}&limit=200`),
      ]);
      setStats(s.stats);
      setScans(l.scans);
    } catch (e) {
      if ((e as { status?: number }).status === 401) {
        router.replace('/login');
        return;
      }
      setError((e as Error).message);
    }
  }, [query, router]);

  useEffect(() => {
    load();
  }, [load]);

  const sendDigest = async () => {
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await apiFetch('/api/admin/digest/run', { method: 'POST' });
      setNotice('Digest sent to the configured recipients.');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const maxDay = stats ? Math.max(1, ...stats.byDay.map((d) => d.count)) : 1;

  return (
    <div className="card">
      <h1>Scan analytics</h1>
      <p className="text-muted">
        Long-term scan tracking: volume, duration, targets, findings, and per-tool timing. <Link className="link" href="/admin">Back to admin</Link>
      </p>
      {error && <div className="error-box">{error}</div>}
      {notice && <div className="info-box">{notice}</div>}

      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          load();
        }}
        style={{ marginTop: 16 }}
      >
        <div className="field">
          <label htmlFor="f-from">From</label>
          <input id="f-from" type="date" value={filters.from} onChange={(e) => setFilters({ ...filters, from: e.target.value })} />
        </div>
        <div className="field">
          <label htmlFor="f-to">To</label>
          <input id="f-to" type="date" value={filters.to} onChange={(e) => setFilters({ ...filters, to: e.target.value })} />
        </div>
        <div className="field">
          <label htmlFor="f-host">Host</label>
          <input id="f-host" type="text" value={filters.host} onChange={(e) => setFilters({ ...filters, host: e.target.value })} placeholder="example.com" />
        </div>
        <div className="field">
          <label htmlFor="f-user">User email</label>
          <input id="f-user" type="text" value={filters.user} onChange={(e) => setFilters({ ...filters, user: e.target.value })} placeholder="user@example.com" />
        </div>
        <div className="field">
          <label htmlFor="f-profile">Profile</label>
          <select id="f-profile" value={filters.profile} onChange={(e) => setFilters({ ...filters, profile: e.target.value })}>
            <option value="">All</option>
            <option value="quick">quick</option>
            <option value="standard">standard</option>
            <option value="deep">deep</option>
            <option value="custom">custom</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="f-status">Status</label>
          <select id="f-status" value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}>
            <option value="">All</option>
            <option value="queued">queued</option>
            <option value="running">running</option>
            <option value="completed">completed</option>
            <option value="failed">failed</option>
            <option value="cancelled">cancelled</option>
          </select>
        </div>
        <div className="field">
          <label>&nbsp;</label>
          <div className="actions" style={{ marginTop: 0 }}>
            <button className="button" type="submit">
              Apply
            </button>
            <a className="button secondary" href={`/api/admin/scans?${query().toString()}&format=csv`}>
              Export CSV
            </a>
            <button className="button secondary" type="button" onClick={sendDigest} disabled={busy}>
              Send digest now
            </button>
          </div>
        </div>
      </form>

      {stats && (
        <>
          <div className="summary-grid" style={{ marginTop: 20 }}>
            <span className="summary-pill">Scans: {stats.total}</span>
            <span className="summary-pill">Completed: {stats.completed}</span>
            <span className="summary-pill">Failed: {stats.failed}</span>
            <span className="summary-pill">Success: {(stats.successRate * 100).toFixed(0)}%</span>
            <span className="summary-pill">Avg: {secs(stats.avgDurationMs)}</span>
            <span className="summary-pill">p95: {secs(stats.p95DurationMs)}</span>
            <span className="summary-pill">Unique hosts: {stats.uniqueHosts}</span>
            <span className="summary-pill">Critical findings: {stats.findings.critical}</span>
            <span className="summary-pill">High findings: {stats.findings.high}</span>
          </div>

          <h2 style={{ marginTop: 28 }}>Scans per day</h2>
          {stats.byDay.length === 0 ? (
            <p className="text-muted">No scans in this range.</p>
          ) : (
            <div style={{ display: 'flex', alignItems: 'flex-end', gap: 4, height: 120, marginTop: 8 }}>
              {stats.byDay.map((d) => (
                <div key={d.date} title={`${d.date}: ${d.count} scans, avg ${secs(d.avgDurationMs)}`} style={{ flex: 1, minWidth: 4 }}>
                  <div style={{ background: 'var(--accent)', height: `${(d.count / maxDay) * 100}%`, borderRadius: 3, minHeight: 2 }} />
                </div>
              ))}
            </div>
          )}

          <div className="row" style={{ marginTop: 24 }}>
            <div>
              <h2>By profile</h2>
              <table className="table">
                <tbody>
                  {stats.byProfile.map((p) => (
                    <tr key={p.profile}>
                      <td>{p.profile}</td>
                      <td>{p.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div>
              <h2>Top targets</h2>
              <table className="table">
                <tbody>
                  {stats.topTargets.map((t) => (
                    <tr key={t.host}>
                      <td>{t.host}</td>
                      <td>{t.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <h2 style={{ marginTop: 24 }}>Module usage</h2>
          <table className="table">
            <tbody>
              {stats.byModule.length === 0 && (
                <tr>
                  <td className="text-muted">No premium modules used in this range.</td>
                </tr>
              )}
              {stats.byModule.map((m) => (
                <tr key={m.module}>
                  <td>{m.module}</td>
                  <td>{m.count}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <h2 style={{ marginTop: 24 }}>Tool timing</h2>
          <table className="table">
            <thead>
              <tr>
                <th>Tool</th>
                <th>Runs</th>
                <th>Failures</th>
                <th>Avg</th>
                <th>p95</th>
              </tr>
            </thead>
            <tbody>
              {stats.toolDurations.map((t) => (
                <tr key={t.tool}>
                  <td>{t.tool}</td>
                  <td>{t.runs}</td>
                  <td>{t.failures}</td>
                  <td>{secs(t.avgMs)}</td>
                  <td>{secs(t.p95Ms)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      <h2 style={{ marginTop: 28 }}>Scans</h2>
      <table className="table">
        <thead>
          <tr>
            <th>When</th>
            <th>User</th>
            <th>Host</th>
            <th>Profile</th>
            <th>Status</th>
            <th>Duration</th>
            <th>Findings</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((s) => (
            <tr key={s.id}>
              <td style={{ whiteSpace: 'nowrap' }}>{new Date(s.createdAt).toLocaleString()}</td>
              <td>{s.userEmail ?? '—'}</td>
              <td>{s.host}</td>
              <td>{s.profile}</td>
              <td>{s.status}</td>
              <td>{s.durationMs === null ? '—' : secs(s.durationMs)}</td>
              <td className="meta-line">
                {s.findings.critical}C · {s.findings.high}H · {s.findings.medium}M · {s.findings.low}L · {s.findings.informational}I
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
