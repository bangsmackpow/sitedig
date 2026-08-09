'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { describeProfile } from '@/shared/profile-info';
import type { CustomScanOptions, ModuleId, PublicJobView, ScanProfile, ToolName } from '@/shared/types';

const STATUS_LABEL: Record<string, string> = {
  queued: 'Queued',
  running: 'Running',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled',
};

interface ModuleView {
  id: ModuleId;
  name: string;
  description: string;
  tools: string[];
  paid: boolean;
  enabled: boolean;
}

const PORT_SCOPE_OPTIONS = [
  { value: 'common', label: 'Common TCP ports (curated)' },
  { value: 'top100', label: 'Top 100 TCP ports' },
  { value: 'top1000', label: 'Top 1,000 TCP ports' },
] as const;

const TOOL_OPTIONS: Array<{ value: ToolName; label: string }> = [
  { value: 'nmap', label: 'Nmap (TCP connect)' },
  { value: 'whatweb', label: 'WhatWeb' },
  { value: 'http', label: 'HTTP headers' },
  { value: 'tls', label: 'TLS certificate' },
  { value: 'wpscan', label: 'WPScan (local-only)' },
];

const TIMEOUT_OPTIONS = [60, 120, 180, 240, 300];

export default function ScanApp() {
  const [target, setTarget] = useState('');
  const [profile, setProfile] = useState<ScanProfile>('quick');
  const [custom, setCustom] = useState<CustomScanOptions>({
    portScope: 'top100',
    enabledTools: ['nmap', 'whatweb', 'http', 'tls'],
    path: '/',
    followRedirects: true,
    userAgent: '',
    timeoutMs: 300_000,
  });
  const [modules, setModules] = useState<ModuleView[]>([]);
  const [selectedModules, setSelectedModules] = useState<ModuleId[]>([]);

  const [consentOpen, setConsentOpen] = useState(false);
  const [consentChecked, setConsentChecked] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [job, setJob] = useState<PublicJobView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    fetch('/api/modules', { cache: 'no-store' })
      .then((r) => r.json())
      .then((data: { modules?: ModuleView[] }) => setModules(data.modules ?? []))
      .catch(() => setModules([]));
  }, []);

  const isBusy = job !== null && (job.status === 'queued' || job.status === 'running');

  const stopPolling = useCallback(() => {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const poll = useCallback((jobId: string) => {
    stopPolling();
    timerRef.current = setInterval(async () => {
      try {
        const res = await fetch(`/api/scan/${encodeURIComponent(jobId)}`, { cache: 'no-store' });
        const data = (await res.json()) as { job?: PublicJobView; error?: { message?: string } };
        if (!res.ok) {
          if (res.status === 404) {
            setJob((prev) =>
              prev
                ? {
                    ...prev,
                    status: 'failed',
                    error: 'The scan was interrupted because the scanner worker restarted. No report is available.',
                  }
                : prev,
            );
            stopPolling();
          } else {
            setError(data.error?.message ?? 'Failed to read scan status.');
            stopPolling();
          }
          return;
        }
        const next = data.job;
        if (!next) return;
        setJob(next);
        if (next.status === 'completed' || next.status === 'failed' || next.status === 'cancelled') {
          stopPolling();
        }
      } catch {
        // transient; keep polling
      }
    }, 2000);
  }, [stopPolling]);

  useEffect(() => stopPolling, [stopPolling]);

  const openConsent = () => {
    setError(null);
    setConsentChecked(false);
    setConsentOpen(true);
  };

  const closeConsent = () => {
    if (!submitting) setConsentOpen(false);
  };

  const submitScan = async () => {
    setSubmitting(true);
    setError(null);
    setJob(null);
    try {
      const body: Record<string, unknown> = { target, profile, consent: true };
      if (profile === 'custom') {
        body.custom = {
          ...custom,
          userAgent: custom.userAgent.trim() || undefined,
        };
      }
      if (selectedModules.length > 0) {
        body.modules = selectedModules;
      }
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = (await res.json()) as { jobId?: string; error?: { message?: string } };
      if (!res.ok || !data.jobId) {
        setError(data.error?.message ?? 'Failed to start the scan.');
        setConsentOpen(false);
        return;
      }
      setConsentOpen(false);
      poll(data.jobId);
    } catch {
      setError('Failed to start the scan.');
      setConsentOpen(false);
    } finally {
      setSubmitting(false);
    }
  };

  const cancelCurrent = async () => {
    if (!job) return;
    try {
      const res = await fetch(`/api/scan/${encodeURIComponent(job.id)}/cancel`, { method: 'POST' });
      const data = (await res.json()) as { job?: PublicJobView; error?: { message?: string } };
      if (res.ok && data.job) setJob(data.job);
      else setError(data.error?.message ?? 'Failed to cancel the scan.');
    } catch {
      setError('Failed to cancel the scan.');
    }
  };

  const toggleTool = (tool: ToolName) => {
    setCustom((prev) => {
      const has = prev.enabledTools.includes(tool);
      const next = has ? prev.enabledTools.filter((t) => t !== tool) : [...prev.enabledTools, tool];
      if (next.length === 0) return prev;
      return { ...prev, enabledTools: next };
    });
  };

  const toggleModule = (id: ModuleId) => {
    setSelectedModules((prev) => (prev.includes(id) ? prev.filter((m) => m !== id) : [...prev, id]));
  };

  const description = describeProfile(profile, profile === 'custom' ? custom : undefined);

  const counts = job?.summaryCounts;
  const summaryParts = counts
    ? [
        counts.critical > 0 ? `${counts.critical} critical` : null,
        counts.high > 0 ? `${counts.high} high` : null,
        counts.medium > 0 ? `${counts.medium} medium` : null,
        counts.low > 0 ? `${counts.low} low` : null,
        counts.informational > 0 ? `${counts.informational} informational` : null,
      ].filter(Boolean)
    : [];

  return (
    <div className="card">
      <h1>Scan a site you own or are authorized to test</h1>
      <p className="lead">
        SiteDig runs a bounded, TCP-only reconnaissance scan and produces a PDF or Markdown report you can download.
      </p>

      <div className="field">
        <label htmlFor="target">Target</label>
        <input
          id="target"
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="example.com  |  https://example.com/app  |  93.184.216.34"
          disabled={isBusy}
          autoComplete="off"
          spellCheck={false}
        />
        <p className="hint">Domains, hostnames, IPv4, IPv6, or full URLs (paths are used for web-level checks).</p>
      </div>

      <div className="row">
        <div className="field">
          <label htmlFor="profile">Profile</label>
          <select id="profile" value={profile} onChange={(e) => setProfile(e.target.value as ScanProfile)} disabled={isBusy}>
            <option value="quick">Quick</option>
            <option value="standard">Standard</option>
            <option value="deep">Deep</option>
            <option value="custom">Custom</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="timeout">Max duration</label>
          <select
            id="timeout"
            value={profile === 'custom' ? String(Math.round((custom.timeoutMs ?? 300000) / 1000)) : '300'}
            onChange={(e) => profile === 'custom' && setCustom((prev) => ({ ...prev, timeoutMs: Number(e.target.value) * 1000 }))}
            disabled={isBusy}
          >
            {TIMEOUT_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {s} seconds
              </option>
            ))}
          </select>
        </div>
      </div>

      {profile === 'custom' && (
        <div className="field">
          <label>Port scope</label>
          <select
            value={custom.portScope}
            onChange={(e) => setCustom((prev) => ({ ...prev, portScope: e.target.value as CustomScanOptions['portScope'] }))}
            disabled={isBusy}
          >
            {PORT_SCOPE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
          <div style={{ height: 12 }} />
          <label>Tools</label>
          <div className="tool-chips">
            {TOOL_OPTIONS.map((t) => (
              <label key={t.value} className="tool-chip">
                <input type="checkbox" checked={custom.enabledTools.includes(t.value)} onChange={() => toggleTool(t.value)} disabled={isBusy} />
                {t.label}
              </label>
            ))}
          </div>
          <div style={{ height: 12 }} />
          <label htmlFor="custom-path">HTTP path</label>
          <input
            id="custom-path"
            type="text"
            value={custom.path}
            onChange={(e) => setCustom((prev) => ({ ...prev, path: e.target.value || '/' }))}
            disabled={isBusy}
          />
          <div style={{ height: 12 }} />
          <label className="consent-row">
            <input
              type="checkbox"
              checked={custom.followRedirects}
              onChange={(e) => setCustom((prev) => ({ ...prev, followRedirects: e.target.checked }))}
              disabled={isBusy}
            />
            <span>Follow redirects (redirect destinations are safety-checked)</span>
          </label>
        </div>
      )}

      {description && (
        <div className="profile-description">
          <h3>{description.name}</h3>
          <p style={{ margin: '4px 0 8px' }}>{description.summary}</p>
          <p className="meta-line">
            Port scope: {description.portScope} · Expected duration: {description.expectedDuration} · Noise: {description.noise}
          </p>
          <p className="meta-line" style={{ marginTop: 6 }}>
            Tools: {description.tools.join(', ')}
          </p>
          <p style={{ margin: '8px 0 2px', fontWeight: 600 }}>Checks</p>
          <ul>
            {description.checks.map((c, i) => (
              <li key={i}>{c}</li>
            ))}
          </ul>
          <p style={{ margin: '8px 0 2px', fontWeight: 600 }}>Limitations</p>
          <ul>
            {description.limitations.map((c, i) => (
              <li key={i}>{c}</li>
            ))}
          </ul>
        </div>
      )}

      {error && <div className="error-box">{error}</div>}

      {job && (
        <div style={{ marginTop: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <span className={`status-badge ${job.status}`}>{STATUS_LABEL[job.status] ?? job.status}</span>
            <span className="meta-line">
              Target: {job.target} · Profile: {job.profile}
            </span>
            {isBusy && (
              <button className="button danger" onClick={cancelCurrent}>
                Cancel
              </button>
            )}
          </div>

          {job.status === 'completed' && job.hasArtifacts && (
            <div style={{ marginTop: 16 }}>
              <p className="meta-line">Reports are downloaded once each — links are single-use.</p>
              <div style={{ display: 'flex', gap: 12, marginTop: 8, flexWrap: 'wrap' }}>
                <a className="button" href={`/api/scan/${encodeURIComponent(job.id)}/download/pdf`}>
                  Download PDF
                </a>
                <a className="button secondary" href={`/api/scan/${encodeURIComponent(job.id)}/download/markdown`}>
                  Download Markdown
                </a>
              </div>
            </div>
          )}

          {job.status === 'completed' && summaryParts.length > 0 && (
            <div className="summary-grid">
              {summaryParts.map((s, i) => (
                <span key={i} className="summary-pill">
                  {s}
                </span>
              ))}
            </div>
          )}

          {(job.status === 'failed' || job.status === 'cancelled') && job.error && <div className="error-box">{job.error}</div>}
          {job.status === 'running' && <div className="info-box">Scan in progress. The worker enforces a maximum duration of 5 minutes.</div>}
          {job.status === 'queued' && <div className="info-box">Your scan is queued behind other scans.</div>}
        </div>
      )}

      {modules.length > 0 && (
        <div className="field" style={{ marginTop: 22 }}>
          <label>Add-on modules</label>
          <div style={{ display: 'grid', gap: 10, marginTop: 8 }}>
            {modules.map((m) => {
              const selected = selectedModules.includes(m.id);
              const disabled = !m.enabled || isBusy;
              return (
                <label
                  key={m.id}
                  className="tool-chip"
                  style={{
                    justifyContent: 'space-between',
                    borderRadius: 10,
                    padding: '10px 14px',
                    cursor: disabled ? 'not-allowed' : 'pointer',
                    opacity: disabled && !m.enabled ? 0.6 : 1,
                    alignItems: 'flex-start',
                  }}
                >
                  <span>
                    <strong>{m.name}</strong>
                    {m.paid && <span style={{ marginLeft: 8, fontSize: 11, color: '#fbbf24' }}>PAID</span>}
                    <br />
                    <span style={{ fontSize: 12, color: 'var(--muted)', fontWeight: 400 }}>{m.description}</span>
                  </span>
                  <input
                    type="checkbox"
                    checked={selected}
                    onChange={() => toggleModule(m.id)}
                    disabled={disabled}
                    style={{ marginTop: 2 }}
                  />
                  {!m.enabled && (
                    <span style={{ fontSize: 11, color: 'var(--muted)', whiteSpace: 'nowrap', marginTop: 2 }}>🔒 not enabled on this deployment</span>
                  )}
                </label>
              );
            })}
          </div>
        </div>
      )}

      <div style={{ marginTop: 24 }}>
        <button className="button" onClick={openConsent} disabled={isBusy || !target.trim()}>
          Start scan
        </button>
      </div>

      {consentOpen && (
        <div className="modal-backdrop" onClick={closeConsent}>
          <div className="modal" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
            <h2>Authorized Use Notice</h2>
            <p>
              You are about to run a network scan against <strong>{target.trim()}</strong>. Before continuing, confirm that:
            </p>
            <ul>
              <li>You own the target, or you have explicit written permission to scan it.</li>
              <li>You understand that scans generate network traffic that may be logged by the target or its providers.</li>
              <li>Scans may affect the availability of the target and its services.</li>
              <li>Unauthorized scanning may violate laws and the terms of service of the target or its network.</li>
              <li>
                This scan will use the <strong>{description.name}</strong> profile ({description.portScope}, expected {description.expectedDuration}).
              </li>
              {selectedModules.length > 0 && (
                <li>
                  Add-on modules: <strong>{selectedModules.map((id) => modules.find((m) => m.id === id)?.name ?? id).join(', ')}</strong>. These run additional
                  detection tools that may generate more network traffic.
                </li>
              )}
            </ul>
            <div className="consent-row">
              <input id="consent" type="checkbox" checked={consentChecked} onChange={(e) => setConsentChecked(e.target.checked)} />
              <label htmlFor="consent">I own this target or have explicit authorization to scan it, and I accept these terms.</label>
            </div>
            <div className="modal-actions">
              <button className="button secondary" onClick={closeConsent} disabled={submitting}>
                Back
              </button>
              <button className="button" onClick={submitScan} disabled={!consentChecked || submitting}>
                {submitting ? 'Starting…' : 'Start scan'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
