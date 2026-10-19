'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { apiFetch } from '@/app/lib/api';
import type { ReportModel, Finding, ScanDiff } from '@/shared/types';

const SEVERITY_ORDER: Record<Finding['severity'], number> = { critical: 5, high: 4, medium: 3, low: 2, informational: 1 };

function severityClass(severity: Finding['severity']): string {
  if (severity === 'critical' || severity === 'high') return 'disabled';
  if (severity === 'medium') return 'info';
  return 'active';
}

export default function ReportPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const [report, setReport] = useState<ReportModel | null>(null);
  const [diff, setDiff] = useState<ScanDiff | null>(null);
  const [expiresAt, setExpiresAt] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const id = params?.id;
    if (!id) return;
    apiFetch<{ report: ReportModel; expiresAt: string }>(`/api/scan/${encodeURIComponent(id)}/report`)
      .then((data) => {
        setReport(data.report);
        setExpiresAt(data.expiresAt);
      })
      .catch((e) => {
        if ((e as { status?: number }).status === 401) {
          router.replace('/login');
          return;
        }
        setError((e as Error).message);
      });
    apiFetch<{ diff: ScanDiff }>(`/api/scan/${encodeURIComponent(id)}/diff`)
      .then((data) => setDiff(data.diff))
      .catch(() => setDiff(null));
  }, [params, router]);

  if (error) {
    return (
      <div className="card">
        <h1>Report unavailable</h1>
        <div className="error-box">{error}</div>
        <p className="meta-line">
          Reports are held in memory only and expire with the artifact retention window. <Link className="link" href="/history">Back to history</Link>
        </p>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="card">
        <h1>Report</h1>
        <div className="info-box">Loading report.</div>
      </div>
    );
  }

  const findings = [...report.findings].sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
  const counts = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: acc[f.severity] + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, informational: 0 } as Record<Finding['severity'], number>,
  );

  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
        <div>
          <h1>Scan report</h1>
          <p className="meta-line">
            {report.meta.target} | {report.meta.profile} | {new Date(report.meta.finishedAt).toLocaleString()}
          </p>
          {expiresAt && <p className="meta-line">Available until {new Date(expiresAt).toLocaleString()}. Reports are never stored.</p>}
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
          <Link className="button secondary" href="/history">History</Link>
          <Link className="button secondary" href="/">New scan</Link>
        </div>
      </div>

      <div className="summary-grid" style={{ marginTop: 14 }}>
        {(['critical', 'high', 'medium', 'low', 'informational'] as const).map((sev) => (
          <span key={sev} className="summary-pill">{counts[sev]} {sev}</span>
        ))}
      </div>

      {report.meta.warnings.length > 0 && (
        <div className="info-box" style={{ marginTop: 14 }}>
          {report.meta.warnings.join('; ')}
        </div>
      )}

      <h2 style={{ marginTop: 24 }}>Executive summary</h2>
      <p>{report.executiveSummary}</p>

      {diff && (
        <section id="changes" style={{ marginTop: 24 }}>
          <h2>Changes since previous scan</h2>
          {!diff.previousScanId ? (
            <p className="meta-line">No previous completed scan was found for this host, so there is nothing to compare yet.</p>
          ) : (
            <>
              <p className="meta-line">
                Compared with <Link className="link" href={`/scan/${encodeURIComponent(diff.previousScanId)}`}>{diff.previousScanId}</Link>.
                Risk: {diff.previousRisk?.score ?? '-'} → {diff.risk.score} ({diff.risk.grade})
                {diff.riskDelta !== null ? ` (${diff.riskDelta >= 0 ? '+' : ''}${diff.riskDelta})` : ''}.
              </p>
              <div className="summary-grid" style={{ marginTop: 8 }}>
                <span className="summary-pill">{diff.newFindings.length} new</span>
                <span className="summary-pill">{diff.resolvedFindings.length} resolved</span>
                <span className="summary-pill">{diff.severityChanges.length} severity changes</span>
                {diff.notAssessed.length > 0 && <span className="summary-pill">{diff.notAssessed.length} not assessed</span>}
                <span className="summary-pill">{diff.unchangedCount} unchanged</span>
              </div>
              {diff.newFindings.length > 0 && (
                <>
                  <h3>New findings</h3>
                  <ul>
                    {diff.newFindings.slice(0, 10).map((f) => (
                      <li key={f.fingerprint}><strong>[{f.severity}]</strong> {f.title}{f.affected ? ` — ${f.affected}` : ''}</li>
                    ))}
                  </ul>
                </>
              )}
              {diff.resolvedFindings.length > 0 && (
                <>
                  <h3>Resolved findings</h3>
                  <ul>
                    {diff.resolvedFindings.slice(0, 10).map((f) => (
                      <li key={f.fingerprint}><strong>[{f.severity}]</strong> {f.title}{f.affected ? ` — ${f.affected}` : ''}</li>
                    ))}
                  </ul>
                </>
              )}
              {diff.notAssessed.length > 0 && (
                <>
                  <h3>Not assessed</h3>
                  <p className="meta-line">These findings were present previously but the relevant tool failed or did not run, so they are not marked resolved.</p>
                  <ul>
                    {diff.notAssessed.slice(0, 10).map((f) => (
                      <li key={f.fingerprint}><strong>[{f.severity}]</strong> {f.title}</li>
                    ))}
                  </ul>
                </>
              )}
            </>
          )}
        </section>
      )}

      <h2>Findings</h2>
      {findings.length === 0 && <p className="meta-line">No findings were recorded.</p>}
      <div style={{ display: 'grid', gap: 12 }}>
        {findings.map((f) => (
          <div key={f.id} style={{ border: '1px solid var(--border)', borderRadius: 10, padding: 14 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              <span className={`pill ${severityClass(f.severity)}`}>{f.severity}</span>
              <strong>{f.title}</strong>
            </div>
            <p style={{ margin: '8px 0' }}>{f.description}</p>
            {f.affected && <p className="meta-line">Affected: {f.affected}</p>}
            {f.evidence.length > 0 && (
              <ul className="meta-line" style={{ margin: '6px 0' }}>
                {f.evidence.slice(0, 8).map((ev, i) => <li key={i}><code>{ev}</code></li>)}
              </ul>
            )}
            {f.remediation && <p className="meta-line"><strong>Remediation:</strong> {f.remediation}</p>}
          </div>
        ))}
      </div>

      <h2>Technical details</h2>
      <h3>Ports</h3>
      {report.ports.length === 0 ? <p className="meta-line">No open ports in scope.</p> : (
        <table className="table">
          <thead><tr><th>Port</th><th>Service</th><th>Version</th></tr></thead>
          <tbody>
            {report.ports.map((p) => <tr key={p.port}><td>{p.port}</td><td>{p.service || 'unknown'}</td><td>{p.version || '-'}</td></tr>)}
          </tbody>
        </table>
      )}

      {report.technologies.length > 0 && (
        <>
          <h3>Technologies</h3>
          <p className="meta-line">{report.technologies.map((t) => `${t.name}${t.version ? ` ${t.version}` : ''}`).join(', ')}</p>
        </>
      )}

      {(report.dnsRecords.length > 0 || report.subdomains.length > 0 || report.whois) && (
        <>
          <h3>DNS & registration</h3>
          {report.dnsRecords.length > 0 && (
            <table className="table">
              <thead><tr><th>Type</th><th>Name</th><th>Value</th></tr></thead>
              <tbody>{report.dnsRecords.slice(0, 50).map((r, i) => <tr key={i}><td>{r.type}</td><td>{r.name}</td><td>{r.value}</td></tr>)}</tbody>
            </table>
          )}
          {report.whois && !report.whois.error && (
            <p className="meta-line">Registrar: {report.whois.registrar ?? 'n/a'} | Expiry: {report.whois.expiryDate ?? 'n/a'}</p>
          )}
        </>
      )}

      {report.crawlRules && (
        <>
          <h3>Crawl rules</h3>
          <p className="meta-line">
            robots.txt: {report.crawlRules.robots.found ? 'found' : 'not found'} | sitemap URLs: {report.crawlRules.sitemap.urlCount}
          </p>
        </>
      )}

      {report.securityTxt && (
        <>
          <h3>security.txt</h3>
          <p className="meta-line">
            {report.securityTxt.found ? `Contacts: ${report.securityTxt.contacts.join(', ') || 'none'}` : 'Not published'}
          </p>
        </>
      )}

      {report.pageRecon && !report.pageRecon.error && (
        <>
          <h3>Page metadata</h3>
          <p className="meta-line">
            {report.pageRecon.metadata.title ?? 'No title'} | {report.pageRecon.links.total} links | {report.pageRecon.thirdParties.length} third-party hosts
          </p>
        </>
      )}

      {report.headerPosture && !report.headerPosture.error && (
        <>
          <h3>HTTP posture</h3>
          <p className="meta-line">
            HSTS: {report.headerPosture.hsts.present ? 'enabled' : 'missing'} | CSP: {report.headerPosture.csp ? (report.headerPosture.csp.reportOnly ? 'report-only' : 'enforced') : 'missing'} | ALPN: {report.headerPosture.alpnProtocol ?? 'n/a'}
          </p>
        </>
      )}

      {report.dnsHardening && !report.dnsHardening.error && (
        <>
          <h3>DNS hardening</h3>
          <p className="meta-line">
            CAA: {report.dnsHardening.caa.length} | DKIM selectors: {report.dnsHardening.dkim.filter((d) => d.found && !d.revoked).map((d) => d.selector).join(', ') || 'none'} | DMARC: {report.dnsHardening.dmarc?.policy ?? 'none'}
          </p>
        </>
      )}

      {report.dnssec && !report.dnssec.error && (
        <>
          <h3>DNSSEC</h3>
          <p className="meta-line">Signed: {String(report.dnssec.signed)} | DNSKEY: {report.dnssec.dnskeyCount} | DS: {report.dnssec.dsCount}</p>
        </>
      )}

      {report.ipIntel && !report.ipIntel.error && (
        <>
          <h3>Infrastructure</h3>
          <p className="meta-line">
            {report.ipIntel.waf ? `WAF: ${report.ipIntel.waf.name} ` : ''}{report.ipIntel.cdn ? `CDN: ${report.ipIntel.cdn.name} ` : ''}
            {report.ipIntel.ips.map((ip) => `${ip.ip}${ip.asn ? ` (${ip.asn})` : ''}`).join(', ')}
          </p>
        </>
      )}

      <h3>Tool execution</h3>
      <table className="table">
        <thead><tr><th>Tool</th><th>Result</th><th>Duration</th></tr></thead>
        <tbody>
          {report.toolResults.map((t, i) => (
            <tr key={i}><td>{t.label}</td><td>{t.ok ? 'ok' : t.error ?? 'failed'}</td><td>{(t.durationMs / 1000).toFixed(1)}s</td></tr>
          ))}
        </tbody>
      </table>

      <p className="meta-line" style={{ marginTop: 20 }}>
        PDF and Markdown downloads are available from the scan page while artifacts remain.
      </p>
    </div>
  );
}
