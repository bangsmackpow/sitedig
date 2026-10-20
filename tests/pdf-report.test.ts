import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { buildReportPresentation } from '../src/shared/report-presentation';
import type { ReportModel } from '../src/shared/types';
import { renderPdf } from '../src/worker/pdf';

function report(overrides: Partial<ReportModel> = {}): ReportModel {
  return {
    meta: {
      target: 'https://example.com/',
      host: 'example.com',
      path: '/',
      profile: 'quick',
      portScope: 'common',
      startedAt: '2026-01-01T00:00:00.000Z',
      finishedAt: '2026-01-01T00:01:00.000Z',
      durationMs: 60_000,
      toolVersions: [],
      status: 'completed',
      warnings: [],
      modules: [],
    },
    executiveSummary: 'Test report.',
    findings: [
      {
        id: 'F-1',
        category: 'exposure',
        severity: 'high',
        title: 'Database port exposed',
        description: 'A database is reachable.',
        evidence: ['port:3306'],
        affected: 'example.com:3306',
        confidence: 'high',
        verified: true,
        remediation: 'Restrict access.',
        sourceTools: ['nmap'],
        corroboration: { level: 'single', supporting: ['nmap'], conflicting: [] },
      },
      {
        id: 'F-2',
        category: 'misconfiguration',
        severity: 'medium',
        title: 'HSTS is not enabled',
        description: 'HSTS is missing.',
        evidence: ['strict-transport-security: missing'],
        affected: 'https://example.com/',
        confidence: 'high',
        verified: true,
        remediation: 'Enable HSTS.',
        sourceTools: ['header-posture'],
        corroboration: { level: 'single', supporting: ['header-posture'], conflicting: [] },
      },
    ],
    ports: [{ port: 3306, state: 'open', protocol: 'tcp', service: 'mysql', version: '8.0' }],
    http: { status: 200, finalUrl: 'https://example.com/', server: 'nginx', poweredBy: null, headers: {}, redirects: [], error: null },
    tls: { connected: true, protocol: 'TLSv1.3', subjectCn: 'example.com', issuerCn: 'CA', validFrom: 'x', validTo: 'y', daysRemaining: 100, selfSigned: false, error: null },
    headerPosture: {
      hsts: { present: false, value: null, maxAge: null, includeSubDomains: false, preload: false },
      csp: null,
      cookies: [],
      alpnProtocol: null,
      httpVersionHint: null,
      error: null,
    },
    technologies: [{ name: 'nginx', version: '1.24' }],
    wordpress: null,
    subdomains: [],
    dnsRecords: [],
    whois: null,
    vulnerabilities: [],
    tlsHardening: null,
    discoveredPaths: [],
    cveContext: [],
    toolResults: [
      { tool: 'nmap', label: 'Nmap TCP discovery', ok: true, timedOut: false, exitCode: 0, startedAt: '', finishedAt: '', durationMs: 1000 },
    ],
    limitations: ['TCP-only.'],
    ...overrides,
  };
}

const dirs: string[] = [];

afterEach(() => {
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe('report presentation', () => {
  it('derives counts, risk, port groups, and posture checks', () => {
    const presentation = buildReportPresentation(report());
    expect(presentation.counts.high).toBe(1);
    expect(presentation.counts.medium).toBe(1);
    expect(presentation.risk.score).toBe(87);
    expect(presentation.risk.grade).toBe('B');
    expect(presentation.portGroups.find((g) => g.key === 'database')?.ports).toHaveLength(1);
    expect(presentation.posture.some((c) => c.label === 'HSTS' && c.status === 'fail')).toBe(true);
    expect(presentation.attackSurface.find((a) => a.label === 'Open ports')?.value).toBe(1);
  });
});

describe('PDF report', () => {
  it('renders a multi-page report with the expected PDF header', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sitedig-pdf-'));
    dirs.push(dir);
    const out = path.join(dir, 'report.pdf');
    await renderPdf(report(), out, { reportId: 'scan-test' });
    const buffer = fs.readFileSync(out);
    expect(buffer.subarray(0, 4).toString()).toBe('%PDF');
    expect(buffer.length).toBeGreaterThan(10_000);
    const pages = (buffer.toString('latin1').match(/\/Type\s*\/Page\b/g) ?? []).length;
    expect(pages).toBeGreaterThanOrEqual(3);
    expect(pages).toBeLessThan(40);
  });
});
