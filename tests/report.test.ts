import { describe, expect, it } from 'vitest';
import { buildExecutiveSummary, renderMarkdown, sortFindings } from '../src/shared/report';
import type { ReportModel } from '../src/shared/types';

function baseReport(overrides: Partial<ReportModel> = {}): ReportModel {
  const report: ReportModel = {
    meta: {
      target: 'https://example.com/',
      host: 'example.com',
      path: '/',
      profile: 'quick',
      portScope: 'common',
      startedAt: '2026-01-01T00:00:00.000Z',
      finishedAt: '2026-01-01T00:00:10.000Z',
      durationMs: 10_000,
      toolVersions: [{ tool: 'nmap', version: 'stub' }],
      status: 'completed',
      warnings: [],
    },
    executiveSummary: 'Summary text.',
    findings: [],
    ports: [],
    http: null,
    tls: null,
    technologies: [],
    wordpress: null,
    subdomains: [],
    dnsRecords: [],
    whois: null,
    vulnerabilities: [],
    tlsHardening: null,
    discoveredPaths: [],
    cveContext: [],
    toolResults: [],
    limitations: ['TCP-only.'],
    ...overrides,
  };
  return report;
}

describe('renderMarkdown', () => {
  it('includes metadata and executive summary', () => {
    const md = renderMarkdown(baseReport());
    expect(md).toContain('# SiteDig Scan Report');
    expect(md).toContain('Summary text.');
    expect(md).toContain('example.com');
    expect(md).toContain('quick');
  });

  it('renders new trust, hardening, and infrastructure sections', () => {
    const report = baseReport({
      crawlRules: {
        robots: { found: true, url: 'https://example.com/robots.txt', status: 200, groups: [], sitemaps: [], aiBots: [{ name: 'GPTBot', allowed: false }], sensitiveDisallows: ['/admin'], error: null },
        sitemap: { found: true, urls: ['https://example.com/a'], urlCount: 1, sitemapCount: 1, error: null },
        error: null,
      },
      securityTxt: { found: false, url: null, status: null, contacts: [], expires: null, policy: null, encryption: null, acknowledgments: null, preferredLanguages: null, error: null },
      pageRecon: {
        url: 'https://example.com/',
        status: 200,
        finalUrl: 'https://example.com/',
        contentType: 'text/html',
        metadata: { title: 'Example', description: null, canonical: null, language: 'en', generator: null, og: {}, twitter: {} },
        links: { internal: 1, external: 0, total: 1, samples: [] },
        mixedContent: [],
        missingSri: [],
        thirdParties: [],
        error: null,
      },
      headerPosture: {
        hsts: { present: true, value: 'max-age=300', maxAge: 300, includeSubDomains: false, preload: false },
        csp: { present: true, reportOnly: false, value: "default-src 'self'", directives: {}, unsafeInline: false, unsafeEval: false, wildcard: false, missingObjectSrc: true, missingBaseUri: true },
        cookies: [],
        alpnProtocol: 'h2',
        httpVersionHint: 'HTTP/2',
        error: null,
      },
      dnsHardening: {
        domain: 'example.com',
        caa: [],
        soa: null,
        srv: [],
        nsAddresses: [],
        dkim: [{ selector: 'default', found: false, keyType: null, revoked: false }],
        bimi: null,
        dmarc: { present: true, policy: 'none', subdomainPolicy: null, pct: 100, rua: [], ruf: [], alignmentDkim: null, alignmentSpf: null },
        error: null,
      },
      dnssec: { signed: false, ad: false, dnskeyCount: 0, dsCount: 0, algorithms: [], error: null },
      ipIntel: { ips: [], waf: { name: 'Cloudflare', evidence: ['header: cf-ray'] }, cdn: null, error: null },
    });
    const md = renderMarkdown(report);
    expect(md).toContain('Crawl Rules & Sitemap');
    expect(md).toContain('security.txt');
    expect(md).toContain('Page Metadata & Assets');
    expect(md).toContain('HTTP Security Posture');
    expect(md).toContain('DNS & Email Hardening');
    expect(md).toContain('DNSSEC');
    expect(md).toContain('IP, ASN & Edge Infrastructure');
  });

  it('renders findings with severity and evidence', () => {
    const report = baseReport({
      findings: [
        {
          id: 'F-001',
          category: 'exposure',
          severity: 'high',
          title: 'Open TCP port 3306',
          description: 'Database exposed.',
          evidence: ['service: mysql'],
          affected: 'example.com:3306',
          confidence: 'high',
          verified: true,
          remediation: 'Restrict access.',
        },
      ],
    });
    const md = renderMarkdown(report);
    expect(md).toContain('[High] Open TCP port 3306');
    expect(md).toContain('service: mysql');
    expect(md).toContain('Restrict access.');
  });

  it('renders ports, TLS, HTTP, and limitations sections', () => {
    const report = baseReport({
      ports: [{ port: 80, state: 'open', protocol: 'tcp', service: 'http', version: '' }],
      http: { status: 200, finalUrl: 'https://example.com/', server: 'nginx', poweredBy: null, headers: {}, redirects: [], error: null },
      tls: { connected: true, protocol: 'TLSv1.3', subjectCn: 'example.com', issuerCn: 'CA', validFrom: 'x', validTo: 'y', daysRemaining: 100, selfSigned: false, error: null },
      wordpress: { detected: true, wpscanRan: true, notes: ['WordPress version 6.4'] },
    });
    const md = renderMarkdown(report);
    expect(md).toContain('Discovered Ports & Services');
    expect(md).toContain('| 80 |');
    expect(md).toContain('HTTP Header Inspection');
    expect(md).toContain('TLS Certificate Inspection');
    expect(md).toContain('Technical Appendix');
    expect(md).toContain('WordPress');
    expect(md).toContain('TCP-only.');
  });

  it('renders a cross-tool validation matrix and a premium upsell teaser by default', () => {
    const report = baseReport({
      findings: [
        {
          id: 'F-001',
          category: 'exposure',
          severity: 'medium',
          title: 'Open TCP port 443 (https)',
          description: 'Exposed.',
          evidence: ['port:443'],
          affected: 'example.com:443',
          confidence: 'high',
          verified: true,
          remediation: 'Restrict.',
          sourceTools: ['nmap', 'tls'],
          corroboration: { level: 'multi', supporting: ['nmap', 'tls'], conflicting: [] },
          playbookKey: 'open-port',
        },
      ],
    });
    const md = renderMarkdown(report);
    expect(md).toContain('## Cross-Tool Validation Matrix');
    expect(md).toContain('Confirmed by 2 independent sources');
    expect(md).toContain('Premium add-on');
    expect(md).toContain('How to Resolve (Remediation Playbook)');
  });

  it('renders the full remediation playbook when the premium module ran', () => {
    const report = baseReport({
      meta: { ...baseReport().meta, modules: ['remediation-playbook'] },
      technologies: [{ name: 'nginx', version: '1.24' }],
      findings: [
        {
          id: 'F-001',
          category: 'misconfiguration',
          severity: 'low',
          title: 'Missing security response headers',
          description: 'Missing headers.',
          evidence: ['missing: content-security-policy'],
          affected: 'https://example.com/',
          confidence: 'high',
          verified: true,
          remediation: 'Add headers.',
          sourceTools: ['http'],
          corroboration: { level: 'single', supporting: ['http'], conflicting: [] },
          playbookKey: 'missing-headers',
        },
      ],
    });
    const md = renderMarkdown(report);
    expect(md).not.toContain('Premium add-on');
    expect(md).toContain('How to resolve: Missing security response headers');
    expect(md).toContain('30-Day Remediation Roadmap');
    expect(md).toContain('add_header Strict-Transport-Security');
  });
});

describe('buildExecutiveSummary', () => {
  it('highlights critical/high findings', () => {
    const summary = buildExecutiveSummary(
      baseReport().meta,
      [{ id: 'F-1', category: 'misconfiguration', severity: 'critical', title: 'Critical thing', description: 'x', evidence: [], affected: null, confidence: 'high', verified: true, remediation: null }],
      1,
    );
    expect(summary).toContain('Critical thing');
  });

  it('notes medium/low when no high/critical', () => {
    const summary = buildExecutiveSummary(
      baseReport().meta,
      [{ id: 'F-1', category: 'misconfiguration', severity: 'medium', title: 'Medium thing', description: 'x', evidence: [], affected: null, confidence: 'high', verified: true, remediation: null }],
      0,
    );
    expect(summary).toContain('medium-severity');
  });

  it('mentions low findings when only low is present', () => {
    const summary = buildExecutiveSummary(
      baseReport().meta,
      [{ id: 'F-1', category: 'misconfiguration', severity: 'low', title: 'Low thing', description: 'x', evidence: [], affected: null, confidence: 'high', verified: true, remediation: null }],
      0,
    );
    expect(summary).toContain('No findings above low severity');
    expect(summary).toContain('1 low-severity finding');
  });

  it('says nothing above informational when only informational present', () => {
    const summary = buildExecutiveSummary(baseReport().meta, [], 0);
    expect(summary).toContain('No findings above informational severity');
  });
});

describe('sortFindings', () => {
  it('sorts by severity descending', () => {
    const findings = [
      { id: 'a', category: 'informational', severity: 'low', title: 'A', description: '', evidence: [], affected: null, confidence: 'high', verified: true, remediation: null },
      { id: 'b', category: 'exposure', severity: 'critical', title: 'B', description: '', evidence: [], affected: null, confidence: 'high', verified: true, remediation: null },
    ];
    const sorted = sortFindings(findings);
    expect(sorted[0].severity).toBe('critical');
  });
});
