import { describe, expect, it } from 'vitest';
import { buildFindings } from '../src/worker/findings';
import type { FindingsInput } from '../src/worker/findings';

function base(overrides: Partial<FindingsInput> = {}): FindingsInput {
  return {
    ports: [],
    http: null,
    tls: null,
    technologies: [],
    wordpressDetected: false,
    wpscan: null,
    wpscanRan: false,
    wpscanError: null,
    wpscanExitNote: null,
    vulnerabilities: [],
    discoveredPaths: [],
    cveContext: [],
    host: 'example.com',
    path: '/',
    ...overrides,
  };
}

describe('buildFindings', () => {
  it('flags database ports as medium exposure', () => {
    const findings = buildFindings(base({ ports: [{ port: 3306, state: 'open', protocol: 'tcp', service: 'mysql', version: '8' }] }));
    const f = findings.find((x) => x.category === 'exposure');
    expect(f).toBeDefined();
    expect(f?.severity).toBe('medium');
    expect(f?.verified).toBe(true);
    expect(f?.affected).toBe('example.com:3306');
  });

  it('flags SSH as low', () => {
    const findings = buildFindings(base({ ports: [{ port: 22, state: 'open', protocol: 'tcp', service: 'ssh', version: '' }] }));
    expect(findings[0].severity).toBe('low');
  });

  it('reports missing security headers', () => {
    const findings = buildFindings(base({ http: { status: 200, finalUrl: 'https://example.com/', server: null, poweredBy: null, headers: {}, redirects: [], error: null } }));
    const f = findings.find((x) => x.title === 'Missing security response headers');
    expect(f).toBeDefined();
    expect(f?.category).toBe('misconfiguration');
  });

  it('reports expired TLS certificate as high', () => {
    const findings = buildFindings(
      base({
        tls: {
          connected: true,
          protocol: 'TLSv1.3',
          subjectCn: 'example.com',
          issuerCn: 'CA',
          validFrom: 'x',
          validTo: 'y',
          daysRemaining: -5,
          selfSigned: false,
          error: null,
        },
      }),
    );
    expect(findings.some((x) => x.title === 'TLS certificate is expired' && x.severity === 'high')).toBe(true);
  });

  it('flags outdated TLS protocol', () => {
    const findings = buildFindings(
      base({
        tls: { connected: true, protocol: 'TLSv1', subjectCn: 'x', issuerCn: 'y', validFrom: 'a', validTo: 'b', daysRemaining: 100, selfSigned: false, error: null },
      }),
    );
    const f = findings.find((x) => x.title === 'Outdated TLS protocol in use');
    expect(f?.category).toBe('outdated-technology');
    expect(f?.severity).toBe('high');
  });

  it('creates WordPress finding and preserves wpscan notes', () => {
    const findings = buildFindings(
      base({ wordpressDetected: true, wpscan: { version: '3.8.25', wordpressVersion: '6.4', notes: ['WordPress readme is exposed.'] } }),
    );
    const f = findings.find((x) => x.category === 'wordpress');
    expect(f).toBeDefined();
    expect(f?.description).toContain('Reported version: 6.4');
    expect(f?.description).toContain('WordPress readme is exposed');
  });

  it('reports http check errors as informational', () => {
    const findings = buildFindings(base({ http: { status: null, finalUrl: null, server: null, poweredBy: null, headers: {}, redirects: [], error: 'ECONNREFUSED' } }));
    expect(findings.some((x) => x.title === 'HTTP check could not complete')).toBe(true);
  });

  it('corroborates a web-port exposure across nmap, http, tls, and httpx', () => {
    const findings = buildFindings(
      base({
        ports: [{ port: 443, state: 'open', protocol: 'tcp', service: 'https', version: 'nginx' }],
        http: { status: 200, finalUrl: 'https://example.com/', server: 'nginx', poweredBy: null, headers: {}, redirects: [], error: null },
        tls: { connected: true, protocol: 'TLSv1.3', subjectCn: 'example.com', issuerCn: 'CA', validFrom: 'x', validTo: 'y', daysRemaining: 100, selfSigned: false, error: null },
        httpx: { url: 'https://example.com/', status: 200, finalUrl: 'https://example.com/', server: 'nginx', headers: {}, cookies: [], tlsVersion: 'TLSv1.3', certExpiry: null, technologies: [], error: null },
      }),
    );
    const port443 = findings.find((x) => x.title.includes('Open TCP port 443'));
    expect(port443?.corroboration?.level).toBe('multi');
    expect(port443?.corroboration?.supporting).toEqual(expect.arrayContaining(['nmap', 'tls', 'httpx']));
  });

  it('flags conflicting server banners between http and httpx', () => {
    const findings = buildFindings(
      base({
        http: { status: 200, finalUrl: 'https://example.com/', server: 'nginx', poweredBy: null, headers: { server: 'nginx' }, redirects: [], error: null },
        httpx: { url: 'https://example.com/', status: 200, finalUrl: 'https://example.com/', server: 'Apache', headers: {}, cookies: [], tlsVersion: null, certExpiry: null, technologies: [], error: null },
      }),
    );
    const banner = findings.find((x) => x.title === 'Web server fingerprint revealed');
    expect(banner?.corroboration?.level).toBe('conflicting');
    expect(banner?.confidence).toBe('medium');
  });

  it('flags cookies missing Secure/HttpOnly from httpx', () => {
    const findings = buildFindings(
      base({
        http: { status: 200, finalUrl: 'https://example.com/', server: null, poweredBy: null, headers: {}, redirects: [], error: null },
        httpx: {
          url: 'https://example.com/',
          status: 200,
          finalUrl: 'https://example.com/',
          server: null,
          headers: {},
          cookies: [{ name: 'sess', secure: false, httpOnly: false }],
          tlsVersion: null,
          certExpiry: null,
          technologies: [],
          error: null,
        },
      }),
    );
    const f = findings.find((x) => x.title.includes('Secure/HttpOnly'));
    expect(f?.severity).toBe('medium');
    expect(f?.sourceTools).toEqual(['httpx']);
    expect(f?.playbookKey).toBe('insecure-cookie');
  });

  it('produces email-security findings from posture data', () => {
    const findings = buildFindings(
      base({
        email: {
          domain: 'example.com',
          spfRecords: ['v=spf1 +all'],
          dmarcRecords: [],
          mx: [{ host: 'mail.example.com', priority: 10 }],
          mtaSts: null,
          tlsRpt: null,
          starttls: { checked: true, mx: 'mail.example.com', supported: false, error: null },
          error: null,
        },
      }),
    );
    expect(findings.some((x) => x.title.includes('No DMARC'))).toBe(true);
    const spf = findings.find((x) => x.title.includes('SPF record allows any sender'));
    expect(spf?.severity).toBe('medium');
    expect(findings.some((x) => x.title.includes('STARTTLS'))).toBe(true);
    expect(findings.some((x) => x.title.includes('MTA-STS'))).toBe(true);
  });

  it('raises archival credential leaks to critical and marks live sensitive paths', () => {
    const findings = buildFindings(
      base({
        archivedUrls: [
          { url: 'https://example.com/.git/config', path: '/.git/config', category: 'sensitive-path', tokenParam: null, live: true },
          { url: 'https://example.com/export?api_key=x', path: '/export', category: 'credential-in-url', tokenParam: 'api_key', live: false },
        ],
      }),
    );
    const cred = findings.find((x) => x.title.includes('credential-like parameters'));
    expect(cred?.severity).toBe('critical');
    const sensitive = findings.find((x) => x.title.includes('sensitive path(s)'));
    expect(sensitive?.severity).toBe('high');
    expect(sensitive?.description).toContain('still answer');
  });

  it('assigns a playbook key and source tools to every finding', () => {
    const findings = buildFindings(base({ ports: [{ port: 22, state: 'open', protocol: 'tcp', service: 'ssh', version: '' }] }));
    for (const f of findings) {
      expect(f.sourceTools && f.sourceTools.length > 0).toBe(true);
      expect(f.corroboration).toBeDefined();
    }
    expect(findings.find((f) => f.title.includes('22'))?.playbookKey).toBe('open-ssh');
  });
});
