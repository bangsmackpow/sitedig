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
});
