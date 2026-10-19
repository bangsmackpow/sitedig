import { afterEach, describe, expect, it, vi } from 'vitest';
import { parseTarget } from '../src/shared/targets';
import type { SafeFetchResult } from '../src/worker/safe-fetch';
import { crawlRulesLookup } from '../src/worker/crawl-rules';
import { securityTxtLookup } from '../src/worker/security-txt';
import { pageReconLookup } from '../src/worker/page-recon';
import { analyzeHeaderPosture } from '../src/worker/header-posture';
import { dnssecLookup } from '../src/worker/dnssec';

const target = parseTarget('https://example.com/shop');

function response(url: URL, body: string, status = 200, headers: Record<string, string> = {}): SafeFetchResult {
  return {
    status,
    finalUrl: url.toString(),
    headers: { 'content-type': 'text/plain', ...headers },
    setCookies: [],
    body,
    truncated: false,
  };
}

describe('web trust parsing', () => {
  it('parses robots rules, AI crawler blocks, and sitemap URLs', async () => {
    const fetchText = async (url: URL) => {
      if (url.pathname === '/robots.txt') {
        return response(
          url,
          ['User-agent: *', 'Disallow: /admin', 'Disallow: /api', 'User-agent: GPTBot', 'Disallow: /', 'Sitemap: https://example.com/sitemap.xml'].join('\n'),
        );
      }
      if (url.pathname === '/sitemap.xml') {
        return response(url, '<urlset><url><loc>https://example.com/a</loc></url><url><loc>https://example.com/b</loc></url></urlset>', 200, { 'content-type': 'application/xml' });
      }
      return response(url, '', 404);
    };
    const result = await crawlRulesLookup(target, { fetchText });
    expect(result.robots.found).toBe(true);
    expect(result.robots.sensitiveDisallows).toEqual(expect.arrayContaining(['/admin', '/api']));
    expect(result.robots.aiBots.find((b) => b.name === 'GPTBot')?.allowed).toBe(false);
    expect(result.sitemap.urlCount).toBe(2);
    expect(result.sitemap.urls).toContain('https://example.com/a');
  });

  it('parses security.txt fields', async () => {
    const fetchText = async (url: URL) =>
      url.pathname === '/.well-known/security.txt'
        ? response(url, ['Contact: mailto:security@example.com', 'Expires: 2030-01-01T00:00:00Z', 'Policy: https://example.com/policy'].join('\n'))
        : response(url, '', 404);
    const result = await securityTxtLookup(target, { fetchText });
    expect(result.found).toBe(true);
    expect(result.contacts).toEqual(['mailto:security@example.com']);
    expect(result.expires).toBe('2030-01-01T00:00:00Z');
  });

  it('extracts metadata, mixed content, SRI gaps, and third parties', async () => {
    const html = `
      <html lang="en"><head>
        <title>Example Shop</title>
        <meta name="description" content="A shop" />
        <meta property="og:title" content="Example" />
        <link rel="canonical" href="/canonical" />
        <link rel="stylesheet" href="https://cdn.example.net/site.css" />
      </head><body>
        <a href="/a">internal</a><a href="https://external.test/x">external</a>
        <script src="http://cdn.example.net/app.js"></script>
        <script src="https://cdn.example.net/lib.js"></script>
      </body></html>`;
    const fetchText = async (url: URL) => response(url, html, 200, { 'content-type': 'text/html' });
    const out = await pageReconLookup(target, { fetchText });
    expect(out.result.metadata.title).toBe('Example Shop');
    expect(out.result.metadata.description).toBe('A shop');
    expect(out.result.metadata.language).toBe('en');
    expect(out.result.metadata.og.title).toBe('Example');
    expect(out.result.metadata.canonical).toBe('https://example.com/canonical');
    expect(out.result.links.internal).toBe(1);
    expect(out.result.links.external).toBe(1);
    expect(out.result.mixedContent.some((m) => m.kind === 'script')).toBe(true);
    expect(out.result.missingSri.length).toBeGreaterThan(0);
    expect(out.result.thirdParties.some((t) => t.host === 'cdn.example.net')).toBe(true);
  });

  it('grades HSTS, CSP, and cookies', () => {
    const posture = analyzeHeaderPosture({
      headers: {
        'strict-transport-security': 'max-age=300',
        'content-security-policy': "default-src * 'unsafe-inline'",
      },
      setCookies: ['sid=secret; Secure; HttpOnly; SameSite=Lax', 'theme=dark'],
      alpnProtocol: 'h2',
    });
    expect(posture.hsts.present).toBe(true);
    expect(posture.hsts.maxAge).toBe(300);
    expect(posture.csp?.unsafeInline).toBe(true);
    expect(posture.csp?.wildcard).toBe(true);
    expect(posture.cookies.find((c) => c.name === 'sid')?.sameSite).toBe('Lax');
    expect(posture.cookies.find((c) => c.name === 'theme')?.secure).toBe(false);
    expect(posture.httpVersionHint).toBe('HTTP/2');
    expect(JSON.stringify(posture)).not.toContain('secret');
  });
});

describe('dnssec', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('detects DNSKEY records and algorithm names', async () => {
    vi.stubGlobal('fetch', async (url: URL | string) => {
      const parsed = new URL(url.toString());
      const type = parsed.searchParams.get('type');
      if (type === 'DNSKEY') {
        return new Response(JSON.stringify({ Status: 0, AD: true, Answer: [{ type: 48, data: '257 3 13 abc' }] }), { status: 200 });
      }
      return new Response(JSON.stringify({ Status: 0, AD: true, Answer: [{ type: 43, data: 'abc' }] }), { status: 200 });
    });
    const result = await dnssecLookup('example.com', 'https://cloudflare-dns.com/dns-query', { resolve: async () => ['93.184.216.34'] });
    expect(result.signed).toBe(true);
    expect(result.ad).toBe(true);
    expect(result.dnskeyCount).toBe(1);
    expect(result.dsCount).toBe(1);
    expect(result.algorithms).toContain('ECDSAP256SHA256');
  });
});
