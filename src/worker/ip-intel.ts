import { promises as dnsPromises } from 'node:dns';
import type { IpIntelResult } from '../shared/types';
import type { DnsResolver } from './dns';
import { safeFetchText } from './safe-fetch';

interface GeoResponse {
  success?: boolean;
  country?: string;
  region?: string;
  city?: string;
  connection?: { asn?: number; org?: string; isp?: string };
}

interface Fingerprint {
  name: string;
  kind: 'waf' | 'cdn';
  headers?: string[];
  serverIncludes?: string[];
  cookies?: string[];
}

const FINGERPRINTS: Fingerprint[] = [
  { name: 'Cloudflare', kind: 'waf', headers: ['cf-ray', 'cf-cache-status'], serverIncludes: ['cloudflare'], cookies: ['__cf_bm', 'cf_clearance'] },
  { name: 'Akamai', kind: 'cdn', headers: ['x-akamai-request-id', 'x-akamai-transformed', 'akamai-grn'], serverIncludes: ['akamai'], cookies: ['ak_bmsc'] },
  { name: 'Fastly', kind: 'cdn', headers: ['x-served-by', 'x-fastly-request-id'], serverIncludes: ['fastly'] },
  { name: 'Sucuri', kind: 'waf', headers: ['x-sucuri-id', 'x-sucuri-cache'], serverIncludes: ['sucuri'], cookies: ['sucuri_cloudproxy_uuid'] },
  { name: 'Imperva', kind: 'waf', headers: ['x-iinfo'], serverIncludes: ['incapsula', 'imperva'], cookies: ['visid_incap', 'incap_ses'] },
  { name: 'AWS CloudFront', kind: 'cdn', headers: ['x-amz-cf-id', 'x-amz-cf-pop'] },
  { name: 'Azure Front Door', kind: 'cdn', headers: ['x-azure-ref', 'x-fd-int-roxy-purgeid'] },
  { name: 'Vercel', kind: 'cdn', headers: ['x-vercel-id', 'x-vercel-cache'], serverIncludes: ['vercel'] },
  { name: 'Netlify', kind: 'cdn', headers: ['x-nf-request-id'], serverIncludes: ['netlify'] },
  { name: 'Google Cloud CDN', kind: 'cdn', headers: ['x-goog-generation', 'x-goog-metageneration'] },
  { name: 'Bunny CDN', kind: 'cdn', headers: ['x-bunny-request-id'], serverIncludes: ['bunnycdn'] },
];

function detectFingerprint(headers: Record<string, string>, cookieNames: string[]): { waf: IpIntelResult['waf']; cdn: IpIntelResult['cdn'] } {
  const server = (headers['server'] ?? '').toLowerCase();
  const via = (headers['via'] ?? '').toLowerCase();
  const headerNames = new Set(Object.keys(headers).map((h) => h.toLowerCase()));
  const lowerCookies = new Set(cookieNames.map((c) => c.toLowerCase()));
  let waf: IpIntelResult['waf'] = null;
  let cdn: IpIntelResult['cdn'] = null;
  for (const fp of FINGERPRINTS) {
    const evidence: string[] = [];
    for (const header of fp.headers ?? []) {
      if (headerNames.has(header)) evidence.push(`header: ${header}`);
    }
    if (fp.serverIncludes?.some((needle) => server.includes(needle))) evidence.push(`server: ${headers['server']}`);
    for (const cookie of fp.cookies ?? []) {
      if ([...lowerCookies].some((c) => c.startsWith(cookie.toLowerCase()))) evidence.push(`cookie: ${cookie}`);
    }
    if (fp.name === 'AWS CloudFront' && via.includes('cloudfront')) evidence.push('via: cloudfront');
    if (fp.name === 'Google Cloud CDN' && via.includes('google')) evidence.push('via: google');
    if (evidence.length === 0) continue;
    const found = { name: fp.name, evidence: evidence.slice(0, 5) };
    if (fp.kind === 'waf' && !waf) waf = found;
    if (fp.kind === 'cdn' && !cdn) cdn = found;
  }
  return { waf, cdn };
}

const GEO_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const geoCache = new Map<string, { at: number; data: GeoResponse | null }>();

async function geoLookup(ip: string, endpoint: string, resolver?: DnsResolver): Promise<GeoResponse | null> {
  const cacheKey = `${endpoint}|${ip}`;
  const cached = geoCache.get(cacheKey);
  if (cached && Date.now() - cached.at < GEO_CACHE_TTL_MS) return cached.data;
  try {
    const res = await safeFetchText(new URL(`${endpoint}/${encodeURIComponent(ip)}`), {
      accept: 'application/json',
      maxBytes: 128 * 1024,
      timeoutMs: 4_000,
      allowRedirects: false,
      resolver,
    });
    if (res.status < 200 || res.status >= 300) return null;
    const data = JSON.parse(res.body) as GeoResponse;
    if (geoCache.size >= 500) geoCache.clear();
    geoCache.set(cacheKey, { at: Date.now(), data });
    return data;
  } catch {
    return null;
  }
}

export async function ipIntelLookup(input: {
  ips: string[];
  headers: Record<string, string>;
  cookieNames?: string[];
  endpoint: string;
  resolver?: DnsResolver;
}): Promise<IpIntelResult> {
  const result: IpIntelResult = { ips: [], waf: null, cdn: null, error: null };
  const fingerprints = detectFingerprint(input.headers, input.cookieNames ?? []);
  result.waf = fingerprints.waf;
  result.cdn = fingerprints.cdn;

  try {
    const ips = input.ips.slice(0, 2);
    const entries = await Promise.all(
      ips.map(async (ip) => {
        const [geo, ptrResult] = await Promise.all([
          geoLookup(ip, input.endpoint, input.resolver),
          dnsPromises.reverse(ip).catch(() => [] as string[]),
        ]);
        return {
          ip,
          ptr: ptrResult[0] ?? null,
          country: geo?.country ?? null,
          region: geo?.region ?? null,
          city: geo?.city ?? null,
          asn: geo?.connection?.asn !== undefined ? `AS${geo.connection.asn}` : null,
          org: geo?.connection?.org ?? null,
          isp: geo?.connection?.isp ?? null,
        };
      }),
    );
    result.ips = entries;
    if (entries.length > 0 && entries.every((e) => !e.country && !e.asn)) {
      result.error = 'IP intelligence lookup returned no data.';
    }
  } catch (e) {
    result.error = (e as Error).message;
  }
  return result;
}
