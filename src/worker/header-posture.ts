import type { CookieObservation, CspAnalysis, HeaderPostureResult, HstsAnalysis } from '../shared/types';

export interface HeaderPostureInput {
  headers: Record<string, string>;
  setCookies: string[];
  alpnProtocol?: string | null;
}

function parseHsts(value: string | undefined): HstsAnalysis {
  if (!value) return { present: false, value: null, maxAge: null, includeSubDomains: false, preload: false };
  const lower = value.toLowerCase();
  const maxAgeMatch = /max-age\s*=\s*"?(\d+)"?/i.exec(value);
  return {
    present: true,
    value: value.slice(0, 500),
    maxAge: maxAgeMatch ? Number(maxAgeMatch[1]) : null,
    includeSubDomains: /includesubdomains/i.test(lower),
    preload: /preload/i.test(lower),
  };
}

function parseCsp(value: string | undefined, reportOnly: boolean): CspAnalysis | null {
  if (!value) return null;
  const directives: Record<string, string[]> = {};
  for (const part of value.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    directives[tokens[0].toLowerCase()] = tokens.slice(1);
  }
  const allValues = Object.values(directives).flat();
  return {
    present: true,
    reportOnly,
    value: value.slice(0, 1000),
    directives,
    unsafeInline: allValues.some((v) => v.toLowerCase() === "'unsafe-inline'"),
    unsafeEval: allValues.some((v) => v.toLowerCase() === "'unsafe-eval'"),
    wildcard: allValues.some((v) => v === '*'),
    missingObjectSrc: !directives['object-src'],
    missingBaseUri: !directives['base-uri'],
  };
}

function parseCookies(values: string[]): CookieObservation[] {
  const out: CookieObservation[] = [];
  for (const raw of values.slice(0, 50)) {
    const parts = raw.split(';').map((p) => p.trim());
    if (parts.length === 0) continue;
    const name = parts[0].split('=')[0]?.trim();
    if (!name) continue;
    let secure = false;
    let httpOnly = false;
    let sameSite: string | null = null;
    let expires: string | null = null;
    let maxAge: number | null = null;
    for (const part of parts.slice(1)) {
      const [keyRaw, ...rest] = part.split('=');
      const key = keyRaw.trim().toLowerCase();
      const value = rest.join('=').trim();
      if (key === 'secure') secure = true;
      else if (key === 'httponly') httpOnly = true;
      else if (key === 'samesite') sameSite = value || null;
      else if (key === 'expires') expires = value || null;
      else if (key === 'max-age') {
        const parsed = Number(value);
        maxAge = Number.isFinite(parsed) ? parsed : null;
      }
    }
    out.push({ name: name.slice(0, 200), secure, httpOnly, sameSite, expires: expires?.slice(0, 100) ?? null, maxAge });
  }
  return out;
}

function versionHint(alpn: string | null): string | null {
  if (!alpn) return null;
  if (alpn === 'h2') return 'HTTP/2';
  if (alpn === 'h3') return 'HTTP/3';
  if (alpn === 'http/1.1') return 'HTTP/1.1';
  return alpn;
}

export function analyzeHeaderPosture(input: HeaderPostureInput): HeaderPostureResult {
  try {
    const hsts = parseHsts(input.headers['strict-transport-security']);
    const enforced = parseCsp(input.headers['content-security-policy'], false);
    const reportOnly = enforced ? null : parseCsp(input.headers['content-security-policy-report-only'], true);
    const alpn = input.alpnProtocol ?? null;
    return {
      hsts,
      csp: enforced ?? reportOnly,
      cookies: parseCookies(input.setCookies),
      alpnProtocol: alpn,
      httpVersionHint: versionHint(alpn),
      error: null,
    };
  } catch (e) {
    return {
      hsts: { present: false, value: null, maxAge: null, includeSubDomains: false, preload: false },
      csp: null,
      cookies: [],
      alpnProtocol: null,
      httpVersionHint: null,
      error: (e as Error).message,
    };
  }
}
