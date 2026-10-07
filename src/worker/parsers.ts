import type {
  ArchivedUrl,
  ArchivedUrlCategory,
  DiscoveredPath,
  DiscoveredPort,
  DiscoveredSubdomain,
  DnsRecord,
  HttpxObservation,
  TlsHardeningResult,
  VulnerabilityFinding,
} from '../shared/types';

/** Parse subfinder `-json` output (JSONL). */
export function parseSubfinderJson(raw: string): DiscoveredSubdomain[] {
  const out: DiscoveredSubdomain[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    try {
      const obj = JSON.parse(t) as { host?: unknown; source?: unknown; input?: unknown };
      if (typeof obj.host === 'string' && obj.host) {
        out.push({ host: obj.host, source: typeof obj.source === 'string' ? obj.source : null });
      }
    } catch {
      // skip malformed lines
    }
  }
  const seen = new Set<string>();
  return out.filter((s) => (seen.has(s.host) ? false : (seen.add(s.host), true)));
}

/** Parse dnsx `-json` output (JSONL). */
export function parseDnsxJson(raw: string): DnsRecord[] {
  const out: DnsRecord[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    try {
      const obj = JSON.parse(t) as { host?: unknown; type?: unknown; value?: unknown; error?: unknown };
      if (obj.error) continue;
      if (typeof obj.host === 'string' && typeof obj.type === 'string' && obj.value !== undefined) {
        out.push({ type: obj.type, name: obj.host, value: String(obj.value) });
      }
    } catch {
      // skip
    }
  }
  return out;
}

/** Parse nuclei `-jsonl` output. */
export function parseNucleiJsonl(raw: string): VulnerabilityFinding[] {
  const out: VulnerabilityFinding[] = [];
  const seen = new Set<string>();
  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    try {
      const obj = JSON.parse(t) as {
        'template-id'?: unknown;
        'template-url'?: unknown;
        info?: { name?: unknown; severity?: unknown; description?: unknown };
        'matched-at'?: unknown;
        'matcher-status'?: unknown;
      };
      if (obj['matcher-status'] === false) continue;
      const templateId = String(obj['template-id'] ?? '');
      const matchedAt = typeof obj['matched-at'] === 'string' ? obj['matched-at'] : null;
      const name = typeof obj.info?.name === 'string' ? obj.info.name : '';
      // Nuclei frequently emits the same template result more than once; dedupe.
      const key = `${templateId}::${matchedAt ?? ''}::${name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const severity = String(obj.info?.severity ?? 'info').toLowerCase();
      const sevMap: Record<string, VulnerabilityFinding['severity']> = {
        info: 'info',
        low: 'low',
        medium: 'medium',
        high: 'high',
        critical: 'critical',
      };
      out.push({
        id: templateId,
        templateId,
        severity: sevMap[severity] ?? 'info',
        title: name || templateId || 'Unknown template',
        description: typeof obj.info?.description === 'string' ? obj.info.description : '',
        matchedAt,
        source: 'nuclei',
      });
    } catch {
      // skip
    }
  }
  return out;
}

/** Parse retire.js `--outputformat json` output. */
export function parseRetireJson(raw: string): VulnerabilityFinding[] {
  const out: VulnerabilityFinding[] = [];
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return out;
  }
  const results = (data as { results?: unknown[] })?.results ?? [];
  for (const entry of results) {
    const e = entry as {
      component?: unknown;
      version?: unknown;
      vulnerabilities?: Array<{ identifiers?: { CVE?: string[]; summary?: unknown }; severity?: unknown }>;
      detection?: { evidence?: unknown };
    };
    const vulns = e.vulnerabilities ?? [];
    for (const v of vulns) {
      const cves = v.identifiers?.CVE ?? [];
      const summary = typeof v.identifiers?.summary === 'string' ? v.identifiers.summary : '';
      const severity = String(v.severity ?? 'medium').toLowerCase();
      const sevMap: Record<string, VulnerabilityFinding['severity']> = { info: 'info', low: 'low', medium: 'medium', high: 'high', critical: 'critical' };
      out.push({
        id: cves[0] ?? summary.slice(0, 40),
        templateId: null,
        severity: sevMap[severity] ?? 'medium',
        title: `${e.component} ${e.version ?? ''} — ${cves[0] ?? 'known vulnerable version'}`.trim(),
        description: summary || `The detected version (${e.version ?? 'unknown'}) of ${e.component} has known vulnerabilities.`,
        matchedAt: null,
        source: 'retire',
      });
    }
  }
  return out;
}

/** Parse testssl.sh `--jsonfile` output into a summarized hardening result. */
export function parseTestsslJson(raw: string): TlsHardeningResult {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return { finished: false, summary: [], weaknesses: [], error: 'testssl.sh produced no parseable JSON output.' };
  }
  const entries = Array.isArray(data) ? data : [data];
  const weaknesses: TlsHardeningResult['weaknesses'] = [];
  const summary: string[] = [];
  const seenWeakness = new Set<string>();
  for (const e of entries) {
    const entry = e as {
      id?: unknown;
      severity?: unknown;
      finding?: unknown;
      vuln?: unknown;
      cve?: unknown;
    };
    const severity = String(entry.severity ?? '').toUpperCase();
    const vuln = entry.vuln === true || /^(CRITICAL|HIGH|MEDIUM)$/.test(severity);
    const id = String(entry.id ?? '');
    const finding = String(entry.finding ?? '');
    if (vuln && finding) {
      const key = `${id}::${finding}`;
      if (!seenWeakness.has(key)) {
        seenWeakness.add(key);
        weaknesses.push({ name: id || finding.slice(0, 40), detail: finding, severity: severity || 'MEDIUM' });
      }
    }
    if (finding && !summary.includes(finding)) {
      summary.push(finding);
    }
  }
  return { finished: true, summary: summary.slice(0, 30), weaknesses, error: null };
}

/** Parse feroxbuster `--json -o` output (JSONL). */
export function parseFeroxJson(raw: string): DiscoveredPath[] {
  const out: DiscoveredPath[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    try {
      const obj = JSON.parse(t) as { url?: unknown; status?: unknown; content_length?: unknown; content_type?: unknown; wildcard?: unknown };
      if (obj.wildcard === true) continue;
      const url = typeof obj.url === 'string' && obj.url ? obj.url : '';
      if (!url) continue;
      let path = url;
      try {
        path = new URL(url).pathname;
      } catch {
        continue;
      }
      const status = typeof obj.status === 'number' ? obj.status : 0;
      if (!path || status < 100) continue;
      out.push({
        path,
        status,
        size: typeof obj.content_length === 'number' ? obj.content_length : null,
        contentType: typeof obj.content_type === 'string' ? obj.content_type : null,
      });
    } catch {
      // skip
    }
  }
  return out;
}

/** Parse nmap grepable (`-oG`) output into discovered ports.
 * Sample line:
 *   Host: 93.184.216.34 (example.com)  Ports: 80/open/tcp//http///, 443/open/tcp//https///  Ignored State: filtered (9998)
 */
export function parseNmapGrepable(output: string): DiscoveredPort[] {
  const ports: DiscoveredPort[] = [];
  for (const line of output.split(/\r?\n/)) {
    if (!line.startsWith('Host:')) continue;
    const segments = line.split('\t');
    const portsSegment = segments.find((s) => s.startsWith('Ports:'));
    if (!portsSegment) continue;
    const body = portsSegment.slice('Ports:'.length).trim();
    for (const entry of body.split(',')) {
      const parts = entry.trim().split('/');
      if (parts.length < 6) continue;
      const [portStr, state, protocol, , service, version] = parts;
      if (state !== 'open') continue;
      const port = Number(portStr);
      if (!Number.isInteger(port) || port < 1 || port > 65535) continue;
      ports.push({ port, state, protocol, service: service || '', version: version || '' });
    }
  }
  // de-duplicate and sort
  const seen = new Set<string>();
  const unique = ports.filter((p) => {
    const key = `${p.port}-${p.service}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return unique.sort((a, b) => a.port - b.port);
}

interface WhatWebPlugins {
  [name: string]: { version?: string[]; string?: string[] } | unknown;
}

export interface WhatWebResult {
  target: string;
  httpStatus: number | null;
  plugins: Array<{ name: string; version: string | null }>;
  wordpressDetected: boolean;
}

/** Parse a whatweb `--log-json` file. */
export function parseWhatwebJson(raw: string): WhatWebResult | null {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    // Some whatweb versions emit JSONL (one object per line).
    try {
      const lines = raw
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);
      data = lines.map((l) => JSON.parse(l));
    } catch {
      return null;
    }
  }

  const arr = Array.isArray(data) ? data : [data];
  const first = arr.find((entry) => entry !== null && typeof entry === 'object') as
    | { target?: unknown; http_status?: unknown; plugins?: WhatWebPlugins }
    | undefined;
  if (!first) return null;

  const plugins = first.plugins ?? {};
  const names = Object.keys(plugins).filter((n) => !isNoisePlugin(n));
  const pluginList = names.map((name) => {
    const info = plugins[name] as { version?: string[] } | undefined;
    const version = Array.isArray(info?.version) && info.version.length > 0 ? info.version[0] : null;
    return { name, version };
  });
  return {
    target: typeof first.target === 'string' ? first.target : '',
    httpStatus: typeof first.http_status === 'number' ? first.http_status : null,
    plugins: pluginList,
    wordpressDetected: names.some((n) => n.toLowerCase().includes('wordpress')),
  };
}

const NOISE_PLUGIN_PATTERNS = ['httpserver', 'strict-transport', 'cookies', 'meta-', 'redirect', 'passwordfield', 'unescaped'];

function isNoisePlugin(name: string): boolean {
  const lower = name.toLowerCase();
  return NOISE_PLUGIN_PATTERNS.some((p) => lower.includes(p));
}

export interface WpscanResult {
  version: string | null;
  wordpressVersion: string | null;
  notes: string[];
}

/** Parse wpscan `--format json --output FILE` output. */
export function parseWpscanJson(raw: string): WpscanResult | null {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!data || typeof data !== 'object') return null;
  const obj = data as Record<string, unknown>;
  const wp = (obj.wordpress ?? {}) as Record<string, unknown>;
  const notes: string[] = [];

  if (typeof wp.readme_url === 'string') notes.push('WordPress readme is exposed.');
  if (typeof wp.version === 'string') notes.push(`WordPress version reported: ${wp.version}`);
  const findings = Array.isArray(obj.interesting_findings) ? (obj.interesting_findings as unknown[]) : [];
  if (findings.length > 0) notes.push(`WPScan reported ${findings.length} interesting finding(s).`);
  const plugins = (obj.plugins ?? {}) as Record<string, unknown>;
  const pluginCount = Object.keys(plugins).length;
  if (pluginCount > 0) notes.push(`WPScan enumerated ${pluginCount} plugin(s).`);
  const themes = (obj.themes ?? {}) as Record<string, unknown>;
  const themeCount = Object.keys(themes).length;
  if (themeCount > 0) notes.push(`WPScan enumerated ${themeCount} theme(s).`);

  return {
    version: typeof obj.version === 'string' ? obj.version : null,
    wordpressVersion: typeof wp.version === 'string' ? wp.version : null,
    notes,
  };
}

/** Normalize a httpx headers map (values may be strings or string arrays). */
function normalizeHeaders(raw: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!raw || typeof raw !== 'object') return out;
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    const lower = key.toLowerCase();
    if (Array.isArray(value)) out[lower] = value.map((v) => String(v)).join(', ');
    else if (value !== undefined && value !== null) out[lower] = String(value);
  }
  return out;
}

/** Parse the first record of httpx `-json` output (JSONL) into an observation. */
export function parseHttpxJsonl(raw: string): HttpxObservation | null {
  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || !t.startsWith('{')) continue;
    let obj: Record<string, unknown>;
    try {
      obj = JSON.parse(t) as Record<string, unknown>;
    } catch {
      continue;
    }
    const headers = normalizeHeaders(obj.headers);
    const setCookie = headers['set-cookie'] ?? '';
    const cookies = setCookie
      ? setCookie
          .split(/,(?=\s*[A-Za-z0-9_-]+=)/)
          .map((c) => c.trim())
          .filter(Boolean)
          .map((c) => ({
            name: c.split('=')[0].trim(),
            secure: /;\s*secure/i.test(c),
            httpOnly: /;\s*httponly/i.test(c),
          }))
      : [];
    const status = typeof obj.status_code === 'number' ? obj.status_code : typeof obj.status === 'number' ? obj.status : null;
    let tech: string[] = [];
    if (Array.isArray(obj.tech)) tech = (obj.tech as unknown[]).map(String);
    else if (typeof obj.tech === 'string' && obj.tech) tech = obj.tech.split(',').map((s) => s.trim());
    const finalUrl = typeof obj.final_url === 'string' && obj.final_url ? obj.final_url : typeof obj.url === 'string' ? obj.url : null;
    return {
      url: typeof obj.url === 'string' ? obj.url : '',
      status,
      finalUrl,
      server: typeof obj.webserver === 'string' && obj.webserver ? obj.webserver : headers['server'] ?? null,
      headers,
      cookies,
      tlsVersion: typeof obj.tls_version === 'string' && obj.tls_version ? obj.tls_version : null,
      certExpiry:
        (typeof obj.tls_expiration_date === 'string' && obj.tls_expiration_date) ||
        (typeof obj.cert_expiry === 'string' && obj.cert_expiry) ||
        null,
      technologies: tech,
      error: typeof obj.error === 'string' && obj.error ? obj.error : null,
    };
  }
  return null;
}

const SENSITIVE_PATH_PATTERNS: RegExp[] = [
  /\.git\//i,
  /\.env(\.|\?|$|#)/i,
  /\.svn\//i,
  /wp-config\.php/i,
  /\.aws\/credentials/i,
  /id_rsa/i,
  /\.sql(\?|$)/i,
  /\.bak(\?|$)/i,
  /\.old(\?|$)/i,
  /backup[-_.]/i,
  /dump[-_.]/i,
  /phpmyadmin/i,
  /adminer/i,
  /web\.config/i,
  /\.DS_Store/i,
  /server-status/i,
  /debug\//i,
];

const TOKEN_QUERY_RE = /(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|secret|password|passwd|session[_-]?id|sig|signature|private[_-]?key)([a-z0-9_-]*)=([^&]{8,})/i;

/** Classify a Wayback Machine URL list and mark sensitive exposures. */
export function parseWaybackUrls(raw: string, targetHost: string): ArchivedUrl[] {
  const out: ArchivedUrl[] = [];
  const seen = new Set<string>();
  for (const line of raw.split(/\r?\n/)) {
    // With --dates the first column is an RFC3339 timestamp; strip it.
    const match = line.trim().match(/^(?:\S+\s+)?(https?:\/\/\S+)$/i);
    const url = match?.[1];
    if (!url) continue;
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      continue;
    }
    const host = parsed.hostname.toLowerCase();
    // Safety: only keep exact-host URLs (never subdomains we did not validate).
    if (host !== targetHost.toLowerCase()) continue;
    const path = parsed.pathname;
    if (!path || seen.has(path)) continue;
    seen.add(path);
    let category: ArchivedUrlCategory = 'other';
    let tokenParam: string | null = null;
    let outUrl = url;
    if (SENSITIVE_PATH_PATTERNS.some((re) => re.test(path))) category = 'sensitive-path';
    const tokenMatch = parsed.search ? parsed.search.slice(1).match(TOKEN_QUERY_RE) : null;
    if (tokenMatch) {
      category = 'credential-in-url';
      tokenParam = decodeURIComponent(tokenMatch[1]).toLowerCase();
      // Never store the secret value in the report; mask it in place.
      const maskedSearch = parsed.search.replace(TOKEN_QUERY_RE, (_m, p1: string, p2: string) => `${p1}${p2}=***`);
      outUrl = `${parsed.origin}${path}${maskedSearch}`;
    }
    out.push({ url: outUrl, path, category, tokenParam, live: false });
  }
  return out;
}
