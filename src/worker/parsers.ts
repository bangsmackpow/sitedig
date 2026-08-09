import type {
  DiscoveredPath,
  DiscoveredPort,
  DiscoveredSubdomain,
  DnsRecord,
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
      const severity = String(obj.info?.severity ?? 'info').toLowerCase();
      const sevMap: Record<string, VulnerabilityFinding['severity']> = {
        info: 'info',
        low: 'low',
        medium: 'medium',
        high: 'high',
        critical: 'critical',
      };
      out.push({
        id: String(obj['template-id'] ?? ''),
        templateId: String(obj['template-id'] ?? ''),
        severity: sevMap[severity] ?? 'info',
        title: typeof obj.info?.name === 'string' ? obj.info.name : String(obj['template-id'] ?? 'Unknown template'),
        description: typeof obj.info?.description === 'string' ? obj.info.description : '',
        matchedAt: typeof obj['matched-at'] === 'string' ? obj['matched-at'] : null,
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
