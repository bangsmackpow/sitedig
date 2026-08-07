import type { DiscoveredPort } from '../shared/types';

/**
 * Parse nmap grepable (`-oG`) output into discovered ports.
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
