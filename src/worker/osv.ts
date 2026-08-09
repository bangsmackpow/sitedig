import type { CveContextFinding } from '../shared/types';

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const TIMEOUT_MS = 20_000;
const MAX_PACKAGES = 15;

export interface OsvPackageQuery {
  ecosystem: string;
  name: string;
  version: string;
}

/** Map a whatweb plugin name to an OSV ecosystem/package. */
export function mapTechnologyToOsv(name: string, version: string | null): OsvPackageQuery | null {
  if (!version) return null;
  const lower = name.toLowerCase();
  const mapping: Array<[string, string, string]> = [
    ['jquery', 'npm', 'jquery'],
    ['jquery-ui', 'npm', 'jquery-ui'],
    ['angular', 'npm', 'angular'],
    ['angularjs', 'npm', 'angular'],
    ['bootstrap', 'npm', 'bootstrap'],
    ['react', 'npm', 'react'],
    ['vue', 'npm', 'vue'],
    ['lodash', 'npm', 'lodash'],
    ['moment', 'npm', 'moment'],
    ['express', 'npm', 'express'],
    ['drupal', 'Packagist', 'drupal/core'],
    ['symfony', 'Packagist', 'symfony/symfony'],
    ['laravel', 'Packagist', 'laravel/framework'],
    ['rails', 'RubyGems', 'rails'],
    ['rack', 'RubyGems', 'rack'],
    ['openssl', 'crates.io', 'openssl-sys'],
    ['nginx', 'OSS-Fuzz', 'nginx'],
    ['apache', 'OSS-Fuzz', 'httpd'],
  ];
  for (const [needle, ecosystem, pkg] of mapping) {
    if (lower.includes(needle)) return { ecosystem, name: pkg, version };
  }
  return null;
}

/**
 * Enrich detected technologies with CVE data from the OSV database (batch
 * query). Returns one entry per matched package.
 */
export async function osvLookup(packages: OsvPackageQuery[]): Promise<CveContextFinding[]> {
  const queries = packages.slice(0, MAX_PACKAGES).map((p) => ({ package: { ecosystem: p.ecosystem, name: p.name }, version: p.version }));
  if (queries.length === 0) return [];

  const findings: CveContextFinding[] = [];
  try {
    const res = await fetch(OSV_BATCH_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ queries }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return [];
    const data = (await res.json()) as { results?: Array<{ vulns?: unknown[] } | null> };
    const results = data.results ?? [];
    for (let i = 0; i < packages.length; i++) {
      const pkg = packages[i];
      const vulns = results[i]?.vulns ?? [];
      if (vulns.length === 0) continue;
      const severities: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const v of vulns as Array<{ severity?: Array<{ type?: unknown; score?: unknown }>; database_specific?: { severity?: unknown } }>) {
        let sev = 'medium';
        const db = v.database_specific?.severity;
        if (typeof db === 'string') sev = db.toLowerCase();
        else {
          const s = v.severity?.[0]?.score;
          if (typeof s === 'string') {
            const cvss = Number(s.split('/')[0]);
            if (!Number.isNaN(cvss)) sev = cvss >= 9 ? 'critical' : cvss >= 7 ? 'high' : cvss >= 4 ? 'medium' : 'low';
          }
        }
        if (sev in severities) severities[sev as keyof typeof severities] += 1;
      }
      findings.push({
        id: `${pkg.name}@${pkg.version}`,
        ecosystem: pkg.ecosystem,
        name: pkg.name,
        version: pkg.version,
        cveCount: vulns.length,
        severities,
      });
    }
    return findings;
  } catch {
    return [];
  }
}
