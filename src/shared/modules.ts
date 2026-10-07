import type { ModuleId, ToolName } from './types';

export interface ModuleDefinition {
  id: ModuleId;
  name: string;
  description: string;
  tools: ToolName[];
  paid: boolean;
}

export const MODULE_DEFINITIONS: Record<ModuleId, ModuleDefinition> = {
  'asset-discovery': {
    id: 'asset-discovery',
    name: 'Asset & DNS Discovery',
    description: 'Passive subdomain enumeration (subfinder), DNS record enumeration (dnsx), WHOIS/registration intel (RDAP), and email/DNS security posture (SPF, DMARC, MTA-STS, MX STARTTLS).',
    tools: ['subfinder', 'dnsx', 'rdap', 'email'],
    paid: true,
  },
  'vuln-scan': {
    id: 'vuln-scan',
    name: 'Vulnerability Scan',
    description: 'Template-driven detection with Nuclei (curated non-destructive templates), vulnerable JavaScript checks (retire.js), and an independent HTTP surface re-check with httpx.',
    tools: ['nuclei', 'retire', 'httpx'],
    paid: true,
  },
  'tls-hardening': {
    id: 'tls-hardening',
    name: 'TLS Hardening Audit',
    description: 'Deep TLS/SSL configuration audit with testssl.sh (protocols, ciphers, known weaknesses).',
    tools: ['testssl'],
    paid: true,
  },
  'content-discovery': {
    id: 'content-discovery',
    name: 'Content Discovery',
    description: 'Rate-limited directory/path discovery with feroxbuster, plus historical URL exposure from the Wayback Machine (waybackurls) with live re-verification.',
    tools: ['feroxbuster', 'waybackurls'],
    paid: true,
  },
  'cve-context': {
    id: 'cve-context',
    name: 'CVE Context',
    description: 'Enrich detected technologies with known vulnerabilities from the OSV database.',
    tools: ['osv'],
    paid: true,
  },
  'remediation-playbook': {
    id: 'remediation-playbook',
    name: 'Remediation Playbook',
    description: 'Client-ready fix plans appended to the report: per-finding steps with exact nginx/Apache commands, verification checks, effort estimates, and a prioritized 30-day roadmap.',
    tools: [],
    paid: true,
  },
};

export const ALL_MODULES = Object.keys(MODULE_DEFINITIONS) as ModuleId[];

export function isModuleId(value: string): value is ModuleId {
  return value in MODULE_DEFINITIONS;
}

/**
 * Parse the `ENABLED_MODULES` env var (comma-separated module ids). Modules not
 * listed are treated as disabled ("paid") features. A missing/empty value
 * enables nothing, so free deployments keep the detection-only behavior.
 */
export function parseEnabledModules(env: Record<string, string | undefined> = process.env): Set<ModuleId> {
  const raw = (env.ENABLED_MODULES ?? '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const set = new Set<ModuleId>();
  for (const m of raw) {
    if (isModuleId(m)) set.add(m);
  }
  return set;
}
