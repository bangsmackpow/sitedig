/**
 * Curated, offline runtime advisories.
 *
 * These are intentionally data-driven so emergency guidance can be added
 * without new tooling. Detection is version-based only; nothing here attempts
 * exploitation.
 */

export interface RuntimeVersion {
  major: number;
  minor: number;
  patch: number;
  raw: string;
}

export interface PhpAdvisoryRule {
  /** Branch key, e.g. "8.4". */
  branch: string;
  /** First fixed release in that branch, e.g. "8.4.27". */
  fixed: string;
}

export interface PhpAdvisory {
  id: string;
  name: string;
  cves: string[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  published: string;
  summary: string;
  impact: string;
  remediation: string;
  references: string[];
  sapis: string[];
  /** Releases at or below this branch are EOL and treated as vulnerable. */
  eolAtOrBelow: { major: number; minor: number };
  rules: PhpAdvisoryRule[];
}

export interface AdvisoryEvaluation {
  state: 'vulnerable' | 'fixed' | 'unknown';
  advisory: PhpAdvisory;
  version: RuntimeVersion | null;
  fixedVersion: string | null;
  branch: string | null;
  reason: string;
}

export const PHP2SHELL: PhpAdvisory = {
  id: 'php2shell',
  name: 'PHP2Shell',
  cves: ['CVE-2026-109618', 'CVE-2026-109619'],
  severity: 'critical',
  published: '2026-10-21',
  summary:
    'Two unauthenticated remote code execution vulnerabilities in PHP core (out-of-memory corruption and stale global state between requests).',
  impact:
    'A crafted HTTP request can run code as the PHP process account before application code runs. All SAPIs serving web requests are in scope; mod_php is highest risk.',
  remediation:
    'Upgrade PHP to the fixed release for the deployed branch (8.2.35, 8.3.36, 8.4.27, or 8.5.12) and restart every PHP worker. Configuration changes reduce specific paths but do not fully mitigate the issue.',
  references: [
    'https://www.php.net/archive/2026.php#2026-10-21-5',
    'https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w',
    'https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp',
    'https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/',
  ],
  sapis: ['mod_php', 'PHP-FPM', 'php-cgi', 'FrankenPHP', 'LiteSpeed'],
  eolAtOrBelow: { major: 8, minor: 1 },
  rules: [
    { branch: '8.2', fixed: '8.2.35' },
    { branch: '8.3', fixed: '8.3.36' },
    { branch: '8.4', fixed: '8.4.27' },
    { branch: '8.5', fixed: '8.5.12' },
  ],
};

export const PHP_ADVISORIES: PhpAdvisory[] = [PHP2SHELL];

/** Parse a PHP version from a header, banner, or technology label. */
export function parseRuntimeVersion(raw: string | null | undefined): RuntimeVersion | null {
  if (!raw) return null;
  const match = /php[\/\s:-]*(\d+)\.(\d+)\.(\d+)/i.exec(raw) ?? /(\d+)\.(\d+)\.(\d+)/.exec(raw);
  if (!match) return null;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  if (![major, minor, patch].every(Number.isFinite)) return null;
  return { major, minor, patch, raw };
}

export function compareRuntimeVersions(a: RuntimeVersion, b: RuntimeVersion): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  return a.patch - b.patch;
}

export function evaluatePhpAdvisory(advisory: PhpAdvisory, version: RuntimeVersion | null): AdvisoryEvaluation {
  if (!version) {
    return {
      state: 'unknown',
      advisory,
      version: null,
      fixedVersion: null,
      branch: null,
      reason: 'PHP version could not be determined from the available fingerprints.',
    };
  }

  const branch = `${version.major}.${version.minor}`;
  const eol = version.major < advisory.eolAtOrBelow.major || (version.major === advisory.eolAtOrBelow.major && version.minor <= advisory.eolAtOrBelow.minor);
  if (eol) {
    return {
      state: 'vulnerable',
      advisory,
      version,
      fixedVersion: null,
      branch,
      reason: `${branch} is end-of-life and has no upstream fix for this advisory.`,
    };
  }

  const rule = advisory.rules.find((candidate) => candidate.branch === branch);
  if (!rule) {
    return {
      state: 'fixed',
      advisory,
      version,
      fixedVersion: null,
      branch,
      reason: `${branch} is not listed as affected by this advisory.`,
    };
  }

  const fixed = parseRuntimeVersion(rule.fixed);
  if (!fixed) {
    return {
      state: 'unknown',
      advisory,
      version,
      fixedVersion: rule.fixed,
      branch,
      reason: 'Advisory data is malformed.',
    };
  }

  if (compareRuntimeVersions(version, fixed) >= 0) {
    return {
      state: 'fixed',
      advisory,
      version,
      fixedVersion: rule.fixed,
      branch,
      reason: `${version.raw} is at or above the fixed release ${rule.fixed}.`,
    };
  }

  return {
    state: 'vulnerable',
    advisory,
    version,
    fixedVersion: rule.fixed,
    branch,
    reason: `${version.raw} is below the fixed release ${rule.fixed} for the ${branch} branch.`,
  };
}
