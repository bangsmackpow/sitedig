import type { CustomScanOptions, ScanProfile, ToolName } from './types';

export interface ProfileDescription {
  id: ScanProfile;
  name: string;
  summary: string;
  tools: string[];
  portScope: string;
  expectedDuration: string;
  noise: string;
  checks: string[];
  limitations: string[];
}

function toolLabel(tool: ToolName): string {
  switch (tool) {
    case 'nmap':
      return 'nmap (TCP connect)';
    case 'whatweb':
      return 'whatweb';
    case 'wpscan':
      return 'wpscan (local-only)';
    case 'http':
      return 'HTTP headers';
    case 'tls':
      return 'TLS certificate inspection';
  }
}

export const PROFILE_DESCRIPTIONS: Record<Exclude<ScanProfile, 'custom'>, ProfileDescription> = {
  quick: {
    id: 'quick',
    name: 'Quick Scan',
    summary:
      'A fast, low-noise reconnaissance scan of common web and service ports. Recommended for a first look.',
    tools: ['nmap (TCP connect)', 'whatweb', 'HTTP headers', 'TLS certificate inspection', 'WordPress detection'],
    portScope: 'Common TCP ports (curated list)',
    expectedDuration: '~30–60 seconds, capped at 5 minutes',
    noise: 'Low. TCP connect scans on ~30 common ports only.',
    checks: [
      'Discover open common TCP ports and services',
      'Identify web technologies and platform fingerprints',
      'Inspect HTTP response headers and security headers',
      'Inspect the TLS certificate and negotiated protocol',
      'Detect WordPress and run local-only WPScan checks when found',
    ],
    limitations: ['Only the curated common port list is checked', 'No UDP, all-port, CIDR, or exploit checks'],
  },
  standard: {
    id: 'standard',
    name: 'Standard Scan',
    summary: 'A broader scan of the top 100 TCP ports with expanded service and version detection.',
    tools: ['nmap (TCP connect)', 'whatweb', 'HTTP headers', 'TLS certificate inspection', 'WordPress detection'],
    portScope: 'Top 100 TCP ports',
    expectedDuration: '~1–3 minutes, capped at 5 minutes',
    noise: 'Moderate. TCP connect scans on the top 100 ports.',
    checks: [
      'Discover open ports across the top 100 TCP ports',
      'Service and version detection on open ports',
      'Identify web technologies and platform fingerprints',
      'Inspect HTTP response headers and security headers',
      'Inspect the TLS certificate and negotiated protocol',
      'Detect WordPress and run local-only WPScan checks when found',
    ],
    limitations: ['Only the top 100 TCP ports are checked', 'No UDP, all-port, CIDR, or exploit checks'],
  },
  deep: {
    id: 'deep',
    name: 'Deep Scan',
    summary: 'The most thorough detection-oriented scan of the top 1,000 TCP ports with detailed enumeration.',
    tools: ['nmap (TCP connect)', 'whatweb', 'HTTP headers', 'TLS certificate inspection', 'WordPress detection'],
    portScope: 'Top 1,000 TCP ports',
    expectedDuration: 'Up to 5 minutes (hard cap)',
    noise: 'High. TCP connect scans across the top 1,000 ports.',
    checks: [
      'Discover open ports across the top 1,000 TCP ports',
      'Detailed service and version detection on open ports',
      'Identify web technologies and platform fingerprints',
      'Inspect HTTP response headers and security headers',
      'Inspect the TLS certificate and negotiated protocol',
      'Detect WordPress and run local-only WPScan checks when found',
    ],
    limitations: ['Only the top 1,000 TCP ports are checked', 'No UDP, all-port, CIDR, or exploit checks'],
  },
};

export function describeProfile(profile: ScanProfile, custom?: CustomScanOptions): ProfileDescription {
  if (profile !== 'custom') return PROFILE_DESCRIPTIONS[profile];
  const tools = (custom?.enabledTools ?? []).map(toolLabel);
  return {
    id: 'custom',
    name: 'Custom Scan',
    summary: 'A user-selected combination of bounded, pre-approved checks.',
    tools,
    portScope: custom?.portScope ?? 'Top 100 TCP ports',
    expectedDuration: 'Up to the selected timeout (max 5 minutes)',
    noise: 'Depends on the selected port scope and tools.',
    checks: ['Only the tools you selected are run', 'Network discovery uses TCP connect scans only', 'No arbitrary command arguments are accepted'],
    limitations: ['No UDP, all-port, CIDR, or exploit checks', 'No external vulnerability database lookups'],
  };
}
