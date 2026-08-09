import { COMMON_PORT_LIST, DEFAULT_HTTP_PATH, DEFAULT_USER_AGENT, MAX_SCAN_TIMEOUT_MS } from './constants';
import { formatHostForUrl } from './net';
import type { CustomScanOptions, ModuleId, NormalizedTarget, PortScope, ScanProfile, ToolName } from './types';

export type ScanTool = ToolName;

export interface ToolStep {
  tool: ScanTool;
  label: string;
  args: string[];
}

export interface ScanPlan {
  profile: ScanProfile;
  portScope: PortScope;
  steps: ToolStep[];
}

export interface PlanOpts {
  outputPath: (name: string) => string;
  wpscanApiToken?: string;
  nucleiTemplates?: string[];
  wordlistPath?: string;
}

export function portScopeArgs(scope: PortScope, commonPorts: number[] = COMMON_PORT_LIST): string[] {
  switch (scope) {
    case 'common':
      return ['-p', commonPorts.join(',')];
    case 'top100':
      return ['--top-ports', '100'];
    case 'top1000':
      return ['--top-ports', '1000'];
  }
}

function isEnabled(tool: ToolName, custom: CustomScanOptions | null): boolean {
  if (!custom) return true;
  return custom.enabledTools.includes(tool);
}

/**
 * Expand a profile into the exact, bounded list of tool steps that will run.
 * All commands are constructed here from fixed templates; user input can only
 * influence bounded values (port scope, path, user-agent, timeout).
 */
export function expandProfile(profile: ScanProfile, target: NormalizedTarget, custom: CustomScanOptions | null, opts: PlanOpts): ScanPlan {
  const portScope: PortScope =
    profile === 'custom' ? (custom?.portScope ?? 'top100') : profile === 'quick' ? 'common' : profile === 'standard' ? 'top100' : 'top1000';

  const path = profile === 'custom' ? (custom?.path ?? DEFAULT_HTTP_PATH) : target.path;
  const userAgent = profile === 'custom' ? (custom?.userAgent ?? DEFAULT_USER_AGENT) : DEFAULT_USER_AGENT;
  const intensity = profile === 'deep' ? '7' : profile === 'standard' ? '5' : '2';
  const hostForUrl = formatHostForUrl(target.host);

  const steps: ToolStep[] = [];

  if (isEnabled('nmap', custom)) {
    steps.push({
      tool: 'nmap',
      label: 'Nmap TCP discovery',
      args: [
        '-sT', // TCP connect scan: works without raw sockets / root privileges
        '-Pn', // skip host discovery; treat target as up
        '-n', // no reverse DNS lookups (privacy + speed)
        '-T4',
        ...portScopeArgs(portScope),
        '--open',
        '--version-intensity',
        intensity,
        '-oG',
        opts.outputPath('nmap.grepable'),
        target.host,
      ],
    });
  }

  if (isEnabled('whatweb', custom)) {
    steps.push({
      tool: 'whatweb',
      label: 'WhatWeb technology detection',
      args: ['-a', '1', '--no-errors', '--user-agent', userAgent, '--log-json', opts.outputPath('whatweb.json'), `${target.scheme}://${hostForUrl}${path}`],
    });
  }

  // HTTP and TLS are in-process checks (no subprocess), but still tracked as
  // steps so the report shows exactly what ran and what succeeded/failed.
  if (isEnabled('http', custom)) {
    steps.push({ tool: 'http', label: 'HTTP header inspection', args: [path] });
  }
  if (isEnabled('tls', custom)) {
    steps.push({ tool: 'tls', label: 'TLS certificate inspection', args: ['443'] });
  }

  // WPScan is conditionally appended at runtime by the scanner only when
  // WordPress is detected (or explicitly enabled in Custom mode). When an API
  // token is configured, it is passed to enrich findings with vulnerability data.
  if (profile === 'custom' && isEnabled('wpscan', custom)) {
    steps.push(wpscanStep(target, path, opts));
  }

  return { profile, portScope, steps };
}

function wpscanStep(target: NormalizedTarget, path: string, opts: PlanOpts): ToolStep {
  const args = ['--url', `${target.scheme}://${formatHostForUrl(target.host)}${path}`, '--no-banner', '--disable-tls-checks', '--format', 'json', '--output', opts.outputPath('wpscan.json')];
  if (opts.wpscanApiToken) {
    args.splice(1, 0, '--api-token', opts.wpscanApiToken);
  }
  return { tool: 'wpscan', label: 'WPScan (local-only)', args };
}

/**
 * Expand a set of enabled paid modules into tool steps. Module tools are only
 * reachable through this path, so a module gate is required before any of them
 * can run.
 */
export function expandModules(modules: ModuleId[], target: NormalizedTarget, opts: PlanOpts): ToolStep[] {
  const steps: ToolStep[] = [];
  const hostForUrl = formatHostForUrl(target.host);
  const webUrl = `${target.scheme}://${hostForUrl}${target.path}`;

  for (const moduleId of modules) {
    switch (moduleId) {
      case 'asset-discovery':
        steps.push({ tool: 'subfinder', label: 'Subfinder passive subdomain discovery', args: ['-d', target.host, '-silent', '-json', '-o', opts.outputPath('subfinder.json')] });
        // dnsx v1.2+ requires a list file (`-l`) or wordlist with `-d`; the
        // scanner writes the target host into domains.txt before running.
        steps.push({ tool: 'dnsx', label: 'dnsx DNS record enumeration', args: ['-l', opts.outputPath('domains.txt'), '-silent', '-json', '-o', opts.outputPath('dnsx.json'), '-a', '-aaaa', '-cname', '-mx', '-ns', '-txt', '-soa'] });
        steps.push({ tool: 'rdap', label: 'WHOIS registration lookup (RDAP)', args: [target.host] });
        break;
      case 'vuln-scan': {
        const templates = opts.nucleiTemplates?.length ? opts.nucleiTemplates : [];
        const nucleiArgs = ['-u', webUrl, '-silent', '-jsonl', '-o', opts.outputPath('nuclei.jsonl'), '-timeout', '8', '-rate-limit', '10', '-c', '5', '-no-interactsh'];
        for (const t of templates) {
          nucleiArgs.push('-t', t);
        }
        steps.push({ tool: 'nuclei', label: 'Nuclei template scan (curated allowlist)', args: nucleiArgs });
        steps.push({ tool: 'retire', label: 'Retire.js vulnerable JavaScript', args: ['--path', opts.outputPath('js'), '--outputformat', 'json', '--outputpath', opts.outputPath('retire.json'), '--exitwith', '3'] });
        break;
      }
      case 'tls-hardening':
        steps.push({ tool: 'testssl', label: 'testssl.sh TLS hardening audit', args: ['--jsonfile', opts.outputPath('testssl.json'), '--fast', `${target.host}:443`] });
        break;
      case 'content-discovery':
        steps.push({
          tool: 'feroxbuster',
          label: 'Feroxbuster content discovery (rate-limited)',
          args: ['-u', webUrl, '--json', '-o', opts.outputPath('ferox.json'), '-w', opts.wordlistPath ?? '/opt/sitedig/wordlists/common.txt', '-d', '1', '-t', '5', '-L', '5', '-q'],
        });
        break;
      case 'cve-context':
        steps.push({ tool: 'osv', label: 'OSV CVE enrichment', args: [target.host] });
        break;
    }
  }
  return steps;
}

/**
 * Defense-in-depth: assert that every argument produced for a tool is one we
 * explicitly allow. This guarantees that even a bug elsewhere cannot smuggle
 * an arbitrary flag into a subprocess.
 *
 * Only flag-like arguments are policed against an allowlist. Positional values
 * are passed as individual argv entries (never through a shell), so they
 * cannot cause command injection; we additionally reject control characters.
 */
export function assertApprovedArgs(tool: ScanTool, args: string[]): void {
  const allowed: { exact: string[] } = (() => {
    switch (tool) {
      case 'nmap':
        return { exact: ['-sT', '-Pn', '-n', '-T4', '--open', '-oG', '-p', '--top-ports', '--version-intensity'] };
      case 'whatweb':
        return { exact: ['-a', '--no-errors', '--user-agent', '--log-json'] };
      case 'wpscan':
        return { exact: ['--url', '--api-token', '--no-banner', '--disable-tls-checks', '--format', '--output'] };
      case 'subfinder':
        return { exact: ['-d', '-silent', '-json', '-o'] };
      case 'dnsx':
        return { exact: ['-l', '-d', '-silent', '-json', '-o', '-a', '-aaaa', '-cname', '-mx', '-ns', '-txt', '-soa'] };
      case 'nuclei':
        return { exact: ['-u', '-silent', '-jsonl', '-o', '-t', '-timeout', '-rate-limit', '-c', '-no-interactsh', '-duc', '-omit-raw'] };
      case 'testssl':
        return { exact: ['--jsonfile', '--fast', '--quiet'] };
      case 'feroxbuster':
        return { exact: ['-u', '--json', '--format', '-o', '-w', '-d', '-t', '-L', '-q', '-n'] };
      case 'retire':
        return { exact: ['--path', '--outputformat', '--outputpath', '--exitwith'] };
      case 'http':
      case 'tls':
      case 'rdap':
      case 'osv':
        return { exact: [] };
    }
  })();

  for (const arg of args) {
    if (/\u0000/.test(arg)) throw new Error(`Rejected argument with null byte for ${tool}`);
    if (arg.startsWith('-') && arg !== '--') {
      if (!allowed.exact.includes(arg)) {
        throw new Error(`Rejected argument for ${tool}: ${arg}`);
      }
      continue;
    }
    if (/[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(arg)) {
      throw new Error(`Rejected argument with control characters for ${tool}`);
    }
  }
}

export { MAX_SCAN_TIMEOUT_MS };
