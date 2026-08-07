import { COMMON_PORT_LIST, DEFAULT_HTTP_PATH, DEFAULT_USER_AGENT, MAX_SCAN_TIMEOUT_MS } from './constants';
import { formatHostForUrl } from './net';
import type { CustomScanOptions, NormalizedTarget, PortScope, ScanProfile, ToolName } from './types';

export type ScanTool = 'nmap' | 'whatweb' | 'wpscan' | 'http' | 'tls';

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
export function expandProfile(
  profile: ScanProfile,
  target: NormalizedTarget,
  custom: CustomScanOptions | null,
  opts: { outputPath: (name: string) => string },
): ScanPlan {
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
  // WordPress is detected (or explicitly enabled in Custom mode).
  if (profile === 'custom' && isEnabled('wpscan', custom)) {
    steps.push({
      tool: 'wpscan',
      label: 'WPScan (local-only)',
      args: ['--url', `${target.scheme}://${hostForUrl}${path}`, '--no-banner', '--disable-tls-checks', '--format', 'json', '--output', opts.outputPath('wpscan.json')],
    });
  }

  return { profile, portScope, steps };
}

/**
 * Defense-in-depth: assert that every argument produced for a tool is one we
 * explicitly allow. This guarantees that even a bug elsewhere cannot smuggle
 * an arbitrary flag (e.g. `--script`, `-sS`, `-O`) into a subprocess.
 *
 * Only flag-like arguments are policed against an allowlist. Positional values
 * are passed as individual argv entries (never through a shell), so they
 * cannot cause command injection; we additionally reject control characters.
 */
export function assertApprovedArgs(tool: ScanTool, args: string[]): void {
  const allowed: { exact: string[] } = (() => {
    switch (tool) {
      case 'nmap':
        return {
          exact: ['-sT', '-Pn', '-n', '-T4', '--open', '-oG', '-p', '--top-ports', '--version-intensity'],
        };
      case 'whatweb':
        return {
          exact: ['-a', '--no-errors', '--user-agent', '--log-json'],
        };
      case 'wpscan':
        return {
          exact: ['--url', '--no-banner', '--disable-tls-checks', '--format', '--output'],
        };
      case 'http':
      case 'tls':
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
