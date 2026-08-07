import { isIP } from 'node:net';
import { isIpv4, isIpv6 } from './net';
import type { NormalizedTarget } from './types';

export class TargetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TargetError';
  }
}

const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))*$/;
const IPV4_CIDR_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/;
const IPV6_CIDR_RE = /^[0-9a-fA-F:.]+::\/\d{1,3}$/;

function looksLikeCidr(raw: string): boolean {
  // A URL with a path legitimately contains "/", so only treat as CIDR when
  // the whole input has no scheme and matches a CIDR shape.
  if (raw.includes('://')) return false;
  return IPV4_CIDR_RE.test(raw) || IPV6_CIDR_RE.test(raw);
}

/**
 * Parse and normalize user-supplied target input.
 *
 * Accepts: full URLs (path preserved for web checks), domains, hostnames,
 * IPv4, and IPv6 addresses. Rejects CIDR ranges (deferred feature), URLs with
 * embedded credentials, and malformed hostnames.
 */
export function parseTarget(rawInput: string): NormalizedTarget {
  const raw = rawInput.trim();
  if (!raw) throw new TargetError('Target is required.');
  if (raw.length > 2048) throw new TargetError('Target is too long.');

  if (looksLikeCidr(raw)) {
    throw new TargetError('CIDR/network ranges are not supported in this version.');
  }

  // Full URL
  if (raw.includes('://')) {
    let parsed: URL;
    try {
      parsed = new URL(raw);
    } catch {
      throw new TargetError('Invalid URL.');
    }
    if (parsed.username || parsed.password) {
      throw new TargetError('URLs containing credentials are not allowed.');
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new TargetError('Only http and https URLs are supported.');
    }
    const hostname = parsed.hostname;
    // WHATWG URL keeps brackets on IPv6 hostnames; strip them for IP detection.
    const host = (hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname).toLowerCase();
    if (!host) throw new TargetError('URL has no hostname.');
    const path = `${parsed.pathname || '/'}${parsed.search}`;
    return {
      kind: isIP(host) === 4 ? 'ipv4' : isIP(host) === 6 ? 'ipv6' : 'url',
      host,
      path,
      scheme: parsed.protocol === 'https:' ? 'https' : 'http',
      raw,
      display: raw,
      isIp: isIP(host) === 4 || isIP(host) === 6,
    };
  }

  // Bare IPv4 / IPv6
  if (isIpv4(raw) || isIpv6(raw)) {
    const normalized = isIpv6(raw) ? raw.toLowerCase() : raw;
    return {
      kind: isIpv4(normalized) ? 'ipv4' : 'ipv6',
      host: normalized,
      path: '/',
      scheme: 'https',
      raw,
      display: normalized,
      isIp: true,
    };
  }

  // Hostname / domain (must not contain slashes, whitespace, or underscores)
  if (raw.includes('/') || /\s/.test(raw) || raw.includes('_')) {
    throw new TargetError('Invalid hostname. Provide a domain, IP address, or full URL.');
  }
  const host = raw.toLowerCase();
  if (host.length > 253) throw new TargetError('Hostname is too long.');
  if (!HOSTNAME_RE.test(host)) {
    throw new TargetError('Invalid hostname format.');
  }

  return {
    kind: 'hostname',
    host,
    path: '/',
    scheme: 'https',
    raw,
    display: host,
    isIp: false,
  };
}
