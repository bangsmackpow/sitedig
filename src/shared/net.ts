import { isIP } from 'node:net';

/**
 * Address validation and blocked-range detection.
 *
 * These rules are the security backbone of the scanner. They are deliberately
 * conservative: any address that is not clearly global unicast is rejected.
 * This protects the host (and the rest of the private network) from being
 * reached through a malicious or rebinding target.
 */

export type IpVersion = 4 | 6;

const IPV4_PARTS = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function isIpv4(ip: string): boolean {
  if (isIP(ip) !== 4) return false;
  // node:net isIP accepts some forms (e.g. leading zeros are rejected actually),
  // but be strict: require dotted quad with each octet <= 255 and no leading zeros.
  const m = IPV4_PARTS.exec(ip);
  if (!m) return false;
  return m.slice(1).every((p) => {
    if (p.length > 1 && p.startsWith('0')) return false;
    return Number(p) <= 255;
  });
}

export function isIpv6(ip: string): boolean {
  return isIP(ip) === 6;
}

export function ipv4ToInt(ip: string): number {
  if (!isIpv4(ip)) throw new Error(`Invalid IPv4 address: ${ip}`);
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

export function ipv4FromInt(value: number): string {
  return [
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ].join('.');
}

/** Expand an IPv6 address into its canonical 8 x 16-bit segment form. */
export function ipv6ToSegments(ip: string): number[] {
  if (!isIpv6(ip)) throw new Error(`Invalid IPv6 address: ${ip}`);
  // Reconstruct full form from node:net which normalizes to 8 groups.
  const normalized = ip.toLowerCase();
  let head: string[];
  let tail: string[];
  let segments: number[];

  const hasDoubleColon = normalized.includes('::');
  if (!hasDoubleColon) {
    head = normalized.split(':');
    tail = [];
  } else {
    const [h, t] = normalized.split('::');
    head = h === '' ? [] : h.split(':');
    tail = t === '' ? [] : t.split(':');
  }
  const fillCount = 8 - head.length - tail.length;
  if (fillCount < 0) throw new Error(`Invalid IPv6 address: ${ip}`);
  segments = head
    .map((s) => parseInt(s || '0', 16))
    .concat(new Array(fillCount).fill(0))
    .concat(tail.map((s) => parseInt(s || '0', 16)));

  if (segments.length !== 8) throw new Error(`Invalid IPv6 address: ${ip}`);
  return segments;
}

function ipv6SegmentsToBigInt(segments: number[]): bigint {
  let value = 0n;
  for (const seg of segments) {
    value = (value << 16n) | BigInt(seg & 0xffff);
  }
  return value;
}

export function ipv6ToBigInt(ip: string): bigint {
  return ipv6SegmentsToBigInt(ipv6ToSegments(ip));
}

export function cidrContainsIpv4(ip: string, cidr: string): boolean {
  const [network, prefixStr] = cidr.split('/');
  const prefix = Number(prefixStr);
  if (!isIpv4(network)) throw new Error(`Invalid IPv4 network: ${network}`);
  const addr = ipv4ToInt(ip);
  const net = ipv4ToInt(network);
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (addr & mask) === (net & mask);
}

export function cidrContainsIpv6(ip: string, cidr: string): boolean {
  const [network, prefixStr] = cidr.split('/');
  const prefix = Number(prefixStr);
  if (!isIpv6(network)) throw new Error(`Invalid IPv6 network: ${network}`);
  const addr = ipv6ToBigInt(ip);
  const net = ipv6ToBigInt(network);
  if (prefix === 0) return true;
  const mask = (1n << BigInt(128 - prefix)) - 1n;
  return (addr & ~mask) === (net & ~mask);
}

/** IPv4 CIDRs that are considered private/reserved and must never be scanned. */
const BLOCKED_IPV4_CIDRS: string[] = [
  '0.0.0.0/8', // "this" network
  '10.0.0.0/8', // RFC1918
  '100.64.0.0/10', // CGNAT shared address space
  '127.0.0.0/8', // loopback
  '169.254.0.0/16', // link-local (incl. 169.254.169.254 cloud metadata)
  '172.16.0.0/12', // RFC1918
  '192.0.0.0/24', // IETF protocol assignments
  '192.0.2.0/24', // TEST-NET-1
  '192.31.196.0/24', // AS112-v4
  '192.52.193.0/24', // AMT
  '192.88.99.0/24', // 6to4 relay anycast (deprecated)
  '192.168.0.0/16', // RFC1918
  '198.18.0.0/15', // network benchmark testing
  '198.51.100.0/24', // TEST-NET-2
  '203.0.113.0/24', // TEST-NET-3
  '224.0.0.0/4', // multicast
  '240.0.0.0/4', // reserved
  '255.255.255.255/32', // limited broadcast
];

/** IPv6 CIDRs that are considered private/reserved and must never be scanned. */
const BLOCKED_IPV6_CIDRS: string[] = [
  '::/128', // unspecified
  '::1/128', // loopback
  '::ffff:0:0/96', // IPv4-mapped IPv6 (handled by translating to v4 when possible)
  '64:ff9b::/96', // IPv4-IPv6 translation (NAT64)
  '100::/64', // discard-only
  '2001::/32', // Teredo
  '2001:10::/28', // ORCHID
  '2001:20::/28', // ORCHIDv2
  '2001:db8::/32', // documentation
  '2002::/16', // 6to4 (deprecated tunneling)
  'fc00::/7', // unique-local
  'fe80::/10', // link-local
  'ff00::/8', // multicast
];

export function isBlockedIpv4(ip: string): boolean {
  if (!isIpv4(ip)) return false;
  return BLOCKED_IPV4_CIDRS.some((cidr) => cidrContainsIpv4(ip, cidr));
}

export function isBlockedIpv6(ip: string): boolean {
  if (!isIpv6(ip)) return false;
  // IPv4-mapped addresses: validate the embedded IPv4 address instead.
  if (ip.startsWith('::ffff:')) {
    const v4 = ip.slice('::ffff:'.length);
    if (isIpv4(v4)) return isBlockedIpv4(v4);
  }
  return BLOCKED_IPV6_CIDRS.some((cidr) => cidrContainsIpv6(ip, cidr));
}

export function isBlockedAddress(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) return isBlockedIpv4(ip);
  if (version === 6) return isBlockedIpv6(ip);
  return true; // not a valid IP => treat as unsafe
}

/**
 * Format a host for use inside a URL string. IPv6 literals must be wrapped in
 * brackets (e.g. `[2606:2800:220:1::1]`).
 */
export function formatHostForUrl(host: string): string {
  return isIpv6(host) ? `[${host}]` : host;
}

/**
 * Returns a human-readable reason if the address is blocked, otherwise null.
 */
export function blockedAddressReason(ip: string): string | null {
  if (!isIP(ip)) return 'not a valid IP address';
  if (isIP(ip) === 4 && !isBlockedIpv4(ip)) return null;
  if (isIP(ip) === 6 && !isBlockedIpv6(ip)) return null;
  return 'resolves to a private or reserved address';
}
