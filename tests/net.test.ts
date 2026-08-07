import { describe, expect, it } from 'vitest';
import {
  cidrContainsIpv4,
  cidrContainsIpv6,
  isBlockedAddress,
  isBlockedIpv4,
  isBlockedIpv6,
  isIpv4,
  isIpv6,
} from '../src/shared/net';

describe('IPv4/IPv6 parsing', () => {
  it('validates dotted quad strictly', () => {
    expect(isIpv4('192.168.1.1')).toBe(true);
    expect(isIpv4('0.0.0.0')).toBe(true);
    expect(isIpv4('255.255.255.255')).toBe(true);
    expect(isIpv4('1.2.3.256')).toBe(false);
    expect(isIpv4('01.2.3.4')).toBe(false);
    expect(isIpv4('not-an-ip')).toBe(false);
  });

  it('validates IPv6', () => {
    expect(isIpv6('2001:db8::1')).toBe(true);
    expect(isIpv6('fe80::1')).toBe(true);
    expect(isIpv6('::1')).toBe(true);
    expect(isIpv6('::ffff:192.0.2.128')).toBe(true);
    expect(isIpv6('192.168.1.1')).toBe(false);
  });
});

describe('CIDR containment', () => {
  it('IPv4 contains', () => {
    expect(cidrContainsIpv4('10.1.2.3', '10.0.0.0/8')).toBe(true);
    expect(cidrContainsIpv4('172.16.5.5', '172.16.0.0/12')).toBe(true);
    expect(cidrContainsIpv4('172.32.5.5', '172.16.0.0/12')).toBe(false);
    expect(cidrContainsIpv4('192.168.1.1', '192.168.0.0/16')).toBe(true);
    expect(cidrContainsIpv4('8.8.8.8', '8.8.8.0/24')).toBe(true);
    expect(cidrContainsIpv4('8.8.9.1', '8.8.8.0/24')).toBe(false);
  });

  it('IPv6 contains', () => {
    expect(cidrContainsIpv6('fc00::1', 'fc00::/7')).toBe(true);
    expect(cidrContainsIpv6('fd12:3456::1', 'fc00::/7')).toBe(true);
    expect(cidrContainsIpv6('fe80::1', 'fc00::/7')).toBe(false);
    expect(cidrContainsIpv6('2001:db8::1', '2001:db8::/32')).toBe(true);
    expect(cidrContainsIpv6('::1', '::1/128')).toBe(true);
  });
});

describe('blocked IPv4 ranges', () => {
  it('blocks RFC1918', () => {
    expect(isBlockedIpv4('10.0.0.1')).toBe(true);
    expect(isBlockedIpv4('172.16.0.1')).toBe(true);
    expect(isBlockedIpv4('172.31.255.255')).toBe(true);
    expect(isBlockedIpv4('192.168.1.1')).toBe(true);
  });

  it('blocks loopback, link-local, CGNAT, metadata', () => {
    expect(isBlockedIpv4('127.0.0.1')).toBe(true);
    expect(isBlockedIpv4('127.8.8.8')).toBe(true);
    expect(isBlockedIpv4('169.254.169.254')).toBe(true);
    expect(isBlockedIpv4('169.254.0.1')).toBe(true);
    expect(isBlockedIpv4('100.64.0.1')).toBe(true);
  });

  it('blocks multicast, reserved, broadcast', () => {
    expect(isBlockedIpv4('224.0.0.1')).toBe(true);
    expect(isBlockedIpv4('239.255.255.255')).toBe(true);
    expect(isBlockedIpv4('240.0.0.1')).toBe(true);
    expect(isBlockedIpv4('255.255.255.255')).toBe(true);
    expect(isBlockedIpv4('0.0.0.0')).toBe(true);
  });

  it('blocks TEST-NET documentation ranges', () => {
    expect(isBlockedIpv4('192.0.2.1')).toBe(true);
    expect(isBlockedIpv4('198.51.100.1')).toBe(true);
    expect(isBlockedIpv4('203.0.113.1')).toBe(true);
    expect(isBlockedIpv4('198.18.0.1')).toBe(true);
  });

  it('allows public addresses', () => {
    expect(isBlockedIpv4('8.8.8.8')).toBe(false);
    expect(isBlockedIpv4('1.1.1.1')).toBe(false);
    expect(isBlockedIpv4('93.184.216.34')).toBe(false);
    expect(isBlockedIpv4('203.0.114.1')).toBe(false);
  });
});

describe('blocked IPv6 ranges', () => {
  it('blocks loopback, unspecified, ULA, link-local, multicast', () => {
    expect(isBlockedIpv6('::1')).toBe(true);
    expect(isBlockedIpv6('::')).toBe(true);
    expect(isBlockedIpv6('fc00::1')).toBe(true);
    expect(isBlockedIpv6('fd00::1')).toBe(true);
    expect(isBlockedIpv6('fe80::1')).toBe(true);
    expect(isBlockedIpv6('ff02::1')).toBe(true);
  });

  it('blocks documentation and translation ranges', () => {
    expect(isBlockedIpv6('2001:db8::1')).toBe(true);
    expect(isBlockedIpv6('2001::1')).toBe(true);
    expect(isBlockedIpv6('64:ff9b::1')).toBe(true);
  });

  it('blocks IPv4-mapped private addresses', () => {
    expect(isBlockedIpv6('::ffff:10.0.0.1')).toBe(true);
    expect(isBlockedIpv6('::ffff:192.168.1.1')).toBe(true);
    expect(isBlockedIpv6('::ffff:127.0.0.1')).toBe(true);
  });

  it('allows public IPv6', () => {
    expect(isBlockedIpv6('2606:2800:220:1::1')).toBe(false);
    expect(isBlockedIpv6('2001:4860:4860::8888')).toBe(false);
  });
});

describe('isBlockedAddress aggregate', () => {
  it('handles any version', () => {
    expect(isBlockedAddress('192.168.1.1')).toBe(true);
    expect(isBlockedAddress('::1')).toBe(true);
    expect(isBlockedAddress('8.8.8.8')).toBe(false);
    expect(isBlockedAddress('not-an-ip')).toBe(true);
  });
});
