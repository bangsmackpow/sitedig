import { describe, expect, it } from 'vitest';
import { parseTarget, TargetError } from '../src/shared/targets';

describe('parseTarget', () => {
  it('parses a bare hostname', () => {
    const t = parseTarget('example.com');
    expect(t.kind).toBe('hostname');
    expect(t.host).toBe('example.com');
    expect(t.path).toBe('/');
    expect(t.scheme).toBe('https');
    expect(t.display).toBe('example.com');
  });

  it('normalizes uppercase hostnames', () => {
    expect(parseTarget('EXAMPLE.COM').host).toBe('example.com');
  });

  it('parses a full URL and preserves the path', () => {
    const t = parseTarget('https://example.com/app?x=1');
    expect(t.kind).toBe('url');
    expect(t.host).toBe('example.com');
    expect(t.path).toBe('/app?x=1');
    expect(t.scheme).toBe('https');
  });

  it('supports http scheme and http-only default paths', () => {
    const t = parseTarget('http://example.com:8080/health');
    expect(t.scheme).toBe('http');
    expect(t.path).toBe('/health');
  });

  it('parses bare IPv4', () => {
    const t = parseTarget('93.184.216.34');
    expect(t.kind).toBe('ipv4');
    expect(t.host).toBe('93.184.216.34');
    expect(t.isIp).toBe(true);
  });

  it('parses bare IPv6 and normalizes case', () => {
    const t = parseTarget('2606:2800:220:1::1');
    expect(t.kind).toBe('ipv6');
    expect(t.isIp).toBe(true);
  });

  it('parses URL with IPv6 host', () => {
    const t = parseTarget('https://[2606:2800:220:1::1]/x');
    expect(t.kind).toBe('ipv6');
    expect(t.isIp).toBe(true);
  });

  it('rejects CIDR ranges (deferred feature)', () => {
    expect(() => parseTarget('192.168.1.0/24')).toThrow(TargetError);
    expect(() => parseTarget('10.0.0.0/8')).toThrow(TargetError);
    expect(() => parseTarget('2001:db8::/32')).toThrow(TargetError);
  });

  it('rejects URLs with embedded credentials', () => {
    expect(() => parseTarget('https://user:pass@example.com')).toThrow(TargetError);
  });

  it('rejects non-http(s) schemes', () => {
    expect(() => parseTarget('ftp://example.com')).toThrow(TargetError);
  });

  it('rejects malformed hostnames', () => {
    expect(() => parseTarget('example..com')).toThrow(TargetError);
    expect(() => parseTarget('-bad.example.com')).toThrow(TargetError);
    expect(() => parseTarget('has space.com')).toThrow(TargetError);
    expect(() => parseTarget('bad_host.com')).toThrow(TargetError);
    expect(() => parseTarget('path/only')).toThrow(TargetError);
    expect(() => parseTarget('')).toThrow(TargetError);
  });

  it('allows single-label hostnames and subdomains', () => {
    expect(parseTarget('localhost.test').host).toBe('localhost.test');
    expect(parseTarget('a.b.c.d').host).toBe('a.b.c.d');
  });
});
