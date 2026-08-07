import { describe, expect, it } from 'vitest';
import { assertNoRebinding, resolveAndValidate, type DnsResolver } from '../src/worker/dns';

function resolverOf(byHost: Record<string, string[]>): DnsResolver {
  return { resolve: async (host) => byHost[host] ?? [] };
}

describe('resolveAndValidate', () => {
  it('accepts public addresses', async () => {
    const res = await resolveAndValidate('example.com', resolverOf({ 'example.com': ['93.184.216.34'] }));
    expect(res.addresses).toEqual(['93.184.216.34']);
  });

  it('rejects unresolvable hosts', async () => {
    await expect(resolveAndValidate('nope.invalid', resolverOf({}))).rejects.toThrow(/Could not resolve/);
  });

  it('rejects blocked addresses', async () => {
    await expect(resolveAndValidate('internal.local', resolverOf({ 'internal.local': ['10.0.0.5'] }))).rejects.toThrow(/blocked/);
    await expect(resolveAndValidate('meta.local', resolverOf({ 'meta.local': ['169.254.169.254'] }))).rejects.toThrow(/blocked/);
    await expect(resolveAndValidate('v6.local', resolverOf({ 'v6.local': ['fd00::1'] }))).rejects.toThrow(/blocked/);
  });
});

describe('assertNoRebinding', () => {
  it('throws when a new address appears', () => {
    const prior = { host: 'example.com', addresses: ['93.184.216.34'] };
    expect(() => assertNoRebinding(prior, { host: 'example.com', addresses: ['93.184.216.34', '1.2.3.4'] })).toThrow(/rebinding/);
  });

  it('passes when the address set is unchanged', () => {
    const prior = { host: 'example.com', addresses: ['93.184.216.34'] };
    expect(() => assertNoRebinding(prior, { host: 'example.com', addresses: ['93.184.216.34'] })).not.toThrow();
  });
});
