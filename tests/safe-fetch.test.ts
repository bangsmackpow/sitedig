import { afterEach, describe, expect, it, vi } from 'vitest';
import { safeFetchText } from '../src/worker/safe-fetch';
import type { DnsResolver } from '../src/worker/dns';

const resolver: DnsResolver = {
  resolve: async (host) => (host === '169.254.169.254' ? ['169.254.169.254'] : ['93.184.216.34']),
};

describe('safeFetchText', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('caps response body size', async () => {
    vi.stubGlobal('fetch', async () => new Response('abcdefghij', { status: 200 }));
    const res = await safeFetchText(new URL('https://example.com/'), { resolver, maxBytes: 5 });
    expect(res.body).toBe('abcde');
    expect(res.truncated).toBe(true);
  });

  it('rejects redirects to blocked addresses', async () => {
    vi.stubGlobal(
      'fetch',
      async () => new Response(null, { status: 302, headers: { location: 'http://169.254.169.254/latest/meta-data/' } }),
    );
    await expect(safeFetchText(new URL('https://example.com/'), { resolver })).rejects.toThrow(/blocked/i);
  });

  it('rejects cross-host redirects when sameHostOnly is set', async () => {
    vi.stubGlobal('fetch', async () => new Response(null, { status: 302, headers: { location: 'https://other.example.net/' } }));
    await expect(safeFetchText(new URL('https://example.com/'), { resolver, sameHostOnly: true })).rejects.toThrow(/cross-host/i);
  });
});
