import { promises as dnsPromises } from 'node:dns';
import { isIP } from 'node:net';
import { blockedAddressReason, isBlockedAddress } from '../shared/net';

export interface DnsResolver {
  resolve(host: string): Promise<string[]>;
}

export const defaultResolver: DnsResolver = {
  async resolve(host: string): Promise<string[]> {
    const addresses: string[] = [];
    if (isIP(host)) {
      return [host];
    }
    try {
      const a = await dnsPromises.resolve4(host);
      addresses.push(...a);
    } catch {
      // no A records
    }
    try {
      const aaaa = await dnsPromises.resolve6(host);
      addresses.push(...aaaa);
    } catch {
      // no AAAA records
    }
    return addresses;
  },
};

export interface ResolveResult {
  host: string;
  addresses: string[];
}

/**
 * Resolve a host and validate that every resulting address is a public,
 * global unicast address. Throws if the hostname cannot be resolved or any
 * address is private/reserved.
 */
export async function resolveAndValidate(
  host: string,
  resolver: DnsResolver = defaultResolver,
): Promise<ResolveResult> {
  const addresses = await resolver.resolve(host);
  if (addresses.length === 0) {
    throw new Error(`Could not resolve host: ${host}`);
  }
  for (const addr of addresses) {
    const reason = blockedAddressReason(addr);
    if (reason) {
      throw new Error(`Target ${host} resolves to a blocked address (${addr}): ${reason}`);
    }
  }
  return { host, addresses };
}

/**
 * Detect DNS rebinding: the set of addresses a host currently resolves to must
 * all be within the previously validated set for the same job.
 */
export function assertNoRebinding(previous: ResolveResult, current: ResolveResult): void {
  const prevSet = new Set(previous.addresses);
  for (const addr of current.addresses) {
    if (!prevSet.has(addr)) {
      throw new Error(`DNS rebinding detected for ${current.host}: address ${addr} was not in the validated set.`);
    }
  }
}

/**
 * Parse a redirect Location header value into an absolute URL if possible.
 */
export function resolveRedirectLocation(location: string, base: URL): URL | null {
  try {
    return new URL(location, base);
  } catch {
    return null;
  }
}

/**
 * Validate that a redirect destination is safe: resolvable to public
 * addresses only. Returns the resolved host/addresses or throws.
 */
export async function validateRedirect(
  redirectUrl: URL,
  resolver: DnsResolver = defaultResolver,
): Promise<ResolveResult> {
  if (redirectUrl.protocol !== 'http:' && redirectUrl.protocol !== 'https:') {
    throw new Error(`Redirect to unsupported protocol: ${redirectUrl.protocol}`);
  }
  return resolveAndValidate(redirectUrl.hostname, resolver);
}

export function assertAddressPublic(ip: string): void {
  if (isBlockedAddress(ip)) {
    throw new Error(`Address is blocked: ${ip}`);
  }
}
