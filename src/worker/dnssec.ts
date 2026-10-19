import { isIP } from 'node:net';
import type { DnssecResult } from '../shared/types';
import type { DnsResolver } from './dns';
import { safeFetchText } from './safe-fetch';

interface DohAnswer {
  name?: string;
  type?: number;
  data?: string;
}

interface DohResponse {
  Status?: number;
  AD?: boolean;
  Answer?: DohAnswer[];
}

const ALGORITHMS: Record<string, string> = {
  '5': 'RSASHA1',
  '7': 'RSASHA1-NSEC3-SHA1',
  '8': 'RSASHA256',
  '10': 'RSASHA512',
  '13': 'ECDSAP256SHA256',
  '14': 'ECDSAP384SHA384',
  '15': 'ED25519',
  '16': 'ED448',
};

async function query(name: string, type: string, endpoint: string, resolver?: DnsResolver): Promise<DohResponse> {
  const url = new URL(endpoint);
  url.searchParams.set('name', name);
  url.searchParams.set('type', type);
  const res = await safeFetchText(url, {
    accept: 'application/dns-json',
    maxBytes: 256 * 1024,
    timeoutMs: 8_000,
    allowRedirects: false,
    resolver,
  });
  if (res.status < 200 || res.status >= 300) throw new Error(`DoH request failed with HTTP ${res.status}`);
  return JSON.parse(res.body) as DohResponse;
}

export async function dnssecLookup(domain: string, endpoint: string, resolver?: DnsResolver): Promise<DnssecResult> {
  const result: DnssecResult = { signed: false, ad: false, dnskeyCount: 0, dsCount: 0, algorithms: [], error: null };
  if (isIP(domain)) {
    result.error = 'Not applicable to a bare IP target.';
    return result;
  }
  try {
    const [dnskey, ds] = await Promise.all([query(domain, 'DNSKEY', endpoint, resolver), query(domain, 'DS', endpoint, resolver)]);
    if ((dnskey.Status ?? 0) !== 0) {
      result.error = `DoH DNSKEY query returned status ${dnskey.Status}`;
      return result;
    }
    const keys = (dnskey.Answer ?? []).filter((a) => a.type === 48);
    const dsRecords = (ds.Answer ?? []).filter((a) => a.type === 43);
    result.dnskeyCount = keys.length;
    result.dsCount = dsRecords.length;
    result.ad = Boolean(dnskey.AD || ds.AD);
    result.signed = keys.length > 0;
    const algorithms = new Set<string>();
    for (const key of keys) {
      const tokens = (key.data ?? '').trim().split(/\s+/);
      const code = tokens[2];
      if (code && ALGORITHMS[code]) algorithms.add(ALGORITHMS[code]);
      else if (code) algorithms.add(`algorithm-${code}`);
    }
    result.algorithms = [...algorithms];
  } catch (e) {
    result.error = (e as Error).message;
  }
  return result;
}
