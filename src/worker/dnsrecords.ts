import { promises as dns } from 'node:dns';
import type { DnsRecord } from '../shared/types';

const QUERY_TIMEOUT_MS = 4000;

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('DNS query timed out')), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}

/**
 * In-process DNS record enumeration. Uses the container's system resolver
 * (which demonstrably works, unlike the `dnsx` binary in this environment),
 * with a bounded timeout per query type.
 */
export async function dnsRecordLookup(host: string): Promise<DnsRecord[]> {
  const records: DnsRecord[] = [];
  const queries: Array<{ type: string; run: () => Promise<unknown> }> = [
    { type: 'A', run: () => dns.resolve4(host) },
    { type: 'AAAA', run: () => dns.resolve6(host) },
    { type: 'CNAME', run: () => dns.resolveCname(host) },
    { type: 'MX', run: () => dns.resolveMx(host) },
    { type: 'NS', run: () => dns.resolveNs(host) },
    { type: 'TXT', run: () => dns.resolveTxt(host) },
  ];

  for (const query of queries) {
    try {
      const result = (await withTimeout(query.run(), QUERY_TIMEOUT_MS)) as unknown[];
      for (const item of result) {
        if (query.type === 'MX') {
          const mx = item as { exchange?: string; priority?: number };
          if (mx.exchange) records.push({ type: 'MX', name: host, value: `${mx.priority ?? 0} ${mx.exchange}` });
        } else if (query.type === 'TXT') {
          records.push({ type: 'TXT', name: host, value: (item as string[]).join('') });
        } else {
          records.push({ type: query.type, name: host, value: String(item) });
        }
      }
    } catch {
      // no records of this type, or timeout — skip
    }
  }
  return records;
}
