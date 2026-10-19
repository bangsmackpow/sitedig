import type { NormalizedTarget, SecurityTxtResult } from '../shared/types';
import { formatHostForUrl } from '../shared/net';
import type { DnsResolver } from './dns';
import { safeFetchText } from './safe-fetch';

export interface SecurityTxtDeps {
  resolver?: DnsResolver;
  userAgent?: string;
  signal?: AbortSignal;
  fetchText?: typeof safeFetchText;
}

function fieldValues(text: string, field: string): string[] {
  const re = new RegExp(`^${field}\\s*:\\s*(.+)$`, 'gim');
  const out: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) out.push(match[1].trim());
  return out;
}

export async function securityTxtLookup(target: NormalizedTarget, deps: SecurityTxtDeps = {}): Promise<SecurityTxtResult> {
  const fetchText = deps.fetchText ?? safeFetchText;
  const base = new URL(`${target.scheme}://${formatHostForUrl(target.host)}/`);
  const result: SecurityTxtResult = {
    found: false,
    url: null,
    status: null,
    contacts: [],
    expires: null,
    policy: null,
    encryption: null,
    acknowledgments: null,
    preferredLanguages: null,
    error: null,
  };

  for (const path of ['/.well-known/security.txt', '/security.txt']) {
    const url = new URL(path, base);
    try {
      const res = await fetchText(url, {
        resolver: deps.resolver,
        userAgent: deps.userAgent,
        signal: deps.signal,
        sameHostOnly: true,
        maxBytes: 128 * 1024,
        timeoutMs: 8_000,
        accept: 'text/plain,*/*',
      });
      result.url = url.toString();
      result.status = res.status;
      if (res.status < 200 || res.status >= 300) continue;
      result.found = true;
      result.error = null;
      result.contacts = fieldValues(res.body, 'Contact').slice(0, 20);
      result.expires = fieldValues(res.body, 'Expires')[0] ?? null;
      result.policy = fieldValues(res.body, 'Policy')[0] ?? null;
      result.encryption = fieldValues(res.body, 'Encryption')[0] ?? null;
      result.acknowledgments = fieldValues(res.body, 'Acknowledgments')[0] ?? null;
      result.preferredLanguages = fieldValues(res.body, 'Preferred-Languages')[0] ?? null;
      break;
    } catch (e) {
      result.error = (e as Error).message;
    }
  }
  return result;
}
