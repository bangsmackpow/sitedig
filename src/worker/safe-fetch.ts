import { DEFAULT_USER_AGENT, MAX_HTTP_REDIRECTS } from '../shared/constants';
import { resolveAndValidate, validateRedirect, type DnsResolver } from './dns';

export interface SafeFetchOptions {
  method?: 'GET' | 'HEAD';
  userAgent?: string;
  accept?: string;
  timeoutMs?: number;
  maxBytes?: number;
  maxRedirects?: number;
  allowRedirects?: boolean;
  sameHostOnly?: boolean;
  resolver?: DnsResolver;
  signal?: AbortSignal;
}

export interface SafeFetchResult {
  status: number;
  finalUrl: string;
  headers: Record<string, string>;
  setCookies: string[];
  body: string;
  truncated: boolean;
}

const DEFAULT_TIMEOUT_MS = 12_000;
const DEFAULT_MAX_BYTES = 512 * 1024;

function collectHeaders(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

function collectSetCookies(headers: Headers): string[] {
  const getSetCookie = (headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
  if (typeof getSetCookie === 'function') return getSetCookie.call(headers);
  const raw = headers.get('set-cookie');
  if (!raw) return [];
  return raw.split(/,(?=[^;]+?=)/g).map((s) => s.trim()).filter(Boolean);
}

async function readBody(res: Response, maxBytes: number): Promise<{ body: string; truncated: boolean }> {
  if (!res.body) return { body: '', truncated: false };
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    if (total + value.byteLength > maxBytes) {
      const remaining = Math.max(0, maxBytes - total);
      if (remaining > 0) chunks.push(value.slice(0, remaining));
      total += remaining;
      truncated = true;
      await reader.cancel().catch(() => undefined);
      break;
    }
    chunks.push(value);
    total += value.byteLength;
  }
  return { body: Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8'), truncated };
}

/**
 * Fetch a URL with the same target-safety guarantees as the scanner checks:
 * every hop is resolved and validated against blocked ranges, redirects are
 * capped, and response size/time are bounded.
 */
export async function safeFetchText(url: URL, opts: SafeFetchOptions = {}): Promise<SafeFetchResult> {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`Unsupported URL protocol: ${url.protocol}`);
  }
  const resolver = opts.resolver;
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxRedirects = opts.maxRedirects ?? MAX_HTTP_REDIRECTS;
  const allowRedirects = opts.allowRedirects ?? true;
  const sameHostOnly = opts.sameHostOnly ?? false;
  const initialHost = url.hostname.toLowerCase();
  let current = url;

  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    if (hop > 0 && sameHostOnly && current.hostname.toLowerCase() !== initialHost) {
      throw new Error(`Blocked cross-host redirect to ${current.hostname}`);
    }
    await resolveAndValidate(current.hostname, resolver);

    if (opts.signal?.aborted) throw new Error('Request was cancelled.');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error('Request timed out.')), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    timer.unref?.();
    const onAbort = () => controller.abort(opts.signal?.reason);
    opts.signal?.addEventListener('abort', onAbort, { once: true });

    try {
      const res = await fetch(current, {
        method: opts.method ?? 'GET',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'user-agent': opts.userAgent ?? DEFAULT_USER_AGENT,
          accept: opts.accept ?? '*/*',
        },
      });

      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get('location');
        res.body?.cancel().catch(() => undefined);
        if (!location || !allowRedirects) {
          return {
            status: res.status,
            finalUrl: current.toString(),
            headers: collectHeaders(res.headers),
            setCookies: collectSetCookies(res.headers),
            body: '',
            truncated: false,
          };
        }
        let next: URL;
        try {
          next = new URL(location, current);
        } catch {
          throw new Error(`Invalid redirect location: ${location}`);
        }
        await validateRedirect(next, resolver);
        current = next;
        continue;
      }

      const { body, truncated } = opts.method === 'HEAD' ? { body: '', truncated: false } : await readBody(res, maxBytes);
      return {
        status: res.status,
        finalUrl: current.toString(),
        headers: collectHeaders(res.headers),
        setCookies: collectSetCookies(res.headers),
        body,
        truncated,
      };
    } finally {
      opts.signal?.removeEventListener('abort', onAbort);
      clearTimeout(timer);
    }
  }

  throw new Error(`Too many redirects (limit ${maxRedirects})`);
}

