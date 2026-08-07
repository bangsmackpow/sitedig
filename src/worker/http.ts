import { connect as tlsConnect, type TLSSocket } from 'node:tls';
import { isIP } from 'node:net';
import {
  DEFAULT_USER_AGENT,
  HTTP_CHECK_TIMEOUT_MS,
  MAX_HTTP_REDIRECTS,
  SECURITY_HEADERS,
  TLS_CHECK_TIMEOUT_MS,
} from '../shared/constants';
import { formatHostForUrl } from '../shared/net';
import type { HttpObservation, NormalizedTarget, TlsObservation } from '../shared/types';
import { resolveAndValidate, resolveRedirectLocation, validateRedirect, type DnsResolver } from './dns';

export interface HttpCheckDeps {
  userAgent?: string;
  followRedirects: boolean;
  resolver?: DnsResolver;
}

const HEADER_KEYS = ['server', 'x-powered-by', ...SECURITY_HEADERS];

export async function httpCheck(target: NormalizedTarget, deps: HttpCheckDeps): Promise<HttpObservation> {
  const userAgent = deps.userAgent || DEFAULT_USER_AGENT;
  const redirects: Array<{ status: number; to: string }> = [];
  const baseUrl = `${target.scheme}://${formatHostForUrl(target.host)}${target.path}`;

  let attemptScheme: 'http' | 'https' = target.scheme;
  let currentUrl = new URL(baseUrl);
  let error: string | null = null;
  let finalStatus: number | null = null;
  let finalHeaders: Record<string, string> = {};
  let finalUrl: string | null = null;

  for (let attempt = 0; attempt < 2; attempt++) {
    if (attempt > 0 && attemptScheme !== 'http') {
      attemptScheme = 'http';
      currentUrl = new URL(`${attemptScheme}://${formatHostForUrl(target.host)}${target.path}`);
    }

    try {
      let hops = 0;
      for (;;) {
        const res = await fetch(currentUrl, {
          redirect: 'manual',
          signal: AbortSignal.timeout(HTTP_CHECK_TIMEOUT_MS),
          headers: { 'user-agent': userAgent, accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' },
        });

        if (res.status >= 300 && res.status < 400) {
          const location = res.headers.get('location');
          if (!location) {
            finalStatus = res.status;
            finalHeaders = collectHeaders(res.headers);
            finalUrl = currentUrl.toString();
            res.body?.cancel();
            break;
          }
          if (!deps.followRedirects) {
            finalStatus = res.status;
            finalHeaders = collectHeaders(res.headers);
            finalUrl = currentUrl.toString();
            res.body?.cancel();
            break;
          }
          if (hops >= MAX_HTTP_REDIRECTS) {
            error = `Too many redirects (limit ${MAX_HTTP_REDIRECTS})`;
            res.body?.cancel();
            break;
          }
          const next = resolveRedirectLocation(location, currentUrl);
          if (!next) {
            error = `Invalid redirect Location: ${location}`;
            res.body?.cancel();
            break;
          }
          // Validate the redirect destination before following it.
          try {
            await validateRedirect(next, deps.resolver);
          } catch (e) {
            error = `Blocked redirect to ${next.hostname}: ${(e as Error).message}`;
            res.body?.cancel();
            break;
          }
          redirects.push({ status: res.status, to: next.toString() });
          hops += 1;
          currentUrl = next;
          res.body?.cancel();
          continue;
        }

        finalStatus = res.status;
        finalHeaders = collectHeaders(res.headers);
        finalUrl = currentUrl.toString();
        res.body?.cancel();
        break;
      }
      break; // success path
    } catch (e) {
      error = (e as Error).message;
      if (attemptScheme === 'https' && attempt === 0) {
        continue; // try http fallback
      }
      break;
    }
  }

  return {
    status: finalStatus,
    finalUrl,
    server: finalHeaders['server'] ?? null,
    poweredBy: finalHeaders['x-powered-by'] ?? null,
    headers: finalHeaders,
    redirects,
    error,
  };
}

function collectHeaders(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  for (const key of HEADER_KEYS) {
    const value = headers.get(key);
    if (value) out[key] = value;
  }
  return out;
}

export async function tlsCheck(target: NormalizedTarget): Promise<TlsObservation> {
  const port = 443;
  return new Promise<TlsObservation>((resolvePromise) => {
    const servername = isIP(target.host) ? undefined : target.host;
    const socket: TLSSocket = tlsConnect({
      host: target.host,
      port,
      servername,
      rejectUnauthorized: false,
      timeout: TLS_CHECK_TIMEOUT_MS,
    });

    let settled = false;
    const finish = (value: TlsObservation) => {
      if (!settled) {
        settled = true;
        resolvePromise(value);
      }
    };

    socket.once('secureConnect', () => {
      try {
        const cert = socket.getPeerCertificate(true) as {
          subject?: { CN?: string };
          issuer?: { CN?: string };
          valid_from?: string;
          valid_to?: string;
        };
        const protocol = socket.getProtocol() ?? null;
        const daysRemaining = cert.valid_to ? Math.floor((Date.parse(cert.valid_to) - Date.now()) / 86_400_000) : null;
        const subjectCn = cert.subject?.CN ?? null;
        const issuerCn = cert.issuer?.CN ?? null;
        socket.end();
        finish({
          connected: true,
          protocol,
          subjectCn,
          issuerCn,
          validFrom: cert.valid_from ?? null,
          validTo: cert.valid_to ?? null,
          daysRemaining,
          selfSigned: Boolean(subjectCn && issuerCn && subjectCn === issuerCn),
          error: null,
        });
      } catch (e) {
        socket.destroy();
        finish({ connected: false, protocol: null, subjectCn: null, issuerCn: null, validFrom: null, validTo: null, daysRemaining: null, selfSigned: false, error: (e as Error).message });
      }
    });

    socket.once('error', (e) => {
      finish({ connected: false, protocol: null, subjectCn: null, issuerCn: null, validFrom: null, validTo: null, daysRemaining: null, selfSigned: false, error: e.message });
    });

    socket.once('timeout', () => {
      socket.destroy();
      finish({ connected: false, protocol: null, subjectCn: null, issuerCn: null, validFrom: null, validTo: null, daysRemaining: null, selfSigned: false, error: 'TLS handshake timed out' });
    });
  });
}
