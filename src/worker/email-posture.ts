import { promises as dnsPromises } from 'node:dns';
import net from 'node:net';
import type { EmailPostureResult } from '../shared/types';
import { defaultResolver, resolveAndValidate } from './dns';

export interface EmailPostureDeps {
  resolveTxt?: (hostname: string) => Promise<string[][]>;
  resolveMx?: (hostname: string) => Promise<Array<{ exchange: string; priority: number }>>;
  /** STARTTLS probe over port 25; injectable for tests. */
  probeStarttls?: (mxHost: string, ehloDomain: string, timeoutMs: number) => Promise<{ supported: boolean; banner: string }>;
}

const TXT_TIMEOUT_MS = 8_000;
const STARTTLS_PROBE_MS = 8_000;

async function txtRecords(name: string, resolveTxt: (hostname: string) => Promise<string[][]>): Promise<string[]> {
  try {
    const records = await resolveTxt(name);
    return records.map((chunks) => chunks.join('').trim()).filter(Boolean);
  } catch {
    return [];
  }
}

function parseDmarcPolicy(records: string[]): { policy: string | null; hasRua: boolean } {
  for (const record of records) {
    const p = record.match(/\bp\s*=\s*(none|quarantine|reject)\b/i)?.[1]?.toLowerCase();
    if (p) return { policy: p, hasRua: /\brua\s*=/i.test(record) };
  }
  return { policy: null, hasRua: false };
}

/**
 * Minimal SMTP EHLO/STARTTLS probe (non-transactional: EHLO then immediate
 * disconnect — no mail is ever sent).
 */
export async function defaultProbeStarttls(mxHost: string, ehloDomain: string, timeoutMs: number): Promise<{ supported: boolean; banner: string }> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: mxHost, port: 25 });
    let buffer = '';
    let stage = 0; // 0 = awaiting greeting, 1 = awaiting EHLO reply
    let settled = false;
    const done = () => {
      if (settled) return false;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      return true;
    };
    const timer = setTimeout(() => {
      if (done()) reject(new Error('STARTTLS probe timed out.'));
    }, timeoutMs);
    timer.unref?.();
    socket.setEncoding('utf8');
    socket.on('error', (e) => {
      if (done()) reject(e);
    });
    socket.on('data', (chunk: string) => {
      buffer += chunk;
      const lines = buffer.split('\r\n');
      if (stage === 0 && lines.some((l) => /^220 /.test(l))) {
        stage = 1;
        buffer = '';
        socket.write(`EHLO ${ehloDomain}\r\n`);
      } else if (stage === 1) {
        const last = lines[lines.length - 2]; // previous element is the last complete line
        if (last !== undefined && /^(250|4\d\d|5\d\d) /.test(last)) {
          const supported = stage === 1 && /\bSTARTTLS\b/i.test(buffer);
          if (done()) resolve({ supported, banner: buffer.split('\r\n')[0] ?? '' });
        }
      }
    });
  });
}

/**
 * Email & DNS security posture for a domain: SPF, DMARC, MTA-STS, TLS-RPT,
 * MX, and a STARTTLS capability probe of the primary MX. All queries are
 * public DNS lookups plus (at most) one EHLO to the customer's own mail server.
 */
export async function lookupEmailPosture(domain: string, deps: EmailPostureDeps = {}): Promise<EmailPostureResult> {
  const resolveTxt = deps.resolveTxt ?? ((name: string) => dnsPromises.resolveTxt(name));
  const resolveMx = deps.resolveMx ?? ((name: string) => dnsPromises.resolveMx(name));

  const result: EmailPostureResult = {
    domain,
    spfRecords: [],
    dmarcRecords: [],
    mx: [],
    mtaSts: null,
    tlsRpt: null,
    starttls: { checked: false, mx: null, supported: null, error: null },
    error: null,
  };

  try {
    const [spfAll, dmarcAll, stsAll, rptAll, mxRecords] = await Promise.all([
      txtRecords(domain, resolveTxt),
      txtRecords(`_dmarc.${domain}`, resolveTxt),
      txtRecords(`_mta-sts.${domain}`, resolveTxt),
      txtRecords(`_smtp._tls.${domain}`, resolveTxt),
      resolveMx(domain).catch(() => [] as Array<{ exchange: string; priority: number }>),
    ]);

    result.spfRecords = spfAll.filter((r) => /^v=spf1(\s|$)/i.test(r));
    result.dmarcRecords = dmarcAll.filter((r) => /^v=DMARC1(\s|$)/i.test(r));
    result.mtaSts = stsAll.find((r) => /^v=STSv1/i.test(r)) ?? null;
    result.tlsRpt = rptAll.find((r) => /^v=TLSRPTv1/i.test(r)) ?? null;
    result.mx = mxRecords
      .map((m) => ({ host: m.exchange.replace(/\.$/, ''), priority: m.priority }))
      .sort((a, b) => a.priority - b.priority)
      .slice(0, 10);
  } catch (e) {
    result.error = (e as Error).message;
    return result;
  }

  if (result.mx.length > 0) {
    const primary = result.mx[0];
    result.starttls.mx = primary.host;
    try {
      // Never probe a mail host that resolves to internal addresses.
      await resolveAndValidate(primary.host, defaultResolver);
      const probe = deps.probeStarttls ?? defaultProbeStarttls;
      const { supported } = await probe(primary.host, domain, STARTTLS_PROBE_MS);
      result.starttls.checked = true;
      result.starttls.supported = supported;
    } catch (e) {
      result.starttls.error = (e as Error).message;
    }
  }

  return result;
}

/** Derived email-posture checks shared by the findings builder. */
export function analyzeEmailPosture(p: EmailPostureResult): {
  spfCount: number;
  spfPermissive: boolean;
  dmarc: { policy: string | null; hasRua: boolean; present: boolean };
} {
  const joined = p.spfRecords.join(' ');
  return {
    spfCount: p.spfRecords.length,
    spfPermissive: /(^|\s)\+(all|\?all)/i.test(joined) || /(^|\s)all$/i.test(joined),
    dmarc: { ...parseDmarcPolicy(p.dmarcRecords), present: p.dmarcRecords.length > 0 },
  };
}

export { TXT_TIMEOUT_MS };
