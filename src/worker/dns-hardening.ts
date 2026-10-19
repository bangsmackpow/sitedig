import { promises as dnsPromises } from 'node:dns';
import { isIP } from 'node:net';
import type { DnsHardeningResult } from '../shared/types';

const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail', 'dkim', 's1', 's2', 'smtp', 'mandrill', 'amazonses'];
const SRV_QUERIES = ['_sip._tcp', '_xmpp-client._tcp', '_autodiscover._tcp'];

async function txt(name: string): Promise<string[]> {
  try {
    const records = await dnsPromises.resolveTxt(name);
    return records.map((parts) => parts.join('')).filter(Boolean);
  } catch {
    return [];
  }
}

function parseTags(record: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of record.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    out[part.slice(0, index).trim().toLowerCase()] = part.slice(index + 1).trim();
  }
  return out;
}

export async function dnsHardeningLookup(domain: string): Promise<DnsHardeningResult> {
  const result: DnsHardeningResult = {
    domain,
    caa: [],
    soa: null,
    srv: [],
    nsAddresses: [],
    dkim: [],
    bimi: null,
    dmarc: null,
    error: null,
  };
  if (isIP(domain)) {
    result.error = 'Not applicable to a bare IP target.';
    return result;
  }

  const [caa, soa, ns, dmarcTxt, bimiTxt] = await Promise.all([
    dnsPromises.resolveCaa(domain).catch(() => []),
    dnsPromises.resolveSoa(domain).catch(() => null),
    dnsPromises.resolveNs(domain).catch(() => [] as string[]),
    txt(`_dmarc.${domain}`),
    txt(`default._bimi.${domain}`),
  ]);

  result.caa = caa.flatMap((rec) => {
    const out: Array<{ flags: number; tag: string; value: string }> = [];
    if (rec.issue) out.push({ flags: rec.critical, tag: 'issue', value: rec.issue });
    if (rec.issuewild) out.push({ flags: rec.critical, tag: 'issuewild', value: rec.issuewild });
    if (rec.iodef) out.push({ flags: rec.critical, tag: 'iodef', value: rec.iodef });
    return out;
  });

  if (soa) {
    result.soa = {
      ns: soa.nsname,
      hostmaster: soa.hostmaster,
      serial: soa.serial,
      refresh: soa.refresh,
      retry: soa.retry,
      expire: soa.expire,
      minimum: soa.minttl,
    };
  }

  const srvResults = await Promise.all(
    SRV_QUERIES.map(async (name) => {
      try {
        const records = await dnsPromises.resolveSrv(`${name}.${domain}`);
        return records.map((r) => ({ name, port: r.port, priority: r.priority, weight: r.weight, target: r.name }));
      } catch {
        return [];
      }
    }),
  );
  result.srv = srvResults.flat().slice(0, 25);

  const nsAddresses = await Promise.all(
    ns.slice(0, 5).map(async (server) => {
      const addresses: string[] = [];
      try {
        addresses.push(...(await dnsPromises.resolve4(server)));
      } catch {
        // no A record
      }
      try {
        addresses.push(...(await dnsPromises.resolve6(server)));
      } catch {
        // no AAAA record
      }
      return { ns: server, addresses: addresses.slice(0, 5) };
    }),
  );
  result.nsAddresses = nsAddresses;

  const dmarcRecord = dmarcTxt.find((record) => /^v=DMARC1\b/i.test(record.trim()));
  if (dmarcRecord) {
    const tags = parseTags(dmarcRecord);
    result.dmarc = {
      present: true,
      policy: tags.p ?? null,
      subdomainPolicy: tags.sp ?? null,
      pct: tags.pct !== undefined && Number.isFinite(Number(tags.pct)) ? Number(tags.pct) : null,
      rua: tags.rua ? tags.rua.split(',').map((s) => s.trim()).filter(Boolean) : [],
      ruf: tags.ruf ? tags.ruf.split(',').map((s) => s.trim()).filter(Boolean) : [],
      alignmentDkim: tags.adkim ?? null,
      alignmentSpf: tags.aspf ?? null,
    };
  }

  result.bimi = bimiTxt.find((record) => /^v=BIMI1\b/i.test(record.trim())) ?? null;

  const dkim = await Promise.all(
    DKIM_SELECTORS.map(async (selector) => {
      const records = await txt(`${selector}._domainkey.${domain}`);
      const record = records.find((r) => /v=DKIM1|(^|;)\s*p=/i.test(r));
      if (!record) return { selector, found: false, keyType: null, revoked: false };
      const tags = parseTags(record);
      return {
        selector,
        found: true,
        keyType: tags.k ?? 'rsa',
        revoked: tags.p === '',
      };
    }),
  );
  result.dkim = dkim;

  return result;
}
