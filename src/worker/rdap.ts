import type { WhoisInfo } from '../shared/types';

const RDAP_BOOTSTRAP = 'https://rdap.org/domain/';
const TIMEOUT_MS = 15_000;

/**
 * WHOIS/registration lookup via the RDAP HTTP protocol (JSON, no binary).
 * rdap.org redirects to the authoritative registrar RDAP server.
 */
export async function rdapLookup(host: string): Promise<WhoisInfo> {
  try {
    const res = await fetch(`${RDAP_BOOTSTRAP}${encodeURIComponent(host)}`, {
      redirect: 'follow',
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { accept: 'application/rdap+json, application/json' },
    });
    if (!res.ok) {
      return { registrar: null, creationDate: null, updateDate: null, expiryDate: null, status: [], nameservers: [], error: `RDAP lookup failed with HTTP ${res.status}` };
    }
    const data = (await res.json()) as Record<string, unknown>;

    const registrar = extractRegistrar(data.entities);
    const nameservers = Array.isArray(data.nameservers)
      ? (data.nameservers as Array<{ ldhName?: unknown }>).map((n) => String(n.ldhName ?? '')).filter(Boolean)
      : [];
    const status = Array.isArray(data.status) ? data.status.map(String) : [];
    const dates = extractDates(data.events);

    return {
      registrar,
      creationDate: dates.registration,
      updateDate: dates.changed,
      expiryDate: dates.expiration,
      status,
      nameservers,
      error: null,
    };
  } catch (e) {
    return { registrar: null, creationDate: null, updateDate: null, expiryDate: null, status: [], nameservers: [], error: (e as Error).message };
  }
}

type VCard = Array<[string, unknown, unknown, string]>;

function extractRegistrar(entities: unknown): string | null {
  if (!Array.isArray(entities)) return null;
  for (const entity of entities as Array<Record<string, unknown>>) {
    const roles = entity.roles as unknown[] | undefined;
    if (roles?.includes('registrar')) {
      const vcard = entity.vcard as VCard | undefined;
      if (Array.isArray(vcard)) {
        for (const entry of vcard) {
          const type = Array.isArray(entry) && typeof entry[0] === 'string' ? entry[0].toLowerCase() : '';
          if (type === 'fn' && entry[3]) return entry[3];
        }
      }
    }
  }
  return null;
}

function extractDates(events: unknown): { registration: string | null; changed: string | null; expiration: string | null } {
  const out = { registration: null as string | null, changed: null as string | null, expiration: null as string | null };
  if (!Array.isArray(events)) return out;
  for (const ev of events as Array<{ eventAction?: unknown; eventDate?: unknown }>) {
    const action = String(ev.eventAction ?? '');
    const date = typeof ev.eventDate === 'string' ? ev.eventDate : null;
    if (!date) continue;
    if (action === 'registration') out.registration = date;
    else if (action === 'last changed') out.changed = date;
    else if (action === 'expiration') out.expiration = date;
  }
  return out;
}
