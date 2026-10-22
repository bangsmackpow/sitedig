import { describe, expect, it } from 'vitest';
import { analyzeEmailPosture, lookupEmailPosture } from '../src/worker/email-posture';

function enodata(): never {
  const error = new Error('queryTxt ENODATA') as Error & { code: string };
  error.code = 'ENODATA';
  throw error;
}

function txtMap(records: Record<string, string[][]>) {
  return async (name: string): Promise<string[][]> => {
    if (records[name]) return records[name];
    return enodata();
  };
}

async function lookup(domain: string, records: Record<string, string[][]>) {
  return lookupEmailPosture(domain, {
    resolveTxt: txtMap(records),
    resolveMx: async () => [],
  });
}

describe('email posture DMARC lookup', () => {
  it('keeps standard DMARC records that use a semicolon after the version', async () => {
    const result = await lookup('example.com', {
      '_dmarc.example.com': [['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']],
    });

    expect(result.dmarcRecords).toEqual(['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']);
    expect(analyzeEmailPosture(result).dmarc).toEqual({ present: true, policy: 'reject', hasRua: true });
  });

  it('joins split TXT chunks before parsing DMARC', async () => {
    const result = await lookup('example.com', {
      '_dmarc.example.com': [['v=DMARC1; p=quarantine;', ' rua=mailto:dmarc@example.com']],
    });

    expect(result.dmarcRecords).toEqual(['v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com']);
    expect(analyzeEmailPosture(result).dmarc).toEqual({ present: true, policy: 'quarantine', hasRua: true });
  });

  it('ignores non-DMARC TXT records', async () => {
    const result = await lookup('example.com', {
      '_dmarc.example.com': [['v=spf1 -all'], ['not-a-policy']],
    });

    expect(result.dmarcRecords).toEqual([]);
    expect(analyzeEmailPosture(result).dmarc.present).toBe(false);
  });

  it('falls back to the apex DMARC record when scanning a www host', async () => {
    const result = await lookup('www.example.com', {
      '_dmarc.example.com': [['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']],
    });

    expect(result.dmarcRecords).toEqual(['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']);
    expect(analyzeEmailPosture(result).dmarc.present).toBe(true);
  });

  it('prefers an exact www DMARC record over the apex record', async () => {
    const result = await lookup('www.example.com', {
      '_dmarc.www.example.com': [['v=DMARC1; p=none']],
      '_dmarc.example.com': [['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']],
    });

    expect(result.dmarcRecords).toEqual(['v=DMARC1; p=none']);
    expect(analyzeEmailPosture(result).dmarc.policy).toBe('none');
  });

  it('treats DNS errors as a missing record without failing the lookup', async () => {
    const result = await lookup('example.com', {});

    expect(result.error).toBeNull();
    expect(result.dmarcRecords).toEqual([]);
  });
});
