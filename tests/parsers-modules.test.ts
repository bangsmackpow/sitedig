import { describe, expect, it } from 'vitest';
import {
  parseDnsxJson,
  parseFeroxJson,
  parseNucleiJsonl,
  parseRetireJson,
  parseSubfinderJson,
  parseTestsslJson,
} from '../src/worker/parsers';

describe('parseSubfinderJson', () => {
  it('parses JSONL subdomains', () => {
    const raw = [
      JSON.stringify({ host: 'api.example.com', source: 'crt.sh' }),
      JSON.stringify({ host: 'www.example.com', source: 'certspotter' }),
      JSON.stringify({ host: 'api.example.com', source: 'crtsh' }),
    ].join('\n');
    const out = parseSubfinderJson(raw);
    expect(out).toHaveLength(2);
    expect(out[0].host).toBe('api.example.com');
  });
});

describe('parseDnsxJson', () => {
  it('parses JSONL DNS records and skips errors', () => {
    const raw = [
      JSON.stringify({ host: 'example.com', type: 'A', value: '1.2.3.4' }),
      JSON.stringify({ host: 'example.com', type: 'NS', value: 'ns1.example.com' }),
      JSON.stringify({ host: 'example.com', type: 'A', error: 'nxdomain' }),
    ].join('\n');
    const out = parseDnsxJson(raw);
    expect(out).toHaveLength(2);
    expect(out[0]).toEqual({ type: 'A', name: 'example.com', value: '1.2.3.4' });
  });
});

describe('parseNucleiJsonl', () => {
  it('parses nuclei findings and filters matcher-status false', () => {
    const raw = [
      JSON.stringify({ 'template-id': 't1', info: { name: 'Thing', severity: 'high', description: 'desc' }, 'matched-at': 'https://x/', 'matcher-status': true }),
      JSON.stringify({ 'template-id': 't2', info: { name: 'NoMatch', severity: 'low' }, 'matched-at': 'https://x/', 'matcher-status': false }),
    ].join('\n');
    const out = parseNucleiJsonl(raw);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe('high');
    expect(out[0].source).toBe('nuclei');
  });

  it('deduplicates repeated template results', () => {
    const raw = [
      JSON.stringify({ 'template-id': 'ssl/weak', info: { name: 'Weak Cipher', severity: 'low' }, 'matched-at': 'example.com:443', 'matcher-status': true }),
      JSON.stringify({ 'template-id': 'ssl/weak', info: { name: 'Weak Cipher', severity: 'low' }, 'matched-at': 'example.com:443', 'matcher-status': true }),
      JSON.stringify({ 'template-id': 'ssl/weak', info: { name: 'Weak Cipher', severity: 'low' }, 'matched-at': 'example.com:8443', 'matcher-status': true }),
    ].join('\n');
    const out = parseNucleiJsonl(raw);
    expect(out).toHaveLength(2);
  });
});

describe('parseRetireJson', () => {
  it('parses retire.js results into vulnerability findings', () => {
    const raw = JSON.stringify({
      results: [
        {
          component: 'jquery',
          version: '2.2.4',
          vulnerabilities: [{ identifiers: { CVE: ['CVE-2015-9251'], summary: 'XSS' }, severity: 'medium' }],
        },
      ],
    });
    const out = parseRetireJson(raw);
    expect(out).toHaveLength(1);
    expect(out[0].title).toContain('jquery');
    expect(out[0].source).toBe('retire');
  });
});

describe('parseTestsslJson', () => {
  it('extracts weaknesses from testssl JSON', () => {
    const raw = JSON.stringify([
      { id: 'SSLv2', severity: 'CRITICAL', finding: 'SSLv2 is offered', vuln: true },
      { id: 'TLS1', severity: 'HIGH', finding: 'TLS 1.0 offered', vuln: true },
      { id: 'cipher', severity: 'OK', finding: 'nothing', vuln: false },
    ]);
    const out = parseTestsslJson(raw);
    expect(out.finished).toBe(true);
    expect(out.weaknesses.length).toBe(2);
    expect(out.weaknesses[0].severity).toBe('CRITICAL');
  });

  it('deduplicates repeated weaknesses', () => {
    const raw = JSON.stringify([
      { id: 'BREACH', severity: 'MEDIUM', finding: 'BREACH vulnerable', vuln: true },
      { id: 'BREACH', severity: 'MEDIUM', finding: 'BREACH vulnerable', vuln: true },
      { id: 'overall_grade', severity: 'MEDIUM', finding: 'B', vuln: true },
    ]);
    const out = parseTestsslJson(raw);
    expect(out.weaknesses.length).toBe(2);
  });
});

describe('parseFeroxJson', () => {
  it('parses feroxbuster JSONL paths and filters wildcard', () => {
    const raw = [
      JSON.stringify({ url: 'https://example.com/admin', status: 200, content_length: 512, content_type: 'text/html' }),
      JSON.stringify({ url: 'https://example.com/wc', status: 200, wildcard: true }),
    ].join('\n');
    const out = parseFeroxJson(raw);
    expect(out).toHaveLength(1);
    expect(out[0].path).toBe('/admin');
  });

  it('filters empty or invalid rows', () => {
    const raw = [
      JSON.stringify({ url: '', status: 0 }),
      JSON.stringify({ url: 'not a url', status: 200 }),
      JSON.stringify({ url: 'https://example.com/ok', status: 200 }),
    ].join('\n');
    const out = parseFeroxJson(raw);
    expect(out).toHaveLength(1);
    expect(out[0].path).toBe('/ok');
  });
});
