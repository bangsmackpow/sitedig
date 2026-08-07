import { describe, expect, it } from 'vitest';
import { assertApprovedArgs, expandProfile } from '../src/shared/profiles';
import { parseTarget } from '../src/shared/targets';
import type { CustomScanOptions } from '../src/shared/types';

const target = parseTarget('https://example.com/shop');
const paths = { outputPath: (name: string) => `/tmp/out/${name}` };

describe('expandProfile', () => {
  it('quick uses common ports and all default tools', () => {
    const plan = expandProfile('quick', target, null, paths);
    expect(plan.portScope).toBe('common');
    const tools = plan.steps.map((s) => s.tool);
    expect(tools).toContain('nmap');
    expect(tools).toContain('whatweb');
    expect(tools).toContain('http');
    expect(tools).toContain('tls');
    expect(tools).not.toContain('wpscan'); // conditional at runtime
  });

  it('standard uses top 100, deep uses top 1000', () => {
    expect(expandProfile('standard', target, null, paths).portScope).toBe('top100');
    expect(expandProfile('deep', target, null, paths).portScope).toBe('top1000');
  });

  it('preserves path for web checks and hostname for nmap', () => {
    const plan = expandProfile('standard', target, null, paths);
    const whatweb = plan.steps.find((s) => s.tool === 'whatweb');
    const nmap = plan.steps.find((s) => s.tool === 'nmap');
    expect(whatweb?.args).toContain('https://example.com/shop');
    expect(nmap?.args).toContain('example.com');
  });

  it('custom respects enabled tools, port scope, path, user-agent', () => {
    const custom: CustomScanOptions = {
      portScope: 'top1000',
      enabledTools: ['nmap', 'http'],
      path: '/custom',
      followRedirects: false,
      userAgent: 'CustomUA/1.0 (Test)',
      timeoutMs: 180_000,
    };
    const plan = expandProfile('custom', target, custom, paths);
    expect(plan.portScope).toBe('top1000');
    const tools = plan.steps.map((s) => s.tool);
    expect(tools).toEqual(expect.arrayContaining(['nmap', 'http']));
    expect(tools).not.toContain('whatweb');
    expect(tools).not.toContain('tls');
    const whatweb = plan.steps.find((s) => s.tool === 'whatweb');
    expect(whatweb).toBeUndefined();
  });

  it('custom can enable wpscan directly', () => {
    const custom: CustomScanOptions = {
      portScope: 'top100',
      enabledTools: ['wpscan', 'nmap'],
      path: '/',
      followRedirects: true,
      userAgent: '',
      timeoutMs: 120_000,
    };
    const plan = expandProfile('custom', target, custom, paths);
    expect(plan.steps.some((s) => s.tool === 'wpscan')).toBe(true);
  });
});

describe('assertApprovedArgs', () => {
  it('accepts generated safe arguments', () => {
    expect(() =>
      assertApprovedArgs('nmap', ['-sT', '-Pn', '-n', '-T4', '-p', '80,443', '--open', '--version-intensity', '5', '-oG', '/tmp/out/x', 'example.com']),
    ).not.toThrow();
    expect(() =>
      assertApprovedArgs('whatweb', ['-a', '1', '--no-errors', '--user-agent', 'UA/1 (Test)', '--log-json', '/tmp/out/w.json', 'https://example.com/']),
    ).not.toThrow();
  });

  it('rejects dangerous nmap flags', () => {
    expect(() => assertApprovedArgs('nmap', ['-sS'])).toThrow();
    expect(() => assertApprovedArgs('nmap', ['-O'])).toThrow();
    expect(() => assertApprovedArgs('nmap', ['--script', 'default'])).toThrow();
    expect(() => assertApprovedArgs('nmap', ['-p', '1-65535', '-sU'])).toThrow();
    expect(() => assertApprovedArgs('nmap', ['--osscan-guess'])).toThrow();
  });

  it('rejects control characters in values', () => {
    expect(() => assertApprovedArgs('whatweb', ['--user-agent', 'x\u0007y'])).toThrow();
    expect(() => assertApprovedArgs('nmap', ['example.com\u0000x'])).toThrow();
  });
});
