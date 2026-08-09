import { describe, expect, it } from 'vitest';
import { assertApprovedArgs, expandModules } from '../src/shared/profiles';
import { MODULE_DEFINITIONS, parseEnabledModules } from '../src/shared/modules';
import { parseTarget } from '../src/shared/targets';

const target = parseTarget('https://example.com/shop');
const opts = {
  outputPath: (name: string) => `/tmp/out/${name}`,
  nucleiTemplates: ['http/misconfiguration'],
  wordlistPath: '/opt/sitedig/wordlists/common.txt',
};

describe('expandModules', () => {
  it('expands asset-discovery into subfinder/dnsx/rdap steps', () => {
    const steps = expandModules(['asset-discovery'], target, opts);
    const tools = steps.map((s) => s.tool);
    expect(tools).toEqual(expect.arrayContaining(['subfinder', 'dnsx', 'rdap']));
    const dnsx = steps.find((s) => s.tool === 'dnsx');
    expect(dnsx?.args).toContain('-l'); // dnsx v1.2+ needs a list file, not -d
  });

  it('expands vuln-scan into nuclei + retire steps', () => {
    const steps = expandModules(['vuln-scan'], target, opts);
    const tools = steps.map((s) => s.tool);
    expect(tools).toEqual(expect.arrayContaining(['nuclei', 'retire']));
    const nuclei = steps.find((s) => s.tool === 'nuclei');
    expect(nuclei?.args).toContain('http/misconfiguration');
  });

  it('expands tls-hardening, content-discovery, cve-context', () => {
    const steps = expandModules(['tls-hardening', 'content-discovery', 'cve-context'], target, opts);
    const tools = steps.map((s) => s.tool);
    expect(tools).toEqual(expect.arrayContaining(['testssl', 'feroxbuster', 'osv']));
  });

  it('respects the target path for web tools', () => {
    const steps = expandModules(['vuln-scan', 'content-discovery'], target, opts);
    const nuclei = steps.find((s) => s.tool === 'nuclei');
    expect(nuclei?.args).toContain('https://example.com/shop');
    const ferox = steps.find((s) => s.tool === 'feroxbuster');
    expect(ferox?.args).toContain('https://example.com/shop');
    expect(ferox?.args).toContain('--json'); // feroxbuster v2.11 uses --json
  });
});

describe('assertApprovedArgs for module tools', () => {
  it('accepts generated module args', () => {
    for (const moduleId of Object.keys(MODULE_DEFINITIONS) as Array<keyof typeof MODULE_DEFINITIONS>) {
      for (const step of expandModules([moduleId], target, opts)) {
        expect(() => assertApprovedArgs(step.tool, step.args)).not.toThrow();
      }
    }
  });

  it('rejects dangerous flags on module tools', () => {
    expect(() => assertApprovedArgs('nuclei', ['--loud'])).toThrow();
    expect(() => assertApprovedArgs('nuclei', ['-stats'])).toThrow();
    expect(() => assertApprovedArgs('feroxbuster', ['--extract-links'])).toThrow();
    expect(() => assertApprovedArgs('testssl', ['--openssl', 'x'])).toThrow();
    expect(() => assertApprovedArgs('retire', ['--ignore', 'x'])).toThrow();
  });
});

describe('parseEnabledModules', () => {
  it('parses a CSV of module ids', () => {
    const set = parseEnabledModules({ ENABLED_MODULES: 'asset-discovery, vuln-scan' });
    expect(set.has('asset-discovery')).toBe(true);
    expect(set.has('vuln-scan')).toBe(true);
    expect(set.has('tls-hardening')).toBe(false);
  });

  it('ignores unknown ids and empty values', () => {
    const set = parseEnabledModules({ ENABLED_MODULES: 'bogus,' });
    expect(set.size).toBe(0);
  });

  it('enables nothing when unset', () => {
    expect(parseEnabledModules({}).size).toBe(0);
  });
});
