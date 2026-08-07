import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { captureToolVersion, runTool } from '../src/worker/runner';

const BIN = path.join(__dirname, 'fixtures', 'stub-bin');
const SLOW_BIN = path.join(__dirname, 'fixtures', 'stub-bin-slow');
const deps = { maxOutputBytes: 1_000_000, binDir: BIN };
const slowDeps = { maxOutputBytes: 1_000_000, binDir: SLOW_BIN };

beforeAll(() => {
  process.env.SCANNER_BIN_DIR = BIN;
});
afterAll(() => {
  delete process.env.SCANNER_BIN_DIR;
});

describe('runTool', () => {
  it('runs a stub tool and returns output', async () => {
    const res = await runTool('nmap', ['-sT', 'example.com'], deps, { timeoutMs: 5000 });
    expect(res.exitCode).toBe(0);
    expect(res.error).toBeNull();
    expect(res.output).toContain('Nmap stub');
  });

  it('enforces a hard output cap', async () => {
    const small = { maxOutputBytes: 32, binDir: BIN };
    const res = await runTool('nmap', ['-sT', 'example.com'], small, { timeoutMs: 5000 });
    expect(res.truncated).toBe(true);
    expect(res.output.length).toBeLessThanOrEqual(32);
  });

  it('times out and kills the process group', async () => {
    const res = await runTool('nmap', ['--slow'], slowDeps, { timeoutMs: 400 });
    expect(res.timedOut).toBe(true);
    // Killed processes report either null (signal) or a non-zero exit code.
    expect(res.exitCode).not.toBe(0);
  });

  it('honors an abort signal', async () => {
    const controller = new AbortController();
    const promise = runTool('nmap', ['--slow'], slowDeps, { timeoutMs: 10_000, signal: controller.signal });
    setTimeout(() => controller.abort(), 200);
    const res = await promise;
    expect(res.exitCode).not.toBe(0);
  });
});

describe('captureToolVersion', () => {
  it('captures a version line from a stub', async () => {
    const version = await captureToolVersion('nmap', deps, ['--version']);
    expect(version).toContain('Nmap stub');
  });
});
