import path from 'node:path';
import type { ToolName } from '../shared/types';

export interface RunResult {
  exitCode: number | null;
  timedOut: boolean;
  output: string;
  truncated: boolean;
  error: string | null;
  signal: string | null;
}

export interface RunnerDeps {
  maxOutputBytes: number;
  /** When set, subprocess tools are resolved to Node stubs (tests only). */
  binDir: string | null;
}

export interface RunOptions {
  timeoutMs: number;
  signal?: AbortSignal;
}

const SUBPROCESS_TOOLS: ToolName[] = [
  'nmap',
  'whatweb',
  'wpscan',
  'subfinder',
  'dnsx',
  'nuclei',
  'retire',
  'testssl',
  'feroxbuster',
];

function resolveCommand(tool: ToolName, deps: RunnerDeps): { file: string; prefix: string[] } {
  if (deps.binDir) {
    return { file: process.execPath, prefix: [path.join(deps.binDir, `${tool}.cjs`)] };
  }
  return { file: tool, prefix: [] };
}

/** Kill a detached process group, then force-kill after a delay. */
function killProcessGroup(pid: number | undefined, graceMs = 3000): void {
  if (!pid) return;
  try {
    if (process.platform !== 'win32') {
      process.kill(-pid, 'SIGTERM');
    } else {
      process.kill(pid, 'SIGTERM');
    }
  } catch {
    // already gone
  }
  setTimeout(() => {
    try {
      if (process.platform !== 'win32') {
        process.kill(-pid, 'SIGKILL');
      } else {
        process.kill(pid, 'SIGKILL');
      }
    } catch {
      // already gone
    }
  }, graceMs).unref?.();
}

/**
 * Execute a scanner subprocess safely.
 *
 * - Arguments are always passed as an array (never a shell string).
 * - The child is detached so the whole process group can be killed on timeout
 *   or cancellation (prevents orphaned scanners).
 * - Output is captured up to a hard cap to prevent memory exhaustion.
 * - `reject: false` keeps exit codes out of exceptions; errors are reported on
 *   the result object.
 */
export async function runTool(
  tool: ToolName,
  args: string[],
  deps: RunnerDeps,
  opts: RunOptions,
): Promise<RunResult> {
  if (!SUBPROCESS_TOOLS.includes(tool)) {
    throw new Error(`runTool called for non-subprocess tool: ${tool}`);
  }
  const { execa } = await import('execa');
  const { file, prefix } = resolveCommand(tool, deps);

  let output = '';
  let truncated = false;

  const child = execa(file, [...prefix, ...args], {
    all: true,
    buffer: false,
    reject: false,
    detached: process.platform !== 'win32',
    killSignal: 'SIGTERM',
    signal: opts.signal,
  });

  child.all?.on('data', (chunk: Buffer) => {
    if (truncated) return;
    if (output.length + chunk.length > deps.maxOutputBytes) {
      output += chunk.toString('utf8', 0, Math.max(0, deps.maxOutputBytes - output.length));
      truncated = true;
    } else {
      output += chunk.toString('utf8');
    }
  });

  let timedOut = false;
  let killTimer: NodeJS.Timeout | null = null;
  if (opts.timeoutMs > 0) {
    killTimer = setTimeout(() => {
      timedOut = true;
      killProcessGroup(child.pid);
    }, opts.timeoutMs);
    killTimer.unref?.();
  }

  const onAbort = () => {
    killProcessGroup(child.pid);
  };
  opts.signal?.addEventListener('abort', onAbort, { once: true });

  let exitCode: number | null = null;
  let signal: string | null = null;
  let error: string | null = null;
  try {
    const result = await child;
    exitCode = result.exitCode ?? null;
    signal = result.signal ?? null;
    // execa resolves with `failed: true` (and `reject: false`) on both non-zero
    // exits and some process failures; surface the real message so a broken
    // tool is never hidden behind "exited with code undefined".
    if (result.failed && !error) {
      const meta = result as unknown as { shortMessage?: string; message?: string };
      error = meta.shortMessage || meta.message || null;
    }
    if (result.isCanceled) {
      error = error ?? 'Process was cancelled.';
    }
  } catch (e) {
    // AbortSignal cancels and spawn failures surface here.
    error = (e as Error).message;
  } finally {
    if (killTimer) clearTimeout(killTimer);
    opts.signal?.removeEventListener('abort', onAbort);
  }

  return { exitCode, timedOut, output, truncated, error, signal };
}

/** Probe a tool's version line. Used for report metadata. */
export async function captureToolVersion(
  tool: ToolName,
  deps: RunnerDeps,
  args: string[],
  timeoutMs = 15_000,
): Promise<string | null> {
  try {
    const res = await runTool(tool, args, deps, { timeoutMs });
    const firstLine = res.output.split(/\r?\n/)[0]?.trim() ?? null;
    return firstLine && firstLine.length <= 120 ? firstLine : null;
  } catch {
    return null;
  }
}

export const VERSION_PROBE_ARGS: Partial<Record<ToolName, string[]>> = {
  nmap: ['--version'],
  whatweb: ['--version'],
  wpscan: ['--version'],
  subfinder: ['-version'],
  dnsx: ['-version'],
  nuclei: ['-version'],
  feroxbuster: ['--version'],
};
