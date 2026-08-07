import {
  DEFAULT_ARTIFACT_TTL_MINUTES,
  DEFAULT_MAX_CONCURRENT_SCANS,
  DEFAULT_MAX_QUEUE,
  DEFAULT_MAX_TOOL_OUTPUT_BYTES,
  DEFAULT_SCAN_TIMEOUT_MS,
  DEFAULT_WEB_PORT,
  DEFAULT_WORKER_PORT,
} from './constants';

export interface WebConfig {
  port: number;
  workerUrl: string;
  serviceToken: string;
  logLevel: string;
}

export interface WorkerConfig {
  port: number;
  serviceToken: string;
  maxConcurrentScans: number;
  maxQueue: number;
  scanTimeoutMs: number;
  maxToolOutputBytes: number;
  logLevel: string;
  allowInternalTargets: boolean;
  artifactDir: string;
  artifactTtlMinutes: number;
  scannerBinDir: string | null;
}

function intEnv(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : fallback;
}

function boolEnv(env: NodeJS.ProcessEnv, name: string, fallback: boolean): boolean {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  return raw.toLowerCase() === 'true' || raw === '1';
}

export function getWebConfig(env: NodeJS.ProcessEnv = process.env): WebConfig {
  return {
    port: intEnv(env, 'WEB_PORT', DEFAULT_WEB_PORT),
    workerUrl: (env.WORKER_URL ?? 'http://localhost:8081').replace(/\/+$/, ''),
    serviceToken: env.SCAN_SERVICE_TOKEN ?? '',
    logLevel: env.LOG_LEVEL ?? 'info',
  };
}

export function getWorkerConfig(env: NodeJS.ProcessEnv = process.env): WorkerConfig {
  const scanTimeout = intEnv(env, 'SCAN_TIMEOUT_MS', DEFAULT_SCAN_TIMEOUT_MS);
  return {
    port: intEnv(env, 'WORKER_PORT', DEFAULT_WORKER_PORT),
    serviceToken: env.SCAN_SERVICE_TOKEN ?? '',
    maxConcurrentScans: intEnv(env, 'MAX_CONCURRENT_SCANS', DEFAULT_MAX_CONCURRENT_SCANS),
    maxQueue: intEnv(env, 'MAX_QUEUE', DEFAULT_MAX_QUEUE),
    scanTimeoutMs: Math.max(1000, Math.min(scanTimeout, DEFAULT_SCAN_TIMEOUT_MS)),
    maxToolOutputBytes: intEnv(env, 'MAX_TOOL_OUTPUT_BYTES', DEFAULT_MAX_TOOL_OUTPUT_BYTES),
    logLevel: env.LOG_LEVEL ?? 'info',
    allowInternalTargets: boolEnv(env, 'ALLOW_INTERNAL_TARGETS', false),
    artifactDir: env.ARTIFACT_DIR ?? './artifacts',
    artifactTtlMinutes: intEnv(env, 'ARTIFACT_TTL_MINUTES', DEFAULT_ARTIFACT_TTL_MINUTES),
    scannerBinDir: env.SCANNER_BIN_DIR ?? null,
  };
}
