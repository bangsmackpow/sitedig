import path from 'node:path';
import {
  DEFAULT_ARTIFACT_TTL_MINUTES,
  DEFAULT_MAX_CONCURRENT_SCANS,
  DEFAULT_MAX_QUEUE,
  DEFAULT_MAX_TOOL_OUTPUT_BYTES,
  DEFAULT_SCAN_TIMEOUT_MS,
  DEFAULT_WEB_PORT,
  DEFAULT_WORKER_PORT,
} from './constants';
import { parseEnabledModules } from './modules';
import type { ModuleId } from './types';

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
  /** Paid add-on modules enabled on this deployment (env ENABLED_MODULES). */
  enabledModules: Set<ModuleId>;
  /** Optional WPScan API token for vulnerability data (env WPSCAN_API_TOKEN). */
  wpscanApiToken: string;
  /** Nuclei template allowlist (paths/ids) used by the vuln-scan module. */
  nucleiTemplates: string[];
  /** Nuclei template directory (absolute path prefix for relative templates). */
  nucleiTemplatesDir: string;
  /** Path to the wordlist used by content-discovery. */
  wordlistPath: string;
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
  const nucleiDir = env.NUCLEI_TEMPLATES_DIR ?? '/opt/nuclei-templates';
  const nucleiRaw = (env.NUCLEI_TEMPLATES ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const nucleiTemplates =
    nucleiRaw.length > 0 ? nucleiRaw.map((t) => (path.isAbsolute(t) ? t : path.join(nucleiDir, t))) : DEFAULT_NUCLEI_TEMPLATES.map((t) => path.join(nucleiDir, t));
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
    enabledModules: parseEnabledModules(env as Record<string, string | undefined>),
    wpscanApiToken: env.WPSCAN_API_TOKEN ?? '',
    nucleiTemplates,
    nucleiTemplatesDir: nucleiDir,
    wordlistPath: env.CONTENT_WORDLIST ?? DEFAULT_CONTENT_WORDLIST,
  };
}

const DEFAULT_NUCLEI_TEMPLATES = [
  'http/misconfiguration',
  'http/exposed-panels',
  'http/headers',
  'ssl',
  'exposures/configs',
];

const DEFAULT_CONTENT_WORDLIST = '/opt/sitedig/wordlists/common.txt';
