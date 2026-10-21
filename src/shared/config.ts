import path from 'node:path';
import {
  DEFAULT_ARTIFACT_TTL_MINUTES,
  DEFAULT_MAX_CONCURRENT_SCANS,
  DEFAULT_MAX_QUEUE,
  DEFAULT_MAX_TOOL_OUTPUT_BYTES,
  DEFAULT_SCAN_TIMEOUT_MS,
  MAX_SCAN_TIMEOUT_MS,
  MODULE_SCAN_TIMEOUT_MS,
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
  deploymentMode: 'hosted' | 'self-hosted';
  databasePath: string;
  appBaseUrl: string;
  initialAdminEmail: string;
  initialAdminPassword: string;
  smtp: {
    host: string;
    port: number;
    secure: boolean;
    username: string;
    password: string;
    from: string;
    configured: boolean;
  };
  /** Outbound email delivery (Resend or SMTP), used for verification, MFA codes, and the admin digest. */
  email: {
    provider: 'resend' | 'smtp';
    from: string;
    resendApiKey: string;
    configured: boolean;
  };
  stripe: {
    secretKey: string;
    webhookSecret: string;
    priceId: string;
    portalReturnUrl: string;
    configured: boolean;
  };
  /** Deployment-level availability ceiling for paid modules (env ENABLED_MODULES). */
  enabledModules: Set<ModuleId>;
  /** Daily admin digest (new signups + scan activity). */
  digest: {
    enabled: boolean;
    hourUtc: number;
    recipients: string[];
  };
  /** Days of scan history to retain (0 disables sweeping). */
  scanHistoryRetentionDays: number;
  /** Maximum recurring scans a single user may create. */
  maxSchedulesPerUser: number;
}

export interface WorkerConfig {
  port: number;
  serviceToken: string;
  /** Base URL of the web service, used to POST scan-history events (optional). */
  webBaseUrl: string;
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
  /** DNS-over-HTTPS JSON endpoint used by the domain-hardening module. */
  dohEndpoint: string;
  /** IP geolocation endpoint used by the infra-intel module (no API key). */
  ipIntelEndpoint: string;
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
  const deploymentMode = env.DEPLOYMENT_MODE === 'hosted' ? 'hosted' : 'self-hosted';
  const smtpHost = env.SMTP_HOST ?? '';
  const smtpUsername = env.SMTP_USERNAME ?? '';
  const smtpPassword = env.SMTP_PASSWORD ?? '';
  const smtpFrom = env.SMTP_FROM ?? '';
  const stripeKey = env.STRIPE_SECRET_KEY ?? '';
  const stripeWebhook = env.STRIPE_WEBHOOK_SECRET ?? '';
  const resendApiKey = env.RESEND_API_KEY ?? '';
  const emailFrom = env.EMAIL_FROM ?? smtpFrom;
  const providerRaw = (env.EMAIL_PROVIDER ?? '').trim().toLowerCase();
  // Default to Resend when a key is present, otherwise SMTP. An explicit
  // EMAIL_PROVIDER always wins.
  const emailProvider: 'resend' | 'smtp' = providerRaw === 'resend' || (providerRaw === '' && resendApiKey) ? 'resend' : 'smtp';
  const emailConfigured = emailProvider === 'resend' ? Boolean(resendApiKey && emailFrom) : Boolean(smtpHost && emailFrom);
  return {
    port: intEnv(env, 'WEB_PORT', DEFAULT_WEB_PORT),
    workerUrl: (env.WORKER_URL ?? 'http://localhost:8081').replace(/\/+$/, ''),
    serviceToken: env.SCAN_SERVICE_TOKEN ?? '',
    logLevel: env.LOG_LEVEL ?? 'info',
    deploymentMode,
    databasePath: env.DATABASE_PATH ?? './data/sitedig.sqlite',
    appBaseUrl: (env.APP_BASE_URL ?? 'http://localhost:3000').replace(/\/+$/, ''),
    initialAdminEmail: (env.INITIAL_ADMIN_EMAIL ?? '').trim().toLowerCase(),
    initialAdminPassword: env.INITIAL_ADMIN_PASSWORD ?? '',
    smtp: {
      host: smtpHost,
      port: intEnv(env, 'SMTP_PORT', 587),
      secure: boolEnv(env, 'SMTP_SECURE', false),
      username: smtpUsername,
      password: smtpPassword,
      from: smtpFrom,
      configured: Boolean(smtpHost && smtpFrom),
    },
    email: {
      provider: emailProvider,
      from: emailFrom,
      resendApiKey,
      configured: emailConfigured,
    },
    stripe: {
      secretKey: stripeKey,
      webhookSecret: stripeWebhook,
      priceId: env.STRIPE_PRICE_ID ?? '',
      portalReturnUrl: env.STRIPE_PORTAL_RETURN_URL ?? '',
      configured: Boolean(stripeKey && stripeWebhook && env.STRIPE_PRICE_ID),
    },
    enabledModules: parseEnabledModules(env as Record<string, string | undefined>),
    digest: {
      enabled: boolEnv(env, 'ADMIN_DIGEST_ENABLED', false),
      hourUtc: Math.min(23, Math.max(0, intEnv(env, 'ADMIN_DIGEST_HOUR', 8))),
      recipients: (env.ADMIN_DIGEST_RECIPIENTS ?? '')
        .split(',')
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean),
    },
    scanHistoryRetentionDays: intEnv(env, 'SCAN_HISTORY_RETENTION_DAYS', 365),
    maxSchedulesPerUser: intEnv(env, 'MAX_SCHEDULES_PER_USER', 10),
  };
}

/** Validate deployment config; throws with a clear message when invalid. */
export function validateWebConfig(config: WebConfig): void {
  // Internal web -> worker calls must never be unauthenticated. Fail closed at
  // startup instead of silently accepting unauthenticated internal requests.
  if (!config.serviceToken) {
    throw new Error('SCAN_SERVICE_TOKEN is required. Generate a long random value and set it on both web and worker.');
  }
  if (config.serviceToken.length < 32) {
    throw new Error('SCAN_SERVICE_TOKEN must be at least 32 characters.');
  }
  if (config.deploymentMode === 'hosted') {
    if (!config.stripe.configured) {
      throw new Error('Hosted mode requires STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, and STRIPE_PRICE_ID.');
    }
    if (!config.email.configured) {
      throw new Error('Hosted mode requires email delivery: set RESEND_API_KEY + EMAIL_FROM, or SMTP_HOST + SMTP_FROM.');
    }
    if (!config.appBaseUrl || config.appBaseUrl === 'http://localhost:3000') {
      throw new Error('Hosted mode requires APP_BASE_URL to be set to the public origin.');
    }
  }
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
  const enabledModules = parseEnabledModules(env as Record<string, string | undefined>);
  let scanTimeoutMs = Math.max(1000, Math.min(scanTimeout, MAX_SCAN_TIMEOUT_MS));
  // Paid modules run much heavier tools (nuclei/testssl); enforce a longer job
  // cap automatically so a low SCAN_TIMEOUT_MS doesn't abort module scans.
  if (enabledModules.size > 0) {
    scanTimeoutMs = Math.max(scanTimeoutMs, MODULE_SCAN_TIMEOUT_MS);
  }
  scanTimeoutMs = Math.min(scanTimeoutMs, MAX_SCAN_TIMEOUT_MS);
  return {
    port: intEnv(env, 'WORKER_PORT', DEFAULT_WORKER_PORT),
    serviceToken: env.SCAN_SERVICE_TOKEN ?? '',
    webBaseUrl: (env.WEB_BASE_URL ?? '').replace(/\/+$/, ''),
    maxConcurrentScans: intEnv(env, 'MAX_CONCURRENT_SCANS', DEFAULT_MAX_CONCURRENT_SCANS),
    maxQueue: intEnv(env, 'MAX_QUEUE', DEFAULT_MAX_QUEUE),
    scanTimeoutMs,
    maxToolOutputBytes: intEnv(env, 'MAX_TOOL_OUTPUT_BYTES', DEFAULT_MAX_TOOL_OUTPUT_BYTES),
    logLevel: env.LOG_LEVEL ?? 'info',
    allowInternalTargets: boolEnv(env, 'ALLOW_INTERNAL_TARGETS', false),
    artifactDir: env.ARTIFACT_DIR ?? './artifacts',
    artifactTtlMinutes: intEnv(env, 'ARTIFACT_TTL_MINUTES', DEFAULT_ARTIFACT_TTL_MINUTES),
    scannerBinDir: env.SCANNER_BIN_DIR ?? null,
    enabledModules,
    wpscanApiToken: env.WPSCAN_API_TOKEN ?? '',
    nucleiTemplates,
    nucleiTemplatesDir: nucleiDir,
    wordlistPath: env.CONTENT_WORDLIST ?? DEFAULT_CONTENT_WORDLIST,
    dohEndpoint: (env.DOH_ENDPOINT ?? 'https://cloudflare-dns.com/dns-query').replace(/\/+$/, ''),
    ipIntelEndpoint: (env.IP_INTEL_ENDPOINT ?? 'https://ipwho.is').replace(/\/+$/, ''),
  };
}

const DEFAULT_NUCLEI_TEMPLATES = [
  'http/technologies/tech-detect.yaml',
  'http/exposures/configs/git-config.yaml',
  'ssl/tls-version.yaml',
  'ssl/deprecated-tls.yaml',
  'ssl/self-signed-ssl.yaml',
  'ssl/expired-ssl.yaml',
  'ssl/weak-cipher-suites.yaml',
];

const DEFAULT_CONTENT_WORDLIST = '/opt/sitedig/wordlists/common.txt';
