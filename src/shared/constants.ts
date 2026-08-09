export const APP_NAME = 'SiteDig';
export const APP_VERSION = typeof process !== 'undefined' ? (process.env.APP_VERSION ?? '0.1.0') : '0.1.0';

export const DEFAULT_USER_AGENT = `${APP_NAME}/${APP_VERSION} (authorized-scan)`;

export const MAX_SCAN_TIMEOUT_MS = 15 * 60 * 1000; // absolute cap (free + modules)
export const DEFAULT_SCAN_TIMEOUT_MS = 10 * 60 * 1000; // default job cap (modules may need more than 5 min)
export const MAX_STEP_TIMEOUT_MS = 150_000; // per-step cap for heavy module tools (nuclei/testssl)
export const DEFAULT_MAX_CONCURRENT_SCANS = 1;
export const DEFAULT_MAX_QUEUE = 3;
export const DEFAULT_MAX_TOOL_OUTPUT_BYTES = 20 * 1024 * 1024;
export const DEFAULT_WEB_PORT = 3000;
export const DEFAULT_WORKER_PORT = 8081;
export const DEFAULT_ARTIFACT_TTL_MINUTES = 30;
export const MAX_HTTP_REDIRECTS = 5;
export const HTTP_CHECK_TIMEOUT_MS = 15_000;
export const TLS_CHECK_TIMEOUT_MS = 10_000;

export const PORT_SCOPE_LABELS = {
  common: 'Common TCP ports',
  top100: 'Top 100 TCP ports',
  top1000: 'Top 1,000 TCP ports',
} as const;

// Curated "common" web/service ports used by the Quick profile.
export const COMMON_PORT_LIST = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 1521,
  1723, 2375, 2376, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 9090, 9200, 11211,
];

export const DEFAULT_HTTP_PATH = '/';

// Security-relevant headers we check for on the target.
export const SECURITY_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-content-type-options',
  'x-frame-options',
  'referrer-policy',
  'permissions-policy',
] as const;
