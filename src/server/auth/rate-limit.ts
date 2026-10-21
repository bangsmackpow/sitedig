import { createHash } from 'node:crypto';

/**
 * Bounded in-memory sliding-window rate limiter. Suitable for the single-instance
 * MVP; swap for a shared store (e.g. SQLite/Redis) when running multiple web
 * replicas.
 */
interface Bucket {
  timestamps: number[];
  windowMs: number;
}

const MAX_BUCKETS = 10_000;
const SWEEP_INTERVAL_MS = 60_000;
const buckets = new Map<string, Bucket>();
let lastSweep = 0;

function evictOldest(): void {
  while (buckets.size >= MAX_BUCKETS) {
    const oldest = buckets.keys().next().value as string | undefined;
    if (oldest === undefined) return;
    buckets.delete(oldest);
  }
}

function sweep(now: number): void {
  if (now - lastSweep < SWEEP_INTERVAL_MS && buckets.size < MAX_BUCKETS) return;
  lastSweep = now;
  for (const [key, bucket] of buckets) {
    bucket.timestamps = bucket.timestamps.filter((t) => now - t < bucket.windowMs);
    if (bucket.timestamps.length === 0) buckets.delete(key);
  }
}

export function rateLimit(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now();
  sweep(now);
  evictOldest();
  let bucket = buckets.get(key);
  if (!bucket) {
    bucket = { timestamps: [], windowMs };
    buckets.set(key, bucket);
  } else {
    bucket.windowMs = windowMs;
    bucket.timestamps = bucket.timestamps.filter((t) => now - t < windowMs);
  }
  if (bucket.timestamps.length >= limit) {
    return false;
  }
  bucket.timestamps.push(now);
  return true;
}

/**
 * Resolve the client IP from a trusted reverse proxy. NPM appends the address
 * it saw to X-Forwarded-For, so the *last* entry is the one to trust; using the
 * first entry lets clients spoof the header and bypass rate limits.
 */
export function clientIp(req: Request): string {
  const real = req.headers.get('x-real-ip')?.trim();
  if (real) return real;
  const fwd = req.headers.get('x-forwarded-for');
  if (fwd) {
    const parts = fwd
      .split(',')
      .map((part) => part.trim())
      .filter(Boolean);
    if (parts.length > 0) return parts[parts.length - 1];
  }
  return 'unknown';
}

export function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

/** Test-only helper; not used by production code. */
export function resetRateLimitsForTests(): void {
  buckets.clear();
  lastSweep = 0;
}
