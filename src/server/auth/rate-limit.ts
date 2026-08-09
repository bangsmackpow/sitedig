import { createHash } from 'node:crypto';

/**
 * Simple in-memory sliding-window rate limiter. Suitable for the single-instance
 * MVP; swap for a shared store (e.g. SQLite/Redis) if/when scaling out.
 */
interface Bucket {
  timestamps: number[];
}

const buckets = new Map<string, Bucket>();

export function rateLimit(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now();
  let bucket = buckets.get(key);
  if (!bucket) {
    bucket = { timestamps: [] };
    buckets.set(key, bucket);
  }
  bucket.timestamps = bucket.timestamps.filter((t) => now - t < windowMs);
  if (bucket.timestamps.length >= limit) {
    return false;
  }
  bucket.timestamps.push(now);
  return true;
}

export function clientIp(req: Request): string {
  const fwd = req.headers.get('x-forwarded-for');
  if (fwd) return fwd.split(',')[0].trim();
  return req.headers.get('x-real-ip') ?? 'unknown';
}

export function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}
