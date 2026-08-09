import { createHash } from 'node:crypto';
import type { NextRequest } from 'next/server';
import { csrfCookieName, getRequestToken } from './sessions';
import { getWebConfig } from '../../shared/config';

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Double-submit CSRF defense-in-depth. The CSRF token cookie is non-HttpOnly and
 * read by the client; state-changing requests must echo it in `x-csrf-token`.
 * SameSite=Lax on the session cookie already blocks most cross-site attacks.
 */
export function verifyCsrf(req: NextRequest): boolean {
  if (!MUTATING_METHODS.has(req.method)) return true;
  const secure = req.nextUrl.protocol === 'https:';
  const cookie = req.cookies.get(csrfCookieName(secure))?.value;
  const header = req.headers.get('x-csrf-token');
  if (!cookie || !header) return false;
  return createHash('sha256').update(cookie).digest('hex') === createHash('sha256').update(header).digest('hex');
}

/** Origin check as an additional layer for mutating requests. */
export function verifyOrigin(req: NextRequest): boolean {
  if (!MUTATING_METHODS.has(req.method)) return true;
  const origin = req.headers.get('origin');
  if (!origin) return true; // non-browser clients
  const base = getWebConfig().appBaseUrl;
  try {
    return new URL(origin).origin === new URL(base).origin;
  } catch {
    return false;
  }
}

/** Both CSRF token echo and origin check must pass for browser mutations. */
export function verifyCsrfOrOrigin(req: NextRequest): boolean {
  return verifyOrigin(req) && verifyCsrf(req);
}
