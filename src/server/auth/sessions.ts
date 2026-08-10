import { randomBytes, createHash } from 'node:crypto';
import type { NextRequest, NextResponse } from 'next/server';
import { getDb } from '../db';
import type { UserRow } from '../users';

export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

const SESSION_COOKIE = 'sitedig_session';
const CSRF_COOKIE = 'sitedig_csrf';
const LEGACY_HOST_PREFIXES = ['__Host-sitedig_session', '__Host-sitedig_csrf'];

export function sessionCookieName(): string {
  return SESSION_COOKIE;
}

export function csrfCookieName(): string {
  return CSRF_COOKIE;
}

export function createSession(userId: number, ipHash?: string, userAgentHash?: string): { token: string; expiresAt: string } {
  const token = randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  const now = new Date().toISOString();
  getDb()
    .prepare(
      `INSERT INTO sessions (user_id, token_hash, expires_at, created_at, last_seen_at, ip_hash, user_agent_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(userId, hashToken(token), expiresAt, now, now, ipHash ?? null, userAgentHash ?? null);
  return { token, expiresAt };
}

export interface SessionUser {
  user: UserRow;
  sessionId: number;
}

export function getSessionUser(token: string | undefined): SessionUser | null {
  if (!token) return null;
  const row = getDb()
    .prepare(
      `SELECT s.id AS session_id, u.*
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = ? AND s.revoked_at IS NULL`,
    )
    .get(hashToken(token)) as (UserRow & { session_id: number; expires_at: string }) | undefined;
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) return null;
  if (row.deleted_at) return null;
  if (row.status === 'disabled') return null;
  return { user: row as UserRow, sessionId: row.session_id };
}

export function touchSession(sessionId: number): void {
  getDb().prepare('UPDATE sessions SET last_seen_at = ? WHERE id = ?').run(new Date().toISOString(), sessionId);
}

export function revokeSession(sessionId: number): void {
  getDb().prepare('UPDATE sessions SET revoked_at = ? WHERE id = ?').run(new Date().toISOString(), sessionId);
}

export function revokeAllUserSessions(userId: number, exceptSessionId?: number): void {
  if (exceptSessionId !== undefined) {
    getDb().prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND id != ?').run(new Date().toISOString(), userId, exceptSessionId);
  } else {
    getDb().prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ?').run(new Date().toISOString(), userId);
  }
}

export interface CookieOptions {
  secure: boolean;
  maxAge?: number;
}

export interface CookieSerializeOptions {
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'lax' | 'strict' | 'none';
  path: string;
  maxAge?: number;
}

export function sessionCookieOptions(opts: CookieOptions): CookieSerializeOptions {
  return {
    httpOnly: true,
    secure: opts.secure,
    sameSite: 'lax',
    path: '/',
    maxAge: opts.maxAge ?? Math.floor(SESSION_TTL_MS / 1000),
  };
}

export function csrfCookieOptions(opts: CookieOptions): CookieSerializeOptions {
  return {
    httpOnly: false,
    secure: opts.secure,
    sameSite: 'lax',
    path: '/',
  };
}

export function getRequestToken(req: NextRequest): string | undefined {
  return req.cookies.get(sessionCookieName())?.value;
}

/**
 * Whether cookies should carry the Secure flag. Derived from the request
 * protocol (which reflects X-Forwarded-Proto behind a reverse proxy).
 */
export function secureRequest(req: NextRequest): boolean {
  return req.nextUrl.protocol === 'https:';
}

export function setSessionCookie(res: NextResponse, token: string, secure: boolean): void {
  res.cookies.set(sessionCookieName(), token, sessionCookieOptions({ secure }));
  // Purge any legacy __Host- cookie from earlier deploys so stale names can
  // never shadow the single canonical cookie.
  for (const legacy of LEGACY_HOST_PREFIXES) {
    res.cookies.set(legacy, '', { ...sessionCookieOptions({ secure }), maxAge: 0 });
  }
}

export function clearSessionCookie(res: NextResponse, secure: boolean): void {
  res.cookies.set(sessionCookieName(), '', { ...sessionCookieOptions({ secure }), maxAge: 0 });
}

export function setCsrfCookie(res: NextResponse, token: string, secure: boolean): void {
  res.cookies.set(csrfCookieName(), token, csrfCookieOptions({ secure }));
  res.cookies.set('__Host-sitedig_csrf', '', { ...csrfCookieOptions({ secure }), maxAge: 0 });
}

export function clearCsrfCookie(res: NextResponse, secure: boolean): void {
  res.cookies.set(csrfCookieName(), '', { ...csrfCookieOptions({ secure }), maxAge: 0 });
}

export function newCsrfToken(): string {
  return randomBytes(32).toString('base64url');
}
