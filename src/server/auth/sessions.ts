import { randomBytes, createHash } from 'node:crypto';
import type { NextRequest, NextResponse } from 'next/server';
import { getDb } from '../db';
import type { UserRow } from '../users';

export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function sessionCookieName(secure: boolean): string {
  return secure ? '__Host-sitedig_session' : 'sitedig_session';
}

export function csrfCookieName(secure: boolean): string {
  return secure ? '__Host-sitedig_csrf' : 'sitedig_csrf';
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
  return req.cookies.get(sessionCookieName(req.nextUrl.protocol === 'https:'))?.value;
}

export function setSessionCookie(res: NextResponse, token: string, secure: boolean): void {
  res.cookies.set(sessionCookieName(secure), token, sessionCookieOptions({ secure }));
}

export function clearSessionCookie(res: NextResponse, secure: boolean): void {
  res.cookies.set(sessionCookieName(secure), '', { ...sessionCookieOptions({ secure }), maxAge: 0 });
}

export function setCsrfCookie(res: NextResponse, token: string, secure: boolean): void {
  res.cookies.set(csrfCookieName(secure), token, csrfCookieOptions({ secure }));
}

export function newCsrfToken(): string {
  return randomBytes(32).toString('base64url');
}
