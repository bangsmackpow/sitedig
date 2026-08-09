import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import type { UserRow } from './users';
import { currentUser, type SessionUser } from './auth/context';

export function json(data: unknown, status = 200): NextResponse {
  return NextResponse.json(data, { status });
}

export function errorJson(message: string, status = 400, code = 'error'): NextResponse {
  return NextResponse.json({ error: { code, message } }, { status });
}

export type GuardResult<T> = { ok: true; value: T } | { ok: false; response: NextResponse };

export async function guardUser(req: NextRequest): Promise<GuardResult<SessionUser>> {
  const su = currentUser(req);
  if (!su) return { ok: false, response: errorJson('Authentication required.', 401, 'unauthorized') };
  return { ok: true, value: su };
}

export async function guardAdmin(req: NextRequest): Promise<GuardResult<SessionUser>> {
  const res = await guardUser(req);
  if (!res.ok) return res;
  if (res.value.user.role !== 'admin') {
    return { ok: false, response: errorJson('Admin access required.', 403, 'forbidden') };
  }
  return res;
}

export function isGuardOk<T>(guard: GuardResult<T>): guard is { ok: true; value: T } {
  return guard.ok;
}

export function hasRoleAdmin(user: UserRow): boolean {
  return user.role === 'admin';
}
