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

export class PayloadTooLargeError extends Error {
  constructor(maxBytes: number) {
    super(`Request body exceeds the ${maxBytes} byte limit.`);
    this.name = 'PayloadTooLargeError';
  }
}

async function readLimitedBody(req: NextRequest, maxBytes: number): Promise<string> {
  const declared = Number(req.headers.get('content-length') ?? '');
  if (Number.isFinite(declared) && declared > maxBytes) throw new PayloadTooLargeError(maxBytes);
  if (!req.body) return '';

  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new PayloadTooLargeError(maxBytes);
      }
      chunks.push(value);
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // The stream may already be released after cancellation.
    }
  }
  return new TextDecoder().decode(Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))));
}

/** Read and parse a JSON body with a hard byte cap (default 64 KiB). */
export async function readJsonLimited(req: NextRequest, maxBytes = 64 * 1024): Promise<unknown> {
  return JSON.parse(await readLimitedBody(req, maxBytes));
}

/** Read a raw text body with a hard byte cap. */
export async function readTextLimited(req: NextRequest, maxBytes = 64 * 1024): Promise<string> {
  return readLimitedBody(req, maxBytes);
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
