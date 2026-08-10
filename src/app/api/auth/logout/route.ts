import type { NextRequest } from 'next/server';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json } from '@/server/http';
import { getRequestToken, getSessionUser, revokeSession, clearSessionCookie, secureRequest } from '@/server/auth/sessions';
import { verifyCsrfOrOrigin } from '@/server/auth/csrf';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest): Promise<Response> {
  await ensureInitialized();
  if (!verifyCsrfOrOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');
  const token = getRequestToken(req);
  const session = token ? getSessionUser(token) : null;
  if (session) {
    revokeSession(session.sessionId);
  }
  const secure = secureRequest(req);
  const res = json({ ok: true });
  clearSessionCookie(res, secure);
  return res;
}
