import type { NextRequest } from 'next/server';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json } from '@/server/http';
import { guardUser } from '@/server/http';
import { buildMePayload } from '@/server/me';
import { isDeletionPending } from '@/server/account';
import { csrfCookieName, newCsrfToken, secureRequest, setCsrfCookie } from '@/server/auth/sessions';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  await ensureInitialized();
  const guard = await guardUser(req);
  if (!guard.ok) return guard.response;
  const payload = buildMePayload(guard.value.user.id);
  if (!payload) return errorJson('Account not found.', 404, 'not_found');
  const res = json({ ...payload, deletionPending: isDeletionPending(guard.value.user.id) });
  // Re-issue the CSRF cookie when it's missing. The session cookie persists
  // ~30 days, but the CSRF cookie can be lost on a browser restart (it used to
  // be a browser-session cookie). Without it, mutating requests fail the
  // double-submit check with "Request origin not allowed" until re-login.
  if (!req.cookies.get(csrfCookieName())?.value) {
    setCsrfCookie(res, newCsrfToken(), secureRequest(req));
  }
  return res;
}
