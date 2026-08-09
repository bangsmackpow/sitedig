import type { NextRequest } from 'next/server';
import { getRequestToken, getSessionUser, touchSession } from './sessions';
import type { SessionUser } from './sessions';

export type { SessionUser };

/** Resolve the current authenticated user from the session cookie, if any. */
export function currentUser(req: NextRequest): SessionUser | null {
  const token = getRequestToken(req);
  if (!token) return null;
  const session = getSessionUser(token);
  if (!session) return null;
  touchSession(session.sessionId);
  return session;
}
