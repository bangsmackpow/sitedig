import type { NextRequest } from 'next/server';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json } from '@/server/http';
import { guardAdmin } from '@/server/http';
import { verifyCsrfOrOrigin } from '@/server/auth/csrf';
import { sendAdminDigest } from '@/server/digest';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  await ensureInitialized();
  if (!verifyCsrfOrOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');
  const guard = await guardAdmin(req);
  if (!guard.ok) return guard.response;

  const result = await sendAdminDigest();
  if (!result.sent) {
    const message =
      result.reason === 'no_recipients'
        ? 'No digest recipients are configured (set ADMIN_DIGEST_RECIPIENTS or create an admin account).'
        : 'Email delivery is not configured.';
    return errorJson(message, 400, result.reason ?? 'not_sent');
  }
  return json(result);
}
