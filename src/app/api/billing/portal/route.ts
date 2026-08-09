import type { NextRequest } from 'next/server';
import { getWebConfig } from '@/shared/config';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json } from '@/server/http';
import { guardUser } from '@/server/http';
import { verifyCsrfOrOrigin } from '@/server/auth/csrf';
import { createPortalSession } from '@/server/billing/stripe';
import { getDb } from '@/server/db';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  await ensureInitialized();
  if (!verifyCsrfOrOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');
  const guard = await guardUser(req);
  if (!guard.ok) return guard.response;

  const cfg = getWebConfig();
  if (!cfg.stripe.configured) return errorJson('Billing is not enabled on this deployment.', 400, 'billing_unavailable');

  const customerId =
    guard.value.user.stripe_customer_id ??
    (getDb().prepare('SELECT stripe_customer_id FROM subscriptions WHERE user_id = ? ORDER BY id DESC LIMIT 1').get(guard.value.user.id) as
      | { stripe_customer_id: string }
      | undefined)?.stripe_customer_id;
  if (!customerId) return errorJson('No billing account found for this user.', 400, 'no_customer');

  try {
    const url = await createPortalSession(customerId, cfg);
    if (!url) return errorJson('Failed to open billing portal.', 500, 'portal_failed');
    return json({ url });
  } catch {
    return errorJson('Failed to open billing portal.', 500, 'portal_failed');
  }
}
