import type { NextRequest } from 'next/server';
import { getWebConfig } from '@/shared/config';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json } from '@/server/http';
import { guardUser } from '@/server/http';
import { verifyCsrfOrOrigin } from '@/server/auth/csrf';
import { createCheckoutSession } from '@/server/billing/stripe';
import { isDeletionPending } from '@/server/account';
import { isUserVerified } from '@/server/users';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  await ensureInitialized();
  if (!verifyCsrfOrOrigin(req)) return errorJson('Request origin not allowed.', 403, 'forbidden');
  const guard = await guardUser(req);
  if (!guard.ok) return guard.response;

  const cfg = getWebConfig();
  if (!cfg.stripe.configured) return errorJson('Billing is not enabled on this deployment.', 400, 'billing_unavailable');
  const user = guard.value.user;
  if (!isUserVerified(user)) return errorJson('Verify your email before upgrading.', 403, 'email_not_verified');
  if (isDeletionPending(user.id)) return errorJson('This account is pending deletion.', 403, 'deletion_pending');

  try {
    const url = await createCheckoutSession(user.id, user.email, user.stripe_customer_id, cfg);
    if (!url) return errorJson('Failed to start checkout.', 500, 'checkout_failed');
    return json({ url });
  } catch {
    return errorJson('Failed to start checkout.', 500, 'checkout_failed');
  }
}
