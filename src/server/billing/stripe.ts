import Stripe from 'stripe';
import { getWebConfig, type WebConfig } from '../../shared/config';
import { getDb } from '../db';
import { getUserById, setStripeCustomerId, getUserByEmail } from '../users';
import { grantEntitlement, revokeEntitlement, PREMIUM_KEY } from '../entitlements';
import { auditLog } from '../audit';

let client: Stripe | null = null;

export function getStripe(config: WebConfig = getWebConfig()): Stripe {
  if (!config.stripe.configured) throw new Error('Stripe is not configured on this deployment.');
  if (!client) {
    client = new Stripe(config.stripe.secretKey, { apiVersion: '2026-07-29.dahlia' });
  }
  return client;
}

/** Stripe statuses that keep Premium active (cancel-at-period-end keeps `active`). */
const ACTIVE_STATUSES = new Set(['active', 'trialing', 'past_due']);

export async function createCheckoutSession(userId: number, email: string, customerId: string | null, config: WebConfig = getWebConfig()): Promise<string | null> {
  const session = await getStripe(config).checkout.sessions.create({
    mode: 'subscription',
    line_items: [{ price: config.stripe.priceId, quantity: 1 }],
    customer: customerId ?? undefined,
    customer_email: customerId ? undefined : email,
    client_reference_id: String(userId),
    metadata: { user_id: String(userId) },
    success_url: `${config.appBaseUrl}/account?checkout=success`,
    cancel_url: `${config.appBaseUrl}/account?checkout=cancelled`,
  });
  return session.url;
}

export async function createPortalSession(customerId: string, config: WebConfig = getWebConfig()): Promise<string | null> {
  const session = await getStripe(config).billingPortal.sessions.create({
    customer: customerId,
    return_url: config.stripe.portalReturnUrl || `${config.appBaseUrl}/account`,
  });
  return session.url;
}

interface SubscriptionLike {
  id: string;
  customer: string | { id: string } | null;
  status: string;
  current_period_end?: number | null;
  current_period_start?: number | null;
  cancel_at_period_end?: boolean | null;
  items?: { data?: Array<{ price?: { id?: string | null } | null }> } | null;
  metadata?: Record<string, string> | null;
}

function findUserIdForSubscription(sub: SubscriptionLike): number | null {
  // Prefer stored mapping, then the Stripe customer id on a user.
  const row = getDb().prepare('SELECT user_id FROM subscriptions WHERE stripe_subscription_id = ?').get(sub.id) as { user_id: number } | undefined;
  if (row) return row.user_id;
  const customerId = typeof sub.customer === 'string' ? sub.customer : sub.customer?.id;
  if (customerId) {
    const byCustomer = getDb().prepare('SELECT user_id FROM subscriptions WHERE stripe_customer_id = ? ORDER BY id DESC').get(customerId) as { user_id: number } | undefined;
    if (byCustomer) return byCustomer.user_id;
    const byUser = getDb().prepare('SELECT id FROM users WHERE stripe_customer_id = ? AND deleted_at IS NULL').get(customerId) as { id: number } | undefined;
    if (byUser) return byUser.id;
  }
  return null;
}

/**
 * Persist a Stripe subscription and synchronize the Premium entitlement.
 * Subscription events are the source of truth for billing.
 */
export function applySubscriptionState(sub: SubscriptionLike): void {
  const userId = findUserIdForSubscription(sub);
  if (!userId) return;
  const now = new Date().toISOString();
  const customerId = typeof sub.customer === 'string' ? sub.customer : sub.customer?.id;
  const priceId = sub.items?.data?.[0]?.price?.id ?? null;
  const periodStart = sub.current_period_start ? new Date(sub.current_period_start * 1000).toISOString() : null;
  const periodEnd = sub.current_period_end ? new Date(sub.current_period_end * 1000).toISOString() : null;
  const cancelAtPeriodEnd = Boolean(sub.cancel_at_period_end);

  getDb()
    .prepare(
      `INSERT INTO subscriptions (user_id, stripe_customer_id, stripe_subscription_id, stripe_price_id, status, current_period_start, current_period_end, cancel_at_period_end, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(stripe_subscription_id) DO UPDATE SET
         status = excluded.status,
         stripe_price_id = excluded.stripe_price_id,
         current_period_start = excluded.current_period_start,
         current_period_end = excluded.current_period_end,
         cancel_at_period_end = excluded.cancel_at_period_end,
         updated_at = excluded.updated_at`,
    )
    .run(userId, customerId ?? '', sub.id, priceId, sub.status, periodStart, periodEnd, cancelAtPeriodEnd ? 1 : 0, now, now);

  const user = getUserById(userId);
  if (user && customerId && user.stripe_customer_id !== customerId) {
    setStripeCustomerId(userId, customerId);
  }

  if (ACTIVE_STATUSES.has(sub.status)) {
    grantEntitlement({ userId, key: PREMIUM_KEY, source: 'stripe', stripeSubscriptionId: sub.id });
    auditLog({ actorUserId: userId, action: 'subscription.active', targetUserId: userId, metadata: { status: sub.status, subscriptionId: sub.id } });
  } else {
    revokeEntitlement({ userId, key: PREMIUM_KEY, source: 'stripe' });
    auditLog({ actorUserId: userId, action: 'subscription.inactive', targetUserId: userId, metadata: { status: sub.status, subscriptionId: sub.id } });
  }
}

/** Handle a Stripe webhook event idempotently. */
export async function handleStripeEvent(event: Stripe.Event): Promise<void> {
  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object as Stripe.Checkout.Session;
      const userId = Number(session.metadata?.user_id ?? session.client_reference_id);
      if (userId && session.customer) {
        const user = getUserById(userId);
        if (user) setStripeCustomerId(userId, String(session.customer));
      }
      if (session.subscription) {
        const sub = await getStripe().subscriptions.retrieve(String(session.subscription));
        applySubscriptionState(sub as unknown as SubscriptionLike);
      }
      break;
    }
    case 'customer.subscription.created':
    case 'customer.subscription.updated':
    case 'customer.subscription.deleted': {
      applySubscriptionState(event.data.object as unknown as SubscriptionLike);
      break;
    }
    case 'invoice.paid': {
      const invoice = event.data.object as Stripe.Invoice;
      const invoiceSub = (invoice as { subscription?: string | null }).subscription;
      if (invoiceSub) {
        try {
          const sub = await getStripe().subscriptions.retrieve(invoiceSub);
          applySubscriptionState(sub as unknown as SubscriptionLike);
        } catch {
          // ignore; subscription events will follow
        }
      }
      break;
    }
    case 'invoice.payment_failed': {
      // Stripe emits customer.subscription.updated with `past_due` while retrying;
      // access is retained during the retry/grace window. Nothing to do here.
      break;
    }
    default:
      break;
  }
}

export async function cancelSubscriptionAtPeriodEnd(userId: number): Promise<void> {
  const row = getDb()
    .prepare('SELECT stripe_subscription_id FROM subscriptions WHERE user_id = ? AND status IN (?, ?) ORDER BY id DESC')
    .get(userId, 'active', 'trialing') as { stripe_subscription_id: string } | undefined;
  if (!row) return;
  await getStripe().subscriptions.update(row.stripe_subscription_id, { cancel_at_period_end: true });
}

export function hasActiveSubscription(userId: number): boolean {
  const row = getDb()
    .prepare('SELECT id FROM subscriptions WHERE user_id = ? AND status IN (?, ?)')
    .get(userId, 'active', 'trialing') as { id: number } | undefined;
  return Boolean(row);
}

export function getSubscriptionForUser(userId: number): SubscriptionLike | null {
  const row = getDb()
    .prepare('SELECT * FROM subscriptions WHERE user_id = ? ORDER BY id DESC LIMIT 1')
    .get(userId) as SubscriptionLike | null;
  return row;
}

export function findUserByEmailForBilling(email: string): ReturnType<typeof getUserByEmail> {
  return getUserByEmail(email);
}
