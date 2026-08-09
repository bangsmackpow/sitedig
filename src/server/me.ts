import { getUserById } from './users';
import { isPremium } from './entitlements';
import { getSubscriptionForUser } from './billing/stripe';
import { completeDeletionIfDue } from './account';
import { toPublicUser } from './auth/service';

export interface MePayload {
  user: ReturnType<typeof toPublicUser>;
  subscription: { status: string; currentPeriodEnd: string | null; cancelAtPeriodEnd: boolean; priceId: string | null } | null;
}

export function buildMePayload(userId: number): MePayload | null {
  completeDeletionIfDue(userId);
  const user = getUserById(userId);
  if (!user) return null;
  const sub = getSubscriptionForUser(userId) as
    | { status: string; current_period_end: string | null; cancel_at_period_end: number | boolean; stripe_price_id: string | null }
    | null;
  return {
    user: toPublicUser(user, isPremium(user)),
    subscription: sub
      ? {
          status: sub.status,
          currentPeriodEnd: sub.current_period_end,
          cancelAtPeriodEnd: Boolean(sub.cancel_at_period_end),
          priceId: sub.stripe_price_id,
        }
      : null,
  };
}
