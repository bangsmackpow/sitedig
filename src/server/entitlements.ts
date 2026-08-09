import { getDb } from './db';
import type { UserRow } from './users';
import type { ModuleId } from '../shared/types';
import { MODULE_DEFINITIONS } from '../shared/modules';

export const PREMIUM_KEY = 'premium';

export const MODULE_ENTITLEMENT_KEYS: Record<ModuleId, string> = {
  'asset-discovery': 'module:asset-discovery',
  'vuln-scan': 'module:vuln-scan',
  'tls-hardening': 'module:tls-hardening',
  'content-discovery': 'module:content-discovery',
  'cve-context': 'module:cve-context',
};

export type EntitlementSource = 'admin' | 'stripe';

export function getActiveEntitlementKeys(userId: number): Set<string> {
  const now = new Date().toISOString();
  const rows = getDb()
    .prepare(
      `SELECT entitlement_key FROM entitlements
       WHERE user_id = ? AND status = 'active' AND (ends_at IS NULL OR ends_at > ?)`,
    )
    .all(userId, now) as Array<{ entitlement_key: string }>;
  return new Set(rows.map((r) => r.entitlement_key));
}

export function hasEntitlement(userId: number, key: string): boolean {
  return getActiveEntitlementKeys(userId).has(key);
}

/** A user is Premium when they are an admin or hold the active premium entitlement. */
export function isPremium(user: UserRow): boolean {
  if (user.role === 'admin') return true;
  return hasEntitlement(user.id, PREMIUM_KEY);
}

export function grantEntitlement(input: {
  userId: number;
  key: string;
  source: EntitlementSource;
  createdByUserId?: number;
  stripeSubscriptionId?: string;
  endsAt?: string;
}): void {
  const now = new Date().toISOString();
  getDb()
    .prepare(
      `INSERT INTO entitlements (user_id, entitlement_key, source, status, starts_at, ends_at, created_by_user_id, stripe_subscription_id, created_at, updated_at)
       VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?)
       ON CONFLICT(user_id, entitlement_key, source) DO UPDATE SET
         status = 'active',
         starts_at = excluded.starts_at,
         ends_at = excluded.ends_at,
         stripe_subscription_id = excluded.stripe_subscription_id,
         updated_at = excluded.updated_at`,
    )
    .run(input.userId, input.key, input.source, now, input.endsAt ?? null, input.createdByUserId ?? null, input.stripeSubscriptionId ?? null, now, now);
}

export function revokeEntitlement(input: { userId: number; key: string; source: EntitlementSource }): void {
  getDb()
    .prepare(`UPDATE entitlements SET status = 'revoked', updated_at = ? WHERE user_id = ? AND entitlement_key = ? AND source = ? AND status = 'active'`)
    .run(new Date().toISOString(), input.userId, input.key, input.source);
}

export function revokeAllActiveEntitlements(userId: number): void {
  getDb().prepare(`UPDATE entitlements SET status = 'revoked', updated_at = ? WHERE user_id = ? AND status = 'active'`).run(new Date().toISOString(), userId);
}

/**
 * Whether a user may use a paid module. Requires both the deployment-level
 * availability ceiling (ENABLED_MODULES) and Premium (admin or entitlement).
 */
export function canUseModule(userId: number, user: UserRow, moduleId: ModuleId, deploymentEnabledModules: Set<ModuleId>): boolean {
  if (!deploymentEnabledModules.has(moduleId)) return false;
  if (moduleId in MODULE_ENTITLEMENT_KEYS && hasEntitlement(userId, MODULE_ENTITLEMENT_KEYS[moduleId])) return true;
  return isPremium(user);
}
