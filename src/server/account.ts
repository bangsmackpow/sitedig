import { getDb } from './db';
import { getUserById, hardDeleteUser, updateUserStatus } from './users';
import { cancelSubscriptionAtPeriodEnd, hasActiveSubscription } from './billing/stripe';
import { auditLog } from './audit';

export async function requestAccountDeletion(userId: number): Promise<void> {
  if (hasActiveSubscription(userId)) {
    await cancelSubscriptionAtPeriodEnd(userId);
    updateUserStatus(userId, 'deletion_pending');
    auditLog({ actorUserId: userId, action: 'account.deletion_requested', targetUserId: userId });
  } else {
    hardDeleteUser(userId);
    auditLog({ actorUserId: userId, action: 'account.deleted', targetUserId: userId });
  }
}

export function completeDeletionIfDue(userId: number): void {
  const user = getUserById(userId);
  if (!user) return;
  if (user.status === 'deletion_pending' && !hasActiveSubscription(userId)) {
    hardDeleteUser(userId);
    auditLog({ actorUserId: userId, action: 'account.deletion_completed', targetUserId: userId });
  }
}

export function isDeletionPending(userId: number): boolean {
  return getUserById(userId)?.status === 'deletion_pending';
}

export function countDeletionPending(): number {
  return (getDb().prepare(`SELECT COUNT(*) AS c FROM users WHERE status = 'deletion_pending'`).get() as { c: number }).c;
}
