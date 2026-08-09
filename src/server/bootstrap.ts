import { getWebConfig, validateWebConfig } from '../shared/config';
import { getDb } from './db';
import { createUser } from './users';
import { hashPassword } from './auth/passwords';
import { auditLog } from './audit';

let initialized = false;

/**
 * Run once per process: validate config, run migrations, and bootstrap the
 * first admin from environment variables when no admin exists. The bootstrap
 * variables can be removed after first startup.
 */
export async function ensureInitialized(): Promise<void> {
  if (initialized) return;
  const cfg = getWebConfig();
  if (cfg.deploymentMode === 'hosted') {
    validateWebConfig(cfg);
  }
  getDb(); // opens DB + runs migrations

  const adminCount = (getDb().prepare(`SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND deleted_at IS NULL`).get() as { c: number }).c;
  if (adminCount === 0) {
    if (!cfg.initialAdminEmail || !cfg.initialAdminPassword) {
      throw new Error('No admin account exists. Set INITIAL_ADMIN_EMAIL and INITIAL_ADMIN_PASSWORD to create the first admin.');
    }
    const user = createUser({ email: cfg.initialAdminEmail, passwordHash: await hashPassword(cfg.initialAdminPassword), role: 'admin', verified: true });
    auditLog({ actorUserId: user.id, action: 'admin.bootstrap', targetUserId: user.id });
  }
  initialized = true;
}

export function isInitialized(): boolean {
  return initialized;
}
