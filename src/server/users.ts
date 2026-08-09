import { getDb } from './db';

export interface UserRow {
  id: number;
  email: string;
  email_normalized: string;
  password_hash: string;
  email_verified_at: string | null;
  role: 'admin' | 'user';
  status: 'active' | 'disabled' | 'deletion_pending';
  stripe_customer_id: string | null;
  created_at: string;
  updated_at: string;
  deleted_at: string | null;
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function createUser(input: {
  email: string;
  passwordHash: string;
  role?: 'admin' | 'user';
  verified?: boolean;
}): UserRow {
  const now = new Date().toISOString();
  const emailNormalized = normalizeEmail(input.email);
  const result = getDb()
    .prepare(
      `INSERT INTO users (email, email_normalized, password_hash, email_verified_at, role, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 'active', ?, ?)`,
    )
    .run(
      input.email,
      emailNormalized,
      input.passwordHash,
      input.verified ? now : null,
      input.role ?? 'user',
      now,
      now,
    );
  return getUserById(Number(result.lastInsertRowid))!;
}

export function getUserById(id: number): UserRow | null {
  const row = getDb().prepare('SELECT * FROM users WHERE id = ? AND deleted_at IS NULL').get(id) as UserRow | undefined;
  return row ?? null;
}

export function getUserByEmail(email: string): UserRow | null {
  const row = getDb()
    .prepare('SELECT * FROM users WHERE email_normalized = ? AND deleted_at IS NULL')
    .get(normalizeEmail(email)) as UserRow | undefined;
  return row ?? null;
}

export function userExistsByEmail(email: string): boolean {
  return Boolean(getUserByEmail(email));
}

export function setUserVerified(id: number): void {
  const now = new Date().toISOString();
  getDb().prepare('UPDATE users SET email_verified_at = ?, updated_at = ? WHERE id = ?').run(now, now, id);
}

export function isUserVerified(user: UserRow): boolean {
  return Boolean(user.email_verified_at);
}

export function updateUserStatus(id: number, status: UserRow['status']): void {
  getDb().prepare('UPDATE users SET status = ?, updated_at = ? WHERE id = ?').run(status, new Date().toISOString(), id);
}

export function setStripeCustomerId(id: number, customerId: string): void {
  getDb().prepare('UPDATE users SET stripe_customer_id = ?, updated_at = ? WHERE id = ?').run(customerId, new Date().toISOString(), id);
}

export function listUsers(query?: string): UserRow[] {
  const db = getDb();
  const base = 'SELECT * FROM users WHERE deleted_at IS NULL';
  const params: unknown[] = [];
  if (query) {
    params.push(`%${normalizeEmail(query)}%`);
    return db.prepare(`${base} AND email_normalized LIKE ? ORDER BY created_at DESC LIMIT 100`).all(...params) as UserRow[];
  }
  return db.prepare(`${base} ORDER BY created_at DESC LIMIT 200`).all() as UserRow[];
}

export function hardDeleteUser(id: number): void {
  // Audit log rows are kept; foreign-key cascade removes sessions, email tokens,
  // subscriptions, and entitlements.
  getDb().prepare('DELETE FROM users WHERE id = ?').run(id);
}
