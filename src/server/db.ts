import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import type { Database as DatabaseType } from 'better-sqlite3';

export type Db = DatabaseType;

export interface Migration {
  version: number;
  sql: string;
}

const MIGRATIONS: Migration[] = [
  {
    version: 1,
    sql: `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  email_normalized TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  email_verified_at TEXT,
  role TEXT NOT NULL DEFAULT 'user',
  status TEXT NOT NULL DEFAULT 'active',
  stripe_customer_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_users_email_normalized ON users(email_normalized);

CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  last_seen_at TEXT,
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  user_agent_hash TEXT,
  ip_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);

CREATE TABLE IF NOT EXISTS email_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  purpose TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_email_tokens_user ON email_tokens(user_id, purpose);

CREATE TABLE IF NOT EXISTS subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  stripe_customer_id TEXT NOT NULL,
  stripe_subscription_id TEXT NOT NULL UNIQUE,
  stripe_price_id TEXT,
  status TEXT NOT NULL,
  current_period_start TEXT,
  current_period_end TEXT,
  cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_customer ON subscriptions(stripe_customer_id);

CREATE TABLE IF NOT EXISTS entitlements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  entitlement_key TEXT NOT NULL,
  source TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  starts_at TEXT,
  ends_at TEXT,
  created_by_user_id INTEGER,
  stripe_subscription_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(user_id, entitlement_key, source)
);
CREATE INDEX IF NOT EXISTS idx_entitlements_user ON entitlements(user_id);

CREATE TABLE IF NOT EXISTS webhook_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  stripe_event_id TEXT NOT NULL UNIQUE,
  event_type TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  processed_at TEXT NOT NULL,
  processing_error TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_user_id INTEGER,
  action TEXT NOT NULL,
  target_user_id INTEGER,
  metadata_json TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);
`,
  },
];

export function openDatabase(dbPath: string): Db {
  if (dbPath !== ':memory:') {
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  }
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  migrate(db);
  return db;
}

export function migrate(db: Db): void {
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at TEXT NOT NULL
    );
  `);
  const applied = new Set<number>(
    (db.prepare('SELECT version FROM schema_migrations').all() as Array<{ version: number }>).map((r) => r.version),
  );
  for (const migration of MIGRATIONS) {
    if (applied.has(migration.version)) continue;
    const run = db.transaction(() => {
      db.exec(migration.sql);
      db.prepare('INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)').run(migration.version, new Date().toISOString());
    });
    run();
  }
}

let singleton: Db | null = null;

/** Process-wide singleton backed by DATABASE_PATH (or DB_PATH override for tests). */
export function getDb(): Db {
  if (singleton) return singleton;
  const dbPath = process.env.DB_PATH || process.env.DATABASE_PATH || './data/sitedig.sqlite';
  singleton = openDatabase(dbPath);
  return singleton;
}

export function resetDbForTests(): void {
  if (singleton) {
    singleton.close();
    singleton = null;
  }
}
