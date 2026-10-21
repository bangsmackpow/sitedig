import { getDb } from './db';

export function getSetting(key: string): string | null {
  const row = getDb().prepare('SELECT value FROM app_settings WHERE key = ?').get(key) as { value: string | null } | undefined;
  return row?.value ?? null;
}

export function setSetting(key: string, value: string): void {
  getDb()
    .prepare(
      `INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    )
    .run(key, value, new Date().toISOString());
}

/** Best-effort cross-process lock stored in app_settings; stale after `ttlMs`. */
export function acquireLock(key: string, ttlMs: number): boolean {
  const now = new Date();
  const staleBefore = new Date(now.getTime() - ttlMs).toISOString();
  const result = getDb()
    .prepare(
      `INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
       WHERE app_settings.updated_at < ?`,
    )
    .run(key, now.toISOString(), now.toISOString(), staleBefore);
  return result.changes > 0;
}

export function releaseLock(key: string): void {
  getDb().prepare('DELETE FROM app_settings WHERE key = ?').run(key);
}
