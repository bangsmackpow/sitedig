import { getDb } from './db';

export function auditLog(input: { actorUserId?: number | null; action: string; targetUserId?: number | null; metadata?: Record<string, unknown> }): void {
  getDb()
    .prepare(`INSERT INTO audit_log (actor_user_id, action, target_user_id, metadata_json, created_at) VALUES (?, ?, ?, ?, ?)`)
    .run(
      input.actorUserId ?? null,
      input.action,
      input.targetUserId ?? null,
      input.metadata ? JSON.stringify(input.metadata) : null,
      new Date().toISOString(),
    );
}

export interface AuditRow {
  id: number;
  actor_user_id: number | null;
  action: string;
  target_user_id: number | null;
  metadata_json: string | null;
  created_at: string;
}

export function listAuditLog(limit = 100): AuditRow[] {
  return getDb().prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?').all(limit) as AuditRow[];
}
