'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { apiFetch, type MePayload } from '@/app/lib/api';

interface AdminUser {
  id: number;
  email: string;
  role: 'admin' | 'user';
  status: string;
  emailVerified: boolean;
  premium: boolean;
  createdAt: string;
}

interface AuditEvent {
  id: number;
  actor_user_id: number | null;
  action: string;
  target_user_id: number | null;
  metadata_json: string | null;
  created_at: string;
}

export default function AdminPage() {
  const router = useRouter();
  const [me, setMe] = useState<MePayload | null>(null);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [query, setQuery] = useState('');

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<'user' | 'admin'>('user');

  const loadAll = useCallback(async () => {
    try {
      const m = await apiFetch<MePayload>('/api/auth/me');
      setMe(m);
      if (m.user.role !== 'admin') {
        setError('Admin access required.');
        return;
      }
      const u = await apiFetch<{ users: AdminUser[] }>('/api/admin/users');
      setUsers(u.users);
      const a = await apiFetch<{ events: AuditEvent[] }>('/api/admin/audit');
      setAudit(a.events);
    } catch (e) {
      if ((e as { status?: number }).status === 401) {
        router.replace('/login');
        return;
      }
      setError((e as Error).message);
    }
  }, [router]);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  const search = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const u = await apiFetch<{ users: AdminUser[] }>(`/api/admin/users?q=${encodeURIComponent(query)}`);
      setUsers(u.users);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const createUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    try {
      await apiFetch('/api/admin/users', { method: 'POST', body: JSON.stringify({ email, password, role }) });
      setEmail('');
      setPassword('');
      setNotice('User created.');
      await loadAll();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const grant = async (id: number) => {
    try {
      await apiFetch(`/api/admin/users/${id}/grant-premium`, { method: 'POST' });
      await loadAll();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const revoke = async (id: number) => {
    try {
      await apiFetch(`/api/admin/users/${id}/revoke-premium`, { method: 'POST' });
      await loadAll();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const toggleStatus = async (u: AdminUser) => {
    try {
      await apiFetch(`/api/admin/users/${u.id}`, { method: 'PATCH', body: JSON.stringify({ status: u.status === 'active' ? 'disabled' : 'active' }) });
      await loadAll();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const remove = async (u: AdminUser) => {
    if (!window.confirm(`Delete ${u.email}?`)) return;
    try {
      await apiFetch(`/api/admin/users/${u.id}`, { method: 'DELETE' });
      await loadAll();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  if (me && me.user.role !== 'admin') {
    return (
      <div className="card">
        <h1>Admin</h1>
        <div className="error-box">Admin access required.</div>
        <Link className="link" href="/">
          Back to scans
        </Link>
      </div>
    );
  }

  return (
    <div className="card">
      <h1>Admin console</h1>
      <p className="text-muted">
        Create users, manage status, and grant or revoke Premium. <Link className="link" href="/">Back to scans</Link>
      </p>
      {error && <div className="error-box">{error}</div>}
      {notice && <div className="info-box">{notice}</div>}

      <form className="row" onSubmit={createUser} style={{ marginTop: 16 }}>
        <div className="field">
          <label htmlFor="u-email">Email</label>
          <input id="u-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </div>
        <div className="field">
          <label htmlFor="u-password">Password</label>
          <input id="u-password" type="text" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </div>
        <div className="field">
          <label htmlFor="u-role">Role</label>
          <select id="u-role" value={role} onChange={(e) => setRole(e.target.value as 'user' | 'admin')}>
            <option value="user">User</option>
            <option value="admin">Admin</option>
          </select>
        </div>
        <div className="field">
          <label>&nbsp;</label>
          <button className="button" type="submit">
            Create user
          </button>
        </div>
      </form>

      <form onSubmit={search} style={{ margin: '16px 0' }}>
        <input type="text" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search by email…" style={{ maxWidth: 320, display: 'inline-block', marginRight: 8 }} />
        <button className="button secondary" type="submit">
          Search
        </button>
      </form>

      <table className="table">
        <thead>
          <tr>
            <th>Email</th>
            <th>Role</th>
            <th>Status</th>
            <th>Premium</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id}>
              <td>
                {u.email}
                {!u.emailVerified && <span style={{ marginLeft: 8 }} className="pill info">unverified</span>}
              </td>
              <td>{u.role}</td>
              <td>
                <span className={`pill ${u.status === 'active' ? 'active' : 'disabled'}`}>{u.status}</span>
              </td>
              <td>{u.premium ? <span className="pill active">Premium</span> : <span className="pill info">Free</span>}</td>
              <td style={{ whiteSpace: 'nowrap' }}>
                <button className="button secondary" style={{ marginRight: 6, padding: '4px 10px' }} onClick={() => (u.premium ? revoke(u.id) : grant(u.id))}>
                  {u.premium ? 'Revoke Premium' : 'Grant Premium'}
                </button>
                <button className="button secondary" style={{ marginRight: 6, padding: '4px 10px' }} onClick={() => toggleStatus(u)}>
                  {u.status === 'active' ? 'Disable' : 'Enable'}
                </button>
                <button className="button danger" style={{ padding: '4px 10px' }} onClick={() => remove(u)}>
                  Delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2 style={{ marginTop: 32 }}>Audit log</h2>
      <table className="table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Target</th>
          </tr>
        </thead>
        <tbody>
          {audit.slice(0, 50).map((a) => (
            <tr key={a.id}>
              <td>{new Date(a.created_at).toLocaleString()}</td>
              <td>{a.actor_user_id ?? 'system'}</td>
              <td>{a.action}</td>
              <td>{a.target_user_id ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
