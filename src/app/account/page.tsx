'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { apiFetch, type MePayload } from '@/app/lib/api';

export default function AccountPage() {
  const router = useRouter();
  const [me, setMe] = useState<MePayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setMe(await apiFetch<MePayload>('/api/auth/me'));
    } catch (e) {
      if ((e as { status?: number }).status === 401) {
        router.replace('/login');
        return;
      }
      setError((e as Error).message);
    }
  }, [router]);

  useEffect(() => {
    load();
  }, [load]);

  const upgrade = async () => {
    setBusy(true);
    setError(null);
    try {
      const data = await apiFetch<{ url: string }>('/api/billing/checkout', { method: 'POST' });
      window.location.href = data.url;
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  };

  const openPortal = async () => {
    setBusy(true);
    setError(null);
    try {
      const data = await apiFetch<{ url: string }>('/api/billing/portal', { method: 'POST' });
      window.location.href = data.url;
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  };

  const deleteAccount = async () => {
    if (!window.confirm('Delete your account? If you have an active subscription, it will be cancelled at the end of the current period.')) return;
    setBusy(true);
    setError(null);
    try {
      await apiFetch('/api/account', { method: 'DELETE' });
      router.push('/login');
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  };

  if (!me) {
    return <div className="card auth-wrap"><div className="info-box">Loading…</div></div>;
  }

  const sub = me.subscription;

  return (
    <div className="card">
      <h1>Account</h1>
      {error && <div className="error-box">{error}</div>}

      <div className="row">
        <div className="field">
          <label>Email</label>
          <p>{me.user.email}</p>
        </div>
        <div className="field">
          <label>Role</label>
          <p>{me.user.role}</p>
        </div>
      </div>

      <div className="field">
        <label>Plan</label>
        <p>
          {me.user.premium ? <span className="pill active">Premium</span> : <span className="pill info">Free</span>}
          {me.user.role === 'admin' && <span style={{ marginLeft: 8 }} className="pill info">Admin</span>}
        </p>
      </div>

      {sub && (
        <div className="field">
          <label>Subscription</label>
          <p>
            <span className={`pill ${sub.status === 'active' || sub.status === 'trialing' ? 'active' : 'disabled'}`}>{sub.status}</span>
            {sub.cancelAtPeriodEnd && <span style={{ marginLeft: 8 }} className="pill info">Cancels at period end</span>}
            {sub.currentPeriodEnd && <span className="text-muted" style={{ marginLeft: 8 }}>Renews {new Date(sub.currentPeriodEnd).toLocaleDateString()}</span>}
          </p>
        </div>
      )}

      <div className="actions">
        {!me.user.premium && me.user.status !== 'deletion_pending' && (
          <button className="button" onClick={upgrade} disabled={busy}>
            Upgrade to Premium
          </button>
        )}
        {sub && (
          <button className="button secondary" onClick={openPortal} disabled={busy}>
            Manage billing
          </button>
        )}
        {me.user.role === 'admin' && (
          <Link className="button secondary" href="/admin">
            Admin console
          </Link>
        )}
        <Link className="button secondary" href="/">
          Back to scans
        </Link>
      </div>

      {me.user.status === 'deletion_pending' && (
        <div className="info-box" style={{ marginTop: 16 }}>
          Your account is marked for deletion and will be removed when your subscription ends.
        </div>
      )}

      <div className="field" style={{ marginTop: 24 }}>
        <button className="button danger" onClick={deleteAccount} disabled={busy}>
          Delete account
        </button>
      </div>
    </div>
  );
}
