'use client';

import { Suspense, useState } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { apiFetch } from '@/app/lib/api';

function ResetPasswordInner() {
  const router = useRouter();
  const params = useSearchParams();
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    const userId = Number(params.get('userId'));
    const token = params.get('token') ?? '';
    try {
      await apiFetch('/api/auth/reset-password', { method: 'POST', body: JSON.stringify({ userId, token, password }) });
      setDone(true);
      router.push('/login');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (done) {
    return (
      <div className="card auth-wrap">
        <h1>Password reset</h1>
        <div className="info-box">Your password has been reset. Signing you in…</div>
      </div>
    );
  }

  return (
    <div className="card auth-wrap">
      <h1>Set a new password</h1>
      {error && <div className="error-box">{error}</div>}
      <form onSubmit={submit}>
        <div className="field">
          <label htmlFor="password">New password</label>
          <input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required />
          <p className="hint">At least 12 characters.</p>
        </div>
        <div className="actions">
          <button className="button" type="submit" disabled={busy}>
            {busy ? 'Saving…' : 'Save password'}
          </button>
        </div>
      </form>
      <p className="text-muted" style={{ marginTop: 16 }}>
        <Link className="link" href="/login">
          Back to sign in
        </Link>
      </p>
    </div>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense>
      <ResetPasswordInner />
    </Suspense>
  );
}
