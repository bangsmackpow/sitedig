'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { apiFetch } from '@/app/lib/api';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await apiFetch('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) });
      router.push('/');
      router.refresh();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card auth-wrap">
      <h1>Sign in</h1>
      <p className="text-muted">Access your SiteDig account.</p>
      {error && <div className="error-box">{error}</div>}
      <form onSubmit={submit}>
        <div className="field">
          <label htmlFor="email">Email</label>
          <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" required />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
        </div>
        <div className="actions">
          <button className="button" type="submit" disabled={busy}>
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </div>
      </form>
      <p className="text-muted" style={{ marginTop: 16 }}>
        <Link className="link" href="/forgot-password">
          Forgot password?
        </Link>
        {' · '}
        <Link className="link" href="/register">
          Create an account
        </Link>
      </p>
    </div>
  );
}
