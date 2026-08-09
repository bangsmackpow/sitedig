'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { apiFetch } from '@/app/lib/api';

export default function RegisterPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setMessage(null);
    setBusy(true);
    try {
      const data = await apiFetch<{ needsVerification: boolean }>('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });
      if (data.needsVerification) {
        setMessage('Account created. Check your email for a verification link, then sign in.');
      } else {
        router.push('/');
        router.refresh();
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card auth-wrap">
      <h1>Create an account</h1>
      <p className="text-muted">Register for free and run base scans, or upgrade to Premium later.</p>
      {error && <div className="error-box">{error}</div>}
      {message && <div className="info-box">{message}</div>}
      <form onSubmit={submit}>
        <div className="field">
          <label htmlFor="email">Email</label>
          <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" required />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required />
          <p className="hint">At least 12 characters.</p>
        </div>
        <div className="actions">
          <button className="button" type="submit" disabled={busy}>
            {busy ? 'Creating…' : 'Create account'}
          </button>
        </div>
      </form>
      <p className="text-muted" style={{ marginTop: 16 }}>
        Already have an account?{' '}
        <Link className="link" href="/login">
          Sign in
        </Link>
      </p>
    </div>
  );
}
