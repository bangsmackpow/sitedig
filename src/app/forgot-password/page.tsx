'use client';

import { useState } from 'react';
import Link from 'next/link';
import { apiFetch } from '@/app/lib/api';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage(null);
    setBusy(true);
    try {
      await apiFetch('/api/auth/request-password-reset', { method: 'POST', body: JSON.stringify({ email }) });
      setMessage('If that email has an account, a password reset link has been sent.');
    } catch (err) {
      setMessage((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card auth-wrap">
      <h1>Reset your password</h1>
      {message && <div className="info-box">{message}</div>}
      <form onSubmit={submit}>
        <div className="field">
          <label htmlFor="email">Email</label>
          <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" required />
        </div>
        <div className="actions">
          <button className="button" type="submit" disabled={busy}>
            {busy ? 'Sending…' : 'Send reset link'}
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
