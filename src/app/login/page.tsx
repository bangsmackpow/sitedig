'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { apiFetch, type PublicUser } from '@/app/lib/api';

type MfaMethod = 'totp' | 'email' | 'recovery';

const METHOD_LABEL: Record<MfaMethod, string> = {
  totp: 'Authenticator app code',
  email: 'Emailed code',
  recovery: 'Recovery code',
};

export default function LoginPage() {
  const router = useRouter();
  const [step, setStep] = useState<'credentials' | 'mfa'>('credentials');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [ticket, setTicket] = useState('');
  const [methods, setMethods] = useState<MfaMethod[]>([]);
  const [method, setMethod] = useState<MfaMethod>('totp');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const nextPath = (): string => {
    const next = new URLSearchParams(window.location.search).get('next');
    return next && next.startsWith('/') && !next.startsWith('//') ? next : '/';
  };

  const submitCredentials = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const res = await apiFetch<{ user?: PublicUser; mfaRequired?: boolean; ticket?: string; methods?: MfaMethod[] }>('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });
      if (res.mfaRequired && res.ticket) {
        const available = res.methods ?? ['totp'];
        setTicket(res.ticket);
        setMethods(available);
        setMethod(available[0] ?? 'totp');
        setNotice(available.includes('email') ? 'We emailed you a sign-in code.' : null);
        setStep('mfa');
        return;
      }
      router.push(nextPath());
      router.refresh();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const submitMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await apiFetch('/api/auth/mfa/verify', { method: 'POST', body: JSON.stringify({ ticket, code, method }) });
      router.push(nextPath());
      router.refresh();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const resend = async () => {
    setError(null);
    setNotice(null);
    try {
      await apiFetch('/api/auth/mfa/send', { method: 'POST', body: JSON.stringify({ ticket }) });
      setNotice('A new code has been emailed to you.');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  if (step === 'mfa') {
    return (
      <div className="card auth-wrap">
        <h1>Two-factor authentication</h1>
        <p className="text-muted">Enter your verification code to finish signing in.</p>
        {error && <div className="error-box">{error}</div>}
        {notice && <div className="info-box">{notice}</div>}
        <form onSubmit={submitMfa}>
          {methods.length > 1 && (
            <div className="field">
              <label htmlFor="method">Method</label>
              <select id="method" value={method} onChange={(e) => setMethod(e.target.value as MfaMethod)}>
                {methods.map((m) => (
                  <option key={m} value={m}>
                    {METHOD_LABEL[m]}
                  </option>
                ))}
              </select>
            </div>
          )}
          <div className="field">
            <label htmlFor="code">{METHOD_LABEL[method]}</label>
            <input
              id="code"
              type="text"
              inputMode={method === 'email' || method === 'totp' ? 'numeric' : 'text'}
              autoComplete="one-time-code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              autoFocus
              required
            />
          </div>
          <div className="actions">
            <button className="button" type="submit" disabled={busy}>
              {busy ? 'Verifying…' : 'Verify'}
            </button>
            {methods.includes('email') && (
              <button className="button secondary" type="button" onClick={resend} disabled={busy}>
                Email me a new code
              </button>
            )}
          </div>
        </form>
        <p className="text-muted" style={{ marginTop: 16 }}>
          <button
            className="link-button"
            onClick={() => {
              setStep('credentials');
              setCode('');
              setError(null);
              setNotice(null);
            }}
          >
            Start over
          </button>
        </p>
      </div>
    );
  }

  return (
    <div className="card auth-wrap">
      <h1>Sign in</h1>
      <p className="text-muted">Access your SiteDig account.</p>
      {error && <div className="error-box">{error}</div>}
      <form onSubmit={submitCredentials}>
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
