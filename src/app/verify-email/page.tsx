'use client';

import { Suspense, useEffect, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { apiFetch } from '@/app/lib/api';

function VerifyEmailInner() {
  const params = useSearchParams();
  const userId = Number(params.get('userId'));
  const token = params.get('token') ?? '';
  const [state, setState] = useState<'idle' | 'loading' | 'ok' | 'error'>('idle');
  const [message, setMessage] = useState('Confirm this email address to activate your account.');

  useEffect(() => {
    if (!userId || !token) {
      setState('error');
      setMessage('This verification link is invalid.');
    }
  }, [userId, token]);

  const verify = async () => {
    setState('loading');
    setMessage('Verifying your email…');
    try {
      await apiFetch('/api/auth/verify-email', { method: 'POST', body: JSON.stringify({ userId, token }) });
      setState('ok');
      setMessage('Your email has been verified. You can now sign in.');
    } catch (e) {
      setState('error');
      setMessage((e as Error).message);
    }
  };

  return (
    <div className="card auth-wrap">
      <h1>Email verification</h1>
      <div className={state === 'error' ? 'error-box' : 'info-box'}>{message}</div>
      {state !== 'ok' && userId > 0 && token && (
        <div className="actions" style={{ marginTop: 16 }}>
          <button className="button" onClick={verify} disabled={state === 'loading'}>
            {state === 'loading' ? 'Verifying…' : 'Verify email'}
          </button>
        </div>
      )}
      <p className="text-muted" style={{ marginTop: 16 }}>
        <Link className="link" href="/login">
          Sign in
        </Link>
      </p>
    </div>
  );
}

export default function VerifyEmailPage() {
  return (
    <Suspense>
      <VerifyEmailInner />
    </Suspense>
  );
}
