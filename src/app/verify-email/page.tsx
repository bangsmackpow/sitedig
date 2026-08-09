'use client';

import { Suspense, useEffect, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { apiFetch } from '@/app/lib/api';

function VerifyEmailInner() {
  const params = useSearchParams();
  const [state, setState] = useState<'loading' | 'ok' | 'error'>('loading');
  const [message, setMessage] = useState('Verifying your email…');

  useEffect(() => {
    const userId = Number(params.get('userId'));
    const token = params.get('token') ?? '';
    if (!userId || !token) {
      setState('error');
      setMessage('This verification link is invalid.');
      return;
    }
    apiFetch('/api/auth/verify-email', { method: 'POST', body: JSON.stringify({ userId, token }) })
      .then(() => {
        setState('ok');
        setMessage('Your email has been verified. You can now sign in.');
      })
      .catch((e) => {
        setState('error');
        setMessage((e as Error).message);
      });
  }, [params]);

  return (
    <div className="card auth-wrap">
      <h1>Email verification</h1>
      <div className={state === 'ok' ? 'info-box' : 'error-box'}>{message}</div>
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
