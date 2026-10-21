'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { apiFetch, type MePayload } from '@/app/lib/api';

interface TotpSetup {
  secret: string;
  otpauthUri: string;
  qrDataUrl: string;
}

export default function AccountPage() {
  const router = useRouter();
  const [me, setMe] = useState<MePayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [mfaPassword, setMfaPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [totpSetup, setTotpSetup] = useState<TotpSetup | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);

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

  // --- MFA actions ---------------------------------------------------------
  const mfaPost = async (body: Record<string, unknown>) =>
    apiFetch<{ mfa: MePayload['mfa']; recoveryCodes?: string[]; totp?: TotpSetup }>('/api/account/mfa', {
      method: 'POST',
      body: JSON.stringify(body),
    });

  const clearMessages = () => {
    setError(null);
    setNotice(null);
  };

  const toggleEmailMfa = async (enabled: boolean) => {
    clearMessages();
    setBusy(true);
    try {
      await mfaPost({ action: 'email', enabled, password: mfaPassword });
      setMfaPassword('');
      setNotice(enabled ? 'Email MFA enabled.' : 'Email MFA disabled.');
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const beginTotp = async () => {
    clearMessages();
    setBusy(true);
    try {
      const res = await mfaPost({ action: 'totp-begin', password: mfaPassword });
      setMfaPassword('');
      setTotpSetup(res.totp ?? null);
      setTotpCode('');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const confirmTotp = async () => {
    clearMessages();
    setBusy(true);
    try {
      const res = await mfaPost({ action: 'totp-confirm', code: totpCode });
      setTotpSetup(null);
      setTotpCode('');
      setRecoveryCodes(res.recoveryCodes ?? null);
      setNotice('Authenticator app enabled. Save your recovery codes.');
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const disableTotp = async () => {
    clearMessages();
    setBusy(true);
    try {
      await mfaPost({ action: 'totp-disable', password: mfaPassword, code: mfaCode });
      setMfaPassword('');
      setMfaCode('');
      setNotice('Authenticator app disabled.');
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const regenerateRecovery = async () => {
    clearMessages();
    setBusy(true);
    try {
      const res = await mfaPost({ action: 'recovery-regenerate', password: mfaPassword, code: mfaCode });
      setMfaPassword('');
      setMfaCode('');
      setRecoveryCodes(res.recoveryCodes ?? null);
      setNotice('New recovery codes generated. Your previous codes no longer work.');
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (!me) {
    return <div className="card auth-wrap"><div className="info-box">Loading…</div></div>;
  }

  const sub = me.subscription;
  const mfa = me.mfa;

  return (
    <div className="card">
      <h1>Account</h1>
      {error && <div className="error-box">{error}</div>}
      {notice && <div className="info-box">{notice}</div>}

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
        <Link className="button secondary" href="/history">
          Scan history
        </Link>
        <Link className="button secondary" href="/">
          Back to scans
        </Link>
      </div>

      <h2 style={{ marginTop: 32 }}>Two-factor authentication</h2>
      <p className="text-muted">Add a second step to sign-in. Email codes work anywhere; an authenticator app is phishing-resistant.</p>

      {!me.user.emailVerified && (
        <div className="info-box">Verify your email address before enabling email MFA.</div>
      )}

      <div className="field">
        <label>Email codes</label>
        <p>
          {mfa.emailEnabled ? <span className="pill active">Enabled</span> : <span className="pill info">Disabled</span>}
        </p>
      </div>

      <div className="field">
        <label>Authenticator app (TOTP)</label>
        <p>
          {mfa.totpEnabled ? <span className="pill active">Enabled</span> : <span className="pill info">Disabled</span>}
          {mfa.totpEnabled && (
            <span className="text-muted" style={{ marginLeft: 8 }}>
              {mfa.recoveryCodesRemaining} recovery code{mfa.recoveryCodesRemaining === 1 ? '' : 's'} remaining
            </span>
          )}
        </p>
      </div>

      <div className="field">
        <label htmlFor="mfa-password">Confirm with your password</label>
        <input
          id="mfa-password"
          type="password"
          value={mfaPassword}
          onChange={(e) => setMfaPassword(e.target.value)}
          placeholder="Current password"
          autoComplete="current-password"
        />
        <p className="hint">Required to enable, disable, or regenerate any MFA setting.</p>
      </div>

      {mfa.totpEnabled && (
        <div className="field">
          <label htmlFor="mfa-code">Authenticator or recovery code</label>
          <input
            id="mfa-code"
            type="text"
            value={mfaCode}
            onChange={(e) => setMfaCode(e.target.value)}
            placeholder="Current code"
            autoComplete="one-time-code"
          />
          <p className="hint">Required to disable TOTP or regenerate recovery codes.</p>
        </div>
      )}

      <div className="actions">
        {!mfa.emailEnabled ? (
          <button className="button secondary" onClick={() => toggleEmailMfa(true)} disabled={busy || !me.user.emailVerified}>
            Enable email codes
          </button>
        ) : (
          <button className="button secondary" onClick={() => toggleEmailMfa(false)} disabled={busy}>
            Disable email codes
          </button>
        )}
        {!mfa.totpEnabled && !totpSetup && (
          <button className="button secondary" onClick={beginTotp} disabled={busy}>
            Set up authenticator app
          </button>
        )}
        {mfa.totpEnabled && (
          <button className="button secondary" onClick={disableTotp} disabled={busy || !mfaCode}>
            Disable authenticator app
          </button>
        )}
        {mfa.totpEnabled && (
          <button className="button secondary" onClick={regenerateRecovery} disabled={busy || !mfaCode}>
            Regenerate recovery codes
          </button>
        )}
      </div>

      {totpSetup && (
        <div className="profile-description" style={{ marginTop: 16 }}>
          <h3>Scan this code with your authenticator app</h3>
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src={totpSetup.qrDataUrl} alt="TOTP QR code" width={220} height={220} style={{ background: '#fff', padding: 8, borderRadius: 8 }} />
          <p className="hint">Or enter this key manually:</p>
          <code style={{ wordBreak: 'break-all' }}>{totpSetup.secret}</code>
          <div className="field" style={{ marginTop: 12 }}>
            <label htmlFor="totp-code">Enter the 6-digit code to confirm</label>
            <input id="totp-code" type="text" inputMode="numeric" value={totpCode} onChange={(e) => setTotpCode(e.target.value)} autoComplete="one-time-code" />
          </div>
          <div className="actions">
            <button className="button" onClick={confirmTotp} disabled={busy}>
              Confirm
            </button>
            <button className="button secondary" onClick={() => setTotpSetup(null)} disabled={busy}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {recoveryCodes && (
        <div className="profile-description" style={{ marginTop: 16 }}>
          <h3>Recovery codes</h3>
          <p className="hint">Save these somewhere safe. Each works once if you lose your authenticator. They are shown only now.</p>
          <div className="summary-grid">
            {recoveryCodes.map((c) => (
              <span key={c} className="summary-pill" style={{ fontFamily: 'monospace' }}>
                {c}
              </span>
            ))}
          </div>
          <div className="actions">
            <button className="button secondary" onClick={() => setRecoveryCodes(null)}>
              I&apos;ve saved them
            </button>
          </div>
        </div>
      )}

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
