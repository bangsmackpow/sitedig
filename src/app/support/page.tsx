import Link from 'next/link';
import { cookies } from 'next/headers';
import { ensureInitialized } from '@/server/bootstrap';
import { getSessionUser, sessionCookieName } from '@/server/auth/sessions';
import { isPremium } from '@/server/entitlements';
import { getWebConfig } from '@/shared/config';

export const dynamic = 'force-dynamic';
export const metadata = { title: 'Support — SiteDig' };

export default async function SupportPage() {
  await ensureInitialized();
  const store = await cookies();
  const session = getSessionUser(store.get(sessionCookieName())?.value);
  const config = getWebConfig();

  if (!session) {
    return (
      <div className="card auth-wrap">
        <h1>Premium support</h1>
        <p className="lead">Support is available to Premium subscribers.</p>
        <p className="text-muted">Sign in to check your plan, or create an account to get started.</p>
        <div className="actions" style={{ marginTop: 16 }}>
          <Link className="button" href="/login?next=%2Fsupport">
            Sign in
          </Link>
          <Link className="button secondary" href="/pricing">
            View pricing
          </Link>
        </div>
      </div>
    );
  }

  if (!isPremium(session.user)) {
    return (
      <div className="card auth-wrap">
        <h1>Premium support</h1>
        <p className="lead">Email support is included with Premium.</p>
        <p className="text-muted">
          Your current plan is Free. Upgrade to Premium to get direct support for scans, reports, and account issues.
        </p>
        <div className="actions" style={{ marginTop: 16 }}>
          <Link className="button" href="/account">
            Upgrade to Premium
          </Link>
          <Link className="button secondary" href="/pricing">
            Compare plans
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="card auth-wrap">
      <h1>Premium support</h1>
      <p className="lead">You are on the Premium plan. We are here to help.</p>
      {config.supportEmail ? (
        <>
          <p className="text-muted">
            Email us from the address on your account ({session.user.email}) so we can find your subscription quickly.
          </p>
          <div className="info-box" style={{ marginTop: 12 }}>
            <strong>{config.supportEmail}</strong>
          </div>
          <div className="actions" style={{ marginTop: 16 }}>
            <a className="button" href={`mailto:${config.supportEmail}?subject=SiteDig%20Premium%20support`}>
              Email support
            </a>
          </div>
          <p className="hint" style={{ marginTop: 12 }}>
            Include the scan ID or target URL and what you expected to happen. Never send passwords or API keys.
          </p>
        </>
      ) : (
        <div className="info-box" style={{ marginTop: 12 }}>
          Support email is not configured on this deployment yet. An administrator needs to set <code>SUPPORT_EMAIL</code>.
        </div>
      )}
    </div>
  );
}
