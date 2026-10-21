import Link from 'next/link';
import { getWebConfig } from '@/shared/config';

export const dynamic = 'force-dynamic';
export const metadata = { title: 'Acceptable Use Policy — SiteDig' };

export default function AcceptableUsePage() {
  const { supportEmail } = getWebConfig();

  return (
    <div className="card">
      <h1>Acceptable Use Policy</h1>
      <p className="meta-line">Effective 21 October 2026</p>

      <p className="lead">
        SiteDig is a detection-oriented reconnaissance service. It exists for authorized security testing, asset
        inventory, and defensive review. Using it against systems you do not own or have permission to test is
        prohibited.
      </p>

      <h2>1. Authorized targets only</h2>
      <p>
        You may scan only systems you own or have explicit, documented permission to test. The authorization must cover
        the specific target, timing, and scan types you request. A public website is not automatically an authorized
        target.
      </p>

      <h2>2. Prohibited activity</h2>
      <ul>
        <li>Scanning third parties without permission, including internet-wide or mass scanning.</li>
        <li>Exploitation, brute force, denial-of-service, evasion, or any destructive testing.</li>
        <li>Attempting to bypass target-safety controls, rate limits, queue limits, or authentication.</li>
        <li>Using SiteDig to harass, stalk, or compete unlawfully, or to violate any law or regulation.</li>
        <li>Reselling scan access or reports as your own service without a separate agreement.</li>
        <li>Uploading malware, exploit payloads, or illegal content.</li>
      </ul>

      <h2>3. Technical limits</h2>
      <p>
        SiteDig runs bounded, non-destructive checks. It may rate-limit, queue, pause, or reject scans to protect the
        service and third parties. You must not attempt to work around those limits. Reports and artifacts are
        time-limited and may expire.
      </p>

      <h2>4. Account responsibility</h2>
      <p>
        You are responsible for activity under your account, for keeping your credentials and MFA factors secure, and
        for ensuring that anyone you invite or authorize follows this policy. Notify us promptly if you suspect account
        compromise.
      </p>

      <h2>5. Data and reports</h2>
      <p>
        Scan results may contain sensitive information about the target. Handle reports according to your agreement
        with the target owner and applicable law. Do not publish another organization&apos;s findings without
        permission.
      </p>

      <h2>6. Enforcement</h2>
      <p>
        We may suspend or terminate accounts that violate this policy, threaten the service, or create legal or
        operational risk. We may also report suspected illegal activity to the appropriate authorities.
      </p>

      <h2>7. Contact</h2>
      <p>
        Questions about this policy, or reports of abuse involving SiteDig, should go to{' '}
        {supportEmail ? (
          <a className="link" href={`mailto:${supportEmail}?subject=SiteDig%20acceptable%20use`}>
            {supportEmail}
          </a>
        ) : (
          <Link className="link" href="/support">
            support
          </Link>
        )}
        .
      </p>

      <p className="text-muted" style={{ marginTop: 24 }}>
        See also <Link className="link" href="/pricing">pricing</Link> and{' '}
        <Link className="link" href="/support">support</Link>.
      </p>
    </div>
  );
}
