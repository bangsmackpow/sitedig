import Link from 'next/link';
import { PREMIUM_MONTHLY_USD, PREMIUM_PLAN_NAME } from '@/shared/pricing';

const premiumModules = [
  'Asset & DNS discovery',
  'Vulnerability scan (nuclei, retire.js, httpx)',
  'TLS hardening audit',
  'Content discovery + Wayback history',
  'CVE context',
  'Remediation playbook',
  'Web trust & crawl analysis',
  'Domain & email hardening',
  'Infrastructure intel',
];

export default function PricingPage() {
  return (
    <div className="card">
      <h1>Simple pricing</h1>
      <p className="lead">
        Start free with the core scanner and the PHP2Shell check. Upgrade when you need the deeper modules,
        recurring scans, change detection, and client-ready remediation plans.
      </p>

      <div className="pricing-grid">
        <section className="pricing-card">
          <div className="pill info">Free</div>
          <p className="price">$0</p>
          <p className="hint">No card required. Free forever.</p>
          <ul className="pricing-list">
            <li>Quick, Standard, Deep, and PHP2Shell Check profiles</li>
            <li>PHP2Shell advisory detection on every scan</li>
            <li>Open ports, web technologies, HTTP headers, TLS certificate</li>
            <li>PDF and Markdown reports</li>
            <li>Scan history and one-click re-run</li>
          </ul>
          <div className="actions">
            <Link className="button secondary" href="/register">
              Create free account
            </Link>
          </div>
        </section>

        <section className="pricing-card featured">
          <div className="pill active">{PREMIUM_PLAN_NAME}</div>
          <p className="price">
            ${PREMIUM_MONTHLY_USD}
            <span className="price-period">/month</span>
          </p>
          <p className="hint">Billed monthly through Stripe. Cancel anytime.</p>
          <ul className="pricing-list">
            <li>Everything in Free</li>
            {premiumModules.map((feature) => (
              <li key={feature}>{feature}</li>
            ))}
            <li>Daily or weekly recurring scans</li>
            <li>Change detection, risk score, and email alerts</li>
            <li>Client-ready remediation playbook and 30-day roadmap</li>
          </ul>
          <div className="actions">
            <Link className="button" href="/account">
              Upgrade in your account
            </Link>
          </div>
        </section>
      </div>

      <p className="hint" style={{ marginTop: 20 }}>
        Prices are in USD. Premium is billed through Stripe. Fair-use limits apply so one account cannot monopolise the
        scan queue. Authorized targets only — every scan still requires the consent acknowledgement.
      </p>
    </div>
  );
}
