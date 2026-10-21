import type { Metadata, Viewport } from 'next';
import Link from 'next/link';
import { APP_NAME, APP_VERSION } from '@/shared/constants';
import AuthNav from '@/app/components/AuthNav';
import ThemeToggle from '@/app/components/ThemeToggle';
import './globals.css';

export const metadata: Metadata = {
  title: `${APP_NAME} — Authorized Reconnaissance Scanner`,
  description:
    'Run authorized, detection-oriented reconnaissance scans against targets you own or have permission to test, and download polished PDF and Markdown reports.',
  robots: { index: false, follow: false },
  icons: {
    icon: [
      { url: '/icon.svg', type: 'image/svg+xml' },
      { url: '/favicon.ico' },
    ],
    shortcut: '/favicon.ico',
    apple: '/apple-icon.png',
  },
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: '#f3f6fb' },
    { media: '(prefers-color-scheme: dark)', color: '#070c16' },
  ],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <script
          dangerouslySetInnerHTML={{
            __html:
              "(function(){try{var t=localStorage.getItem('sitedig-theme');if(t!=='light'&&t!=='dark'){t=window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';}document.documentElement.dataset.theme=t;}catch(e){document.documentElement.dataset.theme='dark';}})();",
          }}
        />
        <a className="skip-link" href="#main">
          Skip to content
        </a>
        <svg className="network-bg" viewBox="0 0 1440 900" preserveAspectRatio="xMidYMin slice" aria-hidden="true">
          <g fill="none" stroke="currentColor" strokeWidth="1">
            <path d="M120 160 360 80 620 210 840 120 1180 250 1340 180" />
            <path d="M80 520 280 440 520 560 760 470 1020 590 1320 500" />
            <path d="M220 760 460 680 700 800 940 700 1180 820" />
            <path d="M360 80 520 560M840 120 1020 590M280 440 460 680M760 470 940 700" />
          </g>
          <g fill="currentColor">
            <circle cx="120" cy="160" r="2.5" />
            <circle cx="360" cy="80" r="2" />
            <circle cx="620" cy="210" r="2.5" />
            <circle cx="840" cy="120" r="2" />
            <circle cx="1180" cy="250" r="2.5" />
            <circle cx="1340" cy="180" r="2" />
            <circle cx="80" cy="520" r="2" />
            <circle cx="280" cy="440" r="2.5" />
            <circle cx="520" cy="560" r="2" />
            <circle cx="760" cy="470" r="2.5" />
            <circle cx="1020" cy="590" r="2" />
            <circle cx="1320" cy="500" r="2.5" />
            <circle cx="220" cy="760" r="2" />
            <circle cx="460" cy="680" r="2.5" />
            <circle cx="700" cy="800" r="2" />
            <circle cx="940" cy="700" r="2.5" />
            <circle cx="1180" cy="820" r="2" />
          </g>
        </svg>
        <header className="topbar">
          <div className="topbar-inner">
            <Link href="/" className="brand" aria-label={`${APP_NAME} home`}>
              <svg className="brand-mark" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
                <path d="M12 2.2 20 6v6.1c0 4.8-3.3 8.2-8 9.7-4.7-1.5-8-4.9-8-9.7V6l8-3.8Z" />
                <path d="m8.4 12.1 2.4 2.4 4.9-5.1" />
              </svg>
              {APP_NAME}
            </Link>
            <span className="brand-sub">Security operations</span>
            <div className="topbar-actions">
              <ThemeToggle />
              <AuthNav />
            </div>
          </div>
        </header>
        <main id="main" className="main">{children}</main>
        <footer className="footer">
          {APP_NAME} v{APP_VERSION} — detection-oriented scanning only. Use only on systems you own or are authorized to test. |{' '}
          <Link className="link" href="/pricing">
            Pricing
          </Link>
          {' · '}
          <Link className="link" href="/acceptable-use">
            Acceptable Use
          </Link>
          {' · '}
          <Link className="link" href="/support">
            Support
          </Link>
        </footer>
      </body>
    </html>
  );
}
