import type { Metadata, Viewport } from 'next';
import { APP_NAME, APP_VERSION } from '@/shared/constants';
import './globals.css';

export const metadata: Metadata = {
  title: `${APP_NAME} — Authorized Reconnaissance Scanner`,
  description:
    'Run authorized, detection-oriented reconnaissance scans against targets you own or have permission to test, and download polished PDF and Markdown reports.',
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="topbar">
          <div className="topbar-inner">
            <span className="brand">{APP_NAME}</span>
            <span className="brand-sub">authorized reconnaissance scanner</span>
          </div>
        </header>
        <main className="main">{children}</main>
        <footer className="footer">
          {APP_NAME} v{APP_VERSION} — detection-oriented scanning only. Use only on systems you own or are authorized to test.
        </footer>
      </body>
    </html>
  );
}
