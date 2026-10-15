import { APP_NAME } from '../../shared/constants';

export interface RenderedEmail {
  subject: string;
  text: string;
  html: string;
}

const ACCENT = '#38bdf8';

/** Minimal, email-client-safe HTML shell (inline styles, no external assets). */
function wrap(title: string, bodyHtml: string): string {
  return `<!doctype html>
<html>
  <body style="margin:0;padding:24px;background:#0f172a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#e2e8f0;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;margin:0 auto;background:#1e293b;border:1px solid #334155;border-radius:12px;">
      <tr>
        <td style="padding:24px;">
          <div style="font-size:20px;font-weight:800;color:${ACCENT};margin-bottom:4px;">${APP_NAME}</div>
          <h1 style="font-size:18px;margin:0 0 16px;color:#e2e8f0;">${title}</h1>
          ${bodyHtml}
        </td>
      </tr>
      <tr>
        <td style="padding:16px 24px;border-top:1px solid #334155;color:#94a3b8;font-size:12px;">
          ${APP_NAME} — detection-oriented reconnaissance. Use only on systems you own or are authorized to test.
        </td>
      </tr>
    </table>
  </body>
</html>`;
}

function button(href: string, label: string): string {
  return `<p style="margin:20px 0;"><a href="${href}" style="display:inline-block;background:${ACCENT};color:#0b1220;text-decoration:none;font-weight:700;padding:10px 18px;border-radius:8px;">${label}</a></p>`;
}

export function verificationEmail(link: string): RenderedEmail {
  return {
    subject: `Verify your ${APP_NAME} email`,
    text: `Verify your ${APP_NAME} account: ${link}`,
    html: wrap('Verify your email', `<p>Confirm this email address to activate your ${APP_NAME} account.</p>${button(link, 'Verify email')}<p style="color:#94a3b8;font-size:13px;">If you didn't create this account, you can ignore this email.</p>`),
  };
}

export function passwordResetEmail(link: string): RenderedEmail {
  return {
    subject: `Reset your ${APP_NAME} password`,
    text: `Reset your ${APP_NAME} password: ${link}`,
    html: wrap('Reset your password', `<p>Use the button below to choose a new password. This link expires shortly.</p>${button(link, 'Reset password')}<p style="color:#94a3b8;font-size:13px;">If you didn't request this, no action is needed.</p>`),
  };
}

export function mfaCodeEmail(code: string, minutes: number): RenderedEmail {
  return {
    subject: `Your ${APP_NAME} sign-in code`,
    text: `Your ${APP_NAME} sign-in code is ${code}. It expires in ${minutes} minutes.`,
    html: wrap(
      'Your sign-in code',
      `<p>Enter this code to finish signing in. It expires in ${minutes} minutes.</p>
       <p style="font-size:28px;font-weight:800;letter-spacing:6px;margin:16px 0;color:${ACCENT};">${code}</p>
       <p style="color:#94a3b8;font-size:13px;">If you didn't try to sign in, change your password immediately.</p>`,
    ),
  };
}

export interface DigestEmailData {
  date: string;
  newUsers: Array<{ email: string; createdAt: string; verified: boolean }>;
  scans: {
    total: number;
    completed: number;
    failed: number;
    cancelled: number;
    totalDurationMs: number;
    avgDurationMs: number;
    p95DurationMs: number;
  };
  byProfile: Array<{ profile: string; count: number }>;
  byModule: Array<{ module: string; count: number }>;
  topTargets: Array<{ host: string; count: number }>;
  findings: { critical: number; high: number; medium: number; low: number; informational: number };
  adminUrl: string;
}

function table(headers: string[], rows: string[][]): string {
  const head = `<tr>${headers.map((h) => `<th style="text-align:left;padding:6px 8px;border-bottom:1px solid #334155;color:#94a3b8;font-weight:600;">${h}</th>`).join('')}</tr>`;
  const body = rows.length
    ? rows
        .map((r) => `<tr>${r.map((c) => `<td style="padding:6px 8px;border-bottom:1px solid #273549;">${c}</td>`).join('')}</tr>`)
        .join('')
    : `<tr><td colspan="${headers.length}" style="padding:8px;color:#94a3b8;">None</td></tr>`;
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;border-collapse:collapse;margin:8px 0 20px;">${head}${body}</table>`;
}

const secs = (ms: number) => `${(ms / 1000).toFixed(1)}s`;

export function digestEmail(data: DigestEmailData): RenderedEmail {
  const s = data.scans;
  const summary = [
    ['Scans run', String(s.total)],
    ['Completed', String(s.completed)],
    ['Failed', String(s.failed)],
    ['Cancelled', String(s.cancelled)],
    ['Avg duration', secs(s.avgDurationMs)],
    ['p95 duration', secs(s.p95DurationMs)],
    ['New signups', String(data.newUsers.length)],
  ]
    .map(
      ([k, v]) =>
        `<tr><td style="padding:4px 8px;color:#94a3b8;">${k}</td><td style="padding:4px 8px;font-weight:700;">${v}</td></tr>`,
    )
    .join('');

  const bodyHtml = `
    <p style="color:#94a3b8;margin:0 0 8px;">Daily summary for ${data.date}</p>
    <table role="presentation" cellpadding="0" cellspacing="0" style="font-size:13px;margin:8px 0 20px;">${summary}</table>
    <h2 style="font-size:15px;margin:0 0 4px;">New signups</h2>
    ${table(['Email', 'Verified'], data.newUsers.map((u) => [u.email, u.verified ? 'yes' : 'no']))}
    <h2 style="font-size:15px;margin:0 0 4px;">Findings observed</h2>
    ${table(
      ['Critical', 'High', 'Medium', 'Low', 'Info'],
      [[String(data.findings.critical), String(data.findings.high), String(data.findings.medium), String(data.findings.low), String(data.findings.informational)]],
    )}
    <h2 style="font-size:15px;margin:0 0 4px;">Scans by profile</h2>
    ${table(['Profile', 'Count'], data.byProfile.map((r) => [r.profile, String(r.count)]))}
    <h2 style="font-size:15px;margin:0 0 4px;">Scans by module</h2>
    ${table(['Module', 'Count'], data.byModule.map((r) => [r.module, String(r.count)]))}
    <h2 style="font-size:15px;margin:0 0 4px;">Top targets</h2>
    ${table(['Host', 'Scans'], data.topTargets.map((r) => [r.host, String(r.count)]))}
    ${button(data.adminUrl, 'Open admin dashboard')}
  `;

  const text = [
    `${APP_NAME} daily summary — ${data.date}`,
    `Scans run: ${s.total} (completed ${s.completed}, failed ${s.failed}, cancelled ${s.cancelled})`,
    `Avg duration: ${secs(s.avgDurationMs)} · p95: ${secs(s.p95DurationMs)}`,
    `New signups: ${data.newUsers.length}`,
    `Findings: critical ${data.findings.critical}, high ${data.findings.high}, medium ${data.findings.medium}, low ${data.findings.low}, info ${data.findings.informational}`,
    `Top targets: ${data.topTargets.map((t) => `${t.host}(${t.count})`).join(', ') || 'none'}`,
    `Admin: ${data.adminUrl}`,
  ].join('\n');

  return { subject: `${APP_NAME} daily digest — ${data.date}`, text, html: wrap('Daily digest', bodyHtml) };
}
