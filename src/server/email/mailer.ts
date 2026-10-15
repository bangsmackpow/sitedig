import nodemailer from 'nodemailer';
import { getWebConfig, type WebConfig } from '../../shared/config';

/**
 * Provider-neutral mailer. Delivery is selected via `EMAIL_PROVIDER`:
 *   - `resend` (default when RESEND_API_KEY is set) posts to the Resend REST API.
 *   - `smtp`   uses nodemailer against SMTP_HOST/SMTP_PORT.
 * Both implement the same `Mailer` interface, so callers never care which is used.
 */
export interface Mailer {
  send(input: { to: string; subject: string; text: string; html?: string }): Promise<void>;
}

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
  html?: string;
}

/** Resend REST transport (no SDK dependency). */
function createResendTransport(config: WebConfig): Mailer {
  const apiKey = config.email.resendApiKey;
  const from = config.email.from;
  return {
    send: async ({ to, subject, text, html }: MailMessage) => {
      const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' },
        body: JSON.stringify({ from, to: [to], subject, text, ...(html ? { html } : {}) }),
      });
      if (!res.ok) {
        const detail = await res.text().catch(() => '');
        throw new Error(`Resend rejected the email (${res.status}): ${detail.slice(0, 200)}`);
      }
    },
  };
}

function createSmtpTransport(config: WebConfig): Mailer {
  const transport = nodemailer.createTransport({
    host: config.smtp.host,
    port: config.smtp.port,
    secure: config.smtp.secure,
    auth: config.smtp.username ? { user: config.smtp.username, pass: config.smtp.password } : undefined,
  });
  return {
    send: async ({ to, subject, text, html }: MailMessage) => {
      await transport.sendMail({ from: config.email.from || config.smtp.from, to, subject, text, html });
    },
  };
}

export function createMailer(config: WebConfig = getWebConfig()): Mailer {
  if (!config.email.configured) {
    return {
      send: async () => {
        throw new Error('Email delivery is not configured.');
      },
    };
  }
  return config.email.provider === 'resend' ? createResendTransport(config) : createSmtpTransport(config);
}

export function buildVerificationLink(config: WebConfig, userId: number, token: string): string {
  return `${config.appBaseUrl}/verify-email?userId=${userId}&token=${encodeURIComponent(token)}`;
}

export function buildPasswordResetLink(config: WebConfig, userId: number, token: string): string {
  return `${config.appBaseUrl}/reset-password?userId=${userId}&token=${encodeURIComponent(token)}`;
}
