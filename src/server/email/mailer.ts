import nodemailer from 'nodemailer';
import { getWebConfig, type WebConfig } from '../../shared/config';

/**
 * Provider-neutral mailer. The MVP ships an SMTP transport; other providers
 * (Resend, Postmark, etc.) can implement the same `Mailer` interface later.
 */
export interface Mailer {
  send(input: { to: string; subject: string; text: string; html?: string }): Promise<void>;
}

export function createMailer(config: WebConfig = getWebConfig()): Mailer {
  if (!config.smtp.configured) {
    return {
      send: async () => {
        throw new Error('SMTP is not configured.');
      },
    };
  }
  const transport = nodemailer.createTransport({
    host: config.smtp.host,
    port: config.smtp.port,
    secure: config.smtp.secure,
    auth: config.smtp.username ? { user: config.smtp.username, pass: config.smtp.password } : undefined,
  });
  return {
    send: async ({ to, subject, text, html }) => {
      await transport.sendMail({ from: config.smtp.from, to, subject, text, html });
    },
  };
}

export function buildVerificationLink(config: WebConfig, userId: number, token: string): string {
  return `${config.appBaseUrl}/verify-email?userId=${userId}&token=${encodeURIComponent(token)}`;
}

export function buildPasswordResetLink(config: WebConfig, userId: number, token: string): string {
  return `${config.appBaseUrl}/reset-password?userId=${userId}&token=${encodeURIComponent(token)}`;
}
