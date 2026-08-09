import { getWebConfig } from '../../shared/config';
import { auditLog } from '../audit';
import { createMailer, buildVerificationLink, buildPasswordResetLink } from '../email/mailer';
import { consumeEmailToken, createEmailToken, invalidateEmailTokens } from '../email/tokens';
import { createUser, getUserByEmail, getUserById, setUserVerified, userExistsByEmail, type UserRow } from '../users';
import { hashPassword, validatePasswordStrength, verifyPassword } from './passwords';
import { revokeAllUserSessions } from './sessions';

export class AuthError extends Error {
  constructor(
    message: string,
    readonly status: number = 400,
  ) {
    super(message);
    this.name = 'AuthError';
  }
}

export interface PublicUser {
  id: number;
  email: string;
  role: 'admin' | 'user';
  emailVerified: boolean;
  premium: boolean;
  status: string;
}

export function toPublicUser(user: UserRow, premium: boolean): PublicUser {
  return {
    id: user.id,
    email: user.email,
    role: user.role,
    emailVerified: Boolean(user.email_verified_at),
    premium,
    status: user.status,
  };
}

export async function register(email: string, password: string): Promise<{ user: UserRow; needsVerification: boolean }> {
  const cfg = getWebConfig();
  if (cfg.deploymentMode === 'self-hosted' && !cfg.smtp.configured) {
    throw new AuthError('Public registration is disabled on this deployment.', 403);
  }
  if (userExistsByEmail(email)) {
    throw new AuthError('An account with this email already exists.', 409);
  }
  const passwordError = validatePasswordStrength(password);
  if (passwordError) throw new AuthError(passwordError, 400);

  const verified = cfg.deploymentMode === 'self-hosted' || !cfg.smtp.configured;
  const user = createUser({ email, passwordHash: await hashPassword(password), verified });

  if (!verified) {
    const token = createEmailToken(user.id, 'email_verify');
    const link = buildVerificationLink(cfg, user.id, token);
    await createMailer(cfg).send({
      to: user.email,
      subject: 'Verify your email',
      text: `Verify your SiteDig account: ${link}`,
      html: `<p>Verify your SiteDig account: <a href="${link}">Verify email</a></p>`,
    });
  }
  auditLog({ actorUserId: user.id, action: 'user.registered', targetUserId: user.id });
  return { user, needsVerification: !verified };
}

export async function login(email: string, password: string): Promise<UserRow> {
  const user = getUserByEmail(email);
  if (!user) throw new AuthError('Invalid email or password.', 401);
  if (user.status === 'disabled') throw new AuthError('Invalid email or password.', 401);
  const valid = await verifyPassword(password, user.password_hash);
  if (!valid) throw new AuthError('Invalid email or password.', 401);
  return user;
}

export async function verifyEmail(userId: number, token: string): Promise<boolean> {
  const ok = consumeEmailToken(userId, 'email_verify', token);
  if (!ok) return false;
  const user = getUserById(userId);
  if (!user) return false;
  setUserVerified(userId);
  auditLog({ actorUserId: userId, action: 'user.email_verified', targetUserId: userId });
  return true;
}

export async function requestPasswordReset(email: string): Promise<void> {
  const cfg = getWebConfig();
  if (!cfg.smtp.configured) {
    throw new AuthError('Password reset is unavailable because email delivery is not configured.', 400);
  }
  const user = getUserByEmail(email);
  // Always succeed to avoid account enumeration.
  if (!user || !user.email_verified_at) return;
  invalidateEmailTokens(user.id, 'password_reset');
  const token = createEmailToken(user.id, 'password_reset');
  const link = buildPasswordResetLink(cfg, user.id, token);
  await createMailer(cfg).send({
    to: user.email,
    subject: 'Reset your password',
    text: `Reset your SiteDig password: ${link}`,
    html: `<p>Reset your SiteDig password: <a href="${link}">Reset password</a></p>`,
  });
}

export async function resetPassword(userId: number, token: string, newPassword: string): Promise<void> {
  const passwordError = validatePasswordStrength(newPassword);
  if (passwordError) throw new AuthError(passwordError, 400);
  if (!consumeEmailToken(userId, 'password_reset', token)) {
    throw new AuthError('This reset link is invalid or has expired.', 400);
  }
  const user = getUserById(userId);
  if (!user) throw new AuthError('Account not found.', 404);
  const { getDb } = await import('../db');
  getDb().prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?').run(await hashPassword(newPassword), new Date().toISOString(), userId);
  invalidateEmailTokens(userId, 'password_reset');
  revokeAllUserSessions(userId);
  auditLog({ actorUserId: userId, action: 'user.password_reset', targetUserId: userId });
}
