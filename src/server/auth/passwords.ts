import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);
const HASH_VERSION = 'scrypt$1';
const KEY_LEN = 64;
const MIN_PASSWORD_LENGTH = 12;

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString('hex');
  const derived = (await scryptAsync(password, salt, KEY_LEN)) as Buffer;
  return `${HASH_VERSION}$${salt}$${derived.toString('hex')}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const match = /^scrypt\$1\$([0-9a-f]+)\$([0-9a-f]+)$/.exec(stored);
  if (!match) return false;
  const [, salt, hashHex] = match;
  const expected = Buffer.from(hashHex, 'hex');
  const derived = (await scryptAsync(password, salt, expected.length)) as Buffer;
  return expected.length === derived.length && timingSafeEqual(derived, expected);
}

export function validatePasswordStrength(password: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`;
  }
  return null;
}
