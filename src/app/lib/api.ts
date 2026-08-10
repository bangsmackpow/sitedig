'use client';

export interface ApiError extends Error {
  status: number;
}

export function getCsrfToken(): string {
  if (typeof document === 'undefined') return '';
  const parts = document.cookie.split('; ');
  for (const part of parts) {
    const idx = part.indexOf('=');
    const name = part.slice(0, idx).trim();
    if (name === 'sitedig_csrf') {
      return decodeURIComponent(part.slice(idx + 1));
    }
  }
  return '';
}

export async function apiFetch<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase();
  const headers = new Headers(init.headers);
  if (init.body && !headers.has('content-type')) headers.set('content-type', 'application/json');
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) headers.set('x-csrf-token', getCsrfToken());
  const res = await fetch(path, { ...init, headers, credentials: 'same-origin' });
  if (!res.ok) {
    let message = `Request failed (${res.status})`;
    try {
      const data = (await res.json()) as { error?: { message?: string } };
      message = data.error?.message ?? message;
    } catch {
      // keep default
    }
    const err = new Error(message) as ApiError;
    err.status = res.status;
    throw err;
  }
  return (await res.json()) as T;
}

export interface PublicUser {
  id: number;
  email: string;
  role: 'admin' | 'user';
  emailVerified: boolean;
  premium: boolean;
  status: string;
}

export interface SubscriptionView {
  status: string;
  currentPeriodEnd: string | null;
  cancelAtPeriodEnd: boolean;
  priceId: string | null;
}

export interface MePayload {
  user: PublicUser;
  subscription: SubscriptionView | null;
  deletionPending: boolean;
}
