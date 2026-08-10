'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter, usePathname } from 'next/navigation';
import { apiFetch, type PublicUser } from '@/app/lib/api';

export default function AuthNav() {
  const router = useRouter();
  const pathname = usePathname();
  const [user, setUser] = useState<PublicUser | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const me = await apiFetch<{ user: PublicUser }>('/api/auth/me');
      setUser(me.user);
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load, pathname]);

  const logout = async () => {
    try {
      await apiFetch('/api/auth/logout', { method: 'POST' });
      setUser(null);
      router.push('/');
      router.refresh();
    } catch {
      // ignore
    }
  };

  if (loading) {
    return <nav className="nav-auth">…</nav>;
  }

  if (user) {
    return (
      <nav className="nav-auth" style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <span className="pill active" title={`Signed in as ${user.email}`}>
          Signed in · {user.email}
        </span>
        {user.role === 'admin' && (
          <Link className="link" href="/admin">
            Admin
          </Link>
        )}
        <Link className="link" href="/account">
          Account
        </Link>
        <button className="link-button" onClick={logout}>
          Log out
        </button>
      </nav>
    );
  }

  return (
    <nav className="nav-auth" style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
      <Link className="link" href="/login">
        Login
      </Link>
      <Link className="link" href="/register">
        Register
      </Link>
    </nav>
  );
}
