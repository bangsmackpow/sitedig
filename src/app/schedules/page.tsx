'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { apiFetch } from '@/app/lib/api';
import type { ModuleId, ScanProfile, ScheduledScan, ScheduleAlertThreshold } from '@/shared/types';

interface ModuleView {
  id: ModuleId;
  name: string;
  description: string;
  paid: boolean;
  enabled: boolean;
  accessible?: boolean;
}

const WEEKDAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

function formatWhen(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : '-';
}

export default function SchedulesPage() {
  const router = useRouter();
  const [schedules, setSchedules] = useState<ScheduledScan[]>([]);
  const [modules, setModules] = useState<ModuleView[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [premiumRequired, setPremiumRequired] = useState(false);

  const [target, setTarget] = useState('');
  const [profile, setProfile] = useState<ScanProfile>('quick');
  const [selectedModules, setSelectedModules] = useState<ModuleId[]>([]);
  const [frequency, setFrequency] = useState<'daily' | 'weekly'>('weekly');
  const [hourUtc, setHourUtc] = useState(8);
  const [minuteUtc, setMinuteUtc] = useState(0);
  const [dayOfWeek, setDayOfWeek] = useState(1);
  const [alertMinSeverity, setAlertMinSeverity] = useState<ScheduleAlertThreshold>('high');
  const [alertOnFailure, setAlertOnFailure] = useState(true);
  const [consent, setConsent] = useState(false);

  const load = useCallback(async () => {
    try {
      const [scheduleData, moduleData] = await Promise.all([
        apiFetch<{ schedules: ScheduledScan[] }>('/api/schedules'),
        apiFetch<{ modules: ModuleView[] }>('/api/modules'),
      ]);
      setSchedules(scheduleData.schedules);
      setModules(moduleData.modules);
    } catch (e) {
      const status = (e as { status?: number }).status;
      if (status === 401) {
        router.replace('/login');
        return;
      }
      if (status === 403) {
        setPremiumRequired(true);
        return;
      }
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [router]);

  useEffect(() => {
    load();
  }, [load]);

  const toggleModule = (id: ModuleId) => {
    setSelectedModules((prev) => (prev.includes(id) ? prev.filter((m) => m !== id) : [...prev, id]));
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await apiFetch('/api/schedules', {
        method: 'POST',
        body: JSON.stringify({
          target,
          profile,
          modules: selectedModules,
          frequency,
          hourUtc,
          minuteUtc,
          dayOfWeek: frequency === 'weekly' ? dayOfWeek : undefined,
          alertMinSeverity,
          alertOnFailure,
          consent,
        }),
      });
      setTarget('');
      setConsent(false);
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const toggleEnabled = async (schedule: ScheduledScan) => {
    setBusy(true);
    setError(null);
    try {
      await apiFetch(`/api/schedules/${schedule.id}`, { method: 'PATCH', body: JSON.stringify({ enabled: !schedule.enabled }) });
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (schedule: ScheduledScan) => {
    if (!window.confirm(`Delete the recurring scan for ${schedule.target}?`)) return;
    setBusy(true);
    setError(null);
    try {
      await apiFetch(`/api/schedules/${schedule.id}`, { method: 'DELETE' });
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (premiumRequired) {
    return (
      <div className="card">
        <h1>Recurring scans</h1>
        <div className="info-box">Scheduled scans are a Premium feature.</div>
        <p>
          <Link className="button" href="/account">View plans</Link>
        </p>
      </div>
    );
  }

  return (
    <div className="card">
      <h1>Recurring scans</h1>
      <p className="text-muted">
        Run authorized scans daily or weekly, compare each result with the previous run, and receive alerts for new high-impact findings.
        Times are UTC. Only scan systems you own or are authorized to test.
      </p>
      {error && <div className="error-box">{error}</div>}
      {loading && <div className="info-box">Loading schedules.</div>}

      <form onSubmit={submit} style={{ marginTop: 18 }}>
        <div className="field">
          <label htmlFor="schedule-target">Target</label>
          <input id="schedule-target" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://example.com" required />
        </div>
        <div className="field">
          <label htmlFor="schedule-profile">Profile</label>
          <select id="schedule-profile" value={profile} onChange={(e) => setProfile(e.target.value as ScanProfile)}>
            <option value="quick">Quick</option>
            <option value="standard">Standard</option>
            <option value="deep">Deep</option>
          </select>
        </div>

        {modules.length > 0 && (
          <div className="field">
            <label>Add-on modules</label>
            <div style={{ display: 'grid', gap: 6 }}>
              {modules.map((m) => (
                <label key={m.id} className="consent-row">
                  <input
                    type="checkbox"
                    checked={selectedModules.includes(m.id)}
                    onChange={() => toggleModule(m.id)}
                    disabled={!m.enabled || m.accessible === false}
                  />
                  <span>{m.name}{!m.enabled || m.accessible === false ? ' (unavailable)' : ''}</span>
                </label>
              ))}
            </div>
          </div>
        )}

        <div className="field">
          <label htmlFor="schedule-frequency">Frequency</label>
          <select id="schedule-frequency" value={frequency} onChange={(e) => setFrequency(e.target.value as 'daily' | 'weekly')}>
            <option value="daily">Daily</option>
            <option value="weekly">Weekly</option>
          </select>
        </div>
        {frequency === 'weekly' && (
          <div className="field">
            <label htmlFor="schedule-day">Day of week</label>
            <select id="schedule-day" value={dayOfWeek} onChange={(e) => setDayOfWeek(Number(e.target.value))}>
              {WEEKDAYS.map((day, index) => <option key={day} value={index}>{day}</option>)}
            </select>
          </div>
        )}
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <div className="field" style={{ flex: '0 0 140px' }}>
            <label htmlFor="schedule-hour">Hour (UTC)</label>
            <input id="schedule-hour" type="number" min={0} max={23} value={hourUtc} onChange={(e) => setHourUtc(Number(e.target.value))} />
          </div>
          <div className="field" style={{ flex: '0 0 140px' }}>
            <label htmlFor="schedule-minute">Minute</label>
            <input id="schedule-minute" type="number" min={0} max={59} value={minuteUtc} onChange={(e) => setMinuteUtc(Number(e.target.value))} />
          </div>
          <div className="field" style={{ flex: '1 1 220px' }}>
            <label htmlFor="schedule-alert">Alert threshold</label>
            <select id="schedule-alert" value={alertMinSeverity} onChange={(e) => setAlertMinSeverity(e.target.value as ScheduleAlertThreshold)}>
              <option value="high">New high/critical findings</option>
              <option value="medium">New medium+ findings</option>
              <option value="all">Any new finding</option>
              <option value="off">No finding alerts</option>
            </select>
          </div>
        </div>
        <label className="consent-row" style={{ marginTop: 10 }}>
          <input type="checkbox" checked={alertOnFailure} onChange={(e) => setAlertOnFailure(e.target.checked)} />
          <span>Email me if the scheduled scan fails</span>
        </label>
        <label className="consent-row" style={{ marginTop: 10 }}>
          <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} required />
          <span>I confirm I am authorized to scan this target on a recurring basis.</span>
        </label>
        <div className="actions" style={{ marginTop: 14 }}>
          <button className="button" type="submit" disabled={busy || !consent}>
            Create schedule
          </button>
          <Link className="button secondary" href="/">Back to scan</Link>
        </div>
      </form>

      <h2 style={{ marginTop: 28 }}>Your schedules</h2>
      {!loading && schedules.length === 0 && <div className="info-box">No recurring scans yet.</div>}
      {schedules.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Target</th>
              <th>Frequency</th>
              <th>Next run</th>
              <th>Last run</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {schedules.map((s) => (
              <tr key={s.id}>
                <td>
                  <div>{s.host}{s.path !== '/' ? s.path : ''}</div>
                  <div className="meta-line">{s.profile}{s.modules.length > 0 ? ` | ${s.modules.join(', ')}` : ''}</div>
                </td>
                <td>{s.frequency === 'weekly' ? `Weekly ${WEEKDAYS[s.dayOfWeek ?? 0]}` : 'Daily'} at {String(s.hourUtc).padStart(2, '0')}:{String(s.minuteUtc).padStart(2, '0')} UTC</td>
                <td>{formatWhen(s.nextRunAt)}</td>
                <td>{formatWhen(s.lastRunAt)}</td>
                <td>
                  <span className={`pill ${s.enabled ? 'active' : 'disabled'}`}>{s.enabled ? 'enabled' : 'paused'}</span>
                  {s.lastError && <div className="meta-line" style={{ maxWidth: 280 }}>{s.lastError}</div>}
                </td>
                <td style={{ whiteSpace: 'nowrap' }}>
                  {s.lastScanId && (
                    <>
                      <Link className="link" href={`/scan/${encodeURIComponent(s.lastScanId)}`}>View</Link>
                      {' | '}
                    </>
                  )}
                  <button className="link-button" onClick={() => toggleEnabled(s)} disabled={busy}>{s.enabled ? 'Pause' : 'Resume'}</button>
                  {' | '}
                  <button className="link-button" onClick={() => remove(s)} disabled={busy}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
