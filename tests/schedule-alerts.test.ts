import { describe, expect, it } from 'vitest';
import type { ScanDiff, ScanFindingSummary, ScheduledScan } from '../src/shared/types';
import { buildScheduleAlert } from '../src/server/schedule-alerts';

function schedule(overrides: Partial<ScheduledScan> = {}): ScheduledScan {
  return {
    id: 1,
    userId: 1,
    userEmail: 'user@example.com',
    target: 'https://example.com/',
    host: 'example.com',
    path: '/',
    scheme: 'https',
    profile: 'quick',
    custom: null,
    modules: [],
    frequency: 'daily',
    hourUtc: 8,
    minuteUtc: 0,
    dayOfWeek: null,
    alertMinSeverity: 'high',
    alertOnFailure: true,
    enabled: true,
    consentAt: '2026-01-01T00:00:00.000Z',
    nextRunAt: '2026-01-02T08:00:00.000Z',
    lastAttemptAt: null,
    lastRunAt: null,
    lastScanId: null,
    lastAlertScanId: null,
    lastAlertAt: null,
    lastError: null,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

function finding(title: string, severity: ScanFindingSummary['severity']): ScanFindingSummary {
  return { fingerprint: title, title, severity, category: 'misconfiguration', affected: 'example.com', sourceTools: ['http'] };
}

function diff(newFindings: ScanFindingSummary[]): ScanDiff {
  return {
    currentScanId: 'scan-2',
    previousScanId: 'scan-1',
    newFindings,
    resolvedFindings: [],
    notAssessed: [],
    severityChanges: [],
    unchangedCount: 0,
    risk: { score: 80, grade: 'B' },
    previousRisk: { score: 90, grade: 'A' },
    riskDelta: -10,
  };
}

describe('schedule alerts', () => {
  it('filters new findings by the schedule threshold', () => {
    const alert = buildScheduleAlert({
      schedule: schedule({ alertMinSeverity: 'high' }),
      diff: diff([finding('High thing', 'high'), finding('Low thing', 'low')]),
      kind: 'findings',
      error: null,
      appBaseUrl: 'https://sitedig.test',
    });
    expect(alert?.newFindings.map((f) => f.title)).toEqual(['High thing']);
    expect(alert?.scanUrl).toBe('https://sitedig.test/scan/scan-2');
  });

  it('suppresses alerts below the threshold', () => {
    const alert = buildScheduleAlert({
      schedule: schedule({ alertMinSeverity: 'high' }),
      diff: diff([finding('Low thing', 'low')]),
      kind: 'findings',
      error: null,
      appBaseUrl: 'https://sitedig.test',
    });
    expect(alert).toBeNull();
  });

  it('sends failure alerts when enabled', () => {
    const alert = buildScheduleAlert({
      schedule: schedule({ alertOnFailure: true }),
      diff: diff([]),
      kind: 'failure',
      error: 'worker unavailable',
      appBaseUrl: 'https://sitedig.test',
    });
    expect(alert?.kind).toBe('failure');
    expect(alert?.error).toBe('worker unavailable');
  });

  it('suppresses failure alerts when disabled', () => {
    const alert = buildScheduleAlert({
      schedule: schedule({ alertOnFailure: false }),
      diff: diff([]),
      kind: 'failure',
      error: 'worker unavailable',
      appBaseUrl: 'https://sitedig.test',
    });
    expect(alert).toBeNull();
  });
});
