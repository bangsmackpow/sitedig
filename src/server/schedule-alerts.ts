import { createLogger } from '../shared/logger';
import { getWebConfig, type WebConfig } from '../shared/config';
import type { ScanDiff, ScanFindingSummary, ScheduleAlertThreshold, ScheduledScan } from '../shared/types';
import { createMailer, type Mailer } from './email/mailer';
import { scheduledScanAlertEmail, type ScheduledScanAlertData } from './email/templates';
import { computeScanDiff } from './scan-diffs';
import { getScan } from './scans';
import { getSchedule, getScheduleByLastScan, recordScheduleAlert } from './schedules';

const log = createLogger();

const SEVERITY_ORDER: Record<ScanFindingSummary['severity'], number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  informational: 1,
};

function thresholdMinimum(threshold: ScheduleAlertThreshold): number {
  switch (threshold) {
    case 'off':
      return Number.POSITIVE_INFINITY;
    case 'high':
      return SEVERITY_ORDER.high;
    case 'medium':
      return SEVERITY_ORDER.medium;
    case 'all':
      return SEVERITY_ORDER.informational;
  }
}

function qualifies(finding: ScanFindingSummary, threshold: ScheduleAlertThreshold): boolean {
  return SEVERITY_ORDER[finding.severity] >= thresholdMinimum(threshold);
}

export interface ScheduleAlertInput {
  schedule: ScheduledScan;
  diff: ScanDiff;
  kind: 'findings' | 'failure';
  error: string | null;
  appBaseUrl: string;
}

/** Build alert content, or null when the change does not meet the schedule threshold. */
export function buildScheduleAlert(input: ScheduleAlertInput): ScheduledScanAlertData | null {
  const { schedule, diff, kind } = input;
  if (kind === 'failure') {
    if (!schedule.alertOnFailure) return null;
    return {
      kind,
      target: schedule.target,
      scanId: diff.currentScanId,
      risk: diff.risk,
      previousRisk: diff.previousRisk,
      newFindings: [],
      resolvedCount: diff.resolvedFindings.length,
      notAssessedCount: diff.notAssessed.length,
      severityChanges: diff.severityChanges.length,
      error: input.error,
      scanUrl: `${input.appBaseUrl}/scan/${encodeURIComponent(diff.currentScanId)}`,
      schedulesUrl: `${input.appBaseUrl}/schedules`,
    };
  }

  const newFindings = diff.newFindings.filter((f) => qualifies(f, schedule.alertMinSeverity));
  const severityChanges = diff.severityChanges.filter((c) => qualifies(c.finding, schedule.alertMinSeverity));
  if (newFindings.length === 0 && severityChanges.length === 0) return null;

  return {
    kind: 'findings',
    target: schedule.target,
    scanId: diff.currentScanId,
    risk: diff.risk,
    previousRisk: diff.previousRisk,
    newFindings,
    resolvedCount: diff.resolvedFindings.length,
    notAssessedCount: diff.notAssessed.length,
    severityChanges: severityChanges.length,
    error: null,
    scanUrl: `${input.appBaseUrl}/scan/${encodeURIComponent(diff.currentScanId)}`,
    schedulesUrl: `${input.appBaseUrl}/schedules`,
  };
}

export interface AlertDeps {
  config?: WebConfig;
  mailer?: Mailer;
}

/** Send at most one alert per scheduled scan. Best-effort; never throws to callers. */
export async function maybeSendScheduleAlert(scanId: string, deps: AlertDeps = {}): Promise<boolean> {
  const scan = getScan(scanId);
  if (!scan) return false;
  const schedule = scan.schedule_id !== null ? getSchedule(scan.schedule_id) : getScheduleByLastScan(scanId);
  if (!schedule) return false;
  if (schedule.lastAlertScanId === scanId) return false;
  if (!schedule.userEmail && !scan.user_email) return false;

  const config = deps.config ?? getWebConfig();
  if (!config.email.configured) return false;

  const diff = computeScanDiff(scanId);
  if (!diff) return false;
  const kind: 'findings' | 'failure' = scan.status === 'completed' ? 'findings' : 'failure';
  const data = buildScheduleAlert({
    schedule,
    diff,
    kind,
    error: scan.error,
    appBaseUrl: config.appBaseUrl,
  });
  if (!data) return false;

  const recipient = scan.user_email ?? schedule.userEmail;
  if (!recipient) return false;

  try {
    const mailer = deps.mailer ?? createMailer(config);
    await mailer.send({ to: recipient, ...scheduledScanAlertEmail(data) });
    recordScheduleAlert(schedule.id, scanId);
    log.info('scheduled_scan_alert_sent', { scheduleId: schedule.id, scanId, kind });
    return true;
  } catch (e) {
    log.warn('scheduled_scan_alert_failed', { scheduleId: schedule.id, scanId, error: (e as Error).message });
    return false;
  }
}
