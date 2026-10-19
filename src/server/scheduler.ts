import { createLogger } from '../shared/logger';
import { getWebConfig, type WebConfig } from '../shared/config';
import type { ModuleId, PortScope, ScanProfile, ScheduledScan, ToolName } from '../shared/types';

type BaseToolName = Extract<ToolName, 'nmap' | 'whatweb' | 'wpscan' | 'http' | 'tls'>;

interface ScheduledCustomOptions {
  portScope: PortScope;
  enabledTools: BaseToolName[];
  path?: string;
  followRedirects?: boolean;
  userAgent?: string;
  timeoutMs?: number;
}
import { canUseModule, isPremium } from './entitlements';
import {
  claimDueSchedule,
  computeNextRun,
  getSchedule,
  listDueScheduleIds,
  markScheduleError,
  markScheduleRun,
  setScheduleEnabled,
} from './schedules';
import { recordScanQueued } from './scans';
import { getUserById, isUserVerified } from './users';

const log = createLogger();
const RETRY_LEASE_MS = 15 * 60 * 1000;

export interface CreateScheduledScanInput {
  target: string;
  profile: ScanProfile;
  consent: true;
  custom?: ScheduledCustomOptions;
  modules?: ModuleId[];
}

export interface SchedulerDeps {
  createScan?: (input: CreateScheduledScanInput) => Promise<{ jobId: string; status: string }>;
  recordScan?: typeof recordScanQueued;
  config?: WebConfig;
  now?: Date;
}

async function defaultCreateScan(input: CreateScheduledScanInput): Promise<{ jobId: string; status: string }> {
  const { createScan } = await import('../app/lib/worker-client');
  return createScan(input);
}

function pause(schedule: ScheduledScan, reason: string): void {
  setScheduleEnabled(schedule.id, false, reason);
  log.warn('scheduled_scan_paused', { scheduleId: schedule.id, userId: schedule.userId, reason });
}

async function dispatchSchedule(schedule: ScheduledScan, deps: Required<Pick<SchedulerDeps, 'createScan' | 'recordScan'>> & { config: WebConfig; now: Date }): Promise<boolean> {
  const user = getUserById(schedule.userId);
  if (!user || user.status !== 'active' || !isUserVerified(user)) {
    pause(schedule, 'Schedule paused because the owner account is inactive or unverified.');
    return false;
  }
  if (!isPremium(user)) {
    pause(schedule, 'Schedule paused because the owner no longer has an active Premium entitlement.');
    return false;
  }
  for (const moduleId of schedule.modules) {
    if (!canUseModule(user.id, user, moduleId, deps.config.enabledModules)) {
      pause(schedule, `Schedule paused because the ${moduleId} module is no longer available.`);
      return false;
    }
  }

  const custom: ScheduledCustomOptions | undefined = schedule.custom
    ? {
        portScope: schedule.custom.portScope,
        enabledTools: schedule.custom.enabledTools.filter(
          (tool): tool is BaseToolName => ['nmap', 'whatweb', 'wpscan', 'http', 'tls'].includes(tool),
        ),
        path: schedule.custom.path,
        followRedirects: schedule.custom.followRedirects,
        userAgent: schedule.custom.userAgent,
        timeoutMs: schedule.custom.timeoutMs,
      }
    : undefined;
  const result = await deps.createScan({
    target: schedule.target,
    profile: schedule.profile,
    consent: true,
    custom,
    modules: schedule.modules,
  });

  try {
    deps.recordScan({
      id: result.jobId,
      userId: user.id,
      userEmail: user.email,
      targetRaw: schedule.target,
      host: schedule.host,
      path: schedule.path,
      scheme: schedule.scheme,
      profile: schedule.profile,
      modules: schedule.modules,
      scheduleId: schedule.id,
    });
  } catch (e) {
    log.warn('scheduled_scan_history_failed', { scheduleId: schedule.id, scanId: result.jobId, error: (e as Error).message });
  }

  const nextRunAt = computeNextRun(
    { frequency: schedule.frequency, hourUtc: schedule.hourUtc, minuteUtc: schedule.minuteUtc, dayOfWeek: schedule.dayOfWeek },
    deps.now,
  );
  markScheduleRun(schedule.id, result.jobId, deps.now, nextRunAt);
  log.info('scheduled_scan_dispatched', { scheduleId: schedule.id, scanId: result.jobId, nextRunAt: nextRunAt.toISOString() });
  return true;
}

let running = false;

/**
 * Dispatch due schedules sequentially. Each due row is claimed atomically with
 * a short retry lease so multiple web instances cannot run the same schedule.
 */
export async function runDueScheduledScans(deps: SchedulerDeps = {}): Promise<number> {
  if (running) return 0;
  running = true;
  const now = deps.now ?? new Date();
  const config = deps.config ?? getWebConfig();
  const createScan = deps.createScan ?? defaultCreateScan;
  const recordScan = deps.recordScan ?? recordScanQueued;
  let dispatched = 0;
  try {
    const dueIds = listDueScheduleIds(now, 10);
    for (const id of dueIds) {
      const schedule = getSchedule(id);
      if (!schedule || !schedule.enabled) continue;
      const leaseUntil = new Date(now.getTime() + RETRY_LEASE_MS);
      if (!claimDueSchedule(id, now, leaseUntil)) continue;
      try {
        if (await dispatchSchedule(schedule, { createScan, recordScan, config, now })) dispatched += 1;
      } catch (e) {
        const message = (e as Error).message ?? 'Scheduled scan failed to start.';
        const code = (e as { code?: string }).code;
        if (code === 'target_rejected' || code === 'module_not_enabled' || code === 'module_locked') {
          pause(schedule, `Schedule paused: ${message}`);
        } else {
          markScheduleError(id, message, leaseUntil);
        }
        log.warn('scheduled_scan_failed', { scheduleId: id, error: message });
      }
    }
  } finally {
    running = false;
  }
  return dispatched;
}
