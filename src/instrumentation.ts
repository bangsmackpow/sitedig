/**
 * Next.js instrumentation: runs once when the web server starts.
 *
 * Starts an hourly maintenance tick that (a) sends the daily admin digest when
 * due and (b) sweeps scan history past its retention window. Both are
 * idempotent and guarded by a last-run date stored in the database, so a single
 * web instance never double-sends.
 */
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME !== 'nodejs') return;

  try {
    const { createLogger } = await import('./shared/logger');
    const log = createLogger();

    const { ensureInitialized } = await import('./server/bootstrap');
    await ensureInitialized();

    const { getWebConfig } = await import('./shared/config');
    const config = getWebConfig();
    const { runScheduledMaintenance } = await import('./server/digest');
    const { runDueScheduledScans } = await import('./server/scheduler');

    const tick = () => {
      runScheduledMaintenance().catch((e) => log.warn('maintenance_tick_failed', { error: (e as Error).message }));
    };
    const scheduleTick = () => {
      runDueScheduledScans().catch((e) => log.warn('scheduled_scans_tick_failed', { error: (e as Error).message }));
    };

    const HOUR_MS = 60 * 60 * 1000;
    const SCHEDULE_TICK_MS = 5 * 60 * 1000;
    // Catch-up run shortly after boot, then hourly for digest/retention.
    setTimeout(tick, 30_000).unref?.();
    setInterval(tick, HOUR_MS).unref?.();
    // Recurring scans get 5-minute precision, independent of the digest tick.
    setTimeout(scheduleTick, 15_000).unref?.();
    setInterval(scheduleTick, SCHEDULE_TICK_MS).unref?.();

    log.info('maintenance_scheduler_started', { digestEnabled: config.digest.enabled, digestHourUtc: config.digest.hourUtc });
  } catch (e) {
    // Never block server startup on maintenance wiring; routes surface config errors.
    // eslint-disable-next-line no-console
    console.warn(`[sitedig] maintenance scheduler failed to start: ${(e as Error).message}`);
  }
}
