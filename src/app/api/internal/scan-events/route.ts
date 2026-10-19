import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import { ensureInitialized } from '@/server/bootstrap';
import { errorJson, json } from '@/server/http';
import { getWebConfig } from '@/shared/config';
import { applyScanEvent } from '@/server/scans';
import { maybeSendScheduleAlert } from '@/server/schedule-alerts';
import type { ScanEventPayload } from '@/shared/types';

export const dynamic = 'force-dynamic';

const findingCounts = z
  .object({
    critical: z.number().int().min(0),
    high: z.number().int().min(0),
    medium: z.number().int().min(0),
    low: z.number().int().min(0),
    informational: z.number().int().min(0),
  })
  .strict();

const findingSummarySchema = z
  .object({
    fingerprint: z.string().min(1).max(64),
    title: z.string().min(1).max(500),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'informational']),
    category: z.enum(['exposure', 'misconfiguration', 'outdated-technology', 'wordpress', 'vulnerability', 'informational']),
    affected: z.string().max(2048).nullable(),
    sourceTools: z.array(z.string().max(64)).max(32),
  })
  .strict();

const payloadSchema = z
  .object({
    scanId: z.string().min(1).max(128),
    status: z.enum(['completed', 'failed', 'cancelled']),
    targetRaw: z.string().max(2048),
    host: z.string().max(255),
    path: z.string().max(2048),
    scheme: z.string().max(16),
    profile: z.string().max(32),
    portScope: z.string().max(32).nullable(),
    modules: z.array(z.string().max(64)).max(16),
    resolvedIps: z.array(z.string().max(64)).max(64),
    ipVersion: z.enum(['ipv4', 'ipv6', 'mixed']).nullable(),
    startedAt: z.string().max(40).nullable(),
    finishedAt: z.string().max(40).nullable(),
    durationMs: z.number().int().min(0).nullable(),
    portCount: z.number().int().min(0),
    findings: findingCounts,
    findingsDetail: z.array(findingSummarySchema).max(1000).optional().default([]),
    tools: z
      .array(
        z
          .object({
            tool: z.string().max(64),
            ok: z.boolean(),
            timedOut: z.boolean(),
            exitCode: z.number().int().nullable(),
            durationMs: z.number().min(0),
          })
          .strict(),
      )
      .max(64),
    toolOk: z.number().int().min(0),
    toolTotal: z.number().int().min(0),
    error: z.string().max(4096).nullable(),
  })
  .strict();

/** Internal bearer-token guard (mirrors the worker's own auth when a token is set). */
function authorized(req: NextRequest): boolean {
  const token = getWebConfig().serviceToken;
  if (!token) return true;
  const header = req.headers.get('authorization') ?? '';
  const expected = `Bearer ${token}`;
  const a = Buffer.from(header);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  await ensureInitialized();
  if (!authorized(req)) return errorJson('Unauthorized.', 401, 'unauthorized');

  const parsed = payloadSchema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return errorJson('Invalid scan event.', 400, 'validation_error');

  try {
    applyScanEvent(parsed.data as ScanEventPayload);
  } catch {
    return errorJson('Failed to record the scan event.', 500, 'internal');
  }
  void maybeSendScheduleAlert(parsed.data.scanId).catch(() => undefined);
  return json({ ok: true });
}
