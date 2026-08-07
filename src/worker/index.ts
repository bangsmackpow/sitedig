import fs from 'node:fs';
import http from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createJobSchema } from '../shared/schemas';
import { APP_NAME, APP_VERSION } from '../shared/constants';
import { getWorkerConfig } from '../shared/config';
import { createLogger } from '../shared/logger';
import type { CustomScanOptions, Job, JobStatus, PublicJobView, ScanProfile } from '../shared/types';
import { JobNotFoundError, QueueFullError, ScannerService, TargetRejectedError } from './scanner';

const MAX_BODY_BYTES = 256 * 1024;

function publicJobView(job: Job): PublicJobView {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  if (job.report) {
    for (const f of job.report.findings) {
      counts[f.severity] += 1;
    }
  }
  return {
    id: job.id,
    status: job.status as JobStatus,
    profile: job.profile,
    target: job.target.display,
    createdAt: job.createdAt,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    error: job.error,
    hasArtifacts: job.status === 'completed' && job.artifacts !== null,
    summaryCounts: job.report ? counts : null,
  };
}

export function startWorkerServer(opts: { config: ReturnType<typeof getWorkerConfig>; service: ScannerService }): http.Server {
  const { config, service } = opts;
  const log = createLogger({ LOG_LEVEL: config.logLevel });

  function isAuthorized(req: IncomingMessage): boolean {
    if (!config.serviceToken) return true;
    const header = req.headers.authorization ?? '';
    return header === `Bearer ${config.serviceToken}`;
  }

  function sendJson(res: ServerResponse, status: number, body: unknown): void {
    const payload = JSON.stringify(body);
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(payload) });
    res.end(payload);
  }

  function sendError(res: ServerResponse, status: number, message: string, code: string): void {
    sendJson(res, status, { error: { code, message } });
  }

  function readBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolvePromise, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      req.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          reject(new Error('Request body too large.'));
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => resolvePromise(Buffer.concat(chunks).toString('utf8')));
      req.on('error', reject);
    });
  }

  async function handleJobCreate(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let raw: string;
    try {
      raw = await readBody(req);
    } catch {
      sendError(res, 413, 'Request body too large.', 'body_too_large');
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      sendError(res, 400, 'Invalid JSON body.', 'invalid_json');
      return;
    }
    const result = createJobSchema.safeParse(parsed);
    if (!result.success) {
      sendError(res, 400, result.error.issues[0]?.message ?? 'Invalid scan request.', 'validation_error');
      return;
    }
    const input = result.data;
    try {
      const job = await service.createJob({
        target: input.target,
        profile: input.profile as ScanProfile,
        custom: input.custom as CustomScanOptions | undefined,
      });
      log.info('job_accepted', { jobId: job.id, profile: job.profile, host: job.target.host });
      sendJson(res, 201, { jobId: job.id, status: job.status });
    } catch (e) {
      if (e instanceof QueueFullError) {
        sendError(res, 409, e.message, 'queue_full');
      } else if (e instanceof TargetRejectedError) {
        sendError(res, 422, e.message, 'target_rejected');
      } else {
        log.error('job_create_failed', { error: (e as Error).message });
        sendError(res, 500, 'Failed to create scan.', 'internal');
      }
    }
  }

  function handleJobStatus(req: IncomingMessage, res: ServerResponse, jobId: string): void {
    const job = service.getJob(jobId);
    if (!job) {
      sendError(res, 404, 'Scan not found. The worker may have restarted since the scan was created.', 'job_not_found');
      return;
    }
    sendJson(res, 200, { job: publicJobView(job) });
  }

  function handleJobCancel(res: ServerResponse, jobId: string): void {
    try {
      const job = service.cancelJob(jobId);
      sendJson(res, 200, { job: publicJobView(job) });
    } catch (e) {
      if (e instanceof JobNotFoundError) {
        sendError(res, 404, e.message, 'job_not_found');
      } else {
        sendError(res, 500, 'Failed to cancel scan.', 'internal');
      }
    }
  }

  function handleArtifactDownload(res: ServerResponse, jobId: string, format: string): void {
    if (format !== 'markdown' && format !== 'pdf') {
      sendError(res, 400, 'Unsupported artifact format.', 'bad_format');
      return;
    }
    const job = service.getJob(jobId);
    if (!job) {
      sendError(res, 404, 'Scan not found.', 'job_not_found');
      return;
    }
    const filePath = service.getArtifactPath(job, format);
    if (!filePath || !fs.existsSync(filePath)) {
      sendError(res, 409, 'Scan has not completed or has no downloadable report.', 'no_artifacts');
      return;
    }

    const mime = format === 'pdf' ? 'application/pdf' : 'text/markdown; charset=utf-8';
    const filename = format === 'pdf' ? `sitedig-report-${jobId}.pdf` : `sitedig-report-${jobId}.md`;
    const safeJobId = jobId.replace(/[^a-zA-Z0-9-]/g, '');

    res.writeHead(200, {
      'content-type': mime,
      'content-disposition': `attachment; filename="${filename}"`,
      'x-robots-tag': 'noindex',
    });

    const stream = fs.createReadStream(filePath);
    stream.on('error', () => {
      // Headers already sent; just abort the connection.
      res.destroy();
    });
    stream.pipe(res);
    res.on('finish', () => {
      service.deleteArtifact(job, format);
      log.info('artifact_delivered', { jobId: safeJobId, format });
    });
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const method = req.method ?? 'GET';
    const segments = url.pathname.split('/').filter(Boolean);

    if (url.pathname === '/health' && method === 'GET') {
      sendJson(res, 200, { ok: true, service: 'worker', app: APP_NAME, version: APP_VERSION });
      return;
    }

    if (!isAuthorized(req)) {
      sendError(res, 401, 'Unauthorized.', 'unauthorized');
      return;
    }

    try {
      if (url.pathname === '/jobs' && method === 'POST') {
        await handleJobCreate(req, res);
        return;
      }
      if (segments.length === 2 && segments[0] === 'jobs' && method === 'GET') {
        handleJobStatus(req, res, segments[1]);
        return;
      }
      if (segments.length === 3 && segments[0] === 'jobs' && segments[2] === 'cancel' && method === 'POST') {
        handleJobCancel(res, segments[1]);
        return;
      }
      if (segments.length === 4 && segments[0] === 'jobs' && segments[2] === 'artifacts' && method === 'GET') {
        handleArtifactDownload(res, segments[1], segments[3]);
        return;
      }
      sendError(res, 404, 'Not found.', 'not_found');
    } catch (e) {
      log.error('request_error', { error: (e as Error).message });
      sendError(res, 500, 'Internal server error.', 'internal');
    }
  });

  return server;
}

export function main(): void {
  const config = getWorkerConfig();
  const log = createLogger({ LOG_LEVEL: config.logLevel });
  const service = new ScannerService(config, log);
  service.start();
  const server = startWorkerServer({ config, service });
  server.listen(config.port, '0.0.0.0', () => {
    log.info('worker_listening', { port: config.port });
  });

  const shutdown = () => {
    log.info('worker_shutting_down', {});
    service.stop();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

if (require.main === module) {
  main();
}
