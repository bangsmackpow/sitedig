import { getWebConfig } from '@/shared/config';
import type { ModuleId, PublicJobView, ScanProfile } from '@/shared/types';

export interface CreateScanInput {
  target: string;
  profile: ScanProfile;
  consent: boolean;
  custom?: {
    portScope: 'common' | 'top100' | 'top1000';
    enabledTools: Array<'nmap' | 'whatweb' | 'wpscan' | 'http' | 'tls'>;
    path?: string;
    followRedirects?: boolean;
    userAgent?: string;
    timeoutMs?: number;
  };
  modules?: ModuleId[];
}

export interface ModuleView {
  id: ModuleId;
  name: string;
  description: string;
  tools: string[];
  paid: boolean;
  enabled: boolean;
}

export class WorkerClientError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
  ) {
    super(message);
    this.name = 'WorkerClientError';
  }
}

export class WorkerUnavailableError extends Error {
  constructor() {
    super('The scanner worker is unavailable. Please try again shortly.');
    this.name = 'WorkerUnavailableError';
  }
}

function config(): { workerUrl: string; token: string } {
  const cfg = getWebConfig();
  return { workerUrl: cfg.workerUrl, token: cfg.serviceToken };
}

async function request(path: string, init?: RequestInit): Promise<Response> {
  const { workerUrl, token } = config();
  const headers = new Headers(init?.headers);
  if (token) headers.set('authorization', `Bearer ${token}`);
  headers.set('accept', 'application/json');

  try {
    const res = await fetch(`${workerUrl}${path}`, { ...init, headers });
    return res;
  } catch {
    throw new WorkerUnavailableError();
  }
}

async function readError(res: Response): Promise<{ message: string; code: string }> {
  try {
    const body = (await res.json()) as { error?: { message?: string; code?: string } };
    return { message: body.error?.message ?? `Request failed with status ${res.status}`, code: body.error?.code ?? 'unknown' };
  } catch {
    return { message: `Request failed with status ${res.status}`, code: 'unknown' };
  }
}

export async function createScan(input: CreateScanInput): Promise<{ jobId: string; status: string }> {
  const res = await request('/jobs', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(input),
  });
  if (res.ok) {
    const data = (await res.json()) as { jobId: string; status: string };
    return data;
  }
  const err = await readError(res);
  throw new WorkerClientError(err.message, res.status, err.code);
}

export async function getModules(): Promise<ModuleView[]> {
  const res = await request('/modules');
  if (res.ok) {
    const data = (await res.json()) as { modules: ModuleView[] };
    return data.modules;
  }
  const err = await readError(res);
  throw new WorkerClientError(err.message, res.status, err.code);
}

export async function getJobStatus(jobId: string): Promise<PublicJobView> {
  const res = await request(`/jobs/${encodeURIComponent(jobId)}`);
  if (res.ok) {
    const data = (await res.json()) as { job: PublicJobView };
    return data.job;
  }
  const err = await readError(res);
  throw new WorkerClientError(err.message, res.status, err.code);
}

export async function downloadArtifact(jobId: string, format: 'markdown' | 'pdf'): Promise<Response> {
  const res = await request(`/jobs/${encodeURIComponent(jobId)}/artifacts/${format}`, { method: 'GET' });
  if (res.ok) return res;
  const err = await readError(res);
  throw new WorkerClientError(err.message, res.status, err.code);
}

export async function cancelScan(jobId: string): Promise<PublicJobView> {
  const res = await request(`/jobs/${encodeURIComponent(jobId)}/cancel`, { method: 'POST' });
  if (res.ok) {
    const data = (await res.json()) as { job: PublicJobView };
    return data.job;
  }
  const err = await readError(res);
  throw new WorkerClientError(err.message, res.status, err.code);
}

export async function workerHealth(): Promise<{ ok: boolean }> {
  const res = await request('/health');
  if (res.ok) return { ok: true };
  return { ok: false };
}
