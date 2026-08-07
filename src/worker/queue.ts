import type { Job } from '../shared/types';

export interface QueueEvents {
  onStart?: (job: Job) => void;
  onFinish?: (job: Job) => void;
  onReject?: (job: Job, reason: string) => void;
}

/**
 * A simple in-memory, worker-owned scan queue with bounded concurrency.
 *
 * All state lives in memory: a worker restart loses queued and active jobs by
 * design (the web service surfaces them as interrupted). No persistence is
 * used in the MVP.
 */
export class ScanQueue {
  private registry = new Map<string, Job>();
  private pending: string[] = [];
  private active = 0;
  private cancelled = new Set<string>();

  constructor(
    private readonly maxConcurrent: number,
    private readonly maxQueue: number,
    private readonly process: (job: Job) => Promise<void>,
    private readonly events: QueueEvents = {},
  ) {}

  get pendingCount(): number {
    return this.pending.length;
  }

  get activeCount(): number {
    return this.active;
  }

  /** Returns false when the queue is full. */
  add(job: Job): boolean {
    if (this.active + this.pending.length >= this.maxConcurrent + this.maxQueue) {
      return false;
    }
    this.registry.set(job.id, job);
    this.pending.push(job.id);
    this.drain();
    return true;
  }

  get(id: string): Job | undefined {
    return this.registry.get(id);
  }

  has(id: string): boolean {
    return this.registry.has(id);
  }

  /** Cancel a job that has not started yet. */
  cancelQueued(id: string): boolean {
    if (!this.pending.includes(id)) return false;
    if (this.cancelled.has(id)) return false;
    const job = this.registry.get(id);
    if (!job) return false;
    this.cancelled.add(id);
    this.pending = this.pending.filter((p) => p !== id);
    job.status = 'cancelled';
    job.finishedAt = new Date().toISOString();
    job.error = 'Cancelled by user before execution began.';
    this.events.onFinish?.(job);
    this.drain();
    return true;
  }

  private drain(): void {
    while (this.active < this.maxConcurrent && this.pending.length > 0) {
      const id = this.pending.shift();
      if (!id) break;
      if (this.cancelled.has(id)) {
        continue;
      }
      const job = this.registry.get(id);
      if (!job) continue;
      this.active += 1;
      job.status = 'running';
      job.startedAt = new Date().toISOString();
      this.events.onStart?.(job);
      this.process(job)
        .then(() => {
          if (job.status === 'running') {
            job.status = 'completed';
            job.finishedAt = job.finishedAt ?? new Date().toISOString();
          }
        })
        .catch((err) => {
          if (job.status === 'completed' || job.status === 'cancelled') return;
          job.status = 'failed';
          job.error = (err as Error).message ?? 'Unknown scan error';
          job.finishedAt = job.finishedAt ?? new Date().toISOString();
          this.events.onReject?.(job, job.error);
        })
        .finally(() => {
          this.active -= 1;
          this.cancelled.delete(id);
          this.events.onFinish?.(job);
          this.drain();
        });
    }
  }
}
