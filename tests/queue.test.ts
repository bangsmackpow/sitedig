import { describe, expect, it } from 'vitest';
import { ScanQueue } from '../src/worker/queue';
import type { Job } from '../src/shared/types';

function makeJob(id: string): Job {
  return {
    id,
    status: 'queued',
    target: { kind: 'hostname', host: 'example.com', path: '/', scheme: 'https', raw: 'example.com', display: 'example.com', isIp: false },
    profile: 'quick',
    custom: null,
    createdAt: new Date().toISOString(),
    startedAt: null,
    finishedAt: null,
    error: null,
    report: null,
    artifacts: null,
  };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('ScanQueue', () => {
  it('rejects jobs beyond maxConcurrent + maxQueue', async () => {
    const queue = new ScanQueue(1, 2, async () => {
      await sleep(50);
    });
    const j1 = makeJob('1');
    const j2 = makeJob('2');
    const j3 = makeJob('3');
    const j4 = makeJob('4');
    expect(queue.add(j1)).toBe(true);
    expect(queue.add(j2)).toBe(true);
    expect(queue.add(j3)).toBe(true);
    expect(queue.add(j4)).toBe(false);
    await sleep(150);
  });

  it('never exceeds maxConcurrent', async () => {
    let concurrent = 0;
    let peak = 0;
    const queue = new ScanQueue(2, 4, async () => {
      concurrent += 1;
      peak = Math.max(peak, concurrent);
      await sleep(60);
      concurrent -= 1;
    });
    for (let i = 0; i < 5; i++) queue.add(makeJob(String(i)));
    await sleep(300);
    expect(peak).toBeLessThanOrEqual(2);
  });

  it('cancels queued jobs', async () => {
    const queue = new ScanQueue(1, 5, async () => {
      await sleep(50);
    });
    const running = makeJob('running');
    const queued = makeJob('queued');
    queue.add(running);
    queue.add(queued);
    await sleep(10);
    expect(queue.cancelQueued('queued')).toBe(true);
    await sleep(100);
    const job = queue.get('queued');
    expect(job?.status).toBe('cancelled');
    expect(job?.error).toContain('Cancelled');
  });

  it('tracks jobs by id and marks running', async () => {
    const queue = new ScanQueue(1, 1, async () => {
      await sleep(40);
    });
    const job = makeJob('x');
    queue.add(job);
    await sleep(10);
    expect(queue.get('x')?.status).toBe('running');
    await sleep(80);
    expect(queue.get('x')?.status).toBe('completed');
  });
});
