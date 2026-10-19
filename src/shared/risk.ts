import type { FindingCounts } from './types';

export type RiskGrade = 'A' | 'B' | 'C' | 'D' | 'F';

/** Simple, explainable risk score derived only from finding severities. */
export function riskScore(counts: FindingCounts): number {
  const score = 100 - 25 * counts.critical - 10 * counts.high - 3 * counts.medium - counts.low;
  return Math.max(0, Math.min(100, score));
}

export function riskGrade(score: number): RiskGrade {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}
