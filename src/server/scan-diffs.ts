import { riskGrade, riskScore } from '../shared/risk';
import type { FindingCounts, FindingSeverityChange, ScanDiff, ScanFindingSummary, ScanRisk } from '../shared/types';
import { getPreviousScan, getScan, getScanFindings, getScanToolStatus, type ScanRow } from './scans';

const SEVERITY_ORDER: Record<ScanFindingSummary['severity'], number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  informational: 1,
};

function countsFor(row: ScanRow): FindingCounts {
  return {
    critical: row.findings_critical,
    high: row.findings_high,
    medium: row.findings_medium,
    low: row.findings_low,
    informational: row.findings_informational,
  };
}

function riskFor(row: ScanRow): ScanRisk {
  const score = riskScore(countsFor(row));
  return { score, grade: riskGrade(score) };
}

function sortFindings(findings: ScanFindingSummary[]): ScanFindingSummary[] {
  return [...findings].sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.title.localeCompare(b.title));
}

/**
 * Compare a completed scan with the previous scan for the same schedule (or
 * same user/host/path). Findings missing because a tool failed or did not run
 * are classified as not assessed rather than resolved.
 */
export function computeScanDiff(currentScanId: string): ScanDiff | null {
  const current = getScan(currentScanId);
  if (!current) return null;
  const currentRisk = riskFor(current);
  const previous = getPreviousScan(current);
  if (!previous) {
    return {
      currentScanId: current.id,
      previousScanId: null,
      newFindings: [],
      resolvedFindings: [],
      notAssessed: [],
      severityChanges: [],
      unchangedCount: 0,
      risk: currentRisk,
      previousRisk: null,
      riskDelta: null,
    };
  }

  const previousFindings = getScanFindings(previous.id);
  const currentFindings = getScanFindings(current.id);
  const previousByFingerprint = new Map(previousFindings.map((f) => [f.fingerprint, f]));
  const currentByFingerprint = new Map(currentFindings.map((f) => [f.fingerprint, f]));
  const currentTools = getScanToolStatus(current.id);

  const newFindings = sortFindings(currentFindings.filter((f) => !previousByFingerprint.has(f.fingerprint)));
  const missing = previousFindings.filter((f) => !currentByFingerprint.has(f.fingerprint));
  const resolvedFindings: ScanFindingSummary[] = [];
  const notAssessed: ScanFindingSummary[] = [];
  for (const finding of missing) {
    const sources = finding.sourceTools ?? [];
    const unavailable = sources.length > 0 && sources.some((tool) => currentTools.get(tool) !== true);
    if (unavailable) notAssessed.push(finding);
    else resolvedFindings.push(finding);
  }

  const severityChanges: FindingSeverityChange[] = [];
  let matchedCount = 0;
  for (const [fingerprint, previousFinding] of previousByFingerprint) {
    const currentFinding = currentByFingerprint.get(fingerprint);
    if (!currentFinding) continue;
    matchedCount += 1;
    if (currentFinding.severity !== previousFinding.severity) {
      severityChanges.push({ finding: currentFinding, from: previousFinding.severity, to: currentFinding.severity });
    }
  }
  const unchangedCount = Math.max(0, matchedCount - severityChanges.length);

  const previousRisk = riskFor(previous);
  return {
    currentScanId: current.id,
    previousScanId: previous.id,
    newFindings,
    resolvedFindings: sortFindings(resolvedFindings),
    notAssessed: sortFindings(notAssessed),
    severityChanges,
    unchangedCount,
    risk: currentRisk,
    previousRisk,
    riskDelta: currentRisk.score - previousRisk.score,
  };
}
