import { riskGrade, riskScore, type RiskGrade } from './risk';
import type { Finding, FindingCounts, ReportModel } from './types';

const CATEGORY_LABELS: Record<Finding['category'], string> = {
  exposure: 'Exposure',
  misconfiguration: 'Misconfiguration',
  'outdated-technology': 'Outdated Technology',
  wordpress: 'WordPress Finding',
  vulnerability: 'Vulnerability',
  informational: 'Informational',
};

const SEVERITY_LABELS: Record<Finding['severity'], string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Informational',
};

const SEVERITY_ORDER: Record<Finding['severity'], number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  informational: 1,
};

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.title.localeCompare(b.title));
}

export type CheckStatus = 'pass' | 'warn' | 'fail' | 'info';

export interface CheckResult {
  label: string;
  status: CheckStatus;
  detail: string;
}

export interface PortGroup {
  key: string;
  label: string;
  ports: ReportModel['ports'];
}

export interface ToolStat {
  tool: string;
  label: string;
  ok: boolean;
  timedOut: boolean;
  durationMs: number;
}

export interface ReportPresentation {
  counts: FindingCounts;
  risk: { score: number; grade: RiskGrade };
  severity: Array<{ key: keyof FindingCounts; label: string; count: number }>;
  categories: Array<{ key: string; label: string; count: number }>;
  topFindings: Finding[];
  keyTakeaways: string[];
  portGroups: PortGroup[];
  posture: CheckResult[];
  dnsEmail: CheckResult[];
  attackSurface: Array<{ label: string; value: number; suffix?: string }>;
  cveSummary: {
    packageCount: number;
    cveCount: number;
    severities: Record<string, number>;
    top: Array<{ name: string; version: string; cveCount: number; criticalHigh: number }>;
  };
  toolStats: {
    total: number;
    ok: number;
    failed: number;
    timedOut: number;
    totalDurationMs: number;
    slowest: ToolStat[];
  };
  coverage: {
    modules: string[];
    toolsRun: number;
    toolsTotal: number;
  };
}

const DB_PORTS = new Set([1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017]);
const WEB_PORTS = new Set([80, 443, 8000, 8080, 8443, 8888]);
const REMOTE_PORTS = new Set([22, 2375, 2376, 3389, 5900, 5985, 5986]);
const MAIL_PORTS = new Set([25, 110, 143, 465, 587, 993, 995]);
const FILE_PORTS = new Set([21, 111, 139, 445]);

function statusFor(ok: boolean, warn = false): CheckStatus {
  if (ok) return 'pass';
  return warn ? 'warn' : 'fail';
}

function portGroupKey(port: number): string {
  if (WEB_PORTS.has(port)) return 'web';
  if (DB_PORTS.has(port)) return 'database';
  if (REMOTE_PORTS.has(port)) return 'remote';
  if (MAIL_PORTS.has(port)) return 'mail';
  if (FILE_PORTS.has(port)) return 'file';
  return 'other';
}

function portGroups(report: ReportModel): PortGroup[] {
  const labels: Record<string, string> = {
    web: 'Web services',
    database: 'Database / cache',
    remote: 'Remote administration',
    mail: 'Mail services',
    file: 'File sharing',
    other: 'Other services',
  };
  const groups = new Map<string, ReportModel['ports']>();
  for (const port of report.ports) {
    const key = portGroupKey(port.port);
    const list = groups.get(key) ?? [];
    list.push(port);
    groups.set(key, list);
  }
  return Object.keys(labels)
    .filter((key) => groups.has(key))
    .map((key) => ({ key, label: labels[key], ports: groups.get(key)! }));
}

function httpPosture(report: ReportModel): CheckResult[] {
  const headers = report.http?.headers ?? {};
  const posture = report.headerPosture;
  const checks: CheckResult[] = [];
  if (report.http && !report.http.error) {
    checks.push({
      label: 'HTTPS',
      status: report.http.finalUrl?.startsWith('https://') ? 'pass' : 'warn',
      detail: report.http.finalUrl?.startsWith('https://') ? 'Final URL uses HTTPS' : 'Final URL is HTTP',
    });
  }
  if (posture) {
    checks.push({
      label: 'HSTS',
      status: posture.hsts.present ? (posture.hsts.maxAge !== null && posture.hsts.maxAge >= 15_552_000 ? 'pass' : 'warn') : 'fail',
      detail: posture.hsts.present
        ? `max-age ${posture.hsts.maxAge ?? 'unknown'}${posture.hsts.includeSubDomains ? ', includeSubDomains' : ''}${posture.hsts.preload ? ', preload' : ''}`
        : 'Not set',
    });
    checks.push({
      label: 'CSP',
      status: posture.csp ? (posture.csp.reportOnly ? 'warn' : 'pass') : 'fail',
      detail: posture.csp
        ? `${posture.csp.reportOnly ? 'Report-only' : 'Enforced'}${posture.csp.unsafeInline ? ', unsafe-inline' : ''}${posture.csp.unsafeEval ? ', unsafe-eval' : ''}`
        : 'Not set',
    });
    checks.push({
      label: 'Cookies',
      status: posture.cookies.length === 0 ? 'info' : posture.cookies.every((c) => c.secure && c.httpOnly) ? 'pass' : 'warn',
      detail: posture.cookies.length === 0 ? 'No cookies observed' : `${posture.cookies.length} cookie(s) observed`,
    });
    checks.push({
      label: 'ALPN',
      status: posture.alpnProtocol === 'h2' || posture.alpnProtocol === 'h3' ? 'pass' : 'info',
      detail: posture.httpVersionHint ?? posture.alpnProtocol ?? 'Not observed',
    });
  }
  const headerChecks: Array<[string, string]> = [
    ['X-Content-Type-Options', 'x-content-type-options'],
    ['X-Frame-Options', 'x-frame-options'],
    ['Referrer-Policy', 'referrer-policy'],
    ['Permissions-Policy', 'permissions-policy'],
  ];
  for (const [label, key] of headerChecks) {
    checks.push({
      label,
      status: headers[key] ? 'pass' : 'warn',
      detail: headers[key] ?? 'Not set',
    });
  }
  return checks;
}

function dnsEmailPosture(report: ReportModel): CheckResult[] {
  const checks: CheckResult[] = [];
  const email = report.email;
  if (email && !email.error) {
    checks.push({
      label: 'SPF',
      status: email.spfRecords.length === 1 ? 'pass' : email.spfRecords.length === 0 ? 'fail' : 'warn',
      detail: email.spfRecords.length === 0 ? 'Not published' : email.spfRecords.join(' | '),
    });
    checks.push({
      label: 'DMARC',
      status: email.dmarcRecords.length === 0 ? 'fail' : /p=(quarantine|reject)/i.test(email.dmarcRecords.join(' ')) ? 'pass' : 'warn',
      detail: email.dmarcRecords.length === 0 ? 'Not published' : email.dmarcRecords.join(' | '),
    });
    checks.push({
      label: 'MX STARTTLS',
      status: email.starttls.checked ? (email.starttls.supported ? 'pass' : 'fail') : 'info',
      detail: email.starttls.checked ? (email.starttls.supported ? 'Offered' : 'Not offered') : 'Not checked',
    });
    checks.push({ label: 'MTA-STS', status: email.mtaSts ? 'pass' : 'warn', detail: email.mtaSts ?? 'Not published' });
    checks.push({ label: 'TLS-RPT', status: email.tlsRpt ? 'pass' : 'warn', detail: email.tlsRpt ?? 'Not published' });
  }
  const hardening = report.dnsHardening;
  if (hardening && !hardening.error) {
    checks.push({ label: 'CAA', status: hardening.caa.length > 0 ? 'pass' : 'warn', detail: hardening.caa.length > 0 ? `${hardening.caa.length} record(s)` : 'Not published' });
    const dkim = hardening.dkim.filter((d) => d.found && !d.revoked);
    checks.push({ label: 'DKIM', status: dkim.length > 0 ? 'pass' : 'warn', detail: dkim.length > 0 ? dkim.map((d) => d.selector).join(', ') : 'No common selector found' });
    if (hardening.dmarc && email?.dmarcRecords.length === 0) {
      checks.push({ label: 'DMARC', status: hardening.dmarc.policy === 'none' ? 'warn' : 'pass', detail: `p=${hardening.dmarc.policy ?? 'unknown'}` });
    }
  }
  if (report.dnssec && !report.dnssec.error) {
    checks.push({
      label: 'DNSSEC',
      status: report.dnssec.signed ? 'pass' : 'warn',
      detail: report.dnssec.signed ? `Signed${report.dnssec.algorithms.length ? ` (${report.dnssec.algorithms.join(', ')})` : ''}` : 'Not enabled',
    });
  }
  return checks;
}

function keyTakeaways(report: ReportModel, counts: FindingCounts, risk: { score: number; grade: RiskGrade }, groups: PortGroup[]): string[] {
  const out: string[] = [];
  const high = counts.critical + counts.high;
  const top = sortFindings(report.findings).find((f) => f.severity === 'critical' || f.severity === 'high');
  if (high > 0) {
    out.push(`${high} critical/high-severity finding${high === 1 ? '' : 's'} require attention${top ? `, led by "${top.title}"` : ''}.`);
  } else {
    out.push('No critical or high-severity findings were observed in this scan.');
  }
  out.push(`Overall risk is ${risk.score}/100 (grade ${risk.grade}).`);
  const db = groups.find((g) => g.key === 'database');
  if (db) out.push(`${db.ports.length} database/cache port${db.ports.length === 1 ? '' : 's'} are reachable: ${db.ports.map((p) => p.port).join(', ')}.`);
  const remote = groups.find((g) => g.key === 'remote');
  if (remote) out.push(`${remote.ports.length} remote-administration port${remote.ports.length === 1 ? '' : 's'} exposed: ${remote.ports.map((p) => p.port).join(', ')}.`);
  if (report.tls?.daysRemaining !== null && report.tls?.daysRemaining !== undefined && report.tls.daysRemaining <= 30) {
    out.push(`The TLS certificate expires in ${report.tls.daysRemaining} day(s).`);
  }
  const posture = httpPosture(report);
  const failing = posture.filter((c) => c.status === 'fail').slice(0, 3);
  if (failing.length > 0) out.push(`HTTP posture gaps: ${failing.map((c) => c.label).join(', ')}.`);
  const dnsFails = dnsEmailPosture(report).filter((c) => c.status === 'fail');
  if (dnsFails.length > 0) out.push(`DNS/email posture gaps: ${dnsFails.map((c) => c.label).join(', ')}.`);
  const failedTools = report.toolResults.filter((t) => !t.ok);
  if (failedTools.length > 0) out.push(`${failedTools.length} tool(s) failed or timed out; some checks were not assessed.`);
  return out.slice(0, 6);
}

export function buildReportPresentation(report: ReportModel): ReportPresentation {
  const counts: FindingCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const finding of report.findings) counts[finding.severity] += 1;
  const score = riskScore(counts);
  const risk = { score, grade: riskGrade(score) };
  const groups = portGroups(report);

  const categoryCounts = new Map<string, number>();
  for (const finding of report.findings) categoryCounts.set(finding.category, (categoryCounts.get(finding.category) ?? 0) + 1);

  const cveSeverities = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const cve of report.cveContext) {
    for (const key of Object.keys(cveSeverities) as Array<keyof typeof cveSeverities>) {
      cveSeverities[key] += cve.severities[key] ?? 0;
    }
  }
  for (const vuln of report.vulnerabilities) {
    const key = vuln.severity === 'info' ? null : vuln.severity;
    if (key && key in cveSeverities) cveSeverities[key as keyof typeof cveSeverities] += 1;
  }

  const toolResults = report.toolResults;
  const failed = toolResults.filter((t) => !t.ok && !t.timedOut).length;
  const timedOut = toolResults.filter((t) => t.timedOut).length;
  const slowest = [...toolResults]
    .sort((a, b) => b.durationMs - a.durationMs)
    .slice(0, 8)
    .map((t) => ({ tool: t.tool, label: t.label, ok: t.ok, timedOut: t.timedOut, durationMs: t.durationMs }));

  return {
    counts,
    risk,
    severity: (['critical', 'high', 'medium', 'low', 'informational'] as const).map((key) => ({
      key,
      label: SEVERITY_LABELS[key],
      count: counts[key],
    })),
    categories: [...categoryCounts.entries()]
      .map(([key, count]) => ({ key, label: CATEGORY_LABELS[key as Finding['category']] ?? key, count }))
      .sort((a, b) => b.count - a.count),
    topFindings: sortFindings(report.findings).slice(0, 5),
    keyTakeaways: keyTakeaways(report, counts, risk, groups),
    portGroups: groups,
    posture: httpPosture(report),
    dnsEmail: dnsEmailPosture(report),
    attackSurface: [
      { label: 'Open ports', value: report.ports.length },
      { label: 'Technologies', value: report.technologies.length },
      { label: 'Subdomains', value: report.subdomains.length },
      { label: 'Discovered paths', value: report.discoveredPaths.length },
      { label: 'Archived sensitive URLs', value: (report.archivedUrls ?? []).filter((a) => a.category !== 'other').length },
      { label: 'Third-party hosts', value: report.pageRecon?.thirdParties.length ?? 0 },
    ],
    cveSummary: {
      packageCount: report.cveContext.length,
      cveCount: report.cveContext.reduce((sum, c) => sum + c.cveCount, 0),
      severities: cveSeverities,
      top: [...report.cveContext]
        .sort((a, b) => b.severities.critical + b.severities.high - (a.severities.critical + a.severities.high) || b.cveCount - a.cveCount)
        .slice(0, 6)
        .map((c) => ({ name: c.name, version: c.version, cveCount: c.cveCount, criticalHigh: c.severities.critical + c.severities.high })),
    },
    toolStats: {
      total: toolResults.length,
      ok: toolResults.filter((t) => t.ok).length,
      failed,
      timedOut,
      totalDurationMs: toolResults.reduce((sum, t) => sum + t.durationMs, 0),
      slowest,
    },
    coverage: {
      modules: report.meta.modules ?? [],
      toolsRun: toolResults.length,
      toolsTotal: toolResults.length,
    },
  };
}
