import { APP_NAME, APP_VERSION } from './constants';
import type { Finding, ReportMeta, ReportModel } from './types';

export const SEVERITY_ORDER: Record<Finding['severity'], number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  informational: 1,
};

export const CATEGORY_LABELS: Record<Finding['category'], string> = {
  exposure: 'Exposure',
  misconfiguration: 'Misconfiguration',
  'outdated-technology': 'Outdated Technology',
  wordpress: 'WordPress Finding',
  informational: 'Informational',
};

export const SEVERITY_LABELS: Record<Finding['severity'], string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Informational',
};

export function buildExecutiveSummary(meta: ReportMeta, findings: Finding[], portCount: number): string {
  const notable = findings.filter((f) => f.severity === 'high' || f.severity === 'critical');
  const medium = findings.filter((f) => f.severity === 'medium').length;
  const low = findings.filter((f) => f.severity === 'low').length;

  let summary = `This report summarises an authorized, detection-oriented reconnaissance scan of ${meta.target} `;
  summary += `using the ${meta.profile} profile. The scan was TCP-only, limited to ${portCount ? `the configured port scope` : 'a restricted port scope'}, and capped at 5 minutes. `;
  summary += `It identifies observed facts such as open ports, web technologies, HTTP headers, and TLS certificate details. It does not perform exploitation or vulnerability confirmation.`;

  if (notable.length > 0) {
    summary += ` The scan surfaced ${notable.length} finding(s) rated high or critical, the most notable being: ${notable
      .slice(0, 5)
      .map((f) => f.title)
      .join('; ')}. These should be reviewed and remediated with priority.`;
  } else if (medium > 0) {
    summary += ` No critical or high-severity findings were identified, but ${medium} medium-severity finding(s)${low > 0 ? ` and ${low} low-severity finding(s)` : ''} were noted and should be reviewed.`;
  } else if (low > 0) {
    summary += ` No findings above low severity were identified; ${low} low-severity finding(s) were noted and should be reviewed.`;
  } else {
    summary += ` No findings above informational severity were identified.`;
  }

  summary += ` All severity ratings are inferred from observed evidence and should be verified against your environment.`;
  return summary;
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const bySeverity = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (bySeverity !== 0) return bySeverity;
    return a.title.localeCompare(b.title);
  });
}

function escMd(text: string): string {
  // Only escape characters that actually break markdown inside inline code and
  // plain text we emit. Over-escaping (e.g. dots in URLs) makes output ugly.
  return text.replace(/[`\\]/g, '\\$&');
}

export function renderMarkdown(report: ReportModel): string {
  const findings = sortFindings(report.findings);
  const lines: string[] = [];

  lines.push(`# ${APP_NAME} Scan Report`);
  lines.push('');
  lines.push(`**Generated:** ${report.meta.finishedAt}`);
  lines.push('');
  lines.push('---');
  lines.push('');

  // Summary
  lines.push('## Executive Summary');
  lines.push('');
  lines.push(report.executiveSummary);
  lines.push('');
  lines.push('| Field | Value |');
  lines.push('| --- | --- |');
  lines.push(`| Target | \`${escMd(report.meta.target)}\` |`);
  lines.push(`| Host | \`${escMd(report.meta.host)}\` |`);
  lines.push(`| Path | \`${escMd(report.meta.path)}\` |`);
  lines.push(`| Profile | ${report.meta.profile} |`);
  lines.push(`| Port scope | ${report.meta.portScope ?? 'n/a'} |`);
  lines.push(`| Started | ${report.meta.startedAt} |`);
  lines.push(`| Finished | ${report.meta.finishedAt} |`);
  lines.push(`| Duration | ${(report.meta.durationMs / 1000).toFixed(1)}s |`);
  lines.push(`| Status | ${report.meta.status} |`);
  if (report.meta.warnings.length > 0) {
    lines.push(`| Warnings | ${report.meta.warnings.map((w) => escMd(w)).join('; ')} |`);
  }
  lines.push('');

  // Findings
  lines.push('## Findings');
  lines.push('');
  if (findings.length === 0) {
    lines.push('No findings were recorded.');
  } else {
    for (const f of findings) {
      lines.push(`### [${SEVERITY_LABELS[f.severity]}] ${f.title}`);
      lines.push('');
      lines.push(`- **Category:** ${CATEGORY_LABELS[f.category]}`);
      lines.push(`- **Confidence:** ${f.confidence}`);
      lines.push(`- **Verified observation:** ${f.verified ? 'Yes' : 'No'}`);
      lines.push('');
      lines.push(f.description);
      if (f.affected) {
        lines.push('');
        lines.push(`**Affected:** \`${escMd(f.affected)}\``);
      }
      if (f.evidence.length > 0) {
        lines.push('');
        lines.push('**Evidence:**');
        for (const ev of f.evidence) {
          lines.push(`- \`${escMd(ev)}\``);
        }
      }
      if (f.remediation) {
        lines.push('');
        lines.push(`**Remediation:** ${f.remediation}`);
      }
      lines.push('');
    }
  }
  lines.push('---');
  lines.push('');

  // Ports
  lines.push('## Discovered Ports & Services');
  lines.push('');
  if (report.ports.length === 0) {
    lines.push('No open TCP ports were discovered within the configured scope.');
  } else {
    lines.push('| Port | Protocol | Service | Version |');
    lines.push('| --- | --- | --- | --- |');
    for (const p of report.ports) {
      lines.push(`| ${p.port} | ${p.protocol} | ${escMd(p.service || 'unknown')} | ${escMd(p.version || '')} |`);
    }
  }
  lines.push('');

  // Technologies
  if (report.technologies.length > 0) {
    lines.push('## Technologies Detected');
    lines.push('');
    lines.push('| Technology | Version |');
    lines.push('| --- | --- |');
    for (const t of report.technologies) {
      lines.push(`| ${escMd(t.name)} | ${t.version ? escMd(t.version) : 'unknown'} |`);
    }
    lines.push('');
  }

  // HTTP
  if (report.http) {
    lines.push('## HTTP Observations');
    lines.push('');
    const h = report.http;
    if (h.error) {
      lines.push(`HTTP check could not be completed: ${h.error}`);
    } else {
      lines.push(`- **Status:** ${h.status ?? 'n/a'}`);
      lines.push(`- **Final URL:** ${h.finalUrl ?? 'n/a'}`);
      if (h.server) lines.push(`- **Server:** ${escMd(h.server)}`);
      if (h.poweredBy) lines.push(`- **X-Powered-By:** ${escMd(h.poweredBy)}`);
      if (h.redirects.length > 0) {
        lines.push('- **Redirects:**');
        for (const r of h.redirects) {
          lines.push(`  - ${r.status} -> ${escMd(r.to)}`);
        }
      }
    }
    lines.push('');
  }

  // TLS
  if (report.tls) {
    lines.push('## TLS Observations');
    lines.push('');
    const t = report.tls;
    if (t.error) {
      lines.push(`TLS check could not be completed: ${t.error}`);
    } else {
      lines.push(`- **Connected:** ${t.connected}`);
      lines.push(`- **Protocol:** ${t.protocol ?? 'n/a'}`);
      lines.push(`- **Subject CN:** ${escMd(t.subjectCn ?? 'n/a')}`);
      lines.push(`- **Issuer CN:** ${escMd(t.issuerCn ?? 'n/a')}`);
      lines.push(`- **Valid from:** ${t.validFrom ?? 'n/a'}`);
      lines.push(`- **Valid to:** ${t.validTo ?? 'n/a'}`);
      if (t.daysRemaining !== null) {
        lines.push(`- **Days remaining:** ${t.daysRemaining}`);
      }
      lines.push(`- **Self-signed:** ${t.selfSigned}`);
    }
    lines.push('');
  }

  // WordPress
  if (report.wordpress) {
    lines.push('## WordPress');
    lines.push('');
    lines.push(`- **Detected:** ${report.wordpress.detected}`);
    lines.push(`- **WPScan run:** ${report.wordpress.wpscanRan}`);
    for (const n of report.wordpress.notes) {
      lines.push(`- ${n}`);
    }
    lines.push('');
  }

  // Tool results (sanitized)
  lines.push('## Tool Execution');
  lines.push('');
  lines.push('| Tool | Result | Exit | Duration |');
  lines.push('| --- | --- | --- | --- |');
  for (const tr of report.toolResults) {
    const result = tr.ok ? (tr.timedOut ? 'timed out' : 'ok') : `error${tr.error ? `: ${tr.error}` : ''}`;
    lines.push(`| ${escMd(tr.label)} | ${escMd(result)} | ${tr.exitCode ?? 'n/a'} | ${(tr.durationMs / 1000).toFixed(1)}s |`);
  }
  lines.push('');

  // Tool versions
  if (report.meta.toolVersions.length > 0) {
    lines.push('## Tool Versions');
    lines.push('');
    lines.push(`| Tool | Version |`);
    lines.push(`| --- | --- |`);
    for (const tv of report.meta.toolVersions) {
      lines.push(`| ${escMd(tv.tool)} | ${tv.version ? escMd(tv.version) : 'unknown'} |`);
    }
    lines.push('');
  }

  // Limitations
  lines.push('## Limitations');
  lines.push('');
  for (const lim of report.limitations) {
    lines.push(`- ${lim}`);
  }
  lines.push('');

  lines.push('---');
  lines.push('');
  lines.push(`*Generated by ${APP_NAME} v${APP_VERSION}. This is a detection-oriented reconnaissance report, not a vulnerability assessment.*`);
  lines.push('');

  return lines.join('\n');
}
