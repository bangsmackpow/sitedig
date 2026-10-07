import { APP_NAME, APP_VERSION } from './constants';
import { collectPlaybook, playbookEnabled, roadmapFor, toolLabel, type PlaybookItem } from './remediation';
import type { Finding, ReportMeta, ReportModel, ToolName } from './types';

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
  vulnerability: 'Vulnerability',
  informational: 'Informational',
};

export const SEVERITY_LABELS: Record<Finding['severity'], string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Informational',
};

/** Stable column order for the cross-tool validation matrix. */
export const TOOL_MATRIX_ORDER: ToolName[] = [
  'nmap',
  'http',
  'tls',
  'whatweb',
  'wpscan',
  'httpx',
  'testssl',
  'nuclei',
  'retire',
  'feroxbuster',
  'waybackurls',
  'subfinder',
  'dnsx',
  'rdap',
  'email',
  'osv',
];

const CONFLICT_TOOL_PREFIXES: Array<[string, ToolName]> = [
  ['nuclei', 'nuclei'],
  ['httpx', 'httpx'],
  ['testssl', 'testssl'],
  ['feroxbuster', 'feroxbuster'],
  ['waybackurls', 'waybackurls'],
];

/** Tools whose notes appear in a finding's conflicting evidence. */
export function conflictingToolsFor(finding: Finding): ToolName[] {
  const out = new Set<ToolName>();
  for (const note of finding.corroboration?.conflicting ?? []) {
    const lower = note.toLowerCase();
    for (const [prefix, tool] of CONFLICT_TOOL_PREFIXES) {
      if (lower.startsWith(prefix)) out.add(tool);
    }
  }
  return [...out];
}

export function buildExecutiveSummary(meta: ReportMeta, findings: Finding[], portCount: number): string {
  const notable = findings.filter((f) => f.severity === 'high' || f.severity === 'critical');
  const medium = findings.filter((f) => f.severity === 'medium').length;
  const low = findings.filter((f) => f.severity === 'low').length;

  let summary = `This report summarises an authorized, detection-oriented reconnaissance scan of ${meta.target} `;
  summary += `using the ${meta.profile} profile. The scan was TCP-only, limited to ${portCount ? `the configured port scope` : 'a restricted port scope'}, and capped at the configured scan duration. `;
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

  const multi = findings.filter((f) => f.corroboration?.level === 'multi').length;
  if (multi > 0) {
    summary += ` ${multi} finding(s) were independently confirmed by two or more tools and can be treated as verified observations.`;
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

/** One-line human summary of the cross-tool validation state. */
export function corroborationLine(finding: Finding): string {
  const c = finding.corroboration;
  if (!c) return '';
  const names = c.supporting.map(toolLabel).join(' + ');
  if (c.level === 'multi') return `Confirmed by ${c.supporting.length} independent sources (${names})`;
  if (c.level === 'conflicting') return `Single source (${names}) with conflicting evidence — verify before acting`;
  if (c.supporting.length === 1) return `Observed by ${names} (single source)`;
  return '';
}

function renderFindingBlock(f: Finding): string[] {
  const lines: string[] = [];
  lines.push(`### [${SEVERITY_LABELS[f.severity]}] ${f.title}`);
  lines.push('');
  lines.push(`- **Category:** ${CATEGORY_LABELS[f.category]}`);
  lines.push(`- **Confidence:** ${f.confidence}`);
  lines.push(`- **Verified observation:** ${f.verified ? 'Yes' : 'No'}`);
  const corroboration = corroborationLine(f);
  if (corroboration) {
    lines.push(`- **Cross-tool validation:** ${corroboration}`);
  }
  lines.push('');
  lines.push(f.description);
  if (f.affected) {
    lines.push('');
    lines.push(`**Affected:** \`${escMd(f.affected)}\``);
  }
  if (f.evidence.length > 0) {
    lines.push('');
    lines.push(`**What the tools saw:**`);
    for (const ev of f.evidence) {
      lines.push(`- \`${escMd(ev)}\``);
    }
  }
  if (f.corroboration && f.corroboration.level === 'conflicting') {
    lines.push('');
    lines.push('**Conflicting evidence:**');
    for (const note of f.corroboration.conflicting) {
      lines.push(`- ${note}`);
    }
  }
  if (f.remediation) {
    lines.push('');
    lines.push(`**Remediation:** ${f.remediation}`);
  }
  lines.push('');
  return lines;
}

function renderValidationMatrix(findings: Finding[]): string[] {
  const withSources = findings.filter((f) => (f.sourceTools?.length ?? 0) > 0);
  const lines: string[] = [];
  lines.push('## Cross-Tool Validation Matrix');
  lines.push('');
  if (withSources.length === 0) {
    lines.push('No tool-attributed findings were recorded.');
    lines.push('');
    return lines;
  }
  const used = new Set<ToolName>();
  for (const f of withSources) {
    for (const t of f.sourceTools ?? []) used.add(t);
    for (const t of conflictingToolsFor(f)) used.add(t);
  }
  const cols = TOOL_MATRIX_ORDER.filter((t) => used.has(t));
  lines.push('Each row is a finding; columns are the tools that contributed evidence. ✓ = independently observed (agrees), ✗ = ran and disagrees, blank = did not apply.');
  lines.push('');
  lines.push(`| Finding | ${cols.map((t) => toolLabel(t)).join(' | ')} |`);
  lines.push(`| --- | ${cols.map(() => '---').join(' | ')} |`);
  for (const f of withSources) {
    const supporting = new Set(f.sourceTools ?? []);
    const conflicting = new Set(conflictingToolsFor(f));
    const cells = cols.map((t) => (conflicting.has(t) && !supporting.has(t) ? '✗' : supporting.has(t) ? '✓' : ''));
    lines.push(`| ${escMd(f.title)} | ${cells.join(' | ')} |`);
  }
  lines.push('');
  return lines;
}

function renderPlaybookSection(report: ReportModel): string[] {
  const lines: string[] = [];
  const items = collectPlaybook(report);
  const actionable = items.filter((i) => i.finding.severity !== 'informational');
  lines.push('## How to Resolve (Remediation Playbook)');
  lines.push('');
  if (!playbookEnabled(report)) {
    if (actionable.length > 0) {
      lines.push(
        `> **Premium add-on:** The Remediation Playbook unlocks step-by-step fix plans with exact commands for your detected stack, verification checks, effort estimates, and a prioritized 30-day roadmap for **${actionable.length} finding(s)** in this report.`,
      );
    } else {
      lines.push('> The Remediation Playbook premium add-on appends step-by-step fix plans and a prioritized roadmap for actionable findings.');
    }
    lines.push('');
    return lines;
  }
  if (items.length === 0) {
    lines.push('No findings map to a remediation playbook entry.');
    lines.push('');
    return lines;
  }
  for (const item of items) {
    lines.push(...playbookLinesMd(item));
  }
  lines.push(...roadmapLinesMd(roadmapFor(items)));
  return lines;
}

export function playbookLinesMd(item: PlaybookItem): string[] {
  const lines: string[] = [];
  lines.push(`### How to resolve: ${item.finding.title}`);
  lines.push('');
  lines.push(item.entry.execSummary);
  lines.push('');
  lines.push(`- **Owner:** ${item.variant.owner} · **Effort:** ${item.variant.effort}`);
  if (item.variant.when) lines.push(`- **Applies to:** ${item.variant.when}`);
  lines.push('');
  item.variant.steps.forEach((s, idx) => {
    lines.push(`${idx + 1}. **${s.title}**`);
    if (s.detail) lines.push(`   ${s.detail}`);
    if (s.commands?.length) {
      lines.push('');
      lines.push('   ```bash');
      for (const c of s.commands) lines.push(`   ${c}`);
      lines.push('   ```');
    }
  });
  if (item.variant.verify.length > 0) {
    lines.push('');
    lines.push('**Verify:**');
    for (const v of item.variant.verify) lines.push(`- ${v}`);
  }
  if (item.variant.refs.length > 0) {
    lines.push('');
    lines.push(`**References:** ${item.variant.refs.map((r) => `<${r}>`).join(' ')}`);
  }
  lines.push('');
  return lines;
}

export function roadmapLinesMd(windows: ReturnType<typeof roadmapFor>): string[] {
  const lines: string[] = [];
  if (windows.length === 0) return lines;
  lines.push('### 30-Day Remediation Roadmap');
  lines.push('');
  for (const w of windows) {
    lines.push(`**${w.window}** — ${w.goal}`);
    for (const item of w.items) {
      lines.push(`- ${item.finding.title} *(owner: ${item.variant.owner}; effort ${item.variant.effort})*`);
    }
    lines.push('');
  }
  return lines;
}

function appendixHeader(lines: string[], title: string): void {
  lines.push(`### ${title}`);
  lines.push('');
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
  if (report.meta.modules && report.meta.modules.length > 0) {
    lines.push(`| Modules | ${report.meta.modules.join(', ')} |`);
  }
  if (report.meta.warnings.length > 0) {
    lines.push(`| Warnings | ${report.meta.warnings.map((w) => escMd(w)).join('; ')} |`);
  }
  lines.push('');

  // Findings (body) — grouped by tool, with cross-tool validation
  lines.push('## Findings');
  lines.push('');
  if (findings.length === 0) {
    lines.push('No findings were recorded.');
    lines.push('');
  } else {
    for (const f of findings) {
      lines.push(...renderFindingBlock(f));
    }
  }
  lines.push(...renderValidationMatrix(findings));
  lines.push(...renderPlaybookSection(report));

  lines.push('---');
  lines.push('');

  // Technical appendix — one subsection per tool
  lines.push('## Technical Appendix');
  lines.push('');

  appendixHeader(lines, 'Discovered Ports & Services (Nmap)');
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
    appendixHeader(lines, 'Technologies Detected (WhatWeb)');
    lines.push('| Technology | Version |');
    lines.push('| --- | --- |');
    for (const t of report.technologies) {
      lines.push(`| ${escMd(t.name)} | ${t.version ? escMd(t.version) : 'unknown'} |`);
    }
    lines.push('');
  }

  // HTTP
  if (report.http) {
    appendixHeader(lines, 'HTTP Header Inspection');
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

  // httpx second-source HTTP validation
  if (report.httpx) {
    appendixHeader(lines, 'HTTP Surface Validation (httpx)');
    const x = report.httpx;
    if (x.error) {
      lines.push(`httpx could not complete: ${x.error}`);
    } else {
      lines.push(`- **URL:** ${escMd(x.url)}`);
      lines.push(`- **Status:** ${x.status ?? 'n/a'}`);
      if (x.finalUrl && x.finalUrl !== x.url) lines.push(`- **Final URL:** ${escMd(x.finalUrl)}`);
      if (x.server) lines.push(`- **Server:** ${escMd(x.server)}`);
      if (x.tlsVersion) lines.push(`- **TLS version:** ${escMd(x.tlsVersion)}`);
      if (x.certExpiry) lines.push(`- **Cert expiry:** ${escMd(x.certExpiry)}`);
      if (x.technologies.length > 0) lines.push(`- **Tech:** ${x.technologies.map(escMd).join(', ')}`);
      if (x.cookies.length > 0) {
        lines.push('- **Cookies:**');
        for (const c of x.cookies) {
          lines.push(`  - \`${escMd(c.name)}\` secure=${c.secure} httponly=${c.httpOnly}`);
        }
      }
    }
    lines.push('');
  }

  // TLS
  if (report.tls) {
    appendixHeader(lines, 'TLS Certificate Inspection');
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

  // TLS hardening
  if (report.tlsHardening) {
    appendixHeader(lines, 'TLS Hardening (testssl.sh)');
    const t = report.tlsHardening;
    if (t.error) {
      lines.push(`testssl.sh could not complete: ${t.error}`);
    } else if (t.weaknesses.length > 0) {
      for (const w of t.weaknesses) {
        lines.push(`- **[${w.severity}] ${escMd(w.name)}** — ${escMd(w.detail)}`);
      }
    } else {
      lines.push('No notable TLS weaknesses were reported by testssl.sh.');
    }
    lines.push('');
  }

  // WordPress
  if (report.wordpress) {
    appendixHeader(lines, 'WordPress (WPScan)');
    lines.push(`- **Detected:** ${report.wordpress.detected}`);
    lines.push(`- **WPScan run:** ${report.wordpress.wpscanRan}`);
    for (const n of report.wordpress.notes) {
      lines.push(`- ${n}`);
    }
    lines.push('');
  }

  // Asset & DNS discovery
  if (report.subdomains.length > 0) {
    appendixHeader(lines, 'Subdomains Discovered (Subfinder)');
    lines.push('| Subdomain | Source |');
    lines.push('| --- | --- |');
    for (const s of report.subdomains.slice(0, 100)) {
      lines.push(`| ${escMd(s.host)} | ${escMd(s.source ?? 'n/a')} |`);
    }
    if (report.subdomains.length > 100) {
      lines.push(`| _… and ${report.subdomains.length - 100} more_ | |`);
    }
    lines.push('');
  }

  if (report.dnsRecords.length > 0) {
    appendixHeader(lines, 'DNS Records');
    lines.push('| Type | Name | Value |');
    lines.push('| --- | --- | --- |');
    for (const r of report.dnsRecords.slice(0, 100)) {
      lines.push(`| ${escMd(r.type)} | ${escMd(r.name)} | ${escMd(r.value)} |`);
    }
    if (report.dnsRecords.length > 100) {
      lines.push(`| _… and ${report.dnsRecords.length - 100} more_ | | |`);
    }
    lines.push('');
  }

  // Email & DNS security posture
  if (report.email) {
    appendixHeader(lines, 'Email & DNS Security Posture');
    const e = report.email;
    if (e.error) {
      lines.push(`Email posture checks could not complete: ${e.error}`);
    } else {
      lines.push(`- **SPF:** ${e.spfRecords.length === 0 ? 'none' : e.spfRecords.map(escMd).join(' | ')}`);
      lines.push(`- **DMARC:** ${e.dmarcRecords.length === 0 ? 'none' : e.dmarcRecords.map(escMd).join(' | ')}`);
      lines.push(`- **MX:** ${e.mx.length === 0 ? 'none' : e.mx.map((m) => `${escMd(m.host)} (pref ${m.priority})`).join(', ')}`);
      lines.push(`- **MTA-STS:** ${e.mtaSts ? escMd(e.mtaSts) : 'none'}`);
      lines.push(`- **TLS-RPT:** ${e.tlsRpt ? escMd(e.tlsRpt) : 'none'}`);
      const st = e.starttls;
      const stLabel = st.checked ? (st.supported ? 'offered' : 'not offered') : st.error ? `not checked (${st.error})` : 'not checked';
      lines.push(`- **MX STARTTLS:** ${stLabel}${st.mx ? ` (${escMd(st.mx)})` : ''}`);
    }
    lines.push('');
  }

  if (report.whois) {
    appendixHeader(lines, 'WHOIS Registration (RDAP)');
    const w = report.whois;
    if (w.error) {
      lines.push(`WHOIS lookup could not be completed: ${w.error}`);
    } else {
      lines.push(`- **Registrar:** ${escMd(w.registrar ?? 'n/a')}`);
      lines.push(`- **Creation date:** ${w.creationDate ?? 'n/a'}`);
      lines.push(`- **Update date:** ${w.updateDate ?? 'n/a'}`);
      lines.push(`- **Expiry date:** ${w.expiryDate ?? 'n/a'}`);
      if (w.nameservers.length > 0) {
        lines.push(`- **Nameservers:** ${w.nameservers.map(escMd).join(', ')}`);
      }
    }
    lines.push('');
  }

  // Vulnerability findings
  if (report.vulnerabilities.length > 0) {
    appendixHeader(lines, 'Vulnerability Findings (Nuclei / Retire.js)');
    lines.push('| Severity | Title | Matched | Source |');
    lines.push('| --- | --- | --- | --- |');
    for (const v of report.vulnerabilities) {
      lines.push(`| ${v.severity.toUpperCase()} | ${escMd(v.title)} | ${v.matchedAt ? escMd(v.matchedAt) : 'n/a'} | ${escMd(v.source)} |`);
    }
    lines.push('');
  }

  // Content discovery
  if (report.discoveredPaths.length > 0) {
    appendixHeader(lines, 'Discovered Paths (Feroxbuster)');
    lines.push('| Status | Path | Size | Type |');
    lines.push('| --- | --- | --- | --- |');
    for (const p of report.discoveredPaths.slice(0, 100)) {
      lines.push(`| ${p.status} | ${escMd(p.path)} | ${p.size ?? 'n/a'} | ${escMd(p.contentType ?? 'n/a')} |`);
    }
    if (report.discoveredPaths.length > 100) {
      lines.push(`| _… and ${report.discoveredPaths.length - 100} more_ | | | |`);
    }
    lines.push('');
  }

  // Wayback Machine URLs
  if (report.archivedUrls && report.archivedUrls.length > 0) {
    appendixHeader(lines, 'URL History (Wayback Machine)');
    const notable = report.archivedUrls.filter((a) => a.category !== 'other');
    lines.push(`- **Total unique same-host URLs archived:** ${report.archivedUrls.length}`);
    if (notable.length > 0) {
      lines.push('| Category | Path | Live today |');
      lines.push('| --- | --- | --- |');
      for (const a of notable.slice(0, 50)) {
        lines.push(`| ${a.category} | ${escMd(a.path)} | ${a.live ? 'yes' : 'no'} |`);
      }
      if (notable.length > 50) {
        lines.push(`| _… and ${notable.length - 50} more_ | | |`);
      }
    } else {
      lines.push('No sensitive-looking or credential-bearing URLs found in the archive.');
    }
    lines.push('');
  }

  // CVE context
  if (report.cveContext.length > 0) {
    appendixHeader(lines, 'CVE Context (OSV)');
    lines.push('| Package | Version | CVEs | Critical/High |');
    lines.push('| --- | --- | --- | --- |');
    for (const c of report.cveContext) {
      lines.push(`| ${escMd(c.name)} | ${escMd(c.version)} | ${c.cveCount} | ${c.severities.critical + c.severities.high} |`);
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
