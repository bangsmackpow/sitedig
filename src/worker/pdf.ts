import fs from 'node:fs';
import PDFDocument from 'pdfkit';
import { APP_NAME, APP_VERSION } from '../shared/constants';
import {
  CATEGORY_LABELS,
  SEVERITY_LABELS,
  conflictingToolsFor,
  corroborationLine,
  sortFindings,
  TOOL_MATRIX_ORDER,
} from '../shared/report';
import { collectPlaybook, playbookEnabled, roadmapFor, toolLabel, type PlaybookItem } from '../shared/remediation';
import type { ReportModel } from '../shared/types';

const WIDTH = 612; // US Letter width (pt)
const MARGIN = 48;
const CONTENT_WIDTH = WIDTH - MARGIN * 2;

const COLORS = {
  primary: '#1a3d5c',
  text: '#222222',
  muted: '#666666',
  border: '#d8dde3',
  bg: '#f4f6f8',
  critical: '#7f1d1d',
  high: '#b91c1c',
  medium: '#b45309',
  low: '#1d4ed8',
  informational: '#4b5563',
};

export function renderPdf(report: ReportModel, outPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'LETTER', margin: MARGIN, info: { Title: `${APP_NAME} Scan Report - ${report.meta.target}`, Author: APP_NAME } });
    const stream = fs.createWriteStream(outPath);
    stream.on('error', reject);
    doc.on('error', reject);
    doc.pipe(stream);

    header(doc, report);
    executiveSummary(doc, report);
    findingsSection(doc, report);
    validationMatrixSection(doc, report);
    playbookSection(doc, report);
    appendixHeader(doc);
    portsSection(doc, report);
    techSection(doc, report);
    httpSection(doc, report);
    httpxSection(doc, report);
    tlsSection(doc, report);
    tlsHardeningSection(doc, report);
    wordpressSection(doc, report);
    assetDiscoverySection(doc, report);
    emailSection(doc, report);
    vulnerabilitiesSection(doc, report);
    contentDiscoverySection(doc, report);
    archivedUrlsSection(doc, report);
    cveContextSection(doc, report);
    toolsSection(doc, report);
    limitationsSection(doc, report);
    footer(doc, report);

    doc.end();
    stream.on('finish', resolve);
  });
}

function severityColor(severity: keyof typeof SEVERITY_LABELS): string {
  return COLORS[severity];
}

function header(doc: PDFKit.PDFDocument, report: ReportModel) {
  doc.rect(0, 0, WIDTH, 90).fill(COLORS.primary);
  doc.fill('#ffffff').font('Helvetica-Bold').fontSize(22).text(`${APP_NAME} Scan Report`, MARGIN, 28, { width: CONTENT_WIDTH });
  doc.fontSize(11).font('Helvetica').text(`Target: ${report.meta.target}`, MARGIN, 58, { width: CONTENT_WIDTH });
  doc.moveDown(2);
}

function sectionTitle(doc: PDFKit.PDFDocument, title: string) {
  doc.fillColor(COLORS.primary).font('Helvetica-Bold').fontSize(14).text(title, MARGIN, doc.y, { width: CONTENT_WIDTH });
  doc.moveDown(0.4);
  doc.moveTo(MARGIN, doc.y).lineTo(WIDTH - MARGIN, doc.y).strokeColor(COLORS.border).lineWidth(1).stroke();
  doc.moveDown(0.6);
  doc.fillColor(COLORS.text);
}

function subsectionTitle(doc: PDFKit.PDFDocument, title: string) {
  doc.fillColor(COLORS.primary).font('Helvetica-Bold').fontSize(11).text(title, MARGIN, doc.y, { width: CONTENT_WIDTH });
  doc.moveDown(0.3);
  doc.fillColor(COLORS.text);
}

function kvRow(doc: PDFKit.PDFDocument, key: string, value: string) {
  doc.font('Helvetica-Bold').fontSize(10).text(key, MARGIN, doc.y, { continued: true, width: 140 });
  doc.font('Helvetica').fontSize(10).fillColor(COLORS.text).text(`  ${value}`, MARGIN + 140, doc.y, { width: CONTENT_WIDTH - 140 });
}

function executiveSummary(doc: PDFKit.PDFDocument, report: ReportModel) {
  sectionTitle(doc, 'Executive Summary');
  doc.font('Helvetica').fontSize(10).fillColor(COLORS.text).text(report.executiveSummary, MARGIN, doc.y, { width: CONTENT_WIDTH });
  doc.moveDown(0.6);

  const meta = report.meta;
  kvRow(doc, 'Host', meta.host);
  kvRow(doc, 'Path', meta.path);
  kvRow(doc, 'Profile', meta.profile);
  kvRow(doc, 'Port scope', meta.portScope ?? 'n/a');
  if (meta.modules && meta.modules.length > 0) kvRow(doc, 'Modules', meta.modules.join(', '));
  kvRow(doc, 'Started', meta.startedAt);
  kvRow(doc, 'Duration', `${(meta.durationMs / 1000).toFixed(1)}s`);
  kvRow(doc, 'Status', meta.status);
  if (meta.warnings.length > 0) {
    kvRow(doc, 'Warnings', meta.warnings.join('; '));
  }
  doc.moveDown();
}

function findingsSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  sectionTitle(doc, 'Findings');
  const findings = sortFindings(report.findings);
  if (findings.length === 0) {
    doc.font('Helvetica').fontSize(10).text('No findings were recorded.', MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.moveDown();
    return;
  }
  for (const f of findings) {
    doc.fillColor(severityColor(f.severity)).font('Helvetica-Bold').fontSize(11).text(`[${SEVERITY_LABELS[f.severity]}] ${f.title}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.moveDown(0.2);
    doc.font('Helvetica').fontSize(9).fillColor(COLORS.muted).text(`Category: ${CATEGORY_LABELS[f.category]}  |  Confidence: ${f.confidence}  |  Verified observation: ${f.verified ? 'Yes' : 'No'}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
    const corroboration = corroborationLine(f);
    if (corroboration) {
      doc.moveDown(0.15);
      doc.fillColor(COLORS.primary).font('Helvetica-Oblique').fontSize(9).text(`Cross-tool validation: ${corroboration}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
    }
    doc.moveDown(0.2);
    doc.fillColor(COLORS.text).font('Helvetica').fontSize(10).text(f.description, MARGIN, doc.y, { width: CONTENT_WIDTH });
    if (f.affected) {
      doc.moveDown(0.2);
      doc.fillColor(COLORS.muted).font('Helvetica-Bold').fontSize(9).text(`Affected: ${f.affected}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
    }
    if (f.evidence.length > 0) {
      doc.moveDown(0.2);
      doc.fillColor(COLORS.muted).font('Helvetica').fontSize(9).text('What the tools saw:', MARGIN, doc.y, { width: CONTENT_WIDTH });
      for (const ev of f.evidence) {
        doc.fillColor(COLORS.text).font('Courier').fontSize(8).text(ev, MARGIN + 12, doc.y, { width: CONTENT_WIDTH - 12 });
      }
    }
    if (f.corroboration && f.corroboration.level === 'conflicting') {
      doc.moveDown(0.2);
      doc.fillColor(COLORS.medium).font('Helvetica-Bold').fontSize(9).text('Conflicting evidence:', MARGIN, doc.y, { width: CONTENT_WIDTH });
      for (const note of f.corroboration.conflicting) {
        doc.fillColor(COLORS.text).font('Helvetica').fontSize(8).text(`- ${note}`, MARGIN + 12, doc.y, { width: CONTENT_WIDTH - 12 });
      }
    }
    if (f.remediation) {
      doc.moveDown(0.2);
      doc.fillColor(COLORS.text).font('Helvetica-Bold').fontSize(9).text(`Remediation: `, MARGIN, doc.y, { continued: true });
      doc.font('Helvetica').fontSize(9).text(f.remediation, doc.x, doc.y, { width: CONTENT_WIDTH - doc.x + MARGIN });
    }
    doc.moveDown(0.8);
  }
}

function validationMatrixSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  const findings = sortFindings(report.findings).filter((f) => (f.sourceTools?.length ?? 0) > 0);
  if (findings.length === 0) return;
  sectionTitle(doc, 'Cross-Tool Validation Matrix');
  doc.font('Helvetica-Oblique').fontSize(8).fillColor(COLORS.muted).text(
    'Each row is a finding; columns are tools that contributed evidence. Y = independently observed (agrees); N = ran and disagrees; blank = did not apply.',
    MARGIN,
    doc.y,
    { width: CONTENT_WIDTH },
  );
  doc.moveDown(0.4);
  const used = new Set<string>();
  for (const f of findings) {
    for (const t of f.sourceTools ?? []) used.add(t);
    for (const t of conflictingToolsFor(f)) used.add(t);
  }
  const cols = TOOL_MATRIX_ORDER.filter((t) => used.has(t));
  const headers = ['Finding', ...cols.map((t) => toolLabel(t))];
  const rows = findings.map((f) => {
    const supporting = new Set(f.sourceTools ?? []);
    const conflicting = new Set(conflictingToolsFor(f));
    return [f.title, ...cols.map((t) => (conflicting.has(t) && !supporting.has(t) ? 'N' : supporting.has(t) ? 'Y' : ''))];
  });
  table(doc, headers, rows);
  doc.moveDown(0.5);
}

function playbookSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  sectionTitle(doc, 'How to Resolve (Remediation Playbook)');
  const items = collectPlaybook(report);
  const actionable = items.filter((i) => i.finding.severity !== 'informational');
  if (!playbookEnabled(report)) {
    doc.font('Helvetica-Oblique').fontSize(9).fillColor(COLORS.muted).text(
      actionable.length > 0
        ? `Premium add-on: the Remediation Playbook unlocks step-by-step fix plans with exact commands, verification checks, effort estimates, and a 30-day roadmap for ${actionable.length} finding(s) in this report.`
        : 'The Remediation Playbook premium add-on appends step-by-step fix plans and a prioritized roadmap for actionable findings.',
      MARGIN,
      doc.y,
      { width: CONTENT_WIDTH },
    );
    doc.moveDown();
    return;
  }
  if (items.length === 0) {
    doc.font('Helvetica').fontSize(10).text('No findings map to a remediation playbook entry.', MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.moveDown();
    return;
  }
  for (const item of items) playbookItem(doc, item);
  roadmap(doc, items);
}

function playbookItem(doc: PDFKit.PDFDocument, item: PlaybookItem) {
  doc.fillColor(COLORS.primary).font('Helvetica-Bold').fontSize(11).text(`How to resolve: ${item.finding.title}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
  doc.moveDown(0.2);
  doc.font('Helvetica').fontSize(9).fillColor(COLORS.text).text(item.entry.execSummary, MARGIN, doc.y, { width: CONTENT_WIDTH });
  doc.moveDown(0.2);
  doc.fillColor(COLORS.muted).font('Helvetica-Oblique').fontSize(8).text(`Owner: ${item.variant.owner}  |  Effort: ${item.variant.effort}${item.variant.when ? `  |  Applies to: ${item.variant.when}` : ''}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
  doc.moveDown(0.3);
  doc.fillColor(COLORS.text).font('Helvetica').fontSize(9);
  item.variant.steps.forEach((s, idx) => {
    doc.font('Helvetica-Bold').fontSize(9).text(`${idx + 1}. ${s.title}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.font('Helvetica');
    if (s.detail) doc.text(s.detail, MARGIN + 12, doc.y, { width: CONTENT_WIDTH - 12 });
    if (s.commands?.length) {
      for (const c of s.commands) {
        doc.fillColor(COLORS.muted).font('Courier').fontSize(8).text(c, MARGIN + 20, doc.y, { width: CONTENT_WIDTH - 32 });
        doc.fillColor(COLORS.text).font('Helvetica').fontSize(9);
      }
    }
    doc.moveDown(0.2);
  });
  if (item.variant.verify.length > 0) {
    doc.fillColor(COLORS.text).font('Helvetica-Bold').fontSize(9).text('Verify:', MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.font('Helvetica');
    for (const v of item.variant.verify) doc.text(`- ${v}`, MARGIN + 12, doc.y, { width: CONTENT_WIDTH - 12 });
  }
  if (item.variant.refs.length > 0) {
    doc.moveDown(0.2);
    doc.fillColor(COLORS.muted).fontSize(8).text(`References: ${item.variant.refs.join(', ')}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
  }
  doc.moveDown(0.8);
}

function roadmap(doc: PDFKit.PDFDocument, items: PlaybookItem[]) {
  const windows = roadmapFor(items);
  if (windows.length === 0) return;
  doc.fillColor(COLORS.primary).font('Helvetica-Bold').fontSize(12).text('30-Day Remediation Roadmap', MARGIN, doc.y, { width: CONTENT_WIDTH });
  doc.moveDown(0.3);
  for (const w of windows) {
    doc.fillColor(COLORS.text).font('Helvetica-Bold').fontSize(9).text(w.window, MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.font('Helvetica-Oblique').fillColor(COLORS.muted).fontSize(8).text(w.goal, MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.font('Helvetica').fillColor(COLORS.text).fontSize(9);
    for (const item of w.items) {
      doc.text(`- ${item.finding.title} (owner: ${item.variant.owner}; effort ${item.variant.effort})`, MARGIN + 12, doc.y, { width: CONTENT_WIDTH - 12 });
    }
    doc.moveDown(0.4);
  }
}

function appendixHeader(doc: PDFKit.PDFDocument) {
  sectionTitle(doc, 'Technical Appendix — Per-Tool Observations');
}

function portsSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  subsectionTitle(doc, 'Nmap — Discovered Ports & Services');
  if (report.ports.length === 0) {
    doc.font('Helvetica').fontSize(10).text('No open TCP ports were discovered within the configured scope.', MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.moveDown();
    return;
  }
  table(doc, ['Port', 'Protocol', 'Service', 'Version'], report.ports.map((p) => [String(p.port), p.protocol, p.service || 'unknown', p.version || '']));
}

function httpSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  const h = report.http;
  if (!h) return;
  subsectionTitle(doc, 'HTTP Header Inspection');
  if (h.error) {
    doc.font('Helvetica').fontSize(10).text(`HTTP check could not be completed: ${h.error}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
  } else {
    kvRow(doc, 'Status', String(h.status ?? 'n/a'));
    kvRow(doc, 'Final URL', h.finalUrl ?? 'n/a');
    if (h.server) kvRow(doc, 'Server', h.server);
    if (h.poweredBy) kvRow(doc, 'X-Powered-By', h.poweredBy);
    if (h.redirects.length > 0) {
      doc.moveDown(0.3);
      for (const r of h.redirects) {
        doc.font('Courier').fontSize(9).fillColor(COLORS.muted).text(`${r.status} -> ${r.to}`, MARGIN + 12, doc.y, { width: CONTENT_WIDTH - 12 });
      }
    }
  }
  doc.moveDown();
}

function httpxSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  const x = report.httpx;
  if (!x) return;
  subsectionTitle(doc, 'Httpx — HTTP Surface Validation');
  if (x.error) {
    doc.font('Helvetica').fontSize(10).text(`httpx could not complete: ${x.error}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
  } else {
    kvRow(doc, 'URL', x.url);
    kvRow(doc, 'Status', String(x.status ?? 'n/a'));
    if (x.finalUrl && x.finalUrl !== x.url) kvRow(doc, 'Final URL', x.finalUrl);
    if (x.server) kvRow(doc, 'Server', x.server);
    if (x.tlsVersion) kvRow(doc, 'TLS version', x.tlsVersion);
    if (x.certExpiry) kvRow(doc, 'Cert expiry', x.certExpiry);
    if (x.technologies.length > 0) kvRow(doc, 'Tech', x.technologies.join(', '));
    if (x.cookies.length > 0) {
      doc.moveDown(0.3);
      for (const c of x.cookies) {
        doc.font('Courier').fontSize(9).fillColor(COLORS.muted).text(`cookie ${c.name} secure=${c.secure} httponly=${c.httpOnly}`, MARGIN + 12, doc.y, { width: CONTENT_WIDTH - 12 });
      }
    }
  }
  doc.moveDown();
}

function tlsSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  const t = report.tls;
  if (!t) return;
  subsectionTitle(doc, 'TLS Certificate Inspection');
  if (t.error) {
    doc.font('Helvetica').fontSize(10).text(`TLS check could not be completed: ${t.error}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
  } else {
    kvRow(doc, 'Protocol', t.protocol ?? 'n/a');
    kvRow(doc, 'Subject CN', t.subjectCn ?? 'n/a');
    kvRow(doc, 'Issuer CN', t.issuerCn ?? 'n/a');
    kvRow(doc, 'Valid from', t.validFrom ?? 'n/a');
    kvRow(doc, 'Valid to', t.validTo ?? 'n/a');
    if (t.daysRemaining !== null) kvRow(doc, 'Days remaining', String(t.daysRemaining));
    kvRow(doc, 'Self-signed', String(t.selfSigned));
  }
  doc.moveDown();
}

function tlsHardeningSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  const t = report.tlsHardening;
  if (!t) return;
  subsectionTitle(doc, 'TLS Hardening (testssl.sh)');
  if (t.error) {
    doc.font('Helvetica').fontSize(9).fillColor(COLORS.muted).text(`testssl.sh could not complete: ${t.error}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
  } else if (t.weaknesses.length > 0) {
    for (const w of t.weaknesses) {
      doc.fillColor(severityColorForTls(w.severity)).font('Helvetica-Bold').fontSize(9).text(`[${w.severity}] ${w.name}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
      doc.font('Helvetica').fontSize(8).fillColor(COLORS.text).text(w.detail, MARGIN + 10, doc.y, { width: CONTENT_WIDTH - 10 });
      doc.moveDown(0.2);
    }
  } else {
    doc.font('Helvetica').fontSize(9).text('No notable TLS weaknesses were reported by testssl.sh.', MARGIN, doc.y, { width: CONTENT_WIDTH });
  }
  doc.moveDown();
}

function techSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  if (report.technologies.length === 0) return;
  subsectionTitle(doc, 'WhatWeb — Technologies Detected');
  table(doc, ['Technology', 'Version'], report.technologies.map((t) => [t.name, t.version ?? 'unknown']));
}

function wordpressSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  if (!report.wordpress) return;
  subsectionTitle(doc, 'WordPress (WPScan)');
  kvRow(doc, 'Detected', String(report.wordpress.detected));
  kvRow(doc, 'WPScan run', String(report.wordpress.wpscanRan));
  if (report.wordpress.notes.length === 0) {
    doc.font('Helvetica').fontSize(9).fillColor(COLORS.muted).text('No WPScan notes.', MARGIN, doc.y, { width: CONTENT_WIDTH });
  }
  for (const n of report.wordpress.notes) {
    doc.font('Courier').fontSize(9).fillColor(COLORS.muted).text(`- ${n}`, MARGIN + 12, doc.y, { width: CONTENT_WIDTH - 12 });
  }
  doc.moveDown();
}

function assetDiscoverySection(doc: PDFKit.PDFDocument, report: ReportModel) {
  if (report.subdomains.length === 0 && report.dnsRecords.length === 0 && !report.whois) return;
  subsectionTitle(doc, 'Asset Discovery (Subfinder / DNS / RDAP)');
  if (report.subdomains.length > 0) {
    doc.font('Helvetica-Bold').fontSize(10).fillColor(COLORS.primary).text('Subdomains', MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.moveDown(0.3);
    table(doc, ['Subdomain', 'Source'], report.subdomains.slice(0, 50).map((s) => [s.host, s.source ?? 'n/a']));
    if (report.subdomains.length > 50) {
      doc.font('Helvetica').fontSize(9).fillColor(COLORS.muted).text(`… and ${report.subdomains.length - 50} more`, MARGIN, doc.y, { width: CONTENT_WIDTH });
      doc.moveDown();
    }
  }
  if (report.dnsRecords.length > 0) {
    doc.font('Helvetica-Bold').fontSize(10).fillColor(COLORS.primary).text('DNS Records', MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.moveDown(0.3);
    table(doc, ['Type', 'Name', 'Value'], report.dnsRecords.slice(0, 50).map((r) => [r.type, r.name, r.value]));
    if (report.dnsRecords.length > 50) {
      doc.font('Helvetica').fontSize(9).fillColor(COLORS.muted).text(`… and ${report.dnsRecords.length - 50} more`, MARGIN, doc.y, { width: CONTENT_WIDTH });
      doc.moveDown();
    }
  }
  if (report.whois) {
    const w = report.whois;
    doc.font('Helvetica-Bold').fontSize(10).fillColor(COLORS.primary).text('WHOIS', MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.moveDown(0.3);
    if (w.error) {
      doc.font('Helvetica').fontSize(9).fillColor(COLORS.muted).text(`WHOIS lookup could not be completed: ${w.error}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
    } else {
      kvRow(doc, 'Registrar', w.registrar ?? 'n/a');
      kvRow(doc, 'Creation', w.creationDate ?? 'n/a');
      kvRow(doc, 'Expiry', w.expiryDate ?? 'n/a');
      if (w.nameservers.length > 0) kvRow(doc, 'Nameservers', w.nameservers.join(', '));
    }
  }
  doc.moveDown();
}

function emailSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  const e = report.email;
  if (!e) return;
  subsectionTitle(doc, 'Email & DNS Security Posture');
  if (e.error) {
    doc.font('Helvetica').fontSize(10).text(`Email posture checks could not complete: ${e.error}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
  } else {
    kvRow(doc, 'SPF', e.spfRecords.length === 0 ? 'none' : e.spfRecords.join(' | '));
    kvRow(doc, 'DMARC', e.dmarcRecords.length === 0 ? 'none' : e.dmarcRecords.join(' | '));
    kvRow(doc, 'MX', e.mx.length === 0 ? 'none' : e.mx.map((m) => `${m.host} (pref ${m.priority})`).join(', '));
    kvRow(doc, 'MTA-STS', e.mtaSts ?? 'none');
    kvRow(doc, 'TLS-RPT', e.tlsRpt ?? 'none');
    const st = e.starttls;
    const stLabel = st.checked ? (st.supported ? 'offered' : 'not offered') : st.error ? `not checked (${st.error})` : 'not checked';
    kvRow(doc, 'MX STARTTLS', `${stLabel}${st.mx ? ` (${st.mx})` : ''}`);
  }
  doc.moveDown();
}

function vulnerabilitiesSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  if (report.vulnerabilities.length === 0) return;
  subsectionTitle(doc, 'Vulnerability Findings (Nuclei / Retire.js)');
  const rows = report.vulnerabilities.map((v) => [v.severity.toUpperCase(), v.title, `${v.source}${v.matchedAt ? ` @ ${v.matchedAt}` : ''}`]);
  table(doc, ['Severity', 'Finding', 'Source'], rows);
  doc.moveDown();
}

function contentDiscoverySection(doc: PDFKit.PDFDocument, report: ReportModel) {
  if (report.discoveredPaths.length === 0) return;
  subsectionTitle(doc, 'Discovered Paths (Feroxbuster)');
  table(doc, ['Status', 'Path', 'Size', 'Type'], report.discoveredPaths.slice(0, 50).map((p) => [String(p.status), p.path, p.size === null ? 'n/a' : String(p.size), p.contentType ?? 'n/a']));
  if (report.discoveredPaths.length > 50) {
    doc.font('Helvetica').fontSize(9).fillColor(COLORS.muted).text(`… and ${report.discoveredPaths.length - 50} more`, MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.moveDown();
  }
  doc.moveDown();
}

function archivedUrlsSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  const archived = report.archivedUrls ?? [];
  if (archived.length === 0) return;
  subsectionTitle(doc, 'URL History (Wayback Machine)');
  doc.font('Helvetica').fontSize(9).fillColor(COLORS.text).text(`Total unique same-host archived URLs: ${archived.length}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
  doc.moveDown(0.3);
  const notable = archived.filter((a) => a.category !== 'other').slice(0, 40);
  if (notable.length > 0) {
    table(doc, ['Category', 'Path', 'Live'], notable.map((a) => [a.category, a.path, a.live ? 'yes' : 'no']));
  } else {
    doc.font('Helvetica').fontSize(9).fillColor(COLORS.muted).text('No sensitive-looking or credential-bearing URLs found in the archive.', MARGIN, doc.y, { width: CONTENT_WIDTH });
  }
  doc.moveDown();
}

function cveContextSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  if (report.cveContext.length === 0) return;
  subsectionTitle(doc, 'CVE Context (OSV)');
  table(doc, ['Package', 'Version', 'CVEs', 'Crit/High'], report.cveContext.map((c) => [c.name, c.version, String(c.cveCount), String(c.severities.critical + c.severities.high)]));
  doc.moveDown();
}

function severityColorForTls(severity: string): string {
  const s = severity.toUpperCase();
  if (s === 'CRITICAL') return COLORS.critical;
  if (s === 'HIGH') return COLORS.high;
  if (s === 'MEDIUM') return COLORS.medium;
  if (s === 'LOW') return COLORS.low;
  return COLORS.informational;
}

function toolsSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  sectionTitle(doc, 'Tool Execution');
  const rows = report.toolResults.map((tr) => {
    const result = tr.ok ? (tr.timedOut ? 'timed out' : 'ok') : `error: ${tr.error ?? ''}`;
    return [tr.label, result, tr.exitCode === null ? 'n/a' : String(tr.exitCode), `${(tr.durationMs / 1000).toFixed(1)}s`];
  });
  table(doc, ['Tool', 'Result', 'Exit', 'Duration'], rows);
  doc.moveDown(0.5);
  if (report.meta.toolVersions.length > 0) {
    doc.font('Helvetica-Bold').fontSize(10).fillColor(COLORS.primary).text('Tool Versions', MARGIN, doc.y, { width: CONTENT_WIDTH });
    doc.moveDown(0.3);
    for (const tv of report.meta.toolVersions) {
      doc.font('Helvetica').fontSize(9).fillColor(COLORS.text).text(`${tv.tool}: ${tv.version ?? 'unknown'}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
    }
    doc.moveDown();
  }
}

function limitationsSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  sectionTitle(doc, 'Limitations');
  for (const lim of report.limitations) {
    doc.font('Helvetica').fontSize(9).fillColor(COLORS.text).text(`- ${lim}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
  }
  doc.moveDown();
}

function footer(doc: PDFKit.PDFDocument, report: ReportModel) {
  doc.moveDown(1);
  doc.moveTo(MARGIN, doc.y).lineTo(WIDTH - MARGIN, doc.y).strokeColor(COLORS.border).stroke();
  doc.moveDown(0.3);
  doc.font('Helvetica-Oblique').fontSize(8).fillColor(COLORS.muted).text(
    `Generated by ${APP_NAME} v${APP_VERSION} on ${report.meta.finishedAt}. This is a detection-oriented reconnaissance report, not a vulnerability assessment.`,
    MARGIN,
    doc.y,
    { width: CONTENT_WIDTH, align: 'center' },
  );
}

function table(doc: PDFKit.PDFDocument, headers: string[], rows: string[][]) {
  const colWidth = CONTENT_WIDTH / headers.length;
  const padding = 6;

  const drawRow = (cells: string[], bold: boolean, fill: boolean) => {
    const lineHeight = 18;
    if (fill) {
      doc.rect(MARGIN, doc.y, CONTENT_WIDTH, lineHeight).fill(COLORS.bg);
    }
    doc.font(bold ? 'Helvetica-Bold' : 'Helvetica').fontSize(9);
    let x = MARGIN;
    for (let i = 0; i < cells.length; i++) {
      doc.fillColor(COLORS.text).text(cells[i], x + padding, doc.y + 5, { width: colWidth - padding * 2, height: lineHeight, ellipsis: true });
      x += colWidth;
    }
    doc.moveDown(lineHeight / 9);
    doc.y += 0;
  };

  drawRow(headers, true, true);
  for (const row of rows) {
    drawRow(row, false, false);
  }
  doc.moveDown(0.3);
}
