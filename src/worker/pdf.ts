import fs from 'node:fs';
import PDFDocument from 'pdfkit';
import { APP_NAME, APP_VERSION } from '../shared/constants';
import { CATEGORY_LABELS, SEVERITY_LABELS, sortFindings } from '../shared/report';
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
    portsSection(doc, report);
    httpSection(doc, report);
    tlsSection(doc, report);
    techSection(doc, report);
    wordpressSection(doc, report);
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
    doc.moveDown(0.2);
    doc.fillColor(COLORS.text).fontSize(10).text(f.description, MARGIN, doc.y, { width: CONTENT_WIDTH });
    if (f.affected) {
      doc.moveDown(0.2);
      doc.fillColor(COLORS.muted).font('Helvetica-Bold').fontSize(9).text(`Affected: ${f.affected}`, MARGIN, doc.y, { width: CONTENT_WIDTH });
    }
    if (f.evidence.length > 0) {
      doc.moveDown(0.2);
      doc.fillColor(COLORS.muted).font('Helvetica').fontSize(9).text('Evidence:', MARGIN, doc.y, { width: CONTENT_WIDTH });
      for (const ev of f.evidence) {
        doc.fillColor(COLORS.text).font('Courier').fontSize(8).text(ev, MARGIN + 12, doc.y, { width: CONTENT_WIDTH - 12 });
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

function portsSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  sectionTitle(doc, 'Discovered Ports & Services');
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
  sectionTitle(doc, 'HTTP Observations');
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

function tlsSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  const t = report.tls;
  if (!t) return;
  sectionTitle(doc, 'TLS Observations');
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

function techSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  if (report.technologies.length === 0) return;
  sectionTitle(doc, 'Technologies Detected');
  table(doc, ['Technology', 'Version'], report.technologies.map((t) => [t.name, t.version ?? 'unknown']));
}

function wordpressSection(doc: PDFKit.PDFDocument, report: ReportModel) {
  if (!report.wordpress) return;
  sectionTitle(doc, 'WordPress');
  kvRow(doc, 'Detected', String(report.wordpress.detected));
  kvRow(doc, 'WPScan run', String(report.wordpress.wpscanRan));
  for (const n of report.wordpress.notes) {
    doc.font('Courier').fontSize(9).fillColor(COLORS.muted).text(`- ${n}`, MARGIN + 12, doc.y, { width: CONTENT_WIDTH - 12 });
  }
  doc.moveDown();
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
