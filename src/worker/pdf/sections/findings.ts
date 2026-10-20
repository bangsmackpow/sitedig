import type { ReportPresentation } from '../../../shared/report-presentation';
import { CATEGORY_LABELS, SEVERITY_LABELS, corroborationLine, sortFindings, TOOL_MATRIX_ORDER } from '../../../shared/report';
import { collectPlaybook, playbookEnabled, roadmapFor, toolLabel } from '../../../shared/remediation';
import type { Finding, ReportModel } from '../../../shared/types';
import { callout, severityPill } from '../components';
import { bulletList, ensureSpace, sectionTitle, subheading } from '../layout';
import { drawTable } from '../table';
import { COLORS, CONTENT_WIDTH, FONTS, PAGE, SEVERITY_STYLES, cleanText, truncate } from '../theme';

function findingHeight(doc: PDFKit.PDFDocument, finding: Finding, innerWidth: number, evidenceLimit: number, descriptionLimit: number): number {
  const description = truncate(finding.description, descriptionLimit);
  doc.font(FONTS.body).fontSize(8.8);
  const descH = doc.heightOfString(description, { width: innerWidth, lineGap: 2 });
  const evidence = finding.evidence.slice(0, evidenceLimit);
  const evidenceH = evidence.length > 0 ? 12 + evidence.length * 11 : 0;
  doc.font(FONTS.body).fontSize(8);
  const remediationH = finding.remediation ? 14 + doc.heightOfString(truncate(finding.remediation, 320), { width: innerWidth, lineGap: 1.5 }) : 0;
  return 54 + descH + evidenceH + remediationH + (finding.affected ? 12 : 0);
}

function renderFindingCard(doc: PDFKit.PDFDocument, finding: Finding): void {
  const innerWidth = CONTENT_WIDTH - 34;
  let evidenceLimit = 6;
  let descriptionLimit = 900;
  let height = findingHeight(doc, finding, innerWidth, evidenceLimit, descriptionLimit);
  if (height > 500) {
    evidenceLimit = 4;
    descriptionLimit = 600;
    height = findingHeight(doc, finding, innerWidth, evidenceLimit, descriptionLimit);
  }
  ensureSpace(doc, Math.min(height, 560) + 12);

  const x = PAGE.marginX;
  const y = doc.y;
  const style = SEVERITY_STYLES[finding.severity];
  doc.roundedRect(x, y, CONTENT_WIDTH, height, 7).fillAndStroke(COLORS.white, COLORS.border);
  doc.rect(x, y, 4, height).fill(style.color);

  const pillWidth = severityPill(doc, x + 14, y + 13, finding.severity);
  doc.font(FONTS.bold).fontSize(10).fillColor(COLORS.ink).text(truncate(finding.title, 120), x + 14 + pillWidth + 10, y + 11, {
    width: CONTENT_WIDTH - pillWidth - 40,
    lineGap: 1,
  });

  const meta = `${CATEGORY_LABELS[finding.category]} · ${finding.confidence} confidence · ${finding.verified ? 'verified observation' : 'unverified'}`;
  doc.font(FONTS.body).fontSize(7.2).fillColor(COLORS.muted).text(meta, x + 14, y + 34, { width: CONTENT_WIDTH - 28 });
  const corroboration = corroborationLine(finding);
  if (corroboration) {
    doc.font(FONTS.body).fontSize(7.2).fillColor(COLORS.info).text(corroboration, x + 14, y + 44, { width: CONTENT_WIDTH - 28 });
  }

  let cursor = y + 58;
  doc.font(FONTS.body).fontSize(8.8).fillColor(COLORS.text).text(truncate(finding.description, descriptionLimit), x + 14, cursor, {
    width: innerWidth,
    lineGap: 2,
  });
  cursor = doc.y + 4;

  if (finding.affected) {
    doc.font(FONTS.bold).fontSize(7.4).fillColor(COLORS.muted).text('AFFECTED', x + 14, cursor, { width: 60, lineBreak: false });
    doc.font(FONTS.body).fontSize(7.4).fillColor(COLORS.text).text(truncate(finding.affected, 120), x + 78, cursor, { width: CONTENT_WIDTH - 92, lineBreak: false, ellipsis: true });
    cursor += 12;
  }

  if (finding.evidence.length > 0) {
    doc.font(FONTS.bold).fontSize(7.2).fillColor(COLORS.muted).text('OBSERVED EVIDENCE', x + 14, cursor, { characterSpacing: 0.4 });
    cursor += 11;
    for (const evidence of finding.evidence.slice(0, evidenceLimit)) {
      doc.rect(x + 14, cursor + 2.5, 2.5, 2.5).fill(style.color);
      doc.font(FONTS.mono).fontSize(6.9).fillColor(COLORS.text).text(truncate(cleanText(evidence), 130), x + 22, cursor, {
        width: innerWidth - 8,
        lineBreak: false,
        ellipsis: true,
      });
      cursor += 11;
    }
  }

  if (finding.remediation) {
    doc.font(FONTS.bold).fontSize(7.2).fillColor(COLORS.success).text('REMEDIATION', x + 14, cursor, { characterSpacing: 0.4 });
    cursor += 10;
    doc.font(FONTS.body).fontSize(7.8).fillColor(COLORS.text).text(truncate(finding.remediation, 320), x + 14, cursor, {
      width: innerWidth,
      lineGap: 1.5,
    });
  }

  doc.y = y + height + 12;
}

const SHORT_TOOL_LABELS: Record<string, string> = {
  'header-posture': 'H.Post',
  'dns-hardening': 'DNS',
  'page-recon': 'Page',
  'crawl-rules': 'Crawl',
  'security-txt': 'sec.txt',
  'ip-intel': 'IP',
  'testssl': 'testssl',
  'nmap': 'Nmap',
  'http': 'HTTP',
  'tls': 'TLS',
  'httpx': 'httpx',
  'retire': 'Retire',
  'osv': 'OSV',
  'nuclei': 'Nuclei',
  'email': 'Email',
  'subfinder': 'Sub',
  'dnsx': 'DNS',
  'rdap': 'WHOIS',
  'feroxbuster': 'Ferox',
  'waybackurls': 'Wayback',
};

function shortToolLabel(tool: string): string {
  return SHORT_TOOL_LABELS[tool] ?? toolLabel(tool);
}

function renderMatrix(doc: PDFKit.PDFDocument, report: ReportModel): void {
  const findings = sortFindings(report.findings).filter((f) => (f.sourceTools?.length ?? 0) > 0);
  if (findings.length === 0) return;
  const used = new Set<string>();
  for (const finding of findings) for (const tool of finding.sourceTools ?? []) used.add(tool);
  const cols = TOOL_MATRIX_ORDER.filter((tool) => used.has(tool));
  if (cols.length === 0) return;

  ensureSpace(doc, 60 + Math.min(findings.length, 80) * 22);
  subheading(doc, 'Cross-tool validation', 'Which independent tools contributed evidence to each finding');
  const columns = [
    { label: 'Finding', width: 210 },
    ...cols.map((tool) => ({ label: shortToolLabel(tool), width: Math.max(28, (CONTENT_WIDTH - 210) / cols.length), align: 'center' as const })),
  ];
  const rows = findings.slice(0, 80).map((finding) => {
    const supporting = new Set(finding.sourceTools ?? []);
    const conflicting = new Set(
      (finding.corroboration?.conflicting ?? [])
        .map((note) => note.split(' ')[0])
        .filter((tool) => used.has(tool)),
    );
    return [
      truncate(finding.title, 52),
      ...cols.map((tool) => (supporting.has(tool) ? 'YES' : conflicting.has(tool) ? 'NO' : '—')),
    ];
  });
  drawTable(doc, { columns, rows, fontSize: 6.7, maxRowHeight: 30 });
}

function renderPlaybook(doc: PDFKit.PDFDocument, report: ReportModel): void {
  const items = collectPlaybook(report);
  const enabled = playbookEnabled(report);
  subheading(doc, 'How to resolve', enabled ? 'Prioritized remediation plan' : 'Premium remediation playbook');
  if (!enabled) {
    const actionable = items.filter((item) => item.finding.severity !== 'informational');
    callout(doc, {
      title: 'Remediation Playbook available',
      body: `Enable the Remediation Playbook module for step-by-step fix plans, exact commands, verification checks, and a 30-day roadmap for ${actionable.length} actionable finding(s).`,
      tone: 'info',
    });
    return;
  }
  if (items.length === 0) {
    callout(doc, { title: 'No playbook entries', body: 'No findings mapped to a remediation playbook entry.', tone: 'info' });
    return;
  }
  for (const item of items) {
    ensureSpace(doc, 80);
    doc.font(FONTS.bold).fontSize(9.5).fillColor(COLORS.ink).text(`How to resolve: ${item.finding.title}`, PAGE.marginX, doc.y, { width: CONTENT_WIDTH });
    doc.moveDown(0.3);
    doc.font(FONTS.body).fontSize(8).fillColor(COLORS.text).text(item.entry.execSummary, PAGE.marginX, doc.y, { width: CONTENT_WIDTH, lineGap: 1.5 });
    doc.moveDown(0.25);
    doc.font(FONTS.body).fontSize(7.6).fillColor(COLORS.muted).text(`Owner: ${item.variant.owner} · Effort: ${item.variant.effort}${item.variant.when ? ` · ${item.variant.when}` : ''}`, PAGE.marginX, doc.y, {
      width: CONTENT_WIDTH,
    });
    doc.moveDown(0.35);
    item.variant.steps.forEach((step, index) => {
      ensureSpace(doc, 30);
      doc.font(FONTS.bold).fontSize(8).fillColor(COLORS.ink).text(`${index + 1}. ${step.title}`, PAGE.marginX + 6, doc.y, { width: CONTENT_WIDTH - 6 });
      if (step.detail) doc.font(FONTS.body).fontSize(7.6).fillColor(COLORS.text).text(step.detail, PAGE.marginX + 18, doc.y, { width: CONTENT_WIDTH - 18, lineGap: 1.5 });
      if (step.commands?.length) {
        for (const command of step.commands) {
          ensureSpace(doc, 16);
          doc.rect(PAGE.marginX + 18, doc.y - 1, CONTENT_WIDTH - 18, 13).fill(COLORS.surfaceAlt);
          doc.font(FONTS.mono).fontSize(6.7).fillColor(COLORS.text).text(truncate(command, 180), PAGE.marginX + 22, doc.y + 2, { width: CONTENT_WIDTH - 26, lineBreak: false, ellipsis: true });
          doc.moveDown(0.85);
        }
      }
      doc.moveDown(0.25);
    });
    if (item.variant.verify.length > 0) {
      doc.font(FONTS.bold).fontSize(7.4).fillColor(COLORS.success).text('Verify', PAGE.marginX + 6, doc.y, { width: CONTENT_WIDTH - 6 });
      bulletList(doc, item.variant.verify, { size: 7.4 });
    }
    doc.moveDown(0.5);
  }
  const roadmap = roadmapFor(items);
  if (roadmap.length > 0) {
    subheading(doc, '30-day remediation roadmap');
    for (const window of roadmap) {
      ensureSpace(doc, 40);
      doc.font(FONTS.bold).fontSize(8.5).fillColor(COLORS.ink).text(window.window, PAGE.marginX, doc.y, { width: CONTENT_WIDTH });
      doc.font(FONTS.body).fontSize(7.6).fillColor(COLORS.muted).text(window.goal, PAGE.marginX, doc.y, { width: CONTENT_WIDTH, lineGap: 1.5 });
      doc.moveDown(0.25);
      for (const item of window.items) {
        doc.font(FONTS.body).fontSize(7.6).fillColor(COLORS.text).text(`• ${item.finding.title} (${item.variant.owner}, effort ${item.variant.effort})`, PAGE.marginX + 8, doc.y, {
          width: CONTENT_WIDTH - 8,
        });
      }
      doc.moveDown(0.45);
    }
  }
}

export function renderFindings(doc: PDFKit.PDFDocument, report: ReportModel, presentation: ReportPresentation): void {
  sectionTitle(
    doc,
    '02 · Findings',
    'Observed findings',
    'Findings are ordered by severity. Evidence is limited to the most useful observations; full tool detail is in the technical appendix.',
  );
  if (report.findings.length === 0) {
    callout(doc, { title: 'No findings recorded', body: 'No findings were observed within the configured scan scope.', tone: 'success' });
    return;
  }

  for (const finding of sortFindings(report.findings)) {
    renderFindingCard(doc, finding);
  }

  renderMatrix(doc, report);
  renderPlaybook(doc, report);
}
