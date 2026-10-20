import type { ReportPresentation } from '../../../shared/report-presentation';
import type { ReportModel } from '../../../shared/types';
import { severityBar } from '../charts';
import { callout, kpiCard, riskCard, severityPill } from '../components';
import { addContentPage, bulletList, ensureSpace, sectionTitle, subheading } from '../layout';
import { COLORS, CONTENT_WIDTH, FONTS, PAGE, truncate } from '../theme';

function priorityRow(doc: PDFKit.PDFDocument, title: string, severity: ReportModel['findings'][number]['severity'], affected: string | null): void {
  ensureSpace(doc, 30);
  const y = doc.y;
  const pillWidth = severityPill(doc, PAGE.marginX, y + 3, severity);
  doc.font(FONTS.bold).fontSize(8.8).fillColor(COLORS.ink).text(truncate(title, 92), PAGE.marginX + pillWidth + 10, y + 1, {
    width: CONTENT_WIDTH - pillWidth - 150,
    lineBreak: false,
    ellipsis: true,
  });
  if (affected) {
    doc.font(FONTS.body).fontSize(7.2).fillColor(COLORS.muted).text(truncate(affected, 70), PAGE.width - PAGE.marginX - 150, y + 3, {
      width: 150,
      align: 'right',
      lineBreak: false,
      ellipsis: true,
    });
  }
  doc.moveTo(PAGE.marginX, y + 24).lineTo(PAGE.width - PAGE.marginX, y + 24).strokeColor(COLORS.border).lineWidth(0.4).stroke();
  doc.y = y + 30;
}

export function renderExecutive(doc: PDFKit.PDFDocument, report: ReportModel, presentation: ReportPresentation): void {
  addContentPage(doc);
  sectionTitle(
    doc,
    '01 · Executive overview',
    'Security posture at a glance',
    'A concise view of the most material observations, exposure, and recommended priorities from this scan.',
  );

  const rowY = doc.y;
  riskCard(doc, PAGE.marginX, rowY, 150, 110, presentation.risk);
  severityBar(doc, presentation, PAGE.marginX + 170, rowY + 6, CONTENT_WIDTH - 170);
  doc.y = rowY + 128;

  const gap = 10;
  const cardW = (CONTENT_WIDTH - gap * 2) / 3;
  const cardH = 68;
  const metrics = [
    { label: 'Open ports', value: String(report.ports.length), sub: 'within configured scope', accent: COLORS.accent },
    { label: 'Findings', value: String(report.findings.length), sub: `${presentation.counts.critical + presentation.counts.high} critical / high`, accent: COLORS.high },
    { label: 'Technologies', value: String(report.technologies.length), sub: 'fingerprinted components', accent: COLORS.info },
    { label: 'Subdomains', value: String(report.subdomains.length), sub: 'passive discovery', accent: '#8B5CF6' },
    { label: 'Tools executed', value: `${presentation.toolStats.ok}/${presentation.toolStats.total}`, sub: 'completed successfully', accent: COLORS.success },
    { label: 'Scan duration', value: `${(report.meta.durationMs / 1000).toFixed(0)}s`, sub: `${report.meta.profile} profile`, accent: COLORS.warn },
  ];
  const gridY = doc.y;
  metrics.forEach((metric, index) => {
    const col = index % 3;
    const row = Math.floor(index / 3);
    kpiCard(doc, PAGE.marginX + col * (cardW + gap), gridY + row * (cardH + gap), cardW, cardH, metric);
  });
  doc.y = gridY + cardH * 2 + gap + 18;

  if (report.meta.warnings.length > 0) {
    callout(doc, {
      title: 'Scan warnings',
      body: report.meta.warnings.join(' · '),
      tone: 'warn',
    });
  }

  subheading(doc, 'Key takeaways');
  bulletList(doc, presentation.keyTakeaways, { size: 9.2 });

  const priorities = presentation.topFindings.slice(0, 3);
  if (priorities.length > 0) {
    ensureSpace(doc, 34 + priorities.length * 30);
    subheading(doc, 'Priority findings', 'Ordered by severity and cross-tool confidence');
    for (const finding of priorities) {
      priorityRow(doc, finding.title, finding.severity, finding.affected);
    }
  }

  if (presentation.toolStats.failed + presentation.toolStats.timedOut > 0) {
    callout(doc, {
      title: 'Coverage note',
      body: `${presentation.toolStats.failed} tool check(s) failed and ${presentation.toolStats.timedOut} timed out. Findings that depend on those tools may not have been assessed. See the technical appendix for details.`,
      tone: 'warn',
    });
  }
}
