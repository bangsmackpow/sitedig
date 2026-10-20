import type { ReportPresentation } from '../../../shared/report-presentation';
import type { ReportModel } from '../../../shared/types';
import { drawCoverBackground, drawMark, wordmark } from '../brand';
import { COLORS, FONTS, PAGE, formatDateTime } from '../theme';

export function renderCover(doc: PDFKit.PDFDocument, report: ReportModel, presentation: ReportPresentation, reportId: string): void {
  doc.y = 0;
  drawCoverBackground(doc);

  drawMark(doc, PAGE.marginX, 44, 54);
  wordmark(doc, PAGE.marginX + 68, 52, 31, COLORS.white);
  doc.font(FONTS.body).fontSize(8).fillColor(COLORS.subtle).text('AUTHORIZED RECONNAISSANCE', PAGE.marginX + 70, 93, {
    characterSpacing: 1.6,
  });

  doc.font(FONTS.bold).fontSize(31).fillColor(COLORS.white).text('Security Reconnaissance Report', PAGE.marginX, 176, {
    width: PAGE.width - PAGE.marginX * 2,
    lineGap: 2,
  });
  doc.font(FONTS.body).fontSize(13).fillColor(COLORS.accent).text(report.meta.target, PAGE.marginX, 252, {
    width: PAGE.width - PAGE.marginX * 2,
  });

  doc.moveTo(PAGE.marginX, 286).lineTo(PAGE.width - PAGE.marginX, 286).strokeColor('#24415F').lineWidth(1).stroke();

  const metaY = 308;
  const rows: Array<[string, string]> = [
    ['Report ID', reportId],
    ['Host', report.meta.host],
    ['Profile', report.meta.profile],
    ['Modules', (report.meta.modules ?? []).length > 0 ? (report.meta.modules ?? []).join(', ') : 'Core checks only'],
    ['Scan completed', formatDateTime(report.meta.finishedAt)],
    ['Duration', `${(report.meta.durationMs / 1000).toFixed(1)} seconds`],
  ];
  rows.forEach(([label, value], index) => {
    const y = metaY + index * 25;
    doc.font(FONTS.body).fontSize(7.5).fillColor(COLORS.subtle).text(label.toUpperCase(), PAGE.marginX, y, { characterSpacing: 0.6 });
    doc.font(FONTS.bold).fontSize(9.5).fillColor(COLORS.white).text(value, PAGE.marginX + 120, y - 2, { width: PAGE.width - PAGE.marginX * 2 - 120 });
  });

  const cardY = 492;
  doc.roundedRect(PAGE.marginX, cardY, PAGE.width - PAGE.marginX * 2, 116, 10).fillAndStroke('#102744', '#284666');
  doc.font(FONTS.bold).fontSize(8).fillColor(COLORS.accent).text('OVERALL RISK', PAGE.marginX + 22, cardY + 18, { characterSpacing: 1 });
  doc.font(FONTS.bold).fontSize(52).fillColor(COLORS.white).text(String(presentation.risk.score), PAGE.marginX + 22, cardY + 34, { lineBreak: false });
  doc.font(FONTS.body).fontSize(10).fillColor(COLORS.subtle).text('/ 100', PAGE.marginX + 128, cardY + 65, { lineBreak: false });
  doc.font(FONTS.bold).fontSize(30).fillColor(COLORS.accent).text(presentation.risk.grade, PAGE.marginX + 190, cardY + 42, { lineBreak: false });
  doc.font(FONTS.body).fontSize(8).fillColor(COLORS.subtle).text('RISK GRADE', PAGE.marginX + 188, cardY + 78, { characterSpacing: 0.8 });

  const counts = presentation.counts;
  const summary = [
    ['CRITICAL', String(counts.critical), '#FCA5A5'],
    ['HIGH', String(counts.high), '#FCA5A5'],
    ['MEDIUM', String(counts.medium), '#FCD34D'],
    ['LOW', String(counts.low), '#93C5FD'],
    ['INFO', String(counts.informational), '#CBD5E1'],
  ];
  summary.forEach(([label, value, color], index) => {
    const x = PAGE.marginX + 300 + index * 44;
    doc.font(FONTS.bold).fontSize(18).fillColor(color).text(value, x, cardY + 44, { width: 40, align: 'center', lineBreak: false });
    doc.font(FONTS.bold).fontSize(6.2).fillColor(COLORS.subtle).text(label, x, cardY + 70, { width: 40, align: 'center', characterSpacing: 0.3 });
  });

  doc.font(FONTS.body).fontSize(7.5).fillColor(COLORS.subtle).text(
    'This report summarizes an authorized, detection-oriented reconnaissance scan. It is not an exploitation or penetration test.',
    PAGE.marginX,
    642,
    { width: PAGE.width - PAGE.marginX * 2, lineGap: 2 },
  );
  doc.font(FONTS.bold).fontSize(7).fillColor(COLORS.accent).text('CONFIDENTIAL', PAGE.marginX, 714, { characterSpacing: 1.4 });
  doc.font(FONTS.body).fontSize(7).fillColor(COLORS.subtle).text('SiteDig · Detection-oriented reconnaissance', PAGE.width - PAGE.marginX - 220, 714, {
    width: 220,
    align: 'right',
  });
}
