import type { ReportPresentation } from '../../shared/report-presentation';
import { legend } from './components';
import { ensureSpace } from './layout';
import { COLORS, FONTS, PAGE, SEVERITY_STYLES, cleanText, truncate } from './theme';

export function stackedBar(
  doc: PDFKit.PDFDocument,
  x: number,
  y: number,
  width: number,
  height: number,
  segments: Array<{ value: number; color: string }>,
): void {
  const total = segments.reduce((sum, segment) => sum + segment.value, 0);
  doc.roundedRect(x, y, width, height, height / 2).fill(COLORS.surfaceAlt);
  if (total === 0) return;
  let cursor = x;
  doc.save();
  doc.roundedRect(x, y, width, height, height / 2).clip();
  for (const segment of segments) {
    if (segment.value <= 0) continue;
    const segmentWidth = (segment.value / total) * width;
    doc.rect(cursor, y, segmentWidth, height).fill(segment.color);
    cursor += segmentWidth;
  }
  doc.restore();
}

export function severityBar(doc: PDFKit.PDFDocument, presentation: ReportPresentation, x: number, y: number, width: number): number {
  const startY = doc.y;
  const segments = presentation.severity.map((item) => ({
    value: item.count,
    color: SEVERITY_STYLES[item.key].color,
  }));
  const total = presentation.counts.critical + presentation.counts.high + presentation.counts.medium + presentation.counts.low + presentation.counts.informational;
  doc.font(FONTS.bold).fontSize(8).fillColor(COLORS.ink).text(total === 0 ? 'No findings' : `${total} finding${total === 1 ? '' : 's'}`, x, y, { width, lineBreak: false });
  stackedBar(doc, x, y + 15, width, 9, segments);
  legend(
    doc,
    x,
    y + 34,
    presentation.severity.map((item) => ({ label: item.label, value: item.count, color: SEVERITY_STYLES[item.key].color })),
    Math.max(100, width / 5),
  );
  const height = total > 0 ? 78 : 30;
  doc.y = startY + height;
  return height;
}

export function horizontalBars(
  doc: PDFKit.PDFDocument,
  input: {
    x?: number;
    width?: number;
    items: Array<{ label: string; value: number; color?: string }>;
    max?: number;
    barColor?: string;
    labelWidth?: number;
    emptyLabel?: string;
  },
): void {
  const x = input.x ?? PAGE.marginX;
  const width = input.width ?? PAGE.width - PAGE.marginX * 2;
  const labelWidth = input.labelWidth ?? 150;
  const barWidth = width - labelWidth - 42;
  const max = input.max ?? Math.max(1, ...input.items.map((item) => item.value));
  ensureSpace(doc, Math.max(28, input.items.length * 20 + 12));
  if (input.items.length === 0) {
    doc.font(FONTS.body).fontSize(8).fillColor(COLORS.muted).text(input.emptyLabel ?? 'No data', x, doc.y, { width });
    doc.moveDown(0.6);
    return;
  }
  for (const item of input.items) {
    const y = doc.y;
    doc.font(FONTS.body).fontSize(8).fillColor(COLORS.text).text(truncate(cleanText(item.label), 36), x, y + 2, {
      width: labelWidth - 8,
      lineBreak: false,
      ellipsis: true,
    });
    doc.roundedRect(x + labelWidth, y + 1, barWidth, 7, 3.5).fill(COLORS.surfaceAlt);
    const valueWidth = max > 0 ? Math.max(2, (item.value / max) * barWidth) : 2;
    doc.roundedRect(x + labelWidth, y + 1, valueWidth, 7, 3.5).fill(item.color ?? input.barColor ?? COLORS.accent);
    doc.font(FONTS.bold).fontSize(7.5).fillColor(COLORS.ink).text(String(item.value), x + width - 32, y + 1, { width: 32, align: 'right', lineBreak: false });
    doc.y = y + 18;
  }
  doc.moveDown(0.4);
}

export function cveBar(doc: PDFKit.PDFDocument, presentation: ReportPresentation, x: number, y: number, width: number): number {
  const startY = doc.y;
  const severities = presentation.cveSummary.severities;
  const segments = [
    { value: severities.critical ?? 0, color: COLORS.critical },
    { value: severities.high ?? 0, color: COLORS.high },
    { value: severities.medium ?? 0, color: COLORS.medium },
    { value: severities.low ?? 0, color: COLORS.low },
  ];
  const total = segments.reduce((sum, s) => sum + s.value, 0);
  doc.font(FONTS.bold).fontSize(8).fillColor(COLORS.ink).text(total === 0 ? 'No known CVEs' : `${total} known CVE record(s)`, x, y, { width, lineBreak: false });
  stackedBar(doc, x, y + 15, width, 9, segments);
  legend(
    doc,
    x,
    y + 34,
    [
      { label: 'Critical', value: severities.critical ?? 0, color: COLORS.critical },
      { label: 'High', value: severities.high ?? 0, color: COLORS.high },
      { label: 'Medium', value: severities.medium ?? 0, color: COLORS.medium },
      { label: 'Low', value: severities.low ?? 0, color: COLORS.low },
    ],
    Math.max(100, width / 4),
  );
  return total > 0 ? 64 : 30;
}
