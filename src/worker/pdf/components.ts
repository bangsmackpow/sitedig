import type { Finding } from '../../shared/types';
import { ensureSpace, pageBottom } from './layout';
import { COLORS, CONTENT_WIDTH, FONTS, PAGE, SEVERITY_STYLES, STATUS_STYLES, formatDuration, truncate } from './theme';

export function severityPill(doc: PDFKit.PDFDocument, x: number, y: number, severity: Finding['severity'], opts: { size?: number } = {}): number {
  const style = SEVERITY_STYLES[severity];
  const size = opts.size ?? 7.5;
  doc.font(FONTS.bold).fontSize(size);
  const label = style.label.toUpperCase();
  const width = doc.widthOfString(label) + 14;
  const height = size + 7;
  doc.roundedRect(x, y, width, height, height / 2).fill(style.bg);
  doc.fillColor(style.color).text(label, x + 7, y + 3.5, { lineBreak: false });
  return width;
}

export function statusChip(doc: PDFKit.PDFDocument, x: number, y: number, status: 'pass' | 'warn' | 'fail' | 'info', opts: { size?: number } = {}): number {
  const style = STATUS_STYLES[status];
  const size = opts.size ?? 6.5;
  doc.font(FONTS.bold).fontSize(size);
  const width = doc.widthOfString(style.label) + 12;
  const height = size + 6;
  doc.roundedRect(x, y, width, height, 2.5).fill(style.bg);
  doc.fillColor(style.color).text(style.label, x + 6, y + 3, { lineBreak: false });
  return width;
}

export function cardBackground(doc: PDFKit.PDFDocument, x: number, y: number, width: number, height: number, opts: { fill?: string; border?: string } = {}): void {
  doc.roundedRect(x, y, width, height, 7).fillAndStroke(opts.fill ?? COLORS.surface, opts.border ?? COLORS.border);
}

export function kpiCard(doc: PDFKit.PDFDocument, x: number, y: number, width: number, height: number, input: { label: string; value: string; sub?: string; accent?: string }): void {
  doc.roundedRect(x, y, width, height, 7).fillAndStroke(COLORS.white, COLORS.border);
  doc.rect(x, y, width, 3).fill(input.accent ?? COLORS.accent);
  doc.font(FONTS.bold).fontSize(7).fillColor(COLORS.muted).text(input.label.toUpperCase(), x + 12, y + 13, { width: width - 24, characterSpacing: 0.6 });
  doc.font(FONTS.bold).fontSize(23).fillColor(COLORS.ink).text(input.value, x + 12, y + 28, { width: width - 24, lineBreak: false });
  if (input.sub) doc.font(FONTS.body).fontSize(7.5).fillColor(COLORS.muted).text(input.sub, x + 12, y + height - 18, { width: width - 24, lineBreak: false });
}

export function callout(doc: PDFKit.PDFDocument, input: { title: string; body: string; tone?: 'info' | 'warn' | 'danger' | 'success' }): void {
  const tone = input.tone ?? 'info';
  const palette = {
    info: { bg: COLORS.infoSoft, border: '#BFDBFE', color: COLORS.info },
    warn: { bg: COLORS.warnSoft, border: '#FDE68A', color: COLORS.warn },
    danger: { bg: COLORS.dangerSoft, border: '#FECACA', color: COLORS.danger },
    success: { bg: COLORS.successSoft, border: '#A7F3D0', color: COLORS.success },
  }[tone];
  doc.font(FONTS.body).fontSize(8.8);
  const bodyHeight = doc.heightOfString(input.body, { width: CONTENT_WIDTH - 34, lineGap: 2 });
  const height = bodyHeight + 38;
  ensureSpace(doc, height);
  const x = PAGE.marginX;
  const y = doc.y;
  doc.roundedRect(x, y, CONTENT_WIDTH, height, 6).fillAndStroke(palette.bg, palette.border);
  doc.rect(x, y, 4, height).fill(palette.color);
  doc.font(FONTS.bold).fontSize(9).fillColor(palette.color).text(input.title, x + 16, y + 10, { width: CONTENT_WIDTH - 32 });
  doc.font(FONTS.body).fontSize(8.8).fillColor(COLORS.text).text(input.body, x + 16, y + 24, { width: CONTENT_WIDTH - 32, lineGap: 2 });
  doc.y = y + height + 12;
}

export function riskCard(doc: PDFKit.PDFDocument, x: number, y: number, width: number, height: number, risk: { score: number; grade: string }, label = 'Risk score'): void {
  doc.roundedRect(x, y, width, height, 8).fillAndStroke(COLORS.navy, COLORS.navy);
  doc.font(FONTS.bold).fontSize(7).fillColor(COLORS.accent).text(label.toUpperCase(), x + 16, y + 14, { characterSpacing: 0.7 });
  doc.font(FONTS.bold).fontSize(42).fillColor(COLORS.white);
  const scoreWidth = doc.widthOfString(String(risk.score));
  doc.text(String(risk.score), x + 16, y + 28, { lineBreak: false });
  doc.font(FONTS.body).fontSize(8).fillColor(COLORS.subtle).text('/ 100', x + 20 + scoreWidth, y + 48, { lineBreak: false });
  doc.font(FONTS.bold).fontSize(20).fillColor(COLORS.accent).text(risk.grade, x + width - 52, y + 30, { width: 36, align: 'center' });
  doc.font(FONTS.body).fontSize(7).fillColor(COLORS.subtle).text('GRADE', x + width - 54, y + 54, { width: 40, align: 'center', characterSpacing: 0.5 });
  const pct = Math.max(0, Math.min(1, risk.score / 100));
  doc.roundedRect(x + 16, y + height - 20, width - 32, 5, 2.5).fill(COLORS.navySoft);
  doc.roundedRect(x + 16, y + height - 20, Math.max(5, (width - 32) * pct), 5, 2.5).fill(COLORS.accent);
}

export function legend(doc: PDFKit.PDFDocument, x: number, y: number, items: Array<{ label: string; value: string | number; color: string }>, gap = 110): void {
  const originalY = doc.y;
  let cursorX = x;
  for (const item of items) {
    doc.circle(cursorX + 4, y + 4, 3).fill(item.color);
    doc.font(FONTS.bold).fontSize(8).fillColor(COLORS.ink).text(String(item.value), cursorX + 12, y, { lineBreak: false });
    doc.font(FONTS.body).fontSize(7.5).fillColor(COLORS.muted).text(item.label, cursorX + 12 + doc.widthOfString(String(item.value)) + 4, y, { lineBreak: false });
    cursorX += gap;
    if (cursorX > PAGE.width - PAGE.marginX - 60) {
      cursorX = x;
      y += 16;
    }
  }
  doc.y = originalY;
}

export function scoreRow(doc: PDFKit.PDFDocument, input: { label: string; status: 'pass' | 'warn' | 'fail' | 'info'; detail: string }, x = PAGE.marginX, width = CONTENT_WIDTH): void {
  ensureSpace(doc, 22);
  const y = doc.y;
  const chipWidth = statusChip(doc, x, y + 4, input.status);
  doc.font(FONTS.bold).fontSize(8.5).fillColor(COLORS.ink).text(input.label, x + chipWidth + 10, y + 4, { width: 124, lineBreak: false });
  doc.font(FONTS.body).fontSize(8).fillColor(COLORS.muted).text(truncate(input.detail, 120), x + chipWidth + 140, y + 4, {
    width: width - chipWidth - 146,
    lineBreak: false,
    ellipsis: true,
  });
  doc.moveTo(x, y + 18).lineTo(x + width, y + 18).strokeColor(COLORS.border).lineWidth(0.5).stroke();
  doc.y = y + 22;
}

export function durationBar(doc: PDFKit.PDFDocument, label: string, durationMs: number, maxMs: number, ok: boolean): void {
  ensureSpace(doc, 18);
  const y = doc.y;
  doc.font(FONTS.body).fontSize(7.5).fillColor(COLORS.text).text(truncate(label, 58), PAGE.marginX, y, { width: 180, lineBreak: false, ellipsis: true });
  const barX = PAGE.marginX + 190;
  const barW = 220;
  doc.roundedRect(barX, y + 1, barW, 6, 3).fill(COLORS.surfaceAlt);
  const width = maxMs > 0 ? Math.max(2, (durationMs / maxMs) * barW) : 2;
  doc.roundedRect(barX, y + 1, width, 6, 3).fill(ok ? COLORS.accent : COLORS.danger);
  doc.font(FONTS.body).fontSize(7).fillColor(COLORS.muted).text(formatDuration(durationMs), barX + barW + 10, y, { width: 70, align: 'right', lineBreak: false });
  doc.y = y + 15;
}

export function pageBreakIfNeeded(doc: PDFKit.PDFDocument, height: number): void {
  ensureSpace(doc, height);
  if (doc.y > pageBottom()) addPageAndReset(doc);
}

function addPageAndReset(doc: PDFKit.PDFDocument): void {
  doc.addPage({ size: 'LETTER', margins: { top: PAGE.marginTop, bottom: PAGE.marginBottom, left: PAGE.marginX, right: PAGE.marginX } });
  doc.y = PAGE.marginTop;
}
