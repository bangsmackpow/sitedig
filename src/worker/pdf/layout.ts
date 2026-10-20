import { COLORS, CONTENT_WIDTH, FONTS, PAGE } from './theme';

export function addContentPage(doc: PDFKit.PDFDocument): void {
  doc.addPage({ size: 'LETTER', margins: { top: PAGE.marginTop, bottom: PAGE.marginBottom, left: PAGE.marginX, right: PAGE.marginX } });
  doc.y = PAGE.marginTop;
}

export function ensureSpace(doc: PDFKit.PDFDocument, height: number): void {
  if (doc.y + height > PAGE.height - PAGE.marginBottom) addContentPage(doc);
}

export function sectionTitle(doc: PDFKit.PDFDocument, kicker: string, title: string, subtitle?: string): void {
  ensureSpace(doc, subtitle ? 78 : 58);
  doc.fillColor(COLORS.accent).font(FONTS.bold).fontSize(8).text(kicker.toUpperCase(), PAGE.marginX, doc.y, {
    width: CONTENT_WIDTH,
    characterSpacing: 1.2,
  });
  doc.moveDown(0.25);
  doc.fillColor(COLORS.ink).font(FONTS.bold).fontSize(21).text(title, PAGE.marginX, doc.y, { width: CONTENT_WIDTH });
  doc.moveDown(0.2);
  doc.moveTo(PAGE.marginX, doc.y).lineTo(PAGE.width - PAGE.marginX, doc.y).strokeColor(COLORS.border).lineWidth(1).stroke();
  doc.moveDown(0.55);
  if (subtitle) {
    doc.fillColor(COLORS.muted).font(FONTS.body).fontSize(9.5).text(subtitle, PAGE.marginX, doc.y, { width: CONTENT_WIDTH, lineGap: 2 });
    doc.moveDown(0.5);
  }
}

export function subheading(doc: PDFKit.PDFDocument, title: string, hint?: string): void {
  ensureSpace(doc, 30);
  doc.fillColor(COLORS.ink).font(FONTS.bold).fontSize(11).text(title, PAGE.marginX, doc.y, { width: CONTENT_WIDTH });
  if (hint) {
    doc.fillColor(COLORS.muted).font(FONTS.body).fontSize(8.5).text(hint, PAGE.marginX, doc.y, { width: CONTENT_WIDTH });
  }
  doc.moveDown(0.45);
}

export function bodyText(doc: PDFKit.PDFDocument, text: string, opts: { size?: number; color?: string; gap?: number } = {}): void {
  const size = opts.size ?? 9.5;
  const color = opts.color ?? COLORS.text;
  doc.font(FONTS.body).fontSize(size).fillColor(color);
  const height = doc.heightOfString(text, { width: CONTENT_WIDTH, lineGap: 2.2 });
  ensureSpace(doc, height + 10);
  doc.text(text, PAGE.marginX, doc.y, { width: CONTENT_WIDTH, lineGap: 2.2 });
  doc.moveDown(opts.gap ?? 0.6);
}

export function bulletList(doc: PDFKit.PDFDocument, items: string[], opts: { size?: number; color?: string } = {}): void {
  const size = opts.size ?? 9.5;
  for (const item of items) {
    doc.font(FONTS.body).fontSize(size).fillColor(opts.color ?? COLORS.text);
    const height = doc.heightOfString(item, { width: CONTENT_WIDTH - 16, lineGap: 2 });
    ensureSpace(doc, height + 6);
    doc.circle(PAGE.marginX + 3, doc.y + 4.5, 1.6).fill(COLORS.accent);
    doc.fillColor(opts.color ?? COLORS.text).text(item, PAGE.marginX + 14, doc.y, { width: CONTENT_WIDTH - 14, lineGap: 2 });
    doc.moveDown(0.28);
  }
  doc.moveDown(0.35);
}

export function keyValue(doc: PDFKit.PDFDocument, label: string, value: string, x = PAGE.marginX, width = CONTENT_WIDTH): void {
  const valueWidth = width - 132;
  doc.font(FONTS.body).fontSize(9).fillColor(COLORS.muted).text(label, x, doc.y, { width: 124, continued: false });
  const y = doc.y - doc.currentLineHeight();
  doc.font(FONTS.bold).fontSize(9).fillColor(COLORS.text).text(value, x + 132, y, { width: valueWidth, lineGap: 1.5 });
  doc.moveDown(0.28);
}

export function drawRule(doc: PDFKit.PDFDocument, color = COLORS.border, gap = 0.5): void {
  ensureSpace(doc, 12);
  doc.moveTo(PAGE.marginX, doc.y).lineTo(PAGE.width - PAGE.marginX, doc.y).strokeColor(color).lineWidth(0.8).stroke();
  doc.moveDown(gap);
}

export function rightAlignedText(doc: PDFKit.PDFDocument, text: string, x: number, y: number, width: number, size = 8.5, color = COLORS.muted): void {
  doc.font(FONTS.body).fontSize(size).fillColor(color).text(text, x, y, { width, align: 'right' });
}

export function textAt(doc: PDFKit.PDFDocument, text: string, x: number, y: number, width: number, opts: { size?: number; color?: string; font?: string; align?: 'left' | 'right' | 'center'; lineGap?: number } = {}): void {
  doc
    .font(opts.font ?? FONTS.body)
    .fontSize(opts.size ?? 9)
    .fillColor(opts.color ?? COLORS.text)
    .text(text, x, y, { width, align: opts.align ?? 'left', lineGap: opts.lineGap ?? 1.5 });
}

export function pageBottom(): number {
  return PAGE.height - PAGE.marginBottom;
}
