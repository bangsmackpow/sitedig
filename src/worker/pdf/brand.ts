import { COLORS, FONTS, PAGE } from './theme';

export function drawMark(doc: PDFKit.PDFDocument, x: number, y: number, size: number, opts: { dark?: boolean } = {}): void {
  doc.save();
  const radius = size * 0.22;
  doc.roundedRect(x, y, size, size, radius).fill(opts.dark ? COLORS.navy : COLORS.navy);
  const cx = x + size * 0.42;
  const cy = y + size * 0.42;
  const r = size * 0.22;
  doc.circle(cx, cy, r).lineWidth(Math.max(1.5, size * 0.06)).strokeColor(COLORS.accent).stroke();
  doc.moveTo(cx + r * 0.78, cy + r * 0.78).lineTo(x + size * 0.78, y + size * 0.78).lineWidth(Math.max(1.5, size * 0.075)).strokeColor(COLORS.accent).lineCap('round').stroke();
  doc.fillColor(COLORS.accent);
  for (const [dx, dy, dot] of [
    [-0.26, -0.22, 0.042],
    [0.08, -0.28, 0.042],
    [-0.12, 0.06, 0.042],
    [0.16, 0.02, 0.042],
  ] as const) {
    doc.circle(cx + r * dx, cy + r * dy, size * dot).fill(COLORS.accent);
  }
  doc.restore();
}

export function wordmark(doc: PDFKit.PDFDocument, x: number, y: number, size: number, color: string): void {
  doc.font(FONTS.bold).fontSize(size).fillColor(color).text('SiteDig', x, y, { lineBreak: false });
}

export function drawCoverBackground(doc: PDFKit.PDFDocument): void {
  doc.save();
  doc.rect(0, 0, PAGE.width, PAGE.height).fill(COLORS.navy);
  doc.rect(0, 0, PAGE.width, 6).fill(COLORS.accent);
  doc.circle(PAGE.width - 40, 90, 150).fillOpacity(0.06).fill(COLORS.accent).fillOpacity(1);
  doc.circle(PAGE.width - 120, PAGE.height - 80, 210).fillOpacity(0.04).fill(COLORS.accent).fillOpacity(1);
  doc.restore();
}
