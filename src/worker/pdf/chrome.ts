import type { ReportModel } from '../../shared/types';
import { drawMark, wordmark } from './brand';
import { COLORS, FONTS, PAGE } from './theme';

export function applyPageChrome(doc: PDFKit.PDFDocument, report: ReportModel, reportId: string): void {
  const range = doc.bufferedPageRange();
  const total = range.count;
  const coverIndex = range.start;
  for (let i = range.start; i < range.start + range.count; i += 1) {
    doc.switchToPage(i);
    if (i === coverIndex) continue;
    const pageNumber = i - range.start + 1;

    doc.save();
    // The footer sits inside the physical page margin. Temporarily remove the
    // flow margins so PDFKit does not auto-insert a new page for the footer.
    const originalMargins = { ...doc.page.margins };
    doc.page.margins.top = 0;
    doc.page.margins.bottom = 0;
    drawMark(doc, PAGE.marginX, 24, 12);
    wordmark(doc, PAGE.marginX + 17, 27, 10.5, COLORS.navy);
    doc.font(FONTS.body).fontSize(7.5).fillColor(COLORS.subtle).text('Security reconnaissance', PAGE.marginX + 63, 29, {
      width: 150,
      lineBreak: false,
    });
    doc
      .font(FONTS.body)
      .fontSize(7.5)
      .fillColor(COLORS.muted)
      .text(report.meta.target, PAGE.marginX + 220, 29, { width: PAGE.width - PAGE.marginX * 2 - 220, align: 'right', lineBreak: false });
    doc.moveTo(PAGE.marginX, 50).lineTo(PAGE.width - PAGE.marginX, 50).strokeColor(COLORS.border).lineWidth(0.7).stroke();

    doc.moveTo(PAGE.marginX, 724).lineTo(PAGE.width - PAGE.marginX, 724).strokeColor(COLORS.border).lineWidth(0.7).stroke();
    doc.font(FONTS.body).fontSize(7.2).fillColor(COLORS.subtle).text('Confidential · Authorized reconnaissance report', PAGE.marginX, 733, {
      width: 260,
      lineBreak: false,
    });
    doc.text(reportId, PAGE.marginX + 180, 733, { width: 220, align: 'center', lineBreak: false });
    doc.text(`Page ${pageNumber} of ${total}`, PAGE.width - PAGE.marginX - 110, 733, { width: 110, align: 'right', lineBreak: false });
    doc.page.margins.top = originalMargins.top;
    doc.page.margins.bottom = originalMargins.bottom;
    doc.restore();
  }
}
