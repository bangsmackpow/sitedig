import { ensureSpace } from './layout';
import { COLORS, FONTS, PAGE, cleanText } from './theme';

export interface TableColumn {
  label: string;
  width: number;
  align?: 'left' | 'right' | 'center';
}

export interface TableOptions {
  columns: TableColumn[];
  rows: string[][];
  x?: number;
  width?: number;
  fontSize?: number;
  maxRowHeight?: number;
  zebra?: boolean;
  headerFill?: string;
}

const PADDING = 5;

export function drawTable(doc: PDFKit.PDFDocument, options: TableOptions): number {
  const x = options.x ?? PAGE.marginX;
  const width = options.width ?? PAGE.width - PAGE.marginX * 2;
  const fontSize = options.fontSize ?? 7.6;
  const maxRowHeight = options.maxRowHeight ?? 52;
  const headerHeight = 20;
  const scale = width / options.columns.reduce((sum, c) => sum + c.width, 0);
  const widths = options.columns.map((c) => c.width * scale);

  const drawHeader = (): void => {
    const headerY = doc.y;
    doc.rect(x, headerY, width, headerHeight).fill(options.headerFill ?? COLORS.navy);
    let cx = x;
    doc.font(FONTS.bold).fontSize(7.2).fillColor(COLORS.white);
    options.columns.forEach((column, index) => {
      doc.text(column.label.toUpperCase(), cx + PADDING, headerY + 6, {
        width: widths[index] - PADDING * 2,
        align: column.align ?? 'left',
        lineBreak: false,
        ellipsis: true,
      });
      cx += widths[index];
    });
    doc.y = headerY + headerHeight;
  };

  ensureSpace(doc, headerHeight + 24);
  drawHeader();

  options.rows.forEach((row, rowIndex) => {
    doc.font(FONTS.body).fontSize(fontSize);
    let rowHeight = 16;
    for (let i = 0; i < options.columns.length; i += 1) {
      const text = cleanText(row[i] ?? '');
      const measured = doc.heightOfString(text, { width: widths[i] - PADDING * 2, lineGap: 1 });
      rowHeight = Math.max(rowHeight, Math.min(maxRowHeight, measured + PADDING * 2));
    }
    if (doc.y + rowHeight > PAGE.height - PAGE.marginBottom) {
      doc.addPage({ size: 'LETTER', margins: { top: PAGE.marginTop, bottom: PAGE.marginBottom, left: PAGE.marginX, right: PAGE.marginX } });
      doc.y = PAGE.marginTop;
      drawHeader();
    }

    const y = doc.y;
    if (options.zebra !== false && rowIndex % 2 === 1) {
      doc.rect(x, y, width, rowHeight).fill(COLORS.surface);
    }
    let cx = x;
    for (let i = 0; i < options.columns.length; i += 1) {
      const text = cleanText(row[i] ?? '');
      doc.font(FONTS.body).fontSize(fontSize).fillColor(COLORS.text).text(text, cx + PADDING, y + PADDING, {
        width: widths[i] - PADDING * 2,
        height: rowHeight - PADDING * 2,
        align: options.columns[i].align ?? 'left',
        lineGap: 1,
        ellipsis: true,
      });
      cx += widths[i];
    }
    doc.moveTo(x, y + rowHeight).lineTo(x + width, y + rowHeight).strokeColor(COLORS.border).lineWidth(0.4).stroke();
    doc.y = y + rowHeight;
  });

  doc.moveDown(0.45);
  return doc.y;
}
