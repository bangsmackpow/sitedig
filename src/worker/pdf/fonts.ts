import fs from 'node:fs';
import path from 'node:path';
import { FONTS } from './theme';

const FONT_FILES = {
  body: 'IBMPlexSans-Regular.ttf',
  semibold: 'IBMPlexSans-SemiBold.ttf',
  bold: 'IBMPlexSans-Bold.ttf',
  mono: 'IBMPlexMono-Regular.ttf',
  monoBold: 'IBMPlexMono-SemiBold.ttf',
} as const;

/**
 * Register the vendored print fonts when present. Falls back to PDFKit's
 * standard fonts so local development and minimal deployments still work.
 */
export function registerReportFonts(doc: PDFKit.PDFDocument): void {
  const dir = process.env.REPORT_FONT_DIR ?? path.join(process.cwd(), 'assets', 'fonts');
  const entries = Object.entries(FONT_FILES) as Array<[keyof typeof FONT_FILES, string]>;
  if (!entries.every(([, file]) => fs.existsSync(path.join(dir, file)))) return;
  doc.registerFont('SiteDigSans', path.join(dir, FONT_FILES.body));
  doc.registerFont('SiteDigSansSemiBold', path.join(dir, FONT_FILES.semibold));
  doc.registerFont('SiteDigSansBold', path.join(dir, FONT_FILES.bold));
  doc.registerFont('SiteDigMono', path.join(dir, FONT_FILES.mono));
  doc.registerFont('SiteDigMonoBold', path.join(dir, FONT_FILES.monoBold));
  FONTS.body = 'SiteDigSans';
  FONTS.semibold = 'SiteDigSansSemiBold';
  FONTS.bold = 'SiteDigSansBold';
  FONTS.mono = 'SiteDigMono';
  FONTS.monoBold = 'SiteDigMonoBold';
}
