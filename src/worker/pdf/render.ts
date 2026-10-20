import fs from 'node:fs';
import PDFDocument from 'pdfkit';
import { APP_NAME, APP_VERSION } from '../../shared/constants';
import { buildReportPresentation } from '../../shared/report-presentation';
import type { ReportModel } from '../../shared/types';
import { applyPageChrome } from './chrome';
import { registerReportFonts } from './fonts';
import { renderAppendix } from './sections/appendix';
import { renderCover } from './sections/cover';
import { renderExecutive } from './sections/executive';
import { renderFindings } from './sections/findings';
import { renderPosture } from './sections/posture';

export interface PdfRenderOptions {
  reportId?: string;
}

export function renderPdf(report: ReportModel, outPath: string, options: PdfRenderOptions = {}): Promise<void> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: 'LETTER',
      margin: 0,
      bufferPages: true,
      info: {
        Title: `${APP_NAME} Security Reconnaissance Report - ${report.meta.target}`,
        Author: APP_NAME,
        Subject: 'Authorized detection-oriented reconnaissance report',
        Creator: `${APP_NAME} v${APP_VERSION}`,
        Keywords: 'security, reconnaissance, report, sitedig',
      },
    });
    const stream = fs.createWriteStream(outPath);
    stream.on('error', reject);
    doc.on('error', reject);
    doc.pipe(stream);
    registerReportFonts(doc);

    const presentation = buildReportPresentation(report);
    const reportId = options.reportId ?? report.meta.finishedAt;

    renderCover(doc, report, presentation, reportId);
    renderExecutive(doc, report, presentation);
    renderFindings(doc, report, presentation);
    renderPosture(doc, report, presentation);
    renderAppendix(doc, report);

    applyPageChrome(doc, report, reportId);
    doc.flushPages();
    doc.end();
    stream.on('finish', resolve);
  });
}
