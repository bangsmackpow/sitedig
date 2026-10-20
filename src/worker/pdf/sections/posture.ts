import type { CheckResult, ReportPresentation } from '../../../shared/report-presentation';
import type { ReportModel } from '../../../shared/types';
import { cveBar, horizontalBars } from '../charts';
import { callout, statusChip } from '../components';
import { addContentPage, ensureSpace, sectionTitle, subheading } from '../layout';
import { drawTable } from '../table';
import { COLORS, CONTENT_WIDTH, FONTS, PAGE, formatDuration } from '../theme';

function checkCard(doc: PDFKit.PDFDocument, check: CheckResult, x: number, y: number, width: number, height: number): void {
  doc.roundedRect(x, y, width, height, 5).fillAndStroke(COLORS.white, COLORS.border);
  const chipWidth = statusChip(doc, x + 9, y + 9, check.status);
  doc.font(FONTS.bold).fontSize(8.2).fillColor(COLORS.ink).text(check.label, x + chipWidth + 17, y + 9, { width: width - chipWidth - 24, lineBreak: false });
  doc.font(FONTS.body).fontSize(7).fillColor(COLORS.muted).text(check.detail, x + chipWidth + 17, y + 20, {
    width: width - chipWidth - 24,
    lineBreak: false,
    ellipsis: true,
  });
}

function checkGrid(doc: PDFKit.PDFDocument, checks: CheckResult[], emptyLabel: string): void {
  if (checks.length === 0) {
    callout(doc, { title: emptyLabel, body: 'The relevant module or observation was not available for this scan.', tone: 'info' });
    return;
  }
  const gap = 10;
  const width = (CONTENT_WIDTH - gap) / 2;
  const height = 36;
  for (let index = 0; index < checks.length; index += 2) {
    ensureSpace(doc, height + gap);
    const y = doc.y;
    for (let col = 0; col < 2; col += 1) {
      const check = checks[index + col];
      if (check) checkCard(doc, check, PAGE.marginX + col * (width + gap), y, width, height);
    }
    doc.y = y + height + gap;
  }
  doc.moveDown(0.3);
}

function tlsCard(doc: PDFKit.PDFDocument, report: ReportModel): void {
  const tls = report.tls;
  if (!tls) return;
  ensureSpace(doc, 92);
  const y = doc.y;
  doc.roundedRect(PAGE.marginX, y, CONTENT_WIDTH, 82, 7).fillAndStroke(COLORS.white, COLORS.border);
  doc.font(FONTS.bold).fontSize(7).fillColor(COLORS.muted).text('TLS CERTIFICATE', PAGE.marginX + 14, y + 12, { characterSpacing: 0.5 });
  if (tls.error) {
    doc.font(FONTS.body).fontSize(8).fillColor(COLORS.danger).text(tls.error, PAGE.marginX + 14, y + 28, { width: CONTENT_WIDTH - 28 });
    doc.y = y + 92;
    return;
  }
  const days = tls.daysRemaining ?? 0;
  const color = days <= 30 ? COLORS.danger : days <= 90 ? COLORS.warn : COLORS.success;
  doc.font(FONTS.bold).fontSize(22).fillColor(color).text(`${days}`, PAGE.marginX + 14, y + 26, { lineBreak: false });
  doc.font(FONTS.body).fontSize(7.5).fillColor(COLORS.muted).text('days remaining', PAGE.marginX + 14, y + 51, { lineBreak: false });
  doc.font(FONTS.body).fontSize(8).fillColor(COLORS.text).text(`${tls.issuerCn ?? 'Unknown issuer'} · ${tls.protocol ?? 'unknown protocol'}`, PAGE.marginX + 150, y + 28, {
    width: CONTENT_WIDTH - 170,
    lineBreak: false,
  });
  doc.font(FONTS.body).fontSize(7.5).fillColor(COLORS.muted).text(`Valid to ${tls.validTo ?? 'unknown'} · ${tls.selfSigned ? 'self-signed' : 'public certificate'}`, PAGE.marginX + 150, y + 42, {
    width: CONTENT_WIDTH - 170,
    lineBreak: false,
  });
  const barX = PAGE.marginX + 150;
  const barW = CONTENT_WIDTH - 170;
  doc.roundedRect(barX, y + 58, barW, 6, 3).fill(COLORS.surfaceAlt);
  doc.roundedRect(barX, y + 58, Math.max(3, barW * Math.min(1, Math.max(0, days / 365))), 6, 3).fill(color);
  doc.y = y + 92;
}

export function renderPosture(doc: PDFKit.PDFDocument, report: ReportModel, presentation: ReportPresentation): void {
  addContentPage(doc);
  sectionTitle(
    doc,
    '03 · Security posture',
    'Controls and hardening',
    'Observed browser, transport, DNS, and email controls. PASS means the control was observed; WARN/FAIL indicates a gap.',
  );

  subheading(doc, 'HTTP and transport posture', 'Headers, cookies, ALPN, and TLS');
  checkGrid(doc, presentation.posture, 'HTTP posture not assessed');
  tlsCard(doc, report);

  ensureSpace(doc, 100);
  subheading(doc, 'DNS and email posture', 'SPF, DMARC, DKIM, DNSSEC, CAA, MTA-STS, and TLS reporting');
  checkGrid(doc, presentation.dnsEmail, 'DNS/email posture not assessed');

  subheading(doc, 'Known vulnerability context', 'CVEs mapped to fingerprinted technologies and detected JavaScript components');
  const cveY = doc.y;
  cveBar(doc, presentation, PAGE.marginX, cveY, CONTENT_WIDTH);
  doc.y = Math.max(doc.y, cveY + 92);
  if (presentation.cveSummary.top.length > 0) {
    drawTable(doc, {
      columns: [
        { label: 'Package', width: 220 },
        { label: 'Version', width: 90 },
        { label: 'CVEs', width: 60, align: 'right' },
        { label: 'Critical / high', width: 120, align: 'right' },
      ],
      rows: presentation.cveSummary.top.map((c) => [c.name, c.version, String(c.cveCount), String(c.criticalHigh)]),
      fontSize: 7.2,
    });
  }

  subheading(doc, 'Exposure overview', 'Open services and attack-surface observations');
  horizontalBars(doc, {
    items: presentation.portGroups.map((group) => ({ label: group.label, value: group.ports.length })),
    emptyLabel: 'No open TCP ports in scope.',
  });
  horizontalBars(doc, {
    items: presentation.attackSurface.filter((item) => item.value > 0).map((item) => ({ label: item.label, value: item.value })),
    emptyLabel: 'No additional attack-surface observations.',
  });

  subheading(doc, 'Tool execution', 'Checks that completed, failed, or timed out');
  if (presentation.toolStats.total === 0) {
    callout(doc, { title: 'No tool results', body: 'No tool execution records were available.', tone: 'info' });
  } else {
    doc.font(FONTS.body).fontSize(8).fillColor(COLORS.text).text(
      `${presentation.toolStats.ok} of ${presentation.toolStats.total} tool checks completed; ${presentation.toolStats.failed} failed and ${presentation.toolStats.timedOut} timed out. Total tool time: ${formatDuration(presentation.toolStats.totalDurationMs)}.`,
      PAGE.marginX,
      doc.y,
      { width: CONTENT_WIDTH, lineGap: 1.5 },
    );
    doc.moveDown(0.5);
    const max = Math.max(1, ...presentation.toolStats.slowest.map((t) => t.durationMs));
    for (const tool of presentation.toolStats.slowest) {
      const y = doc.y;
      doc.font(FONTS.body).fontSize(7.5).fillColor(COLORS.text).text(tool.label, PAGE.marginX, y + 1, { width: 190, lineBreak: false, ellipsis: true });
      const barX = PAGE.marginX + 200;
      const barW = CONTENT_WIDTH - 270;
      doc.roundedRect(barX, y + 2, barW, 6, 3).fill(COLORS.surfaceAlt);
      doc.roundedRect(barX, y + 2, Math.max(2, (tool.durationMs / max) * barW), 6, 3).fill(tool.ok ? COLORS.accent : COLORS.danger);
      doc.font(FONTS.body).fontSize(7).fillColor(COLORS.muted).text(formatDuration(tool.durationMs), PAGE.width - PAGE.marginX - 70, y + 1, { width: 70, align: 'right', lineBreak: false });
      doc.y = y + 15;
    }
  }
}
