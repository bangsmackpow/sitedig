import type { ReportModel } from '../../../shared/types';
import { callout } from '../components';
import { addContentPage, bulletList, ensureSpace, keyValue, sectionTitle, subheading } from '../layout';
import { drawTable } from '../table';
import { COLORS, CONTENT_WIDTH, FONTS, PAGE, SEVERITY_STYLES, formatDuration, truncate } from '../theme';

function emailValue(value: string | null): string {
  return value ? truncate(value, 120) : 'none';
}

export function renderAppendix(doc: PDFKit.PDFDocument, report: ReportModel): void {
  addContentPage(doc);
  sectionTitle(
    doc,
    '04 · Technical appendix',
    'Detailed observations',
    'Raw normalized observations from the tools and modules that ran. This section is intended for technical reviewers.',
  );

  subheading(doc, 'Open ports and services (Nmap)');
  if (report.ports.length === 0) {
    doc.font(FONTS.body).fontSize(8).fillColor(COLORS.muted).text('No open TCP ports were discovered in scope.', PAGE.marginX, doc.y, { width: CONTENT_WIDTH });
    doc.moveDown(0.6);
  } else {
    drawTable(doc, {
      columns: [
        { label: 'Port', width: 55, align: 'right' },
        { label: 'Protocol', width: 55 },
        { label: 'Service', width: 130 },
        { label: 'Version', width: 210 },
      ],
      rows: report.ports.map((p) => [String(p.port), p.protocol, p.service || 'unknown', p.version || '—']),
    });
  }

  if (report.technologies.length > 0) {
    subheading(doc, 'Fingerprinted technologies (WhatWeb)');
    drawTable(doc, {
      columns: [
        { label: 'Technology', width: 240 },
        { label: 'Version', width: 100 },
        { label: 'Source', width: 110 },
      ],
      rows: report.technologies.map((t) => [t.name, t.version ?? 'unknown', 'WhatWeb']),
    });
  }

  if (report.http) {
    subheading(doc, 'HTTP header inspection');
    if (report.http.error) {
      callout(doc, { title: 'HTTP check did not complete', body: report.http.error, tone: 'warn' });
    } else {
      keyValue(doc, 'Status', String(report.http.status ?? 'n/a'));
      keyValue(doc, 'Final URL', report.http.finalUrl ?? 'n/a');
      if (report.http.server) keyValue(doc, 'Server', truncate(report.http.server, 100));
      if (report.http.poweredBy) keyValue(doc, 'X-Powered-By', truncate(report.http.poweredBy, 100));
      const headerRows = Object.entries(report.http.headers)
        .filter(([key]) => key !== 'set-cookie')
        .slice(0, 40)
        .map(([key, value]) => [key, truncate(value, 120)]);
      if (headerRows.length > 0) {
        drawTable(doc, { columns: [{ label: 'Header', width: 180 }, { label: 'Value', width: 330 }], rows: headerRows, fontSize: 6.8, maxRowHeight: 32 });
      }
      if (report.http.redirects.length > 0) {
        subheading(doc, 'Redirect chain');
        drawTable(doc, {
          columns: [{ label: 'Status', width: 60 }, { label: 'Destination', width: 440 }],
          rows: report.http.redirects.map((r) => [String(r.status), truncate(r.to, 150)]),
          fontSize: 7,
        });
      }
    }
  }

  if (report.httpx) {
    subheading(doc, 'HTTP surface validation (httpx)');
    if (report.httpx.error) {
      callout(doc, { title: 'httpx did not complete', body: report.httpx.error, tone: 'warn' });
    } else {
      keyValue(doc, 'Status', String(report.httpx.status ?? 'n/a'));
      keyValue(doc, 'Final URL', report.httpx.finalUrl ?? report.httpx.url);
      if (report.httpx.server) keyValue(doc, 'Server', truncate(report.httpx.server, 100));
      if (report.httpx.tlsVersion) keyValue(doc, 'TLS version', report.httpx.tlsVersion);
      if (report.httpx.technologies.length > 0) keyValue(doc, 'Technologies', report.httpx.technologies.join(', '));
      if (report.httpx.cookies.length > 0) {
        drawTable(doc, {
          columns: [
            { label: 'Cookie', width: 220 },
            { label: 'Secure', width: 80, align: 'center' },
            { label: 'HttpOnly', width: 90, align: 'center' },
          ],
          rows: report.httpx.cookies.map((c) => [c.name, c.secure ? 'yes' : 'no', c.httpOnly ? 'yes' : 'no']),
          fontSize: 7,
        });
      }
    }
  }

  if (report.tls) {
    subheading(doc, 'TLS certificate inspection');
    keyValue(doc, 'Connected', String(report.tls.connected));
    keyValue(doc, 'Protocol', report.tls.protocol ?? 'n/a');
    keyValue(doc, 'Subject CN', report.tls.subjectCn ?? 'n/a');
    keyValue(doc, 'Issuer CN', report.tls.issuerCn ?? 'n/a');
    keyValue(doc, 'Valid from', report.tls.validFrom ?? 'n/a');
    keyValue(doc, 'Valid to', report.tls.validTo ?? 'n/a');
    keyValue(doc, 'Days remaining', report.tls.daysRemaining !== null ? String(report.tls.daysRemaining) : 'n/a');
    keyValue(doc, 'Self-signed', report.tls.selfSigned ? 'yes' : 'no');
  }

  if (report.tlsHardening) {
    subheading(doc, 'TLS hardening (testssl.sh)');
    if (report.tlsHardening.error) {
      callout(doc, { title: 'testssl.sh did not complete', body: report.tlsHardening.error, tone: 'warn' });
    } else if (report.tlsHardening.weaknesses.length > 0) {
      drawTable(doc, {
        columns: [
          { label: 'Severity', width: 70 },
          { label: 'Weakness', width: 160 },
          { label: 'Detail', width: 280 },
        ],
        rows: report.tlsHardening.weaknesses.map((w) => [w.severity.toUpperCase(), w.name, truncate(w.detail, 140)]),
        fontSize: 7,
      });
    } else {
      doc.font(FONTS.body).fontSize(8).fillColor(COLORS.success).text('No notable TLS weaknesses were reported by testssl.sh.', PAGE.marginX, doc.y, { width: CONTENT_WIDTH });
      doc.moveDown(0.6);
    }
  }

  if (report.wordpress?.detected) {
    subheading(doc, 'WordPress (WPScan)');
    keyValue(doc, 'Detected', 'yes');
    keyValue(doc, 'WPScan run', report.wordpress.wpscanRan ? 'yes' : 'no');
    if (report.wordpress.notes.length > 0) bulletList(doc, report.wordpress.notes, { size: 8 });
  }

  if (report.subdomains.length > 0) {
    subheading(doc, 'Passive subdomain discovery (Subfinder)');
    drawTable(doc, {
      columns: [{ label: 'Subdomain', width: 300 }, { label: 'Source', width: 150 }],
      rows: report.subdomains.slice(0, 100).map((s) => [s.host, s.source ?? 'n/a']),
      fontSize: 7,
    });
  }

  if (report.dnsRecords.length > 0) {
    subheading(doc, 'DNS records');
    drawTable(doc, {
      columns: [
        { label: 'Type', width: 55 },
        { label: 'Name', width: 160 },
        { label: 'Value', width: 300 },
      ],
      rows: report.dnsRecords.slice(0, 100).map((r) => [r.type, r.name, truncate(r.value, 140)]),
      fontSize: 6.8,
      maxRowHeight: 38,
    });
  }

  if (report.email) {
    subheading(doc, 'Email and DNS security posture');
    keyValue(doc, 'SPF', emailValue(report.email.spfRecords.join(' | ')));
    keyValue(doc, 'DMARC', emailValue(report.email.dmarcRecords.join(' | ')));
    keyValue(doc, 'MX', report.email.mx.length > 0 ? report.email.mx.map((m) => `${m.host} (${m.priority})`).join(', ') : 'none');
    keyValue(doc, 'MTA-STS', emailValue(report.email.mtaSts));
    keyValue(doc, 'TLS-RPT', emailValue(report.email.tlsRpt));
    keyValue(
      doc,
      'MX STARTTLS',
      report.email.starttls.checked ? (report.email.starttls.supported ? 'offered' : 'not offered') : 'not checked',
    );
  }

  if (report.whois) {
    subheading(doc, 'WHOIS registration (RDAP)');
    if (report.whois.error) {
      callout(doc, { title: 'WHOIS lookup did not complete', body: report.whois.error, tone: 'warn' });
    } else {
      keyValue(doc, 'Registrar', report.whois.registrar ?? 'n/a');
      keyValue(doc, 'Creation date', report.whois.creationDate ?? 'n/a');
      keyValue(doc, 'Update date', report.whois.updateDate ?? 'n/a');
      keyValue(doc, 'Expiry date', report.whois.expiryDate ?? 'n/a');
      if (report.whois.nameservers.length > 0) keyValue(doc, 'Nameservers', report.whois.nameservers.join(', '));
    }
  }

  if (report.vulnerabilities.length > 0) {
    subheading(doc, 'Vulnerability findings (Nuclei / Retire.js)');
    drawTable(doc, {
      columns: [
        { label: 'Severity', width: 70 },
        { label: 'Title', width: 230 },
        { label: 'Matched', width: 140 },
        { label: 'Source', width: 70 },
      ],
      rows: report.vulnerabilities.map((v) => [v.severity.toUpperCase(), v.title, truncate(v.matchedAt ?? 'n/a', 60), v.source]),
      fontSize: 6.9,
    });
  }

  if (report.discoveredPaths.length > 0) {
    subheading(doc, 'Discovered paths (Feroxbuster)');
    drawTable(doc, {
      columns: [
        { label: 'Status', width: 55 },
        { label: 'Path', width: 260 },
        { label: 'Size', width: 70, align: 'right' },
        { label: 'Type', width: 120 },
      ],
      rows: report.discoveredPaths.slice(0, 100).map((p) => [String(p.status), truncate(p.path, 100), p.size === null ? '—' : String(p.size), p.contentType ?? '—']),
      fontSize: 6.8,
      maxRowHeight: 30,
    });
  }

  const archived = report.archivedUrls ?? [];
  if (archived.length > 0) {
    subheading(doc, 'Wayback Machine URL history');
    keyValue(doc, 'Archived same-host URLs', String(archived.length));
    drawTable(doc, {
      columns: [
        { label: 'Category', width: 110 },
        { label: 'Path', width: 300 },
        { label: 'Live today', width: 80, align: 'center' },
      ],
      rows: archived.filter((a) => a.category !== 'other').slice(0, 80).map((a) => [a.category, truncate(a.path, 120), a.live ? 'yes' : 'no']),
      fontSize: 6.8,
    });
  }

  if (report.cveContext.length > 0) {
    subheading(doc, 'CVE context (OSV)');
    drawTable(doc, {
      columns: [
        { label: 'Package', width: 200 },
        { label: 'Version', width: 90 },
        { label: 'CVEs', width: 70, align: 'right' },
        { label: 'Critical / high', width: 130, align: 'right' },
      ],
      rows: report.cveContext.map((c) => [c.name, c.version, String(c.cveCount), String(c.severities.critical + c.severities.high)]),
      fontSize: 7,
    });
  }

  if (report.crawlRules) {
    subheading(doc, 'Crawl rules, sitemap, and security.txt');
    const robots = report.crawlRules.robots;
    keyValue(doc, 'robots.txt', robots.found ? `found (HTTP ${robots.status ?? 'n/a'})` : robots.error ?? 'not found');
    keyValue(doc, 'Sitemap URLs', String(report.crawlRules.sitemap.urlCount));
    if (robots.aiBots.length > 0) keyValue(doc, 'AI crawler rules', robots.aiBots.map((b) => `${b.name}=${b.allowed ? 'allowed' : 'blocked'}`).join(', '));
    if (robots.sensitiveDisallows.length > 0) keyValue(doc, 'Sensitive disallows', robots.sensitiveDisallows.join(', '));
  }
  if (report.securityTxt) {
    keyValue(doc, 'security.txt', report.securityTxt.found ? (report.securityTxt.url ?? 'found') : 'not found');
    if (report.securityTxt.contacts.length > 0) keyValue(doc, 'Security contacts', report.securityTxt.contacts.join(', '));
  }

  if (report.pageRecon) {
    subheading(doc, 'Page metadata and third parties');
    if (report.pageRecon.error) {
      callout(doc, { title: 'Page analysis did not complete', body: report.pageRecon.error, tone: 'warn' });
    } else {
      const meta = report.pageRecon.metadata;
      keyValue(doc, 'Title', meta.title ?? 'n/a');
      keyValue(doc, 'Description', meta.description ?? 'n/a');
      keyValue(doc, 'Canonical', meta.canonical ?? 'n/a');
      keyValue(doc, 'Language', meta.language ?? 'n/a');
      keyValue(doc, 'Links', `${report.pageRecon.links.total} total (${report.pageRecon.links.internal} internal, ${report.pageRecon.links.external} external)`);
      keyValue(doc, 'Mixed content', String(report.pageRecon.mixedContent.length));
      keyValue(doc, 'Missing SRI', String(report.pageRecon.missingSri.length));
      if (report.pageRecon.thirdParties.length > 0) {
        drawTable(doc, {
          columns: [
            { label: 'Third-party host', width: 280 },
            { label: 'Category', width: 130 },
            { label: 'Resources', width: 80, align: 'right' },
          ],
          rows: report.pageRecon.thirdParties.slice(0, 30).map((t) => [t.host, t.category, String(t.count)]),
          fontSize: 6.8,
        });
      }
    }
  }

  if (report.headerPosture) {
    const posture = report.headerPosture;
    subheading(doc, 'HTTP security posture detail');
    keyValue(doc, 'HSTS', posture.hsts.present ? `${posture.hsts.value ?? 'present'}` : 'not set');
    keyValue(doc, 'CSP', posture.csp ? (posture.csp.reportOnly ? 'report-only' : 'enforced') : 'not set');
    keyValue(doc, 'ALPN', posture.alpnProtocol ?? 'n/a');
    if (posture.cookies.length > 0) {
      drawTable(doc, {
        columns: [
          { label: 'Cookie', width: 220 },
          { label: 'Secure', width: 70, align: 'center' },
          { label: 'HttpOnly', width: 80, align: 'center' },
          { label: 'SameSite', width: 100 },
        ],
        rows: posture.cookies.map((c) => [c.name, c.secure ? 'yes' : 'no', c.httpOnly ? 'yes' : 'no', c.sameSite ?? '—']),
        fontSize: 7,
      });
    }
  }

  if (report.dnsHardening) {
    const hardening = report.dnsHardening;
    subheading(doc, 'DNS and email hardening detail');
    keyValue(doc, 'CAA', hardening.caa.length > 0 ? hardening.caa.map((c) => `${c.tag}=${c.value}`).join(', ') : 'none');
    if (hardening.soa) keyValue(doc, 'SOA', `${hardening.soa.ns} (serial ${hardening.soa.serial})`);
    if (hardening.nsAddresses.length > 0) keyValue(doc, 'Nameserver IPs', hardening.nsAddresses.map((n) => `${n.ns} [${n.addresses.join(', ')}]`).join('; '));
    if (hardening.dmarc) keyValue(doc, 'DMARC', `p=${hardening.dmarc.policy ?? 'n/a'}${hardening.dmarc.rua.length ? `; rua=${hardening.dmarc.rua.join(',')}` : ''}`);
    keyValue(doc, 'DKIM selectors', hardening.dkim.filter((d) => d.found && !d.revoked).map((d) => d.selector).join(', ') || 'none');
    keyValue(doc, 'BIMI', hardening.bimi ? 'present' : 'none');
  }

  if (report.dnssec) {
    subheading(doc, 'DNSSEC');
    keyValue(doc, 'Signed', report.dnssec.signed ? 'yes' : 'no');
    keyValue(doc, 'Authenticated data', report.dnssec.ad ? 'yes' : 'no');
    keyValue(doc, 'DNSKEY / DS', `${report.dnssec.dnskeyCount} / ${report.dnssec.dsCount}`);
    if (report.dnssec.algorithms.length > 0) keyValue(doc, 'Algorithms', report.dnssec.algorithms.join(', '));
  }

  if (report.ipIntel) {
    subheading(doc, 'IP, ASN, and edge infrastructure');
    if (report.ipIntel.waf) keyValue(doc, 'WAF', report.ipIntel.waf.name);
    if (report.ipIntel.cdn) keyValue(doc, 'CDN', report.ipIntel.cdn.name);
    if (report.ipIntel.ips.length > 0) {
      drawTable(doc, {
        columns: [
          { label: 'IP', width: 110 },
          { label: 'PTR', width: 120 },
          { label: 'Country', width: 65 },
          { label: 'City', width: 90 },
          { label: 'ASN', width: 65 },
          { label: 'Org', width: 100 },
        ],
        rows: report.ipIntel.ips.map((ip) => [ip.ip, ip.ptr ?? '—', ip.country ?? '—', ip.city ?? '—', ip.asn ?? '—', truncate(ip.org ?? '—', 40)]),
        fontSize: 6.8,
      });
    }
  }

  subheading(doc, 'Tool execution and versions');
  if (report.toolResults.length > 0) {
    drawTable(doc, {
      columns: [
        { label: 'Tool', width: 220 },
        { label: 'Result', width: 120 },
        { label: 'Exit', width: 50, align: 'right' },
        { label: 'Duration', width: 70, align: 'right' },
      ],
      rows: report.toolResults.map((t) => [
        t.label,
        t.ok ? (t.timedOut ? 'timed out' : 'ok') : truncate(t.error ?? 'failed', 70),
        t.exitCode === null ? '—' : String(t.exitCode),
        formatDuration(t.durationMs),
      ]),
      fontSize: 6.9,
      maxRowHeight: 34,
    });
  }
  if (report.meta.toolVersions.length > 0) {
    keyValue(doc, 'Tool versions', report.meta.toolVersions.map((v) => `${v.tool} ${v.version ?? 'unknown'}`).join(' · '));
  }

  subheading(doc, 'Limitations');
  bulletList(doc, report.limitations, { size: 8 });
}
