import { SECURITY_HEADERS } from '../shared/constants';
import type { DiscoveredPort, Finding, HttpObservation, TlsObservation } from '../shared/types';
import type { WpscanResult } from './parsers';

const DB_PORTS = new Set([1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017]);

export interface FindingsInput {
  ports: DiscoveredPort[];
  http: HttpObservation | null;
  tls: TlsObservation | null;
  technologies: Array<{ name: string; version: string | null }>;
  wordpressDetected: boolean;
  wpscan: WpscanResult | null;
  host: string;
  path: string;
}

let counter = 0;
function nextId(): string {
  counter += 1;
  return `F-${String(counter).padStart(3, '0')}`;
}

export function buildFindings(input: FindingsInput): Finding[] {
  const findings: Finding[] = [];

  // Open ports
  for (const port of input.ports) {
    let severity: Finding['severity'] = 'informational';
    if (DB_PORTS.has(port.port)) severity = 'medium';
    else if (port.port === 22) severity = 'low';

    findings.push({
      id: nextId(),
      category: 'exposure',
      severity,
      title: `Open TCP port ${port.port}${port.service ? ` (${port.service})` : ''}`,
      description: `The target exposes TCP port ${port.port}, which is reachable from the scan vantage point${
        port.service ? ` and appears to run ${port.service}` : ''
      }.${DB_PORTS.has(port.port) ? ' This service is not intended to be Internet-facing and should be restricted.' : ''}`,
      evidence: [`port:${port.port}`, `state:${port.state}`, `protocol:${port.protocol}`, port.service ? `service:${port.service}` : '', port.version ? `version:${port.version}` : ''].filter(Boolean),
      affected: `${input.host}:${port.port}`,
      confidence: 'high',
      verified: true,
      remediation:
        port.port === 22
          ? 'Restrict SSH access to authorized hosts using a firewall allow-list.'
          : DB_PORTS.has(port.port)
            ? 'Restrict access to this database/cache service to authorized networks only.'
            : 'Confirm this port/service needs to be reachable from the Internet; otherwise restrict it.',
    });
  }

  // HTTP headers
  const http = input.http;
  if (http && !http.error) {
    const missing = SECURITY_HEADERS.filter((h) => !http.headers[h]);
    if (missing.length > 0) {
      findings.push({
        id: nextId(),
        category: 'misconfiguration',
        severity: 'low',
        title: 'Missing security response headers',
        description: `The target does not return the following security-relevant response headers: ${missing.join(', ')}.`,
        evidence: missing.map((h) => `missing: ${h}`),
        affected: http.finalUrl ?? `${input.host}${input.path}`,
        confidence: 'high',
        verified: true,
        remediation: 'Configure the web server/application to emit the missing headers (e.g. HSTS, CSP, X-Content-Type-Options, Referrer-Policy).',
      });
    }
    if (http.server) {
      findings.push({
        id: nextId(),
        category: 'informational',
        severity: 'informational',
        title: 'Web server fingerprint revealed',
        description: `The HTTP 'Server' header identifies the platform: ${http.server}.`,
        evidence: [`server: ${http.server}`],
        affected: http.finalUrl ?? `${input.host}${input.path}`,
        confidence: 'high',
        verified: true,
        remediation: 'Consider hiding or customizing the server banner if it is not required.',
      });
    }
    if (http.poweredBy) {
      findings.push({
        id: nextId(),
        category: 'informational',
        severity: 'informational',
        title: 'Framework fingerprint revealed',
        description: `The HTTP 'X-Powered-By' header identifies the framework: ${http.poweredBy}.`,
        evidence: [`x-powered-by: ${http.poweredBy}`],
        affected: http.finalUrl ?? `${input.host}${input.path}`,
        confidence: 'high',
        verified: true,
        remediation: 'Remove the X-Powered-By header if not required.',
      });
    }
  }
  if (http && http.error) {
    findings.push({
      id: nextId(),
      category: 'informational',
      severity: 'informational',
      title: 'HTTP check could not complete',
      description: `The HTTP header check failed: ${http.error}.`,
      evidence: [http.error],
      affected: `${input.host}${input.path}`,
      confidence: 'high',
      verified: true,
      remediation: null,
    });
  }

  // TLS
  if (input.tls) {
    if (input.tls.error) {
      findings.push({
        id: nextId(),
        category: 'informational',
        severity: 'informational',
        title: 'TLS check could not complete',
        description: `The TLS inspection failed: ${input.tls.error}.`,
        evidence: [input.tls.error],
        affected: `${input.host}:443`,
        confidence: 'high',
        verified: true,
        remediation: null,
      });
    } else {
      const t = input.tls;
      if (t.daysRemaining !== null && t.daysRemaining < 0) {
        findings.push({
          id: nextId(),
          category: 'misconfiguration',
          severity: 'high',
          title: 'TLS certificate is expired',
          description: `The certificate presented on port 443 expired ${Math.abs(t.daysRemaining)} day(s) ago.`,
          evidence: [`valid_to: ${t.validTo}`],
          affected: `${input.host}:443`,
          confidence: 'high',
          verified: true,
          remediation: 'Renew and re-issue the certificate immediately.',
        });
      } else if (t.daysRemaining !== null && t.daysRemaining <= 30) {
        findings.push({
          id: nextId(),
          category: 'misconfiguration',
          severity: 'medium',
          title: 'TLS certificate expires soon',
          description: `The certificate presented on port 443 expires in ${t.daysRemaining} day(s).`,
          evidence: [`valid_to: ${t.validTo}`],
          affected: `${input.host}:443`,
          confidence: 'high',
          verified: true,
          remediation: 'Schedule certificate renewal before expiry.',
        });
      }
      if (t.protocol && t.protocol.toUpperCase().localeCompare('TLSv1.2') < 0) {
        findings.push({
          id: nextId(),
          category: 'outdated-technology',
          severity: 'high',
          title: 'Outdated TLS protocol in use',
          description: `The server negotiated ${t.protocol}, which is considered outdated.`,
          evidence: [`protocol: ${t.protocol}`],
          affected: `${input.host}:443`,
          confidence: 'high',
          verified: true,
          remediation: 'Disable TLS 1.0/1.1 and enforce TLS 1.2 or newer.',
        });
      }
      if (t.selfSigned) {
        findings.push({
          id: nextId(),
          category: 'informational',
          severity: 'low',
          title: 'Self-signed TLS certificate',
          description: 'The certificate presented is self-signed; clients will not be able to validate its chain.',
          evidence: [`subject: ${t.subjectCn ?? 'n/a'}`, `issuer: ${t.issuerCn ?? 'n/a'}`],
          affected: `${input.host}:443`,
          confidence: 'high',
          verified: true,
          remediation: 'Use a certificate from a public CA for production endpoints.',
        });
      }
    }
  }

  // Technologies
  if (input.technologies.length > 0) {
    findings.push({
      id: nextId(),
      category: 'informational',
      severity: 'informational',
      title: 'Web technologies detected',
      description: 'The following technologies were fingerprinted on the target.',
      evidence: input.technologies.map((t) => `${t.name}${t.version ? ` ${t.version}` : ''}`),
      affected: `${input.host}${input.path}`,
      confidence: 'medium',
      verified: true,
      remediation: 'Keep all detected platforms and their components up to date.',
    });
  }

  // WordPress
  if (input.wordpressDetected) {
    const notes = input.wpscan?.notes ?? [];
    findings.push({
      id: nextId(),
      category: 'wordpress',
      severity: 'informational',
      title: 'WordPress detected',
      description: `WordPress was detected on the target.${input.wpscan?.wordpressVersion ? ` Reported version: ${input.wpscan.wordpressVersion}.` : ''}${notes.length ? ` Local WPScan checks noted: ${notes.join(' ')}` : ''}`,
      evidence: [...(input.wpscan?.wordpressVersion ? [`wordpress: ${input.wpscan.wordpressVersion}`] : []), ...notes],
      affected: `${input.host}${input.path}`,
      confidence: 'high',
      verified: true,
      remediation: 'Keep WordPress core, themes, and plugins updated and remove exposed files (e.g. readme.txt).',
    });
  }

  return findings;
}

export function summaryStats(findings: Finding[]): { critical: number; high: number; medium: number; low: number; info: number } {
  const stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    stats[f.severity === 'informational' ? 'info' : f.severity] += 1;
  }
  return stats;
}
