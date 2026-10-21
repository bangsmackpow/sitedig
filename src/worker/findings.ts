import { SECURITY_HEADERS } from '../shared/constants';
import { evaluatePhpAdvisory, parseRuntimeVersion, PHP2SHELL } from '../shared/advisories';
import { detectPhpRuntime } from './php-runtime';
import type {
  ArchivedUrl,
  Corroboration,
  CveContextFinding,
  DiscoveredPath,
  DiscoveredPort,
  EmailPostureResult,
  Finding,
  HttpObservation,
  HttpxObservation,
  TlsHardeningResult,
  TlsObservation,
  ToolName,
  VulnerabilityFinding,
  CrawlRulesResult,
  SecurityTxtResult,
  PageReconResult,
  HeaderPostureResult,
  DnsHardeningResult,
  DnssecResult,
  IpIntelResult,
} from '../shared/types';
import { analyzeEmailPosture } from './email-posture';
import type { WpscanResult } from './parsers';

const DB_PORTS = new Set([1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017]);

export interface FindingsInput {
  ports: DiscoveredPort[];
  http: HttpObservation | null;
  tls: TlsObservation | null;
  technologies: Array<{ name: string; version: string | null }>;
  wordpressDetected: boolean;
  wpscan: WpscanResult | null;
  wpscanRan: boolean;
  wpscanError: string | null;
  wpscanExitNote: string | null;
  vulnerabilities: VulnerabilityFinding[];
  discoveredPaths: DiscoveredPath[];
  cveContext: CveContextFinding[];
  host: string;
  path: string;
  // --- cross-tool validation inputs (optional; absent for free-core scans) ---
  httpx?: HttpxObservation | null;
  email?: EmailPostureResult | null;
  archivedUrls?: ArchivedUrl[];
  tlsHardening?: TlsHardeningResult | null;
  crawlRules?: CrawlRulesResult | null;
  securityTxt?: SecurityTxtResult | null;
  pageRecon?: PageReconResult | null;
  headerPosture?: HeaderPostureResult | null;
  dnsHardening?: DnsHardeningResult | null;
  dnssec?: DnssecResult | null;
  ipIntel?: IpIntelResult | null;
  /** Which tools executed successfully during this scan (for conflict notes). */
  toolOk?: Partial<Record<ToolName, boolean>>;
}

let counter = 0;
function nextId(): string {
  counter += 1;
  return `F-${String(counter).padStart(3, '0')}`;
}

/**
 * Reset the finding-id counter. Exposed for tests that assert deterministic
 * ids across multiple buildFindings calls.
 */
export function resetFindingCounter(): void {
  counter = 0;
}

function corroborate(supporting: ToolName[], conflicting: string[] = []): Corroboration {
  const unique = Array.from(new Set(supporting));
  const level: Corroboration['level'] = conflicting.length > 0 ? 'conflicting' : unique.length >= 2 ? 'multi' : 'single';
  return { level, supporting: unique, conflicting };
}

/** Multi-source agreement raises confidence; conflicts cap it at medium. */
function applyCorroboration(finding: Finding, corroboration: Corroboration): Finding {
  finding.corroboration = corroboration;
  if (corroboration.level === 'multi' && finding.confidence !== 'high') finding.confidence = 'high';
  if (corroboration.level === 'conflicting' && finding.confidence === 'high') finding.confidence = 'medium';
  return finding;
}

function nucleiMatch(vulnerabilities: VulnerabilityFinding[], pattern: RegExp): VulnerabilityFinding | undefined {
  return vulnerabilities.find((v) => v.source === 'nuclei' && (v.templateId ?? '').match(pattern));
}

function testsslMatch(tlsHardening: TlsHardeningResult | null | undefined, pattern: RegExp): boolean {
  return Boolean(tlsHardening?.weaknesses.some((w) => pattern.test(w.name) || pattern.test(w.detail)));
}

function techOverlap(a: string[], b: string[]): string[] {
  const lowerB = b.map((s) => s.toLowerCase());
  return a.filter((name) => lowerB.some((other) => other.includes(name.toLowerCase()) || name.toLowerCase().includes(other)));
}

function bannerAgrees(a: string | null, b: string | null): boolean {
  if (!a || !b) return false;
  const norm = (s: string) => s.toLowerCase().replace(/\/.*/, '').trim();
  return norm(a) === norm(b);
}

export function buildFindings(input: FindingsInput): Finding[] {
  const findings: Finding[] = [];
  const httpx = input.httpx && !input.httpx.error ? input.httpx : null;
  const testsslRan = Boolean(input.toolOk?.testssl);
  const nucleiRan = Boolean(input.toolOk?.nuclei);

  // Open ports
  for (const port of input.ports) {
    let severity: Finding['severity'] = 'informational';
    if (DB_PORTS.has(port.port)) severity = 'medium';
    else if (port.port === 22) severity = 'low';

    const supporting: ToolName[] = ['nmap'];
    if (port.port === 80 && input.http && !input.http.error) supporting.push('http');
    if (port.port === 443 && input.tls?.connected) supporting.push('tls');
    if ((port.port === 80 || port.port === 443) && httpx) supporting.push('httpx');

    const finding: Finding = {
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
      sourceTools: supporting,
      playbookKey: DB_PORTS.has(port.port) ? 'open-db-port' : port.port === 22 ? 'open-ssh' : 'open-port',
    };
    findings.push(applyCorroboration(finding, corroborate(supporting)));
  }

  // HTTP headers
  const http = input.http;
  if (http && !http.error) {
    const missing = SECURITY_HEADERS.filter((h) => !http.headers[h]);
    if (missing.length > 0) {
      const conflicting: string[] = [];
      const supporting: ToolName[] = ['http'];
      if (httpx) {
        const missingInHttpx = missing.filter((h) => !httpx.headers[h]);
        if (missingInHttpx.length === missing.length) supporting.push('httpx');
        else {
          const present = missing.filter((h) => httpx.headers[h]);
          conflicting.push(`httpx saw ${present.join(', ')} on ${httpx.finalUrl ?? httpx.url} — the headers may only be set on some responses/redirects.`);
        }
      }
      const finding: Finding = {
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
        sourceTools: supporting,
        playbookKey: 'missing-headers',
      };
      findings.push(applyCorroboration(finding, corroborate(supporting, conflicting)));
    }
    if (http.server) {
      const supporting: ToolName[] = ['http'];
      const conflicting: string[] = [];
      if (httpx?.server) {
        if (bannerAgrees(http.server, httpx.server)) supporting.push('httpx');
        else conflicting.push(`httpx reports the Server banner as "${httpx.server}" instead of "${http.server}" (different vhost/CDN?).`);
      }
      const finding: Finding = {
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
        sourceTools: supporting,
        playbookKey: 'server-banner',
      };
      findings.push(applyCorroboration(finding, corroborate(supporting, conflicting)));
    }
    if (http.poweredBy) {
      const supporting: ToolName[] = ['http', ...(httpx?.headers['x-powered-by'] ? (['httpx'] as ToolName[]) : [])];
      const finding: Finding = {
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
        sourceTools: supporting,
        playbookKey: 'powered-by',
      };
      findings.push(applyCorroboration(finding, corroborate(supporting)));
    }
    // httpx-only observations (cookies)
    const insecureCookies = (httpx?.cookies ?? []).filter((c) => !c.secure || !c.httpOnly);
    if (insecureCookies.length > 0) {
      const finding: Finding = {
        id: nextId(),
        category: 'misconfiguration',
        severity: 'medium',
        title: 'Cookies missing Secure/HttpOnly flags',
        description: `Set-Cookie responses for ${httpx!.finalUrl ?? httpx!.url} omit one or both of the Secure/HttpOnly flags: ${insecureCookies
          .map((c) => `${c.name}${c.secure ? '' : ' (no Secure)'}${c.httpOnly ? '' : ' (no HttpOnly)'}`)
          .join(', ')}. Session cookies without these flags can be stolen via XSS or sent over plain HTTP.`,
        evidence: insecureCookies.map((c) => `cookie:${c.name} secure:${c.secure} httponly:${c.httpOnly}`),
        affected: httpx!.finalUrl ?? httpx!.url,
        confidence: 'high',
        verified: true,
        remediation: 'Set the Secure and HttpOnly attributes on all session cookies; add SameSite=Lax/Strict where appropriate.',
        sourceTools: ['httpx'],
        playbookKey: 'insecure-cookie',
      };
      findings.push(applyCorroboration(finding, corroborate(['httpx'])));
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
      sourceTools: ['http'],
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
        sourceTools: ['tls'],
      });
    } else {
      const t = input.tls;
      if (t.daysRemaining !== null && t.daysRemaining < 0) {
        const supporting: ToolName[] = ['tls'];
        const conflicting: string[] = [];
        if (nucleiMatch(input.vulnerabilities, /expired/)) supporting.push('nuclei');
        else if (nucleiRan) conflicting.push('Nuclei ran but did not match its expired-ssl template — verify the certificate expiry view.');
        if (testsslMatch(input.tlsHardening, /expire/i)) supporting.push('testssl');
        else if (testsslRan) conflicting.push('testssl.sh ran but did not report an expired certificate.');
        const finding: Finding = {
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
          sourceTools: supporting,
          playbookKey: 'cert-expired',
        };
        findings.push(applyCorroboration(finding, corroborate(supporting, conflicting)));
      } else if (t.daysRemaining !== null && t.daysRemaining <= 30) {
        const supporting: ToolName[] = ['tls'];
        if (httpx?.certExpiry) supporting.push('httpx');
        const finding: Finding = {
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
          sourceTools: supporting,
          playbookKey: 'cert-expiring',
        };
        findings.push(applyCorroboration(finding, corroborate(supporting)));
      }
      if (t.protocol && t.protocol.toUpperCase().localeCompare('TLSv1.2') < 0) {
        const supporting: ToolName[] = ['tls'];
        if (nucleiMatch(input.vulnerabilities, /deprecated-tls|tls-version/)) supporting.push('nuclei');
        if (testsslMatch(input.tlsHardening, /TLS\s?1[.\s]?[01]|SSLv3|SSLv2/i)) supporting.push('testssl');
        const finding: Finding = {
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
          sourceTools: supporting,
          playbookKey: 'tls-legacy',
        };
        findings.push(applyCorroboration(finding, corroborate(supporting)));
      }
      if (t.selfSigned) {
        const supporting: ToolName[] = ['tls'];
        if (nucleiMatch(input.vulnerabilities, /self-signed/)) supporting.push('nuclei');
        if (testsslMatch(input.tlsHardening, /self-s|selfsigned/i)) supporting.push('testssl');
        const finding: Finding = {
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
          sourceTools: supporting,
          playbookKey: 'self-signed',
        };
        findings.push(applyCorroboration(finding, corroborate(supporting)));
      }
    }
  }

  // TLS hardening weaknesses (testssl-only evidence, corroborated by nuclei where matched)
  for (const w of input.tlsHardening?.weaknesses ?? []) {
    const sev: Finding['severity'] = w.severity === 'CRITICAL' ? 'critical' : w.severity === 'HIGH' ? 'high' : w.severity === 'MEDIUM' ? 'medium' : 'low';
    const supporting: ToolName[] = ['testssl'];
    const weaknessPattern = w.name.slice(0, 12).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (weaknessPattern && nucleiMatch(input.vulnerabilities, new RegExp(weaknessPattern, 'i'))) supporting.push('nuclei');
    const finding: Finding = {
      id: nextId(),
      category: 'misconfiguration',
      severity: sev,
      title: `TLS weakness: ${w.name}`,
      description: `testssl.sh reported: ${w.detail}`,
      evidence: [`testssl: ${w.name}`, w.detail],
      affected: `${input.host}:443`,
      confidence: 'high',
      verified: true,
      remediation: 'Apply the recommended TLS configuration changes and re-run the TLS audit to confirm.',
      sourceTools: supporting,
      playbookKey: 'tls-legacy',
    };
    findings.push(applyCorroboration(finding, corroborate(supporting)));
  }

  // Technologies
  if (input.technologies.length > 0) {
    const names = input.technologies.map((t) => t.name);
    const supporting: ToolName[] = ['whatweb'];
    const httpxTech = httpx?.technologies ?? [];
    if (httpx && techOverlap(names, httpxTech).length > 0) supporting.push('httpx');
    const nmapBanners = input.ports.map((p) => `${p.service} ${p.version}`.trim()).filter((s) => s);
    if (techOverlap(names, nmapBanners).length > 0) supporting.push('nmap');
    const finding: Finding = {
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
      sourceTools: supporting,
      playbookKey: 'tech-versions',
    };
    findings.push(applyCorroboration(finding, corroborate(supporting)));
  }

  // Curated runtime advisories (free, version-based, no exploitation).
  const php = detectPhpRuntime({ technologies: input.technologies, http: input.http, httpx: input.httpx });
  if (php.present) {
    const evaluation = evaluatePhpAdvisory(PHP2SHELL, parseRuntimeVersion(php.version));
    const tools: ToolName[] = [];
    if (php.sources.includes('whatweb')) tools.push('whatweb');
    if (php.sources.includes('httpx')) tools.push('httpx');
    if (php.sources.includes('http')) tools.push('http');
    const supporting = tools.length > 0 ? tools : ['http' as ToolName];
    const evidence = [
      `detected PHP: ${php.version ?? 'version unknown'}`,
      `source: ${php.source ?? php.sources.join(', ')}`,
      ...(evaluation.fixedVersion ? [`fixed release: ${evaluation.fixedVersion}`] : []),
      ...(evaluation.branch ? [`branch: ${evaluation.branch}`] : []),
      `SAPIs in scope: ${PHP2SHELL.sapis.join(', ')}`,
      `advisory: ${PHP2SHELL.references[0]}`,
      'detection is version-based only; no exploit was attempted',
    ];

    if (evaluation.state === 'vulnerable') {
      const finding: Finding = {
        id: nextId(),
        category: 'vulnerability',
        severity: 'critical',
        title: `PHP ${php.version} is vulnerable to PHP2Shell (${PHP2SHELL.cves.join(' / ')})`,
        description: `${evaluation.reason} ${PHP2SHELL.summary} ${PHP2SHELL.impact}`,
        evidence,
        affected: `${input.host}${input.path}`,
        confidence: php.confidence === 'high' ? 'high' : 'medium',
        verified: true,
        remediation: PHP2SHELL.remediation,
        sourceTools: supporting,
        playbookKey: PHP2SHELL.id,
      };
      findings.push(applyCorroboration(finding, corroborate(supporting)));
    } else if (evaluation.state === 'unknown') {
      const finding: Finding = {
        id: nextId(),
        category: 'vulnerability',
        severity: 'medium',
        title: 'PHP detected but version could not be determined (PHP2Shell exposure unknown)',
        description: `${PHP2SHELL.summary} The runtime was fingerprinted, but the version is hidden or was not reported. Verify the deployed PHP version against the fixed releases.`,
        evidence,
        affected: `${input.host}${input.path}`,
        confidence: 'low',
        verified: false,
        remediation: PHP2SHELL.remediation,
        sourceTools: supporting,
        playbookKey: PHP2SHELL.id,
      };
      findings.push(applyCorroboration(finding, corroborate(supporting)));
    }
  }

  // WordPress
  if (input.wordpressDetected) {
    const notes = input.wpscan?.notes ?? [];
    let description = `WordPress was detected on the target.${input.wpscan?.wordpressVersion ? ` Reported version: ${input.wpscan.wordpressVersion}.` : ''}${notes.length ? ` Local WPScan checks noted: ${notes.join(' ')}` : ''}`;
    if (input.wpscanExitNote) {
      description += ` ${input.wpscanExitNote}`;
    }
    if (input.wpscanRan && input.wpscanError) {
      description += ` Local WPScan checks failed to complete: ${input.wpscanError}. Full output is available in the server logs.`;
    }
    const supporting: ToolName[] = ['whatweb'];
    if (input.wpscanRan && input.wpscan) supporting.push('wpscan');
    if (httpx && httpx.technologies.some((t) => t.toLowerCase().includes('wordpress'))) supporting.push('httpx');
    const finding: Finding = {
      id: nextId(),
      category: 'wordpress',
      severity: 'informational',
      title: 'WordPress detected',
      description,
      evidence: [
        ...(input.wpscan?.wordpressVersion ? [`wordpress: ${input.wpscan.wordpressVersion}`] : []),
        ...notes,
        ...(input.wpscanExitNote ? [input.wpscanExitNote] : []),
        ...(input.wpscanError ? [`wpscan_error: ${input.wpscanError}`] : []),
      ],
      affected: `${input.host}${input.path}`,
      confidence: 'high',
      verified: true,
      remediation: 'Keep WordPress core, themes, and plugins updated and remove exposed files (e.g. readme.txt).',
      sourceTools: supporting,
      playbookKey: 'wordpress',
    };
    findings.push(applyCorroboration(finding, corroborate(supporting)));
  }

  // Vulnerability findings (nuclei / retire.js)
  const sevMap: Record<VulnerabilityFinding['severity'], Finding['severity']> = {
    info: 'informational',
    low: 'low',
    medium: 'medium',
    high: 'high',
    critical: 'critical',
  };
  for (const v of input.vulnerabilities) {
    const tool: ToolName = v.source === 'nuclei' ? 'nuclei' : 'retire';
    const supporting: ToolName[] = [tool];
    // retire.js findings on the same component corroborate OSV CVE context.
    if (tool === 'retire' && input.cveContext.some((c) => c.name.toLowerCase().includes(String(v.id).slice(0, 8).toLowerCase()) || v.id.toLowerCase().includes(c.name.toLowerCase()))) supporting.push('osv');
    const finding: Finding = {
      id: nextId(),
      category: 'vulnerability',
      severity: sevMap[v.severity] ?? 'medium',
      title: v.title,
      description: v.description || `Detected by ${v.source}${v.templateId ? ` (template ${v.templateId})` : ''}.`,
      evidence: [v.templateId ? `template: ${v.templateId}` : `source: ${v.source}`, v.matchedAt ? `matched: ${v.matchedAt}` : ''].filter(Boolean),
      affected: v.matchedAt ?? `${input.host}${input.path}`,
      confidence: 'medium',
      verified: true,
      remediation: 'Investigate the finding and apply the vendor fix or mitigating control.',
      sourceTools: supporting,
      playbookKey: 'vuln-generic',
    };
    findings.push(applyCorroboration(finding, corroborate(supporting)));
  }

  // Content discovery paths of interest (corroborated when also archived)
  const interestingStatus = (s: number) => s >= 200 && s < 300 && s !== 204;
  const interestingPaths = input.discoveredPaths.filter((p) => interestingStatus(p.status));
  const archivedByPath = new Map((input.archivedUrls ?? []).map((a) => [a.path, a]));
  if (interestingPaths.length > 0) {
    const supporting: ToolName[] = ['feroxbuster'];
    const alsoArchived = interestingPaths.filter((p) => archivedByPath.has(p.path));
    if (alsoArchived.length > 0 && input.toolOk?.waybackurls) supporting.push('waybackurls');
    const finding: Finding = {
      id: nextId(),
      category: 'exposure',
      severity: alsoArchived.length > 0 ? 'medium' : 'informational',
      title: `${interestingPaths.length} discoverable path(s) found`,
      description:
        'Content discovery found HTTP 2xx responses for the following paths.' +
        (alsoArchived.length > 0 ? ` ${alsoArchived.length} of these paths are also present in Wayback Machine history, confirming long-standing exposure.` : ''),
      evidence: interestingPaths.slice(0, 20).map((p) => `${p.status} ${p.path}`),
      affected: `${input.host}${input.path}`,
      confidence: 'high',
      verified: true,
      remediation: 'Review each discovered path and restrict access to anything not intended to be public.',
      sourceTools: supporting,
      playbookKey: 'exposed-paths',
    };
    findings.push(applyCorroboration(finding, corroborate(supporting)));
  }

  // Wayback Machine exposure findings
  const archivedList = input.archivedUrls ?? [];
  const sensitiveArchived = archivedList.filter((a) => a.category === 'sensitive-path');
  const credentialArchived = archivedList.filter((a) => a.category === 'credential-in-url');
  const liveSensitive = sensitiveArchived.filter((a) => a.live);
  if (sensitiveArchived.length > 0) {
    const supporting: ToolName[] = ['waybackurls'];
    if (liveSensitive.length > 0 && input.toolOk?.feroxbuster) supporting.push('feroxbuster');
    const finding: Finding = {
      id: nextId(),
      category: 'exposure',
      severity: liveSensitive.length > 0 ? 'high' : sensitiveArchived.length > 3 ? 'medium' : 'low',
      title: `${sensitiveArchived.length} sensitive path(s) found in URL history`,
      description:
        `The Wayback Machine archives sensitive-looking URLs for this host (${sensitiveArchived.map((a) => a.path).slice(0, 10).join(', ')}). ` +
        (liveSensitive.length > 0
          ? `LIVE RE-CHECK: ${liveSensitive.length} of these still answer today — the data may still be publicly readable.`
          : 'None answered during live re-verification, but archived copies remain readable at web.archive.org.'),
      evidence: sensitiveArchived.slice(0, 20).map((a) => `${a.live ? 'LIVE' : 'archived'} ${a.path}`),
      affected: `${input.host}`,
      confidence: liveSensitive.length > 0 ? 'high' : 'medium',
      verified: true,
      remediation: 'Remove or protect the exposed files, purge cached copies from the Wayback Machine (https://web.archive.org/help/contact), and rotate any secrets they contained.',
      sourceTools: supporting,
      playbookKey: 'archived-exposure',
    };
    findings.push(applyCorroboration(finding, corroborate(supporting)));
  }
  if (credentialArchived.length > 0) {
    const finding: Finding = {
      id: nextId(),
      category: 'exposure',
      severity: 'critical',
      title: `${credentialArchived.length} archived URL(s) contained credential-like parameters`,
      description: `Wayback Machine captures include URLs whose query strings carry credential-like values (parameter names: ${[...new Set(credentialArchived.map((a) => a.tokenParam))].filter(Boolean).join(', ')}). The values themselves are not reproduced in this report.`,
      evidence: credentialArchived.slice(0, 20).map((a) => `${a.live ? 'LIVE' : 'archived'} ${a.path}?…${a.tokenParam}`),
      affected: `${input.host}`,
      confidence: 'high',
      verified: true,
      remediation: 'Rotate every credential that appeared in these URLs and stop passing secrets in query strings.',
      sourceTools: ['waybackurls'],
      playbookKey: 'leaked-url-credentials',
    };
    findings.push(applyCorroboration(finding, corroborate(['waybackurls'])));
  }

  // Email & DNS security posture
  const email = input.email;
  if (email && !email.error) {
    const analysis = analyzeEmailPosture(email);
    const supporting: ToolName[] = ['email'];
    const hasMail = email.mx.length > 0;

    if (!analysis.dmarc.present) {
      const finding: Finding = {
        id: nextId(),
        category: 'misconfiguration',
        severity: hasMail ? 'high' : 'medium',
        title: hasMail ? 'No DMARC policy published for a domain that sends email' : 'No DMARC policy published',
        description: hasMail
          ? `The domain publishes ${email.mx.length} MX record(s) but has no _dmarc TXT record. Without DMARC, attackers can spoof the domain in phishing campaigns and receivers have no policy to reject those messages.`
          : 'The domain has no _dmarc TXT record. DMARC tells receiving mail servers how to treat forged messages using your domain.',
        evidence: [`dmarc: missing`, `mx: ${email.mx.map((m) => m.host).join(', ') || 'none'}`],
        affected: email.domain,
        confidence: 'high',
        verified: true,
        remediation: 'Publish a DMARC record (start at p=none with an aggregate report address, then move to p=quarantine and p=reject).',
        sourceTools: supporting,
        playbookKey: 'dmarc-missing',
      };
      findings.push(applyCorroboration(finding, corroborate(supporting)));
    } else if (analysis.dmarc.policy === 'none' || !analysis.dmarc.hasRua) {
      const finding: Finding = {
        id: nextId(),
        category: 'misconfiguration',
        severity: 'medium',
        title: 'DMARC policy is monitoring-only (p=none)',
        description: `A DMARC record exists (${email.dmarcRecords.join(' | ')})${analysis.dmarc.policy === 'none' ? ' but the enforcement policy is p=none, so spoofed mail is still delivered' : ''}${!analysis.dmarc.hasRua ? ' and no aggregate report address (rua=) is configured, so you cannot see abuse attempts' : ''}.`,
        evidence: email.dmarcRecords.map((r) => `dmarc: ${r}`),
        affected: email.domain,
        confidence: 'high',
        verified: true,
        remediation: 'Review aggregate reports, then raise the policy to p=quarantine and eventually p=reject.',
        sourceTools: supporting,
        playbookKey: 'dmarc-none',
      };
      findings.push(applyCorroboration(finding, corroborate(supporting)));
    }

    if (analysis.spfCount === 0 && hasMail) {
      const finding: Finding = {
        id: nextId(),
        category: 'misconfiguration',
        severity: 'medium',
        title: 'No SPF record for a domain that sends email',
        description: 'The domain publishes MX records but no v=spf1 TXT record, so receivers cannot validate which servers may send for it.',
        evidence: [`spf: missing`, `mx: ${email.mx.map((m) => m.host).join(', ')}`],
        affected: email.domain,
        confidence: 'high',
        verified: true,
        remediation: 'Publish a single SPF record listing the authorized senders, ending in -all.',
        sourceTools: supporting,
        playbookKey: 'spf-missing',
      };
      findings.push(applyCorroboration(finding, corroborate(supporting)));
    }
    if (analysis.spfCount > 1) {
      const finding: Finding = {
        id: nextId(),
        category: 'misconfiguration',
        severity: 'medium',
        title: 'Multiple SPF records published',
        description: `RFC 7208 allows only one SPF record; ${analysis.spfCount} were found (${email.spfRecords.join(' | ')}). Receivers may ignore all of them, breaking deliverability and DMARC alignment.`,
        evidence: email.spfRecords.map((r) => `spf: ${r}`),
        affected: email.domain,
        confidence: 'high',
        verified: true,
        remediation: 'Merge the records into a single SPF line.',
        sourceTools: supporting,
        playbookKey: 'spf-permissive',
      };
      findings.push(applyCorroboration(finding, corroborate(supporting)));
    }
    if (analysis.spfPermissive) {
      const finding: Finding = {
        id: nextId(),
        category: 'misconfiguration',
        severity: 'medium',
        title: 'SPF record allows any sender',
        description: `The SPF policy ends in a permissive qualifier (+all / ?all / all): ${email.spfRecords.join(' | ')}. This effectively disables sender validation and simplifies domain spoofing.`,
        evidence: email.spfRecords.map((r) => `spf: ${r}`),
        affected: email.domain,
        confidence: 'high',
        verified: true,
        remediation: 'Replace the end qualifier with -all (hard fail) after listing authorized senders.',
        sourceTools: supporting,
        playbookKey: 'spf-permissive',
      };
      findings.push(applyCorroboration(finding, corroborate(supporting)));
    }

    if (email.starttls.checked && email.starttls.supported === false) {
      const finding: Finding = {
        id: nextId(),
        category: 'exposure',
        severity: 'medium',
        title: `MX host ${email.starttls.mx} does not advertise STARTTLS`,
        description: 'The primary mail server does not support opportunistic TLS, so inbound mail may be relayed in clear text.',
        evidence: [`mx: ${email.starttls.mx ?? 'n/a'}`, 'starttls: not offered'],
        affected: email.domain,
        confidence: 'medium',
        verified: true,
        remediation: 'Enable STARTTLS on the mail server or move to a provider that enforces TLS on MX connections.',
        sourceTools: supporting,
        playbookKey: 'mx-starttls',
      };
      findings.push(applyCorroboration(finding, corroborate(supporting)));
    }
    if (email.starttls.error) {
      findings.push({
        id: nextId(),
        category: 'informational',
        severity: 'informational',
        title: 'MX STARTTLS probe did not complete',
        description: `The STARTTLS capability probe was not completed: ${email.starttls.error}`,
        evidence: [`probe_error: ${email.starttls.error}`],
        affected: email.domain,
        confidence: 'high',
        verified: false,
        remediation: null,
        sourceTools: ['email'],
      });
    }

    if (hasMail && !email.mtaSts) {
      const finding: Finding = {
        id: nextId(),
        category: 'misconfiguration',
        severity: 'low',
        title: 'No MTA-STS policy published',
        description: 'Without an MTA-STS policy, mail relayed to this domain cannot enforce TLS with downgrade protection.',
        evidence: ['mta-sts: missing'],
        affected: email.domain,
        confidence: 'high',
        verified: true,
        remediation: 'Publish an MTA-STS policy (mx.google.com style: TXT _mta-sts record + https://mta-sts.<domain>/.well-known/mta-sts.txt).',
        sourceTools: supporting,
        playbookKey: 'mta-sts',
      };
      findings.push(applyCorroboration(finding, corroborate(supporting)));
    }
    if (hasMail && !email.tlsRpt) {
      const finding: Finding = {
        id: nextId(),
        category: 'misconfiguration',
        severity: 'low',
        title: 'No TLS reporting (TLS-RPT) policy published',
        description: 'TLS-RPT lets you see when other mail servers fail to deliver to your domain over TLS.',
        evidence: ['tls-rpt: missing'],
        affected: email.domain,
        confidence: 'high',
        verified: true,
        remediation: 'Publish a _smtp._tls TXT record (v=TLSRPTv1; rua=mailto:…) to receive TLS failure reports.',
        sourceTools: supporting,
        playbookKey: 'mta-sts',
      };
      findings.push(applyCorroboration(finding, corroborate(supporting)));
    }
  }

  // CVE context for detected technologies
  for (const c of input.cveContext) {
    const total = c.cveCount;
    const crit = c.severities.critical + c.severities.high;
    const supporting: ToolName[] = ['osv'];
    const whatwebHit = input.technologies.some((t) => t.name.toLowerCase().includes(c.name.toLowerCase()));
    if (whatwebHit) supporting.push('whatweb');
    const finding: Finding = {
      id: nextId(),
      category: 'outdated-technology',
      severity: crit > 0 ? 'high' : c.severities.medium > 0 ? 'medium' : 'low',
      title: `${c.name} ${c.version} has ${total} known CVE(s)`,
      description: `${c.ecosystem} package ${c.name} ${c.version} was fingerprinted on the target and maps to ${total} known vulnerability record(s) in OSV.`,
      evidence: [
        `ecosystem: ${c.ecosystem}`,
        `package: ${c.name}`,
        `version: ${c.version}`,
        `cve_count: ${total}`,
        ...Object.entries(c.severities)
          .filter(([, n]) => n > 0)
          .map(([k, n]) => `${k}: ${n}`),
      ],
      affected: `${input.host}${input.path}`,
      confidence: 'medium',
      verified: true,
      remediation: `Upgrade ${c.name} to a patched version and verify no conflicting plugins/extensions.`,
      sourceTools: supporting,
      playbookKey: 'cve-package',
    };
    findings.push(applyCorroboration(finding, corroborate(supporting)));
  }

  // --- Web trust posture -----------------------------------------------
  const posture = input.headerPosture;
  if (posture && !posture.error) {
    if (!posture.hsts.present) {
      findings.push(
        applyCorroboration(
          {
            id: nextId(),
            category: 'misconfiguration',
            severity: 'low',
            title: 'HSTS is not enabled',
            description: 'The response does not include a Strict-Transport-Security header, so browsers are not instructed to force HTTPS on future visits.',
            evidence: ['strict-transport-security: missing'],
            affected: input.pageRecon?.finalUrl ?? `${input.host}${input.path}`,
            confidence: 'high',
            verified: true,
            remediation: 'Enable HSTS after confirming HTTPS is stable, starting with a short max-age and increasing it once verified.',
            sourceTools: ['header-posture'],
            playbookKey: 'hsts-missing',
          },
          corroborate(['header-posture']),
        ),
      );
    } else if (posture.hsts.maxAge === null || posture.hsts.maxAge < 15_552_000) {
      findings.push(
        applyCorroboration(
          {
            id: nextId(),
            category: 'misconfiguration',
            severity: 'low',
            title: 'HSTS max-age is weak',
            description: `HSTS is enabled but ${posture.hsts.maxAge === null ? 'has no parseable max-age' : `uses max-age=${posture.hsts.maxAge}`}. A value of at least 15552000 seconds (180 days) is recommended.`,
            evidence: [`strict-transport-security: ${posture.hsts.value ?? 'present'}`],
            affected: input.pageRecon?.finalUrl ?? `${input.host}${input.path}`,
            confidence: 'high',
            verified: true,
            remediation: 'Raise the HSTS max-age to at least 15552000 seconds; add includeSubDomains and preload only once every subdomain supports HTTPS.',
            sourceTools: ['header-posture'],
            playbookKey: 'hsts-missing',
          },
          corroborate(['header-posture']),
        ),
      );
    }

    if (!posture.csp) {
      findings.push(
        applyCorroboration(
          {
            id: nextId(),
            category: 'misconfiguration',
            severity: 'low',
            title: 'Content-Security-Policy is not enforced',
            description: 'No enforcing Content-Security-Policy header was observed. CSP limits the impact of injected scripts and third-party content.',
            evidence: ['content-security-policy: missing'],
            affected: input.pageRecon?.finalUrl ?? `${input.host}${input.path}`,
            confidence: 'high',
            verified: true,
            remediation: 'Deploy a CSP starting in report-only mode, then enforce it after reviewing violations.',
            sourceTools: ['header-posture'],
            playbookKey: 'csp-weak',
          },
          corroborate(['header-posture']),
        ),
      );
    } else if (posture.csp.reportOnly) {
      findings.push({
        id: nextId(),
        category: 'informational',
        severity: 'informational',
        title: 'Content-Security-Policy is report-only',
        description: 'A CSP is present but only in report-only mode, so violations are reported without blocking content.',
        evidence: ['content-security-policy-report-only: present'],
        affected: input.pageRecon?.finalUrl ?? `${input.host}${input.path}`,
        confidence: 'high',
        verified: true,
        remediation: 'Review violation reports, then promote the policy to an enforcing Content-Security-Policy header.',
        sourceTools: ['header-posture'],
        playbookKey: 'csp-weak',
      });
    } else if (
      posture.csp.unsafeInline ||
      posture.csp.unsafeEval ||
      posture.csp.wildcard ||
      posture.csp.missingObjectSrc ||
      posture.csp.missingBaseUri
    ) {
      const weaknesses = [
        posture.csp.unsafeInline ? "'unsafe-inline'" : null,
        posture.csp.unsafeEval ? "'unsafe-eval'" : null,
        posture.csp.wildcard ? 'wildcard source' : null,
        posture.csp.missingObjectSrc ? 'missing object-src' : null,
        posture.csp.missingBaseUri ? 'missing base-uri' : null,
      ].filter(Boolean);
      findings.push(
        applyCorroboration(
          {
            id: nextId(),
            category: 'misconfiguration',
            severity: 'low',
            title: 'Content-Security-Policy contains weak directives',
            description: `The CSP includes ${weaknesses.join(', ')}, which reduces its protection against script injection.`,
            evidence: weaknesses.map((w) => `csp: ${w}`),
            affected: input.pageRecon?.finalUrl ?? `${input.host}${input.path}`,
            confidence: 'high',
            verified: true,
            remediation: 'Remove unsafe-inline/unsafe-eval and wildcard sources; use nonces or hashes for inline scripts.',
            sourceTools: ['header-posture'],
            playbookKey: 'csp-weak',
          },
          corroborate(['header-posture']),
        ),
      );
    }

    const sameSiteMissing = posture.cookies.filter((c) => !c.sameSite && c.name);
    if (sameSiteMissing.length > 0) {
      findings.push({
        id: nextId(),
        category: 'misconfiguration',
        severity: 'low',
        title: 'Cookies without a SameSite attribute',
        description: `The following cookies do not declare SameSite: ${sameSiteMissing.map((c) => c.name).join(', ')}. Cross-site request forgery exposure depends on browser defaults and the cookie's purpose.`,
        evidence: sameSiteMissing.map((c) => `cookie:${c.name} samesite:missing`),
        affected: input.pageRecon?.finalUrl ?? `${input.host}${input.path}`,
        confidence: 'medium',
        verified: true,
        remediation: 'Set SameSite=Lax or Strict on cookies that do not need cross-site use, and SameSite=None combined with Secure where they do.',
        sourceTools: ['header-posture'],
        playbookKey: 'insecure-cookie',
      });
    }
    if (!input.httpx) {
      const insecure = posture.cookies.filter((c) => !c.secure || !c.httpOnly);
      if (insecure.length > 0) {
        findings.push({
          id: nextId(),
          category: 'misconfiguration',
          severity: 'medium',
          title: 'Cookies missing Secure/HttpOnly flags',
          description: `Cookies were set without the full Secure/HttpOnly protections: ${insecure.map((c) => c.name).join(', ')}.`,
          evidence: insecure.map((c) => `cookie:${c.name} secure:${c.secure} httponly:${c.httpOnly}`),
          affected: input.pageRecon?.finalUrl ?? `${input.host}${input.path}`,
          confidence: 'high',
          verified: true,
          remediation: 'Set Secure and HttpOnly on session cookies unless a documented client-side requirement exists.',
          sourceTools: ['header-posture'],
          playbookKey: 'insecure-cookie',
        });
      }
    }
  }

  const page = input.pageRecon;
  if (page && !page.error) {
    if (page.mixedContent.length > 0) {
      const active = page.mixedContent.filter((m) => m.kind === 'script' || m.kind === 'stylesheet' || m.kind === 'iframe');
      findings.push({
        id: nextId(),
        category: 'misconfiguration',
        severity: active.length > 0 ? 'medium' : 'low',
        title: 'Mixed content is loaded over HTTP',
        description: `${page.mixedContent.length} resource(s) are loaded over HTTP from an HTTPS page${active.length > 0 ? `, including ${active.length} active resource(s)` : ''}. Browsers may block these or expose them to tampering.`,
        evidence: page.mixedContent.slice(0, 10).map((m) => `${m.kind}: ${m.url}`),
        affected: page.finalUrl ?? page.url,
        confidence: 'high',
        verified: true,
        remediation: 'Serve every asset over HTTPS and update hard-coded http:// URLs.',
        sourceTools: ['page-recon'],
        playbookKey: 'mixed-content',
      });
    }
    if (page.missingSri.length > 0) {
      findings.push({
        id: nextId(),
        category: 'misconfiguration',
        severity: 'low',
        title: 'Third-party scripts/styles lack Subresource Integrity',
        description: `${page.missingSri.length} cross-origin script or stylesheet resource(s) do not use an integrity attribute, so a compromised CDN could alter the code.`,
        evidence: page.missingSri.slice(0, 10).map((m) => `${m.kind}: ${m.url}`),
        affected: page.finalUrl ?? page.url,
        confidence: 'high',
        verified: true,
        remediation: 'Add integrity and crossorigin attributes to third-party scripts/styles where the provider supports SRI.',
        sourceTools: ['page-recon'],
        playbookKey: 'missing-sri',
      });
    }
  }

  const crawl = input.crawlRules;
  if (crawl && crawl.robots.found && crawl.robots.sensitiveDisallows.length > 0) {
    findings.push({
      id: nextId(),
      category: 'exposure',
      severity: 'informational',
      title: 'robots.txt discloses sensitive-looking paths',
      description: `robots.txt disallows paths that suggest administrative or sensitive areas: ${crawl.robots.sensitiveDisallows.slice(0, 8).join(', ')}.`,
      evidence: crawl.robots.sensitiveDisallows.slice(0, 10).map((p) => `disallow: ${p}`),
      affected: `${input.host}/robots.txt`,
      confidence: 'medium',
      verified: true,
      remediation: 'Do not rely on robots.txt for access control. Protect sensitive paths with authentication and authorization.',
      sourceTools: ['crawl-rules'],
      playbookKey: 'robots-disclosure',
    });
  }

  const security = input.securityTxt;
  if (security?.found === false && !security.error) {
    findings.push({
      id: nextId(),
      category: 'informational',
      severity: 'informational',
      title: 'No security.txt vulnerability disclosure policy',
      description: 'No RFC 9116 security.txt file was found, so researchers have no published channel for reporting vulnerabilities.',
      evidence: ['security.txt: not found'],
      affected: `${input.host}/.well-known/security.txt`,
      confidence: 'high',
      verified: true,
      remediation: 'Publish /.well-known/security.txt with a Contact and Expires field.',
      sourceTools: ['security-txt'],
      playbookKey: 'security-txt',
    });
  }

  // --- Domain hardening -------------------------------------------------
  const dnsHardening = input.dnsHardening;
  if (dnsHardening && !dnsHardening.error) {
    if (dnsHardening.caa.length === 0) {
      findings.push({
        id: nextId(),
        category: 'misconfiguration',
        severity: 'low',
        title: 'No CAA records published',
        description: 'The domain does not restrict which certificate authorities may issue certificates for it.',
        evidence: ['caa: missing'],
        affected: dnsHardening.domain,
        confidence: 'high',
        verified: true,
        remediation: 'Publish CAA records listing your certificate authority (and an iodef contact).',
        sourceTools: ['dns-hardening'],
        playbookKey: 'caa-missing',
      });
    }
    const dmarc = dnsHardening.dmarc;
    if (dmarc?.present && (!input.email || input.email.error) && dmarc.policy === 'none') {
      findings.push({
        id: nextId(),
        category: 'misconfiguration',
        severity: 'medium',
        title: 'DMARC policy is monitoring-only (p=none)',
        description: 'A DMARC record exists but the enforcement policy is p=none, so spoofed mail is still delivered.',
        evidence: ['dmarc: p=none'],
        affected: dnsHardening.domain,
        confidence: 'high',
        verified: true,
        remediation: 'Review aggregate reports, then raise the policy to quarantine and eventually reject.',
        sourceTools: ['dns-hardening'],
        playbookKey: 'dmarc-none',
      });
    }
    if (dmarc?.present && !dnsHardening.dkim.some((d) => d.found && !d.revoked)) {
      findings.push({
        id: nextId(),
        category: 'misconfiguration',
        severity: 'medium',
        title: 'No DKIM key found for common selectors',
        description: `DMARC is published but no DKIM key was found on common selectors (${dnsHardening.dkim.map((d) => d.selector).join(', ')}). This may mean a non-standard selector is in use.`,
        evidence: dnsHardening.dkim.slice(0, 8).map((d) => `selector ${d.selector}: ${d.found ? 'found' : 'not found'}`),
        affected: dnsHardening.domain,
        confidence: 'medium',
        verified: true,
        remediation: 'Confirm which DKIM selector your mail provider uses and publish the corresponding public key.',
        sourceTools: ['dns-hardening'],
        playbookKey: 'dkim-missing',
      });
    }
  }

  const dnssec = input.dnssec;
  if (dnssec && !dnssec.error && !dnssec.signed) {
    findings.push({
      id: nextId(),
      category: 'misconfiguration',
      severity: 'low',
      title: 'DNSSEC is not enabled',
      description: 'No DNSKEY records were returned for the domain, so DNS answers are not cryptographically signed.',
      evidence: ['dnskey: none', 'ds: none'],
      affected: input.host,
      confidence: 'high',
      verified: true,
      remediation: 'Enable DNSSEC at the registrar and DNS provider, then publish the DS record.',
      sourceTools: ['dnssec'],
      playbookKey: 'dnssec-missing',
    });
  }

  // --- Infrastructure intel --------------------------------------------
  const intel = input.ipIntel;
  if (intel && !intel.error && (intel.waf || intel.cdn || intel.ips.length > 0)) {
    const parts: string[] = [];
    if (intel.waf) parts.push(`WAF: ${intel.waf.name}`);
    if (intel.cdn) parts.push(`CDN: ${intel.cdn.name}`);
    const first = intel.ips[0];
    if (first?.asn || first?.org) parts.push(`network: ${[first.asn, first.org].filter(Boolean).join(' ')}`);
    findings.push({
      id: nextId(),
      category: 'informational',
      severity: 'informational',
      title: 'Hosting and edge infrastructure identified',
      description: parts.length > 0 ? `The target appears to be served through ${parts.join('; ')}.` : 'Hosting metadata was collected for the resolved IP addresses.',
      evidence: [
        ...(intel.waf ? intel.waf.evidence.map((e) => `waf: ${e}`) : []),
        ...(intel.cdn ? intel.cdn.evidence.map((e) => `cdn: ${e}`) : []),
        ...intel.ips.slice(0, 2).map((ip) => `ip: ${ip.ip}${ip.ptr ? ` (${ip.ptr})` : ''}${ip.asn ? ` ${ip.asn}` : ''}`),
      ],
      affected: input.host,
      confidence: 'medium',
      verified: false,
      remediation: null,
      sourceTools: ['ip-intel'],
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
