export type ScanProfile = 'quick' | 'standard' | 'deep' | 'custom';

export type PortScope = 'common' | 'top100' | 'top1000';

export type ToolName =
  | 'nmap'
  | 'whatweb'
  | 'wpscan'
  | 'http'
  | 'tls'
  | 'subfinder'
  | 'dnsx'
  | 'rdap'
  | 'email'
  | 'nuclei'
  | 'httpx'
  | 'retire'
  | 'testssl'
  | 'feroxbuster'
  | 'waybackurls'
  | 'osv'
  | 'crawl-rules'
  | 'security-txt'
  | 'page-recon'
  | 'header-posture'
  | 'dns-hardening'
  | 'dnssec'
  | 'ip-intel';

/** Paid add-on modules. Each maps to a set of tools and is env-gated. */
export type ModuleId =
  | 'asset-discovery'
  | 'vuln-scan'
  | 'tls-hardening'
  | 'content-discovery'
  | 'cve-context'
  | 'remediation-playbook'
  | 'web-trust'
  | 'domain-hardening'
  | 'infra-intel';

export type JobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

export type TargetKind = 'url' | 'hostname' | 'ipv4' | 'ipv6';

export interface NormalizedTarget {
  kind: TargetKind;
  /** Host portion: hostname, or the normalized IP string. */
  host: string;
  /** Supplied path (defaults to "/"); used only for web-level checks. */
  path: string;
  /** Scheme used for web-level checks (from explicit URL or defaulted). */
  scheme: 'http' | 'https';
  /** Original user input, trimmed. */
  raw: string;
  /** Canonical display string, e.g. "https://example.com/app". */
  display: string;
  /** Whether this target was supplied as a bare IP. */
  isIp: boolean;
}

export interface CustomScanOptions {
  portScope: PortScope;
  enabledTools: ToolName[];
  path: string;
  followRedirects: boolean;
  userAgent: string;
  timeoutMs: number;
}

export interface ScanRequestInput {
  target: string;
  profile: ScanProfile;
  consent: boolean;
  custom?: CustomScanOptions;
  /** Paid add-on modules requested for this scan. */
  modules?: ModuleId[];
}

export type CorroborationLevel = 'single' | 'multi' | 'conflicting';

/** Cross-tool validation state for a finding. */
export interface Corroboration {
  level: CorroborationLevel;
  /** Tools whose independent observations agree with this finding. */
  supporting: ToolName[];
  /** Human-readable notes where tools disagree (or failed to confirm). */
  conflicting: string[];
}

export interface Finding {
  id: string;
  category: 'exposure' | 'misconfiguration' | 'outdated-technology' | 'wordpress' | 'vulnerability' | 'informational';
  severity: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  evidence: string[];
  affected: string | null;
  confidence: 'high' | 'medium' | 'low';
  verified: boolean;
  remediation: string | null;
  /** Tools that contributed evidence to this finding. */
  sourceTools?: ToolName[];
  /** Cross-tool validation result; set by the findings builder. */
  corroboration?: Corroboration;
  /** Key into the remediation playbook catalog. */
  playbookKey?: string;
}

export interface DiscoveredPort {
  port: number;
  state: string;
  protocol: string;
  service: string;
  version: string;
}

export interface HttpObservation {
  status: number | null;
  finalUrl: string | null;
  server: string | null;
  poweredBy: string | null;
  headers: Record<string, string>;
  redirects: Array<{ status: number; to: string }>;
  error: string | null;
}

export interface TlsObservation {
  connected: boolean;
  protocol: string | null;
  subjectCn: string | null;
  issuerCn: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  selfSigned: boolean;
  /** ALPN protocol negotiated during the handshake (e.g. h2 or http/1.1). */
  alpnProtocol?: string | null;
  error: string | null;
}

export interface ToolResultRecord {
  tool: ToolName;
  label: string;
  ok: boolean;
  timedOut: boolean;
  exitCode: number | null;
  error: string | null;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
}

export interface ToolVersion {
  tool: string;
  version: string | null;
}

export interface ReportMeta {
  target: string;
  host: string;
  path: string;
  profile: ScanProfile;
  portScope: PortScope | null;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  toolVersions: ToolVersion[];
  status: 'completed' | 'partial';
  warnings: string[];
  /** Paid modules enabled for this scan (drives playbook/teaser rendering). */
  modules?: ModuleId[];
}

// --- Paid module observation types -----------------------------------------

export interface DiscoveredSubdomain {
  host: string;
  source: string | null;
}

export interface DnsRecord {
  type: string;
  name: string;
  value: string;
}

export interface WhoisInfo {
  registrar: string | null;
  creationDate: string | null;
  updateDate: string | null;
  expiryDate: string | null;
  status: string[];
  nameservers: string[];
  error: string | null;
}

export interface VulnerabilityFinding {
  id: string;
  templateId: string | null;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  matchedAt: string | null;
  source: 'nuclei' | 'retire';
}

export interface TlsHardeningResult {
  finished: boolean;
  summary: string[];
  weaknesses: Array<{ name: string; detail: string; severity: string }>;
  error: string | null;
}

export interface DiscoveredPath {
  path: string;
  status: number;
  size: number | null;
  contentType: string | null;
}

export interface CveContextFinding {
  id: string;
  ecosystem: string;
  name: string;
  version: string;
  cveCount: number;
  severities: Record<string, number>;
}

/** Second-source HTTP surface observation produced by httpx. */
export interface HttpxObservation {
  url: string;
  status: number | null;
  finalUrl: string | null;
  server: string | null;
  headers: Record<string, string>;
  cookies: Array<{ name: string; secure: boolean; httpOnly: boolean }>;
  tlsVersion: string | null;
  certExpiry: string | null;
  technologies: string[];
  error: string | null;
}

export type ArchivedUrlCategory = 'sensitive-path' | 'credential-in-url' | 'other';

/** A URL the Wayback Machine has stored for the target host. */
export interface ArchivedUrl {
  url: string;
  path: string;
  category: ArchivedUrlCategory;
  /** Query parameter name that leaked a credential (value never stored). */
  tokenParam: string | null;
  /** Whether the URL still answers today (live re-verification). */
  live: boolean;
}

export interface EmailPostureResult {
  domain: string;
  /** SPF TXT records found on the domain (RFC requires at most one). */
  spfRecords: string[];
  /** DMARC TXT records found on _dmarc.<domain>. */
  dmarcRecords: string[];
  mx: Array<{ host: string; priority: number }>;
  /** MTA-STS policy id TXT (_mta-sts.<domain>), if any. */
  mtaSts: string | null;
  /** TLS reporting policy (_smtp._tls.<domain>), if any. */
  tlsRpt: string | null;
  starttls: { checked: boolean; mx: string | null; supported: boolean | null; error: string | null };
  error: string | null;
}

// --- Web trust module observations -----------------------------------------

export interface CrawlRuleGroup {
  userAgents: string[];
  allow: string[];
  disallow: string[];
}

export interface CrawlRulesResult {
  robots: {
    found: boolean;
    url: string | null;
    status: number | null;
    groups: CrawlRuleGroup[];
    sitemaps: string[];
    aiBots: Array<{ name: string; allowed: boolean }>;
    sensitiveDisallows: string[];
    error: string | null;
  };
  sitemap: {
    found: boolean;
    urls: string[];
    urlCount: number;
    sitemapCount: number;
    error: string | null;
  };
  error: string | null;
}

export interface SecurityTxtResult {
  found: boolean;
  url: string | null;
  status: number | null;
  contacts: string[];
  expires: string | null;
  policy: string | null;
  encryption: string | null;
  acknowledgments: string | null;
  preferredLanguages: string | null;
  error: string | null;
}

export interface PageMetadata {
  title: string | null;
  description: string | null;
  canonical: string | null;
  language: string | null;
  generator: string | null;
  og: Record<string, string>;
  twitter: Record<string, string>;
}

export interface PageAssetIssue {
  url: string;
  kind: string;
}

export interface ThirdPartyDomain {
  host: string;
  category: string;
  count: number;
}

export interface PageReconResult {
  url: string;
  status: number | null;
  finalUrl: string | null;
  contentType: string | null;
  metadata: PageMetadata;
  links: { internal: number; external: number; total: number; samples: string[] };
  mixedContent: PageAssetIssue[];
  missingSri: PageAssetIssue[];
  thirdParties: ThirdPartyDomain[];
  error: string | null;
}

export interface HstsAnalysis {
  present: boolean;
  value: string | null;
  maxAge: number | null;
  includeSubDomains: boolean;
  preload: boolean;
}

export interface CspAnalysis {
  present: boolean;
  reportOnly: boolean;
  value: string | null;
  directives: Record<string, string[]>;
  unsafeInline: boolean;
  unsafeEval: boolean;
  wildcard: boolean;
  missingObjectSrc: boolean;
  missingBaseUri: boolean;
}

export interface CookieObservation {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  expires: string | null;
  maxAge: number | null;
}

export interface HeaderPostureResult {
  hsts: HstsAnalysis;
  csp: CspAnalysis | null;
  cookies: CookieObservation[];
  alpnProtocol: string | null;
  httpVersionHint: string | null;
  error: string | null;
}

// --- Domain hardening module observations ----------------------------------

export interface DnsHardeningResult {
  domain: string;
  caa: Array<{ flags: number; tag: string; value: string }>;
  soa: { ns: string; hostmaster: string; serial: number; refresh: number; retry: number; expire: number; minimum: number } | null;
  srv: Array<{ name: string; port: number; priority: number; weight: number; target: string }>;
  nsAddresses: Array<{ ns: string; addresses: string[] }>;
  dkim: Array<{ selector: string; found: boolean; keyType: string | null; revoked: boolean }>;
  bimi: string | null;
  dmarc: {
    present: boolean;
    policy: string | null;
    subdomainPolicy: string | null;
    pct: number | null;
    rua: string[];
    ruf: string[];
    alignmentDkim: string | null;
    alignmentSpf: string | null;
  } | null;
  error: string | null;
}

export interface DnssecResult {
  signed: boolean;
  ad: boolean;
  dnskeyCount: number;
  dsCount: number;
  algorithms: string[];
  error: string | null;
}

// --- Infrastructure intel module observations ------------------------------

export interface IpIntelResult {
  ips: Array<{
    ip: string;
    ptr: string | null;
    country: string | null;
    region: string | null;
    city: string | null;
    asn: string | null;
    org: string | null;
    isp: string | null;
  }>;
  waf: { name: string; evidence: string[] } | null;
  cdn: { name: string; evidence: string[] } | null;
  error: string | null;
}

export interface ReportModel {
  meta: ReportMeta;
  executiveSummary: string;
  findings: Finding[];
  ports: DiscoveredPort[];
  http: HttpObservation | null;
  tls: TlsObservation | null;
  technologies: Array<{ name: string; version: string | null }>;
  wordpress: { detected: boolean; wpscanRan: boolean; notes: string[] } | null;
  subdomains: DiscoveredSubdomain[];
  dnsRecords: DnsRecord[];
  whois: WhoisInfo | null;
  vulnerabilities: VulnerabilityFinding[];
  tlsHardening: TlsHardeningResult | null;
  discoveredPaths: DiscoveredPath[];
  cveContext: CveContextFinding[];
  httpx?: HttpxObservation | null;
  archivedUrls?: ArchivedUrl[];
  email?: EmailPostureResult | null;
  crawlRules?: CrawlRulesResult | null;
  securityTxt?: SecurityTxtResult | null;
  pageRecon?: PageReconResult | null;
  headerPosture?: HeaderPostureResult | null;
  dnsHardening?: DnsHardeningResult | null;
  dnssec?: DnssecResult | null;
  ipIntel?: IpIntelResult | null;
  toolResults: ToolResultRecord[];
  limitations: string[];
}

export interface JobArtifactMeta {
  markdownBytes: number;
  pdfBytes: number;
  markdownPath: string;
  pdfPath: string;
}

export interface Job {
  id: string;
  status: JobStatus;
  target: NormalizedTarget;
  profile: ScanProfile;
  custom: CustomScanOptions | null;
  modules: ModuleId[];
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  error: string | null;
  report: ReportModel | null;
  artifacts: JobArtifactMeta | null;
}

export interface PublicJobView {
  id: string;
  status: JobStatus;
  profile: ScanProfile;
  target: string;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  error: string | null;
  hasArtifacts: boolean;
  summaryCounts: { critical: number; high: number; medium: number; low: number; informational: number } | null;
}

/** Severity roll-up persisted with scan history. */
export interface FindingCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

/** Compact per-tool timing record persisted for scan analytics. */
export interface ScanToolTiming {
  tool: string;
  ok: boolean;
  timedOut: boolean;
  exitCode: number | null;
  durationMs: number;
}

/** Metadata-only finding summary used for scan-to-scan change detection. */
export interface ScanFindingSummary {
  fingerprint: string;
  title: string;
  severity: Finding['severity'];
  category: Finding['category'];
  affected: string | null;
  sourceTools: ToolName[];
}

export type ScheduleFrequency = 'daily' | 'weekly';
export type ScheduleAlertThreshold = 'off' | 'high' | 'medium' | 'all';

export interface ScheduledScan {
  id: number;
  userId: number;
  userEmail: string | null;
  target: string;
  host: string;
  path: string;
  scheme: 'http' | 'https';
  profile: ScanProfile;
  custom: CustomScanOptions | null;
  modules: ModuleId[];
  frequency: ScheduleFrequency;
  hourUtc: number;
  minuteUtc: number;
  dayOfWeek: number | null;
  alertMinSeverity: ScheduleAlertThreshold;
  alertOnFailure: boolean;
  enabled: boolean;
  consentAt: string;
  nextRunAt: string;
  lastAttemptAt: string | null;
  lastRunAt: string | null;
  lastScanId: string | null;
  lastAlertScanId: string | null;
  lastAlertAt: string | null;
  lastError: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface ScanRisk {
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
}

export interface FindingSeverityChange {
  finding: ScanFindingSummary;
  from: Finding['severity'];
  to: Finding['severity'];
}

export interface ScanDiff {
  currentScanId: string;
  previousScanId: string | null;
  newFindings: ScanFindingSummary[];
  resolvedFindings: ScanFindingSummary[];
  notAssessed: ScanFindingSummary[];
  severityChanges: FindingSeverityChange[];
  unchangedCount: number;
  risk: ScanRisk;
  previousRisk: ScanRisk | null;
  riskDelta: number | null;
}

/**
 * Completion summary the worker posts to the web so long-term scan history can
 * be recorded. Reports themselves are never sent or stored - only metadata.
 */
export interface ScanEventPayload {
  scanId: string;
  status: 'completed' | 'failed' | 'cancelled';
  targetRaw: string;
  host: string;
  path: string;
  scheme: string;
  profile: string;
  portScope: string | null;
  modules: string[];
  resolvedIps: string[];
  ipVersion: 'ipv4' | 'ipv6' | 'mixed' | null;
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  portCount: number;
  findings: FindingCounts;
  /** Metadata-only summaries used for diffs; omitted by older workers. */
  findingsDetail?: ScanFindingSummary[];
  tools: ScanToolTiming[];
  toolOk: number;
  toolTotal: number;
  error: string | null;
}
