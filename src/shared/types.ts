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
  | 'nuclei'
  | 'retire'
  | 'testssl'
  | 'feroxbuster'
  | 'osv';

/** Paid add-on modules. Each maps to a set of tools and is env-gated. */
export type ModuleId = 'asset-discovery' | 'vuln-scan' | 'tls-hardening' | 'content-discovery' | 'cve-context';

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
