export type ScanProfile = 'quick' | 'standard' | 'deep' | 'custom';

export type PortScope = 'common' | 'top100' | 'top1000';

export type ToolName = 'nmap' | 'whatweb' | 'wpscan' | 'http' | 'tls';

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
}

export interface Finding {
  id: string;
  category: 'exposure' | 'misconfiguration' | 'outdated-technology' | 'wordpress' | 'informational';
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

export interface ReportModel {
  meta: ReportMeta;
  executiveSummary: string;
  findings: Finding[];
  ports: DiscoveredPort[];
  http: HttpObservation | null;
  tls: TlsObservation | null;
  technologies: Array<{ name: string; version: string | null }>;
  wordpress: { detected: boolean; wpscanRan: boolean; notes: string[] } | null;
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
