export const PAGE = {
  width: 612,
  height: 792,
  marginX: 50,
  marginTop: 78,
  marginBottom: 68,
};

export const CONTENT_WIDTH = PAGE.width - PAGE.marginX * 2;

export const FONTS = {
  body: 'Helvetica',
  semibold: 'Helvetica-Bold',
  bold: 'Helvetica-Bold',
  mono: 'Courier',
  monoBold: 'Courier-Bold',
};

export const COLORS = {
  ink: '#0F172A',
  navy: '#0B1B33',
  navySoft: '#13294B',
  accent: '#0EA5E9',
  accentSoft: '#E0F2FE',
  text: '#1E293B',
  muted: '#64748B',
  subtle: '#94A3B8',
  border: '#E2E8F0',
  surface: '#F8FAFC',
  surfaceAlt: '#F1F5F9',
  white: '#FFFFFF',
  success: '#059669',
  successSoft: '#D1FAE5',
  warn: '#D97706',
  warnSoft: '#FEF3C7',
  danger: '#DC2626',
  dangerSoft: '#FEE2E2',
  info: '#2563EB',
  infoSoft: '#DBEAFE',
  critical: '#991B1B',
  high: '#DC2626',
  medium: '#D97706',
  low: '#2563EB',
  informational: '#64748B',
};

export const SEVERITY_STYLES = {
  critical: { color: COLORS.critical, bg: '#FEE2E2', label: 'Critical' },
  high: { color: COLORS.high, bg: '#FEE2E2', label: 'High' },
  medium: { color: COLORS.medium, bg: '#FEF3C7', label: 'Medium' },
  low: { color: COLORS.low, bg: '#DBEAFE', label: 'Low' },
  informational: { color: COLORS.informational, bg: '#E2E8F0', label: 'Informational' },
} as const;

export const STATUS_STYLES = {
  pass: { color: COLORS.success, bg: COLORS.successSoft, label: 'PASS' },
  warn: { color: COLORS.warn, bg: COLORS.warnSoft, label: 'WARN' },
  fail: { color: COLORS.danger, bg: COLORS.dangerSoft, label: 'FAIL' },
  info: { color: COLORS.info, bg: COLORS.infoSoft, label: 'INFO' },
} as const;

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const minutes = Math.floor(ms / 60_000);
  const seconds = Math.round((ms % 60_000) / 1000);
  return `${minutes}m ${seconds}s`;
}

export function formatDateTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }) + ' UTC';
}

export function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, Math.max(0, max - 1))}…` : text;
}

export function cleanText(text: string): string {
  return text.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ').replace(/\s+/g, ' ').trim();
}
