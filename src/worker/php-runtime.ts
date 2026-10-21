import { parseRuntimeVersion } from '../shared/advisories';
import type { HttpObservation, HttpxObservation } from '../shared/types';

export interface PhpRuntimeDetection {
  present: boolean;
  version: string | null;
  source: string | null;
  sources: string[];
  confidence: 'high' | 'medium' | 'low';
}

const PHP_VERSION_RE = /php[\/\s:-]*(\d+\.\d+\.\d+)/i;
const PHP_TOKEN_RE = /(?:^|[\s,;])php(?:\b|:|\/|\s|$)/i;

function phpTechName(name: string): boolean {
  const lower = name.trim().toLowerCase();
  return lower === 'php' || lower.startsWith('php:') || lower.startsWith('php ');
}

function phpTechVersion(name: string, version: string | null): string | null {
  if (version) return version;
  const match = PHP_VERSION_RE.exec(name);
  return match ? match[1] : null;
}

/**
 * Extract a PHP version from observations the free scan already collects.
 * This is deliberately passive: headers, whatweb, and httpx tech detection.
 */
export function detectPhpRuntime(input: {
  technologies: Array<{ name: string; version: string | null }>;
  http: HttpObservation | null;
  httpx?: HttpxObservation | null;
}): PhpRuntimeDetection {
  const candidates: Array<{ version: string | null; source: string; confidence: PhpRuntimeDetection['confidence'] }> = [];
  const sources: string[] = [];

  for (const tech of input.technologies) {
    if (!phpTechName(tech.name)) continue;
    candidates.push({
      version: phpTechVersion(tech.name, tech.version),
      source: 'whatweb PHP plugin',
      confidence: 'high',
    });
    sources.push('whatweb');
  }

  const poweredBy = input.http?.poweredBy ?? input.http?.headers['x-powered-by'] ?? null;
  if (poweredBy && /php/i.test(poweredBy)) {
    candidates.push({ version: PHP_VERSION_RE.exec(poweredBy)?.[1] ?? null, source: 'X-Powered-By header', confidence: 'high' });
    sources.push('http');
  }

  const server = input.http?.server ?? input.http?.headers['server'] ?? null;
  if (server && /php/i.test(server)) {
    candidates.push({ version: PHP_VERSION_RE.exec(server)?.[1] ?? null, source: 'Server header', confidence: 'medium' });
    sources.push('http');
  }

  for (const tech of input.httpx?.technologies ?? []) {
    if (!PHP_TOKEN_RE.test(tech) && !/^php/i.test(tech.trim())) continue;
    candidates.push({
      version: PHP_VERSION_RE.exec(tech)?.[1] ?? phpTechVersion(tech, null),
      source: 'httpx tech-detect',
      confidence: 'high',
    });
    sources.push('httpx');
  }

  if (input.httpx?.cookies.some((cookie) => cookie.name.toUpperCase() === 'PHPSESSID')) {
    candidates.push({ version: null, source: 'PHPSESSID cookie', confidence: 'low' });
    sources.push('httpx');
  }

  const present = candidates.length > 0;
  if (!present) return { present: false, version: null, source: null, sources: [], confidence: 'low' };

  const withVersion = candidates.find((candidate) => candidate.version && parseRuntimeVersion(candidate.version));
  const chosen = withVersion ?? candidates[0];
  return {
    present: true,
    version: chosen.version,
    source: chosen.source,
    sources: Array.from(new Set(sources)),
    confidence: chosen.confidence,
  };
}
