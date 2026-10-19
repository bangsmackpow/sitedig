import type { CrawlRuleGroup, CrawlRulesResult, NormalizedTarget } from '../shared/types';
import { formatHostForUrl } from '../shared/net';
import type { DnsResolver } from './dns';
import { safeFetchText, type SafeFetchResult } from './safe-fetch';

export interface CrawlRulesDeps {
  resolver?: DnsResolver;
  userAgent?: string;
  signal?: AbortSignal;
  fetchText?: typeof safeFetchText;
}

const AI_BOTS = ['GPTBot', 'CCBot', 'Google-Extended', 'ClaudeBot', 'PerplexityBot', 'anthropic-ai', 'Bytespider', 'Amazonbot'];
const SENSITIVE_RE = /(^|\/)(admin|api|backup|backups|\.git|\.env|private|internal|config|debug|staging|test|secret|secrets|wp-admin)(\/|$)/i;

function parseRobots(text: string): { groups: CrawlRuleGroup[]; sitemaps: string[] } {
  const groups: CrawlRuleGroup[] = [];
  const sitemaps: string[] = [];
  let current: CrawlRuleGroup | null = null;
  let expectingAgents = false;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;
    const index = line.indexOf(':');
    if (index === -1) continue;
    const key = line.slice(0, index).trim().toLowerCase();
    const value = line.slice(index + 1).trim();
    if (key === 'user-agent') {
      if (!current || !expectingAgents) {
        current = { userAgents: [], allow: [], disallow: [] };
        groups.push(current);
        expectingAgents = true;
      }
      if (value) current.userAgents.push(value);
    } else if (key === 'allow' || key === 'disallow') {
      expectingAgents = false;
      if (!current) {
        current = { userAgents: ['*'], allow: [], disallow: [] };
        groups.push(current);
      }
      if (key === 'allow') current.allow.push(value);
      else if (value) current.disallow.push(value);
    } else if (key === 'sitemap') {
      expectingAgents = false;
      if (value) sitemaps.push(value);
    }
  }
  return { groups, sitemaps };
}

function aiBotAllowed(groups: CrawlRuleGroup[], name: string): boolean {
  const exact = groups.filter((g) => g.userAgents.some((ua) => ua.toLowerCase() === name.toLowerCase()));
  const wildcard = groups.filter((g) => g.userAgents.some((ua) => ua === '*'));
  const applicable = exact.length > 0 ? exact : wildcard;
  if (applicable.length === 0) return true;
  for (const group of applicable) {
    const blocksAll = group.disallow.some((d) => d === '/' || d === '/*');
    const allowsAll = group.allow.some((a) => a === '/' || a === '/*');
    if (blocksAll && !allowsAll) return false;
  }
  return true;
}

function extractLocUrls(xml: string): string[] {
  const urls: string[] = [];
  const re = /<loc>\s*([^<\s]+)\s*<\/loc>/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(xml)) !== null && urls.length < 500) {
    urls.push(match[1]);
  }
  return urls;
}

async function fetchSitemap(
  url: URL,
  deps: CrawlRulesDeps,
  depth: number,
  state: { urls: Set<string>; sitemapCount: number; found: boolean; error: string | null },
): Promise<void> {
  if (depth > 2 || state.sitemapCount >= 5) return;
  state.sitemapCount += 1;
  try {
    const res = await deps.fetchText!(url, {
      resolver: deps.resolver,
      userAgent: deps.userAgent,
      signal: deps.signal,
      sameHostOnly: true,
      maxBytes: 512 * 1024,
      timeoutMs: 8_000,
      accept: 'application/xml,text/xml,*/*',
    });
    if (res.status < 200 || res.status >= 300) return;
    state.found = true;
    const locs = extractLocUrls(res.body);
    const isIndex = /<sitemapindex\b/i.test(res.body);
    if (isIndex) {
      for (const loc of locs.slice(0, 5)) {
        if (state.sitemapCount >= 5) break;
        try {
          const next = new URL(loc, url);
          if (next.hostname.toLowerCase() !== url.hostname.toLowerCase()) continue;
          await fetchSitemap(next, deps, depth + 1, state);
        } catch {
          // ignore malformed sitemap entry
        }
      }
      return;
    }
    for (const loc of locs) state.urls.add(loc);
  } catch (e) {
    state.error = (e as Error).message;
  }
}

export async function crawlRulesLookup(target: NormalizedTarget, deps: CrawlRulesDeps = {}): Promise<CrawlRulesResult> {
  const fetchText = deps.fetchText ?? safeFetchText;
  const base = new URL(`${target.scheme}://${formatHostForUrl(target.host)}/`);
  const result: CrawlRulesResult = {
    robots: { found: false, url: null, status: null, groups: [], sitemaps: [], aiBots: [], sensitiveDisallows: [], error: null },
    sitemap: { found: false, urls: [], urlCount: 0, sitemapCount: 0, error: null },
    error: null,
  };

  const robotsUrl = new URL('/robots.txt', base);
  result.robots.url = robotsUrl.toString();
  try {
    const res: SafeFetchResult = await fetchText(robotsUrl, {
      resolver: deps.resolver,
      userAgent: deps.userAgent,
      signal: deps.signal,
      sameHostOnly: true,
      maxBytes: 256 * 1024,
      timeoutMs: 8_000,
      accept: 'text/plain,*/*',
    });
    result.robots.status = res.status;
    if (res.status >= 200 && res.status < 300) {
      result.robots.found = true;
      const parsed = parseRobots(res.body);
      result.robots.groups = parsed.groups;
      result.robots.sitemaps = parsed.sitemaps;
      result.robots.aiBots = AI_BOTS.map((name) => ({ name, allowed: aiBotAllowed(parsed.groups, name) }));
      result.robots.sensitiveDisallows = Array.from(
        new Set(parsed.groups.flatMap((g) => g.disallow.filter((d) => SENSITIVE_RE.test(d)))),
      ).slice(0, 25);
    }
  } catch (e) {
    result.robots.error = (e as Error).message;
  }

  const candidateSitemaps = result.robots.sitemaps.length > 0 ? result.robots.sitemaps : [new URL('/sitemap.xml', base).toString()];
  const state = { urls: new Set<string>(), sitemapCount: 0, found: false, error: null as string | null };
  for (const candidate of candidateSitemaps.slice(0, 5)) {
    try {
      const url = new URL(candidate, base);
      if (url.hostname.toLowerCase() !== base.hostname.toLowerCase()) continue;
      await fetchSitemap(url, { ...deps, fetchText }, 0, state);
    } catch {
      // ignore malformed URL
    }
  }
  result.sitemap.found = state.found;
  result.sitemap.urls = Array.from(state.urls).slice(0, 500);
  result.sitemap.urlCount = state.urls.size;
  result.sitemap.sitemapCount = state.sitemapCount;
  result.sitemap.error = state.error;

  if (result.robots.error && result.sitemap.error) {
    result.error = `robots.txt: ${result.robots.error}; sitemap: ${result.sitemap.error}`;
  }
  return result;
}
