import type { NormalizedTarget, PageAssetIssue, PageMetadata, PageReconResult, ThirdPartyDomain } from '../shared/types';
import { formatHostForUrl } from '../shared/net';
import type { DnsResolver } from './dns';
import { safeFetchText } from './safe-fetch';

export interface PageReconDeps {
  resolver?: DnsResolver;
  userAgent?: string;
  signal?: AbortSignal;
  fetchText?: typeof safeFetchText;
}

export interface PageReconOutput {
  result: PageReconResult;
  headers: Record<string, string>;
  setCookies: string[];
}

const TRACKERS: Array<{ host: string; category: string }> = [
  { host: 'google-analytics.com', category: 'analytics' },
  { host: 'googletagmanager.com', category: 'tag-manager' },
  { host: 'doubleclick.net', category: 'advertising' },
  { host: 'googlesyndication.com', category: 'advertising' },
  { host: 'facebook.net', category: 'advertising' },
  { host: 'facebook.com', category: 'social' },
  { host: 'hotjar.com', category: 'analytics' },
  { host: 'segment.com', category: 'analytics' },
  { host: 'mixpanel.com', category: 'analytics' },
  { host: 'amplitude.com', category: 'analytics' },
  { host: 'clarity.ms', category: 'analytics' },
  { host: 'tiktok.com', category: 'advertising' },
  { host: 'linkedin.com', category: 'social' },
  { host: 'twitter.com', category: 'social' },
  { host: 'x.com', category: 'social' },
  { host: 'hubspot.com', category: 'marketing' },
  { host: 'intercom.io', category: 'support' },
  { host: 'criteo.com', category: 'advertising' },
  { host: 'taboola.com', category: 'advertising' },
  { host: 'outbrain.com', category: 'advertising' },
];

function attrMap(tag: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(tag)) !== null) {
    out[match[1].toLowerCase()] = match[2] ?? match[3] ?? match[4] ?? '';
  }
  return out;
}

function tags(html: string, name: string): string[] {
  const re = new RegExp(`<${name}\\b[^>]*>`, 'gi');
  const out: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) !== null) out.push(match[0]);
  return out;
}

function textOf(html: string, name: string): string | null {
  const re = new RegExp(`<${name}\\b[^>]*>([\\s\\S]*?)<\\/${name}>`, 'i');
  const match = re.exec(html);
  return match ? match[1].replace(/\s+/g, ' ').trim().slice(0, 500) : null;
}

function resolveUrl(value: string, base: URL): URL | null {
  try {
    const url = new URL(value, base);
    return url.protocol === 'http:' || url.protocol === 'https:' ? url : null;
  } catch {
    return null;
  }
}

function trackerCategory(host: string): string | null {
  const lower = host.toLowerCase();
  for (const entry of TRACKERS) {
    if (lower === entry.host || lower.endsWith(`.${entry.host}`)) return entry.category;
  }
  return null;
}

function parseMetadata(html: string, base: URL): PageMetadata {
  const meta: PageMetadata = {
    title: textOf(html, 'title'),
    description: null,
    canonical: null,
    language: null,
    generator: null,
    og: {},
    twitter: {},
  };
  for (const tag of tags(html, 'meta')) {
    const attrs = attrMap(tag);
    const content = attrs.content ?? '';
    const name = (attrs.name ?? '').toLowerCase();
    const property = (attrs.property ?? '').toLowerCase();
    if (name === 'description' && !meta.description) meta.description = content.slice(0, 500);
    if (name === 'generator' && !meta.generator) meta.generator = content.slice(0, 200);
    if (property.startsWith('og:') && content) meta.og[property.slice(3)] = content.slice(0, 500);
    if (name.startsWith('twitter:') && content) meta.twitter[name.slice(8)] = content.slice(0, 500);
  }
  for (const tag of tags(html, 'html')) {
    const attrs = attrMap(tag);
    if (attrs.lang) meta.language = attrs.lang.slice(0, 40);
    break;
  }
  for (const tag of tags(html, 'link')) {
    const attrs = attrMap(tag);
    if ((attrs.rel ?? '').toLowerCase().split(/\s+/).includes('canonical') && attrs.href) {
      const resolved = resolveUrl(attrs.href, base);
      meta.canonical = resolved ? resolved.toString() : attrs.href.slice(0, 500);
      break;
    }
  }
  return meta;
}

export async function pageReconLookup(target: NormalizedTarget, deps: PageReconDeps = {}): Promise<PageReconOutput> {
  const fetchText = deps.fetchText ?? safeFetchText;
  const url = new URL(`${target.scheme}://${formatHostForUrl(target.host)}${target.path}`);
  const result: PageReconResult = {
    url: url.toString(),
    status: null,
    finalUrl: null,
    contentType: null,
    metadata: { title: null, description: null, canonical: null, language: null, generator: null, og: {}, twitter: {} },
    links: { internal: 0, external: 0, total: 0, samples: [] },
    mixedContent: [],
    missingSri: [],
    thirdParties: [],
    error: null,
  };

  try {
    const res = await fetchText(url, {
      resolver: deps.resolver,
      userAgent: deps.userAgent,
      signal: deps.signal,
      maxBytes: 1024 * 1024,
      timeoutMs: 12_000,
      accept: 'text/html,application/xhtml+xml,*/*',
    });
    result.status = res.status;
    result.finalUrl = res.finalUrl;
    result.contentType = res.headers['content-type'] ?? null;
    if (res.status < 200 || res.status >= 300) {
      result.error = `HTTP ${res.status}`;
      return { result, headers: res.headers, setCookies: res.setCookies };
    }
    const base = new URL(res.finalUrl);
    const firstParty = base.hostname.toLowerCase();
    const isHttps = base.protocol === 'https:';
    result.metadata = parseMetadata(res.body, base);

    const internalSamples: string[] = [];
    const externalSamples: string[] = [];
    for (const tag of tags(res.body, 'a')) {
      const attrs = attrMap(tag);
      if (!attrs.href) continue;
      const link = resolveUrl(attrs.href, base);
      if (!link) continue;
      result.links.total += 1;
      if (link.hostname.toLowerCase() === firstParty) {
        result.links.internal += 1;
        if (internalSamples.length < 10) internalSamples.push(link.toString());
      } else {
        result.links.external += 1;
        if (externalSamples.length < 10) externalSamples.push(link.toString());
      }
    }
    result.links.samples = [...internalSamples, ...externalSamples];

    const thirdPartyCounts = new Map<string, { category: string; count: number }>();
    const assetIssue = (issues: PageAssetIssue[], kind: string, asset: URL) => {
      if (issues.length < 25) issues.push({ url: asset.toString().slice(0, 500), kind });
    };
    const considerAsset = (value: string, kind: string, integrity: string | undefined) => {
      const asset = resolveUrl(value, base);
      if (!asset) return;
      if (isHttps && asset.protocol === 'http:') assetIssue(result.mixedContent, kind, asset);
      if (asset.hostname.toLowerCase() !== firstParty) {
        if (!integrity && (kind === 'script' || kind === 'stylesheet')) assetIssue(result.missingSri, kind, asset);
        const category = trackerCategory(asset.hostname) ?? 'other';
        const existing = thirdPartyCounts.get(asset.hostname) ?? { category, count: 0 };
        existing.count += 1;
        thirdPartyCounts.set(asset.hostname, existing);
      }
    };

    for (const tag of tags(res.body, 'script')) {
      const attrs = attrMap(tag);
      if (attrs.src) considerAsset(attrs.src, 'script', attrs.integrity);
    }
    for (const tag of tags(res.body, 'link')) {
      const attrs = attrMap(tag);
      const rel = (attrs.rel ?? '').toLowerCase();
      if (attrs.href && rel.split(/\s+/).includes('stylesheet')) considerAsset(attrs.href, 'stylesheet', attrs.integrity);
    }
    for (const tag of tags(res.body, 'img')) {
      const attrs = attrMap(tag);
      if (attrs.src) considerAsset(attrs.src, 'image', attrs.integrity);
    }
    for (const tag of tags(res.body, 'iframe')) {
      const attrs = attrMap(tag);
      if (attrs.src) considerAsset(attrs.src, 'iframe', attrs.integrity);
    }

    const thirdParties: ThirdPartyDomain[] = [...thirdPartyCounts.entries()]
      .map(([host, v]) => ({ host, category: v.category, count: v.count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 50);
    result.thirdParties = thirdParties;

    return { result, headers: res.headers, setCookies: res.setCookies };
  } catch (e) {
    result.error = (e as Error).message;
    return { result, headers: {}, setCookies: [] };
  }
}
