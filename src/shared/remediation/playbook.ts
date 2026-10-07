import type { Finding, ReportModel } from '../types';
import { detectWebStack, getVariant, PLAYBOOKS, type PlaybookEntry, type PlaybookVariant } from './catalog';

export interface PlaybookItem {
  finding: Finding;
  entry: PlaybookEntry;
  variant: PlaybookVariant;
}

/** True when the scan ran with the remediation-playbook premium module. */
export function playbookEnabled(report: ReportModel): boolean {
  return (report.meta.modules ?? []).includes('remediation-playbook');
}

/** Resolve the detected stack and match each actionable finding to its playbook. */
export function collectPlaybook(report: ReportModel): PlaybookItem[] {
  const stack = detectWebStack({
    technologies: report.technologies,
    serverBanner: report.http?.server ?? null,
    poweredBy: report.http?.poweredBy ?? null,
    wordpressDetected: report.wordpress?.detected ?? false,
  });
  const items: PlaybookItem[] = [];
  for (const finding of report.findings) {
    if (!finding.playbookKey) continue;
    const entry = PLAYBOOKS[finding.playbookKey];
    if (!entry) continue;
    items.push({ finding, entry, variant: getVariant(entry, stack) });
  }
  return items;
}

const EFFORT_ORDER: Record<PlaybookVariant['effort'], number> = { S: 0, M: 1, L: 2 };

export interface RoadmapWindow {
  window: string;
  goal: string;
  items: PlaybookItem[];
}

/** Prioritized 30-day remediation roadmap: urgent+quick first. */
export function roadmapFor(items: PlaybookItem[]): RoadmapWindow[] {
  const actionable = items.filter((i) => i.finding.severity !== 'informational');
  const bySeverity = new Map<string, PlaybookItem[]>();
  for (const item of actionable) {
    const key = item.finding.severity;
    if (!bySeverity.has(key)) bySeverity.set(key, []);
    bySeverity.get(key)!.push(item);
  }
  const sortEffort = (arr: PlaybookItem[]) => [...arr].sort((a, b) => EFFORT_ORDER[a.variant.effort] - EFFORT_ORDER[b.variant.effort]);
  const critHigh = sortEffort(bySeverity.get('critical') ?? []).concat(sortEffort(bySeverity.get('high') ?? []));
  const week1 = critHigh.filter((i) => i.variant.effort === 'S');
  const week2 = critHigh.filter((i) => i.variant.effort !== 'S');
  const med = sortEffort(bySeverity.get('medium') ?? []);
  const low = sortEffort(bySeverity.get('low') ?? []);
  const windows: RoadmapWindow[] = [];
  if (week1.length > 0) windows.push({ window: 'Week 1 — quick wins', goal: 'Eliminate the highest-severity issues that take a day or less to fix.', items: week1 });
  if (week2.length > 0) windows.push({ window: 'Week 2 — urgent structural', goal: 'Close the remaining high/critical gaps that need changes or coordination.', items: week2 });
  if (med.length > 0) windows.push({ window: 'Week 3 — medium findings', goal: 'Fix medium-severity items before they compound.', items: med });
  if (low.length > 0) windows.push({ window: 'Week 4 — polish & prevention', goal: 'Low-severity hardening plus process changes (monitoring, renewal automation, patch cadence) so the next scan comes back cleaner.', items: low });
  return windows;
}

export function toolLabel(tool: string): string {
  switch (tool) {
    case 'nmap': return 'Nmap';
    case 'whatweb': return 'WhatWeb';
    case 'wpscan': return 'WPScan';
    case 'http': return 'HTTP header check';
    case 'tls': return 'TLS inspection';
    case 'subfinder': return 'Subfinder';
    case 'dnsx': return 'DNS records';
    case 'rdap': return 'RDAP/WHOIS';
    case 'email': return 'Email & DNS posture';
    case 'nuclei': return 'Nuclei';
    case 'httpx': return 'httpx';
    case 'retire': return 'Retire.js';
    case 'testssl': return 'testssl.sh';
    case 'feroxbuster': return 'Feroxbuster';
    case 'waybackurls': return 'Wayback Machine';
    case 'osv': return 'OSV';
    default: return tool;
  }
}
