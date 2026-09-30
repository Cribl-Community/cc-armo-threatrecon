import { pick, type FieldStrategy } from './fields.ts';
import type { EvidenceEvent, SearchResult } from './types.ts';

export type EventCategory = 'Firewall' | 'Proxy' | 'DNS' | 'IDS' | 'Endpoint' | 'Other';
export const CATEGORY_ORDER: EventCategory[] = ['Firewall', 'Proxy', 'DNS', 'IDS', 'Endpoint', 'Other'];

/**
 * Timeline grouping is a labeling heuristic over dataset / event-type / sourcetype
 * names only. It never claims more than "this event came from a dataset named like X".
 */
const CATEGORY_RULES: [EventCategory, RegExp][] = [
  ['IDS', /\b(ids|ips|suricata|snort|alert|notice|intrusion)/],
  ['DNS', /\b(dns|bind|named|query|resolver)/],
  ['Proxy', /\b(proxy|squid|zscaler|bluecoat|web|http|swg)/],
  ['Firewall', /\b(firewall|fw|pan|palo|asa|fortigate|fortinet|netflow|vpc|flow|traffic|conn|connection)/],
  ['Endpoint', /\b(endpoint|edr|sysmon|windows|wineventlog|crowdstrike|defender|process|linux|audit)/],
];

export function categorize(e: EvidenceEvent, strategy: FieldStrategy): EventCategory {
  const hay = `${e.dataset} ${pick(e.fields, strategy.eventType) ?? ''} ${String(e.fields.sourcetype ?? '')}`.toLowerCase().replace(/[_\-.]/g, ' ');
  for (const [cat, re] of CATEGORY_RULES) if (re.test(hay)) return cat;
  return 'Other';
}

export interface Ranked {
  value: string;
  count: number;
}

const rank = (values: (string | null)[], top = 5): Ranked[] => {
  const m = new Map<string, number>();
  for (const v of values) if (v) m.set(v, (m.get(v) ?? 0) + 1);
  return [...m.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, top)
    .map(([value, count]) => ({ value, count }));
};

const distinct = (values: (string | null)[]) => new Set(values.filter(Boolean)).size;

export interface EvidenceSummary {
  events: number;
  totalEvents: number;
  truncated: boolean;
  firstSeen: number | null;
  lastSeen: number | null;
  datasets: Ranked[];
  datasetCount: number;
  sourceHosts: Ranked[];
  sourceHostCount: number;
  destinations: Ranked[];
  users: Ranked[];
  userCount: number;
  eventTypes: Ranked[];
  matchedFields: Ranked[];
  categories: { category: EventCategory; count: number }[];
}

export function summarize(result: SearchResult, s: FieldStrategy): EvidenceSummary {
  const ev = result.events;
  const times = ev.map((e) => e.time).filter((t) => Number.isFinite(t));
  const hosts = ev.map((e) => pick(e.fields, s.sourceHost));
  const users = ev.map((e) => pick(e.fields, s.user));
  const cats = new Map<EventCategory, number>();
  for (const e of ev) {
    const c = categorize(e, s);
    cats.set(c, (cats.get(c) ?? 0) + 1);
  }
  return {
    events: ev.length,
    totalEvents: Math.max(result.totalEvents, ev.length),
    truncated: result.truncated,
    firstSeen: times.length ? Math.min(...times) : null,
    lastSeen: times.length ? Math.max(...times) : null,
    datasets: rank(ev.map((e) => e.dataset), 10),
    datasetCount: distinct(ev.map((e) => e.dataset)),
    sourceHosts: rank(hosts),
    sourceHostCount: distinct(hosts),
    destinations: rank(ev.map((e) => pick(e.fields, s.destinationHost) ?? pick(e.fields, s.destinationIp))),
    users: rank(users),
    userCount: distinct(users),
    eventTypes: rank(ev.map((e) => pick(e.fields, s.eventType))),
    matchedFields: rank(ev.flatMap((e) => e.matchedFields), 10),
    categories: CATEGORY_ORDER.filter((c) => cats.has(c)).map((category) => ({ category, count: cats.get(category)! })),
  };
}

// ── Evidence table columns: only those with at least one value ─────────
export interface Column {
  key: string;
  label: string;
  get: (e: EvidenceEvent) => string | null;
}

export function evidenceColumns(events: EvidenceEvent[], s: FieldStrategy): Column[] {
  const candidates: Column[] = [
    { key: 'sourceHost', label: 'Source Host', get: (e) => pick(e.fields, s.sourceHost) },
    { key: 'eventType', label: 'Event Type', get: (e) => pick(e.fields, s.eventType) },
    { key: 'sourceIp', label: 'Source IP', get: (e) => pick(e.fields, s.sourceIp) },
    { key: 'destinationIp', label: 'Destination IP', get: (e) => pick(e.fields, s.destinationIp) },
    { key: 'destinationPort', label: 'Destination Port', get: (e) => pick(e.fields, s.destinationPort) },
    { key: 'user', label: 'User', get: (e) => pick(e.fields, s.user) },
    { key: 'details', label: 'Details', get: (e) => pick(e.fields, s.details) },
  ];
  return candidates.filter((c) => events.some((e) => c.get(e) !== null));
}

// ── Timeline buckets ──────────────────────────────────────────────────
export interface TimelineBucket {
  start: number;
  end: number;
  counts: Partial<Record<EventCategory, number>>;
  total: number;
  eventIds: string[];
}

export function bucketize(events: EvidenceEvent[], startMs: number, endMs: number, s: FieldStrategy, buckets = 96): TimelineBucket[] {
  const span = Math.max(1, endMs - startMs);
  const size = span / buckets;
  const out: TimelineBucket[] = Array.from({ length: buckets }, (_, i) => ({ start: startMs + i * size, end: startMs + (i + 1) * size, counts: {}, total: 0, eventIds: [] }));
  for (const e of events) {
    if (e.time < startMs || e.time > endMs) continue;
    const i = Math.min(buckets - 1, Math.floor((e.time - startMs) / size));
    const c = categorize(e, s);
    out[i].counts[c] = (out[i].counts[c] ?? 0) + 1;
    out[i].total += 1;
    out[i].eventIds.push(e.id);
  }
  return out;
}

// ── Relationship graph: only co-occurring values from actual events ────
export interface RelNode {
  id: string;
  kind: 'ioc' | 'host' | 'user' | 'dataset' | 'destination';
  label: string;
  count: number;
}
export interface RelEdge {
  from: string;
  to: string;
  count: number;
}

export function relationships(iocValue: string, events: EvidenceEvent[], s: FieldStrategy, perColumn = 5) {
  const top = (kind: RelNode['kind'], get: (e: EvidenceEvent) => string | null) =>
    rank(events.map(get), perColumn).map((r) => ({ id: `${kind}:${r.value}`, kind, label: r.value, count: r.count }) as RelNode);
  const hostOf = (e: EvidenceEvent) => pick(e.fields, s.sourceHost);
  const userOf = (e: EvidenceEvent) => pick(e.fields, s.user);
  const destOf = (e: EvidenceEvent) => pick(e.fields, s.destinationHost) ?? pick(e.fields, s.destinationIp);
  const columns = {
    host: top('host', hostOf),
    user: top('user', userOf),
    dataset: top('dataset', (e) => e.dataset),
    destination: top('destination', (e) => {
      const d = destOf(e);
      return d && d !== iocValue ? d : null;
    }),
  };
  const known = new Set(['ioc', ...Object.values(columns).flat().map((n) => n.id)]);
  const edgeCounts = new Map<string, number>();
  const link = (a: string | null, b: string | null) => {
    if (!a || !b || !known.has(a) || !known.has(b)) return;
    const k = `${a}→${b}`;
    edgeCounts.set(k, (edgeCounts.get(k) ?? 0) + 1);
  };
  for (const e of events) {
    const h = hostOf(e) ? `host:${hostOf(e)}` : null;
    const u = userOf(e) ? `user:${userOf(e)}` : null;
    const d = `dataset:${e.dataset}`;
    const dst = destOf(e) && destOf(e) !== iocValue ? `destination:${destOf(e)}` : null;
    link('ioc', h ?? u ?? d);
    link(h, u ?? d);
    link(u, d);
    link(d, dst);
  }
  const edges: RelEdge[] = [...edgeCounts.entries()].map(([k, count]) => {
    const [from, to] = k.split('→');
    return { from, to, count };
  });
  return { columns, edges };
}
