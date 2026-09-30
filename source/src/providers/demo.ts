/**
 * DEMO DATA ONLY. Deterministic synthetic fixtures for presentations.
 * Every result produced here is marked `demo: true` by the runner and labelled
 * "DEMO DATA" in the UI. Nothing here is ever mixed into real provider output.
 */
import { vtGuiUrl } from '../core/virustotal.ts';
import type { EvidenceEvent, Indicator, LookupResult, SearchResult, TimeRange, VtResult } from '../core/types.ts';
import { ProviderFailure, type EvidenceLookupProvider, type ProviderContext, type ProviderSet, type SearchProvider, type ThreatIntelProvider } from './types.ts';

export interface DemoScenario {
  id: 'malicious-ip' | 'clean-ip' | 'observed-benign' | 'no-evidence';
  title: string;
  description: string;
  ioc: string;
}

/** RFC 5737 / RFC 2606 documentation values so demos never accuse a real third party. */
export const DEMO_SCENARIOS: DemoScenario[] = [
  { id: 'malicious-ip', title: 'Malicious IP', description: 'Internal C2 list match, flagged by VirusTotal, observed on 12 hosts', ioc: '203.0.113.45' },
  { id: 'clean-ip', title: 'Clean IP', description: 'Known to VirusTotal, no engine detections, not observed', ioc: '198.51.100.20' },
  { id: 'observed-benign', title: 'Observed, not malicious', description: 'Seen in proxy and DNS telemetry, no intel matches', ioc: 'updates.example.net' },
  { id: 'no-evidence', title: 'No evidence', description: 'A file hash nobody has seen', ioc: '9f2c4e8a1b7d3f6092c5e1a4b8d7f3e6c2a9b1d4e7f0a3c6b9d2e5f8a1c4b7e0' },
];

export const DEMO_DATASETS = ['firewall_traffic', 'proxy_web', 'dns_queries'];

const scenarioFor =(value: string) => DEMO_SCENARIOS.find((s) => s.ioc === value)?.id ?? 'no-evidence';

function rng(seedStr: string) {
  let h = 2166136261;
  for (let i = 0; i < seedStr.length; i++) h = Math.imul(h ^ seedStr.charCodeAt(i), 16777619);
  let a = h >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const wait = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal.addEventListener('abort', () => {
      clearTimeout(t);
      reject(new DOMException('Aborted', 'AbortError'));
    });
  });

const DEMO_LOOKUPS = ['threat_intel_ips.csv', 'known_c2.csv', 'watchlist_internal.csv', 'suspicious_domains.csv'];

class DemoLookups implements EvidenceLookupProvider {
  readonly kind = 'lookups';
  readonly demo = true;
  async listLookups() {
    return DEMO_LOOKUPS.map((id) => ({ id, groupId: 'default', size: null, description: 'Demo lookup' }));
  }
  async check(ind: Indicator, ctx: ProviderContext): Promise<LookupResult> {
    await wait(700, ctx.signal);
    const sc = scenarioFor(ind.value);
    const tables = DEMO_LOOKUPS.map((id) => {
      const matched = sc === 'malicious-ip' && (id === 'threat_intel_ips.csv' || id === 'known_c2.csv');
      const rows: Record<string, string>[] = matched
        ? [id === 'known_c2.csv' ? { indicator: ind.value, campaign: 'DEMO-CAMPAIGN-7', confidence: 'high', added: '2026-08-14' } : { ip: ind.value, category: 'c2', source: 'internal-ti', first_seen: '2026-07-02' }]
        : [];
      return { id, groupId: 'default', matched, matchedColumns: matched ? [id === 'known_c2.csv' ? 'indicator' : 'ip'] : [], rows, rowCount: 1200 + Math.floor(rng(id)() * 4000) };
    });
    return { tables, matchedTables: tables.filter((t) => t.matched).length, checkedTables: tables.length, skipped: [] };
  }
}

const HOSTS = ['web-01', 'web-02', 'laptop-23', 'laptop-87', 'app-03', 'db-02', 'laptop-11', 'vdi-104', 'laptop-56', 'build-07', 'mail-01', 'laptop-42'];
const USERS = ['jdoe', 'asmith', 'mkhan', 'lchen', 'svc_build', 'rgarcia'];

function demoEvents(ind: Indicator, range: TimeRange, sc: DemoScenario['id']): EvidenceEvent[] {
  if (sc !== 'malicious-ip' && sc !== 'observed-benign') return [];
  const r = rng(`${ind.value}|${sc}`);
  const n = sc === 'malicious-ip' ? 47 : 23;
  const hosts = sc === 'malicious-ip' ? HOSTS : HOSTS.slice(0, 5);
  const events: EvidenceEvent[] = [];
  const span = range.endMs - range.startMs;
  for (let i = 0; i < n; i++) {
    // Cluster activity in two bursts so the timeline is realistic.
    const burst = r() < 0.6 ? 0.35 : 0.8;
    const t = Math.round(range.startMs + span * Math.min(0.999, Math.max(0.001, burst + (r() - 0.5) * 0.3)));
    const host = hosts[Math.floor(r() * r() * hosts.length)];
    const user = USERS[Math.floor(r() * USERS.length)];
    const srcIp = `10.${1 + Math.floor(r() * 4)}.${Math.floor(r() * 10)}.${2 + Math.floor(r() * 250)}`;
    const kind = sc === 'malicious-ip' ? (r() < 0.45 ? 'firewall' : r() < 0.75 ? 'proxy' : 'dns') : r() < 0.6 ? 'proxy' : 'dns';
    let fields: Record<string, unknown>;
    if (kind === 'firewall') {
      const alert = r() < 0.3;
      fields = { src_host: host, src_ip: srcIp, dst_ip: ind.value, dst_port: 443, action: alert ? 'alert' : 'allow', event_type: alert ? 'alert' : 'connection', message: alert ? 'Possible C2 beacon pattern' : 'TLS connection established', bytes_out: Math.floor(r() * 9000) };
    } else if (kind === 'proxy') {
      const url = ind.type === 'domain' ? `https://${ind.value}/v2/check` : `https://${ind.value}/api/beacon`;
      fields = { src_host: host, src_ip: srcIp, user, url, dst_ip: ind.type === 'domain' ? '192.0.2.80' : ind.value, dst_port: 443, event_type: 'proxy', message: `HTTPS request (user: ${user})`, status: 200 };
    } else {
      fields = { src_host: host, src_ip: srcIp, query: ind.type === 'domain' ? ind.value : `${ind.value.split('.').reverse().join('.')}.in-addr.arpa`, event_type: 'dns', dst_port: 53, message: 'DNS query' };
    }
    const dataset = kind === 'firewall' ? 'firewall_traffic' : kind === 'proxy' ? 'proxy_web' : 'dns_queries';
    const matchedFields = Object.entries(fields)
      .filter(([, v]) => v === ind.value)
      .map(([k]) => k);
    events.push({ id: `demo-${i}`, time: t, dataset, fields, matchedFields });
  }
  return events.sort((a, b) => b.time - a.time);
}

class DemoSearch implements SearchProvider {
  readonly kind = 'search';
  readonly demo = true;
  async listDatasets() {
    return ['firewall_traffic', 'proxy_web', 'dns_queries', 'edr_process'].map((id) => ({ id, provider: 'cribl_lake', type: 'demo', description: 'Demo dataset' }));
  }
  async search(ind: Indicator, range: TimeRange, datasets: string[], ctx: ProviderContext, onProgress?: (p: { phase: 'submitting' | 'running' | 'fetching'; jobId?: string; detail?: string }) => void): Promise<SearchResult> {
    onProgress?.({ phase: 'submitting' });
    await wait(500, ctx.signal);
    onProgress?.({ phase: 'running', jobId: 'demo-job', detail: 'Scanning demo datasets' });
    await wait(1900, ctx.signal);
    onProgress?.({ phase: 'fetching', jobId: 'demo-job' });
    await wait(300, ctx.signal);
    const all = demoEvents(ind, range, scenarioFor(ind.value));
    const events = datasets.length ? all.filter((e) => datasets.includes(e.dataset)) : all;
    return { query: '(demo query — no search was run)', jobId: 'demo-job', datasets: datasets.length ? datasets : ['firewall_traffic', 'proxy_web', 'dns_queries', 'edr_process'], events, totalEvents: events.length, truncated: false, completion: 'completed' };
  }
}

class DemoVirusTotal implements ThreatIntelProvider {
  readonly kind = 'virustotal';
  readonly demo = true;
  async lookup(ind: Indicator, ctx: ProviderContext): Promise<VtResult> {
    await wait(1100, ctx.signal);
    const sc = scenarioFor(ind.value);
    if (sc === 'no-evidence') throw new ProviderFailure({ kind: 'not_found', httpStatus: 404, message: 'VirusTotal has no record for this indicator.' });
    const base: VtResult = {
      objectType: ind.type === 'domain' ? 'domain' : ind.type.startsWith('ip') ? 'ip_address' : 'file',
      id: ind.value,
      stats: { malicious: 0, suspicious: 0, harmless: 62, undetected: 30, timeout: 0, other: 0 },
      totalEngines: 92,
      reputation: 0,
      tags: [],
      categories: [],
      popularThreatLabels: [],
      asn: 64500,
      asOwner: 'DEMO-NET (documentation ASN)',
      country: 'NL',
      network: ind.type.startsWith('ip') ? `${ind.value.split('.').slice(0, 3).join('.')}.0/24` : null,
      registrar: ind.type === 'domain' ? 'Demo Registrar' : null,
      meaningfulName: null,
      typeDescription: null,
      size: null,
      lastAnalysisDate: Date.now() - 36 * 3_600_000,
      firstSeenDate: Date.parse('2025-11-14T00:00:00Z'),
      guiUrl: vtGuiUrl(ind),
    };
    if (sc === 'malicious-ip') {
      return { ...base, stats: { malicious: 14, suspicious: 3, harmless: 52, undetected: 23, timeout: 0, other: 0 }, reputation: -38, tags: ['c2', 'malware', 'botnet'], categories: ['command and control'], popularThreatLabels: ['c2', 'trojan'] };
    }
    if (sc === 'observed-benign') return { ...base, categories: ['content delivery', 'software updates'] };
    return base;
  }
}

export const demoProviders = (): ProviderSet => ({ lookups: new DemoLookups(), search: new DemoSearch(), virustotal: new DemoVirusTotal() });
