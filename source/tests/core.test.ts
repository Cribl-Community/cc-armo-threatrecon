import { test } from 'node:test';
import assert from 'node:assert/strict';
import { candidateTypes, maskIndicator, normalize, parseIndicator } from '../src/core/ioc.ts';
import { presetRange, validateRange } from '../src/core/timeRange.ts';
import { computeVerdict, vtVerdict } from '../src/core/verdict.ts';
import { parseVtObject, vtError, vtEndpoint } from '../src/core/virustotal.ts';
import { DEFAULT_FIELDS } from '../src/core/fields.ts';
import { bucketize, evidenceColumns, relationships, summarize } from '../src/core/evidence.ts';
import { incidentStory } from '../src/core/story.ts';
import type { EvidenceEvent, Indicator, Outcomes, SearchResult, VtResult } from '../src/core/types.ts';

// ── IOC classification & normalization ─────────────────────────────
test('classifies each IOC type', () => {
  assert.deepEqual(candidateTypes('185.199.108.153'), ['ipv4']);
  assert.deepEqual(candidateTypes('2001:db8::1'), ['ipv6']);
  assert.deepEqual(candidateTypes('::ffff:192.0.2.1'), ['ipv6']);
  assert.deepEqual(candidateTypes('Evil.Example.COM.'), ['domain']);
  assert.deepEqual(candidateTypes('d41d8cd98f00b204e9800998ecf8427e'), ['md5']);
  assert.deepEqual(candidateTypes('da39a3ee5e6b4b0d3255bfef95601890afd80709'), ['sha1']);
  assert.deepEqual(candidateTypes('E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855'), ['sha256']);
});

test('rejects invalid values', () => {
  for (const bad of ['', '256.1.1.1', '1.2.3', 'abc', 'deadbeef', 'http://x.com', 'a b.com', '2001:db8:::1', '-bad.com', 'x.1']) {
    assert.equal(parseIndicator(bad).ok, false, bad);
  }
  const r = parseIndicator('foo');
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.message, 'Unable to determine IOC type.');
});

test('normalization never changes meaning', () => {
  assert.equal(normalize('  10.0.0.1 ', 'ipv4'), '10.0.0.1');
  assert.equal(normalize('Evil.Example.COM.', 'domain'), 'evil.example.com');
  assert.equal(normalize('ABCDEF0123456789ABCDEF0123456789', 'md5'), 'abcdef0123456789abcdef0123456789');
  assert.equal(normalize('2001:DB8::1', 'ipv6'), '2001:db8::1');
});

test('manual type override still validates', () => {
  assert.equal(parseIndicator('10.0.0.1', 'domain').ok, false);
  assert.equal(parseIndicator('example.com', 'domain').ok, true);
});

test('masks IOC for diagnostics', () => {
  assert.equal(maskIndicator('185.199.108.153'), '185…53');
  assert.ok(!maskIndicator('evil.example.com').includes('example'));
});

// ── Time range ─────────────────────────────────────────────────────
test('time range validation', () => {
  const now = Date.parse('2026-09-30T12:00:00Z');
  assert.equal(validateRange(presetRange('24h', now), now).ok, true);
  assert.deepEqual(validateRange({ preset: 'custom', startMs: now, endMs: now - 1, timezone: 'UTC' }, now), { ok: false, error: 'Start must be before end.' });
  assert.equal(validateRange({ preset: 'custom', startMs: now - 1000, endMs: now + 3_600_000, timezone: 'UTC' }, now).ok, false);
  const broad = validateRange(presetRange('30d', now), now);
  assert.ok(broad.ok && broad.warning);
  assert.equal(validateRange({ preset: 'custom', startMs: now - 200 * 86_400_000, endMs: now, timezone: 'UTC' }, now).ok, false);
});

// ── VirusTotal parsing ─────────────────────────────────────────────
const ip: Indicator = { raw: '203.0.113.45', value: '203.0.113.45', type: 'ipv4' };
const vtBody = {
  data: {
    type: 'ip_address',
    id: '203.0.113.45',
    attributes: { last_analysis_stats: { malicious: 5, suspicious: 1, harmless: 60, undetected: 25, timeout: 0 }, reputation: -12, tags: ['c2'], asn: 64500, as_owner: 'X', country: 'NL', network: '203.0.113.0/24', last_analysis_date: 1759000000 },
  },
};

test('parses VT object without hard-coding engine totals', () => {
  const v = parseVtObject(vtBody, ip);
  assert.equal(v.totalEngines, 91);
  assert.equal(v.stats.malicious, 5);
  assert.equal(v.reputation, -12);
  assert.equal(v.lastAnalysisDate, 1759000000 * 1000);
  assert.equal(v.guiUrl, 'https://www.virustotal.com/gui/ip-address/203.0.113.45');
  assert.equal(vtEndpoint(ip), 'https://www.virustotal.com/api/v3/ip_addresses/203.0.113.45');
});

test('negative community reputation alone is not malicious', () => {
  const v = parseVtObject({ data: { type: 'ip_address', attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 70, undetected: 20 }, reputation: -90 } } }, ip);
  assert.equal(vtVerdict(v), 'clean');
});

test('maps VT errors', () => {
  assert.equal(vtError(404).kind, 'not_found');
  assert.equal(vtError(429).message, 'VirusTotal rate limit reached. Try again later.');
  assert.equal(vtError(403).message, 'VirusTotal access is not enabled for this App.');
  assert.equal(vtError(401).kind, 'not_configured');
  assert.equal(vtError(500).kind, 'server');
});

// ── Verdict ────────────────────────────────────────────────────────
const vt = (malicious: number, suspicious = 0): VtResult => ({ ...parseVtObject(vtBody, ip), stats: { malicious, suspicious, harmless: 60, undetected: 30, timeout: 0, other: 0 }, totalEngines: 90 + malicious + suspicious });
const ev = (n: number): EvidenceEvent[] => Array.from({ length: n }, (_, i) => ({ id: `e${i}`, time: 1_000 + i, dataset: 'fw', fields: { src_host: `h${i % 3}` }, matchedFields: ['dst_ip'] }));
const sr = (n: number): SearchResult => ({ query: 'q', jobId: 'j', datasets: ['fw'], events: ev(n), totalEvents: n, truncated: false, completion: 'completed' });
const lk = (matched: number) => ({ tables: [], matchedTables: matched, checkedTables: 4, skipped: [] });
const outcomes = (o: { l?: number | 'err'; s?: number | 'err'; v?: VtResult | 'err' | 'nf' }): Outcomes => ({
  lookups: o.l === undefined ? { status: 'skipped', demo: false } : o.l === 'err' ? { status: 'error', error: { kind: 'permission', message: 'Permission denied' }, demo: false } : { status: 'complete', data: lk(o.l), demo: false },
  search: o.s === undefined ? { status: 'skipped', demo: false } : o.s === 'err' ? { status: 'error', error: { kind: 'timeout', message: 'Timed out' }, demo: false } : { status: 'complete', data: sr(o.s), demo: false },
  virustotal: o.v === undefined ? { status: 'skipped', demo: false } : o.v === 'err' ? { status: 'error', error: { kind: 'rate_limited', message: 'Rate limited' }, demo: false } : o.v === 'nf' ? { status: 'error', error: { kind: 'not_found', message: 'No record' }, demo: false } : { status: 'complete', data: o.v, demo: false },
});
const all = ['lookups', 'search', 'virustotal'] as const;

test('verdict matrix', () => {
  assert.equal(computeVerdict(outcomes({ l: 2, s: 47, v: vt(14) }), [...all]).level, 'malicious');
  assert.equal(computeVerdict(outcomes({ l: 1, s: 5, v: vt(0) }), [...all]).level, 'malicious');
  const notObserved = computeVerdict(outcomes({ l: 0, s: 0, v: vt(20) }), [...all]);
  assert.equal(notObserved.level, 'malicious');
  assert.equal(notObserved.qualifier, 'Not observed');
  assert.equal(computeVerdict(outcomes({ l: 0, s: 0, v: vt(1) }), [...all]).level, 'suspicious');
  assert.equal(computeVerdict(outcomes({ l: 1, s: 0, v: vt(0) }), [...all]).level, 'internal_match');
  assert.equal(computeVerdict(outcomes({ l: 0, s: 3, v: vt(0) }), [...all]).level, 'observed');
  assert.equal(computeVerdict(outcomes({ l: 0, s: 0, v: vt(0) }), [...all]).level, 'no_evidence');
  assert.equal(computeVerdict(outcomes({ l: 0, s: 'err', v: vt(0) }), [...all]).level, 'inconclusive');
  assert.equal(computeVerdict(outcomes({ l: 'err', s: 'err', v: 'err' }), [...all]).level, 'inconclusive');
});

test('VirusTotal "no record" is a completed negative, not a failure', () => {
  const v = computeVerdict(outcomes({ l: 0, s: 0, v: 'nf' }), [...all]);
  assert.equal(v.level, 'no_evidence');
  assert.match(v.explanation, /VirusTotal has no record/);
  assert.equal(computeVerdict(outcomes({ l: 0, s: 0, v: 'err' }), [...all]).level, 'inconclusive');
});

test('verdict respects selected providers only', () => {
  const v = computeVerdict(outcomes({ s: 4 }), ['search']);
  assert.equal(v.level, 'observed');
  assert.equal(v.signals.internalMatch, null);
  assert.equal(v.signals.externalVerdict, null);
});

test('no-evidence wording never claims safety', () => {
  const v = computeVerdict(outcomes({ l: 0, s: 0 }), ['lookups', 'search']);
  assert.equal(v.level, 'no_evidence');
  assert.match(v.explanation, /No matching telemetry was found/);
  assert.doesNotMatch(v.explanation.toLowerCase(), /safe/);
});

// ── Evidence aggregation ───────────────────────────────────────────
test('summaries come only from returned events', () => {
  const events: EvidenceEvent[] = [
    { id: '1', time: 3000, dataset: 'proxy_web', fields: { src_host: 'web-01', user: 'jdoe', event_type: 'proxy' }, matchedFields: ['url'] },
    { id: '2', time: 1000, dataset: 'firewall_traffic', fields: { src_host: 'web-01', dst_port: 443, event_type: 'connection' }, matchedFields: ['dst_ip'] },
    { id: '3', time: 2000, dataset: 'dns_queries', fields: { src_host: 'laptop-23', event_type: 'dns' }, matchedFields: ['query'] },
  ];
  const s = summarize({ query: '', jobId: null, datasets: [], events, totalEvents: 3, truncated: false, completion: 'completed' }, DEFAULT_FIELDS);
  assert.equal(s.firstSeen, 1000);
  assert.equal(s.lastSeen, 3000);
  assert.equal(s.datasetCount, 3);
  assert.equal(s.sourceHostCount, 2);
  assert.deepEqual(s.sourceHosts[0], { value: 'web-01', count: 2 });
  assert.deepEqual(s.categories.map((c) => c.category), ['Firewall', 'Proxy', 'DNS']);
  const cols = evidenceColumns(events, DEFAULT_FIELDS).map((c) => c.key);
  assert.ok(cols.includes('user') && cols.includes('destinationPort') && !cols.includes('sourceIp'));
  const b = bucketize(events, 0, 4000, DEFAULT_FIELDS, 4);
  assert.equal(b.reduce((a, x) => a + x.total, 0), 3);
  const rel = relationships('1.2.3.4', events, DEFAULT_FIELDS);
  assert.ok(rel.edges.some((e) => e.from === 'ioc' && e.to === 'host:web-01'));
});

test('incident story states observations, not conclusions', () => {
  const o = outcomes({ l: 0, s: 3, v: vt(0) });
  o.lookups.data!.tables = [];
  const summary = summarize(o.search.data!, DEFAULT_FIELDS);
  const story = incidentStory(ip, { preset: '24h', startMs: 0, endMs: 10_000, timezone: 'UTC' }, [...all], o, summary).join(' ');
  assert.match(story, /was observed 3 times/);
  assert.match(story, /was not found in the 4 internal lookup tables checked/);
  assert.doesNotMatch(story.toLowerCase(), /attack|compromised|safe/);
});
