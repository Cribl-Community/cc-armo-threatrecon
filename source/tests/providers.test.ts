import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_SETTINGS, type AppSettings } from '../src/core/settings.ts';
import { detectionQuery, evidenceQuery, datasetScope } from '../src/core/query.ts';
import { eventTimeMs, jobId, jobStatus, parseNdjson } from '../src/core/searchParse.ts';
import { DEFAULT_FIELDS } from '../src/core/fields.ts';
import type { Indicator } from '../src/core/types.ts';
import { CriblSearchProvider } from '../src/providers/criblSearch.ts';
import { CriblLookupProvider } from '../src/providers/criblLookups.ts';
import { VirusTotalProvider } from '../src/providers/virustotal.ts';
import { ProviderFailure } from '../src/providers/types.ts';

const API = 'https://cribl.test/api/v1';
const ip: Indicator = { raw: '203.0.113.45', value: '203.0.113.45', type: 'ipv4' };
const range = { preset: '24h' as const, startMs: 1_759_000_000_000, endMs: 1_759_086_400_000, timezone: 'UTC' };

type Handler = (url: string, init: RequestInit) => { status?: number; body: unknown };
let calls: { url: string; method: string; body?: string }[] = [];
function mockFetch(handler: Handler) {
  calls = [];
  (globalThis as unknown as { fetch: typeof fetch }).fetch = (async (input: string | URL, init: RequestInit = {}) => {
    const url = String(input);
    calls.push({ url, method: init.method ?? 'GET', body: typeof init.body === 'string' ? init.body : undefined });
    const r = handler(url, init);
    const text = typeof r.body === 'string' ? r.body : JSON.stringify(r.body);
    return new Response(text, { status: r.status ?? 200 });
  }) as typeof fetch;
}
const ctx = (s: Partial<AppSettings> = {}) => ({ signal: new AbortController().signal, settings: { ...DEFAULT_SETTINGS, ...s } });

beforeEach(() => {
  (globalThis as unknown as { window: unknown }).window = { CRIBL_API_URL: API };
});

// ── Query syntax (documented forms only) ─────────────────────────────
test('evidence query: explicit cribl, single line, documented operators', () => {
  const q = evidenceQuery(ip, ['firewall', 'proxy'], { ...DEFAULT_FIELDS, ip: ['src_ip', 'dst_ip'], rawFallback: true }, 500);
  assert.equal(q, 'cribl (dataset="firewall" or dataset="proxy") | where src_ip == "203.0.113.45" or dst_ip == "203.0.113.45" or _raw has "203.0.113.45" | sort by _time desc | limit 500');
  assert.ok(!q.includes('\n'));
});

test('query builder rejects injected field names and escapes values', () => {
  const evil: Indicator = { raw: 'x', value: 'a"b', type: 'domain' };
  const q = evidenceQuery(evil, ['ds'], { ...DEFAULT_FIELDS, domain: ['domain', 'x) or 1==1 or (y'], rawFallback: false }, 10);
  assert.ok(q.includes('domain == "a\\"b"'));
  assert.ok(!q.includes('1==1'));
  assert.equal(datasetScope(['good', 'bad"ds']), 'dataset="good"');
});

test('detection query uses only matched fields', () => {
  assert.equal(detectionQuery(ip, ['fw'], ['dst_ip'], 'src_host'), 'cribl dataset="fw" | where dst_ip == "203.0.113.45" | summarize events=count() by dataset, src_host | sort by events desc');
});

// ── Response parsing ─────────────────────────────────────────────────
test('parses NDJSON header + events; handles both status shapes', () => {
  const nd = `{"isFinished":true,"totalEventCount":2,"offset":0}\n{"_time":1759000100,"dataset":"fw","dst_ip":"203.0.113.45"}\n{"_time":1759000200,"dataset":"fw"}\n`;
  const p = parseNdjson(nd);
  assert.equal(p.header.totalEventCount, 2);
  assert.equal(p.rows.length, 2);
  assert.equal(eventTimeMs(1759000100), 1759000100000);
  assert.equal(eventTimeMs(1759000100123), 1759000100123);
  assert.equal(jobStatus({ items: [{ status: 'completed' }], count: 1 }), 'completed');
  assert.equal(jobStatus({ status: 'running' }), 'running');
  assert.equal(jobId({ items: [{ id: '1349305736255.Acp7er' }], count: 1 }), '1349305736255.Acp7er');
});

// ── Cribl Search provider end to end ─────────────────────────────────
test('search: create → poll → NDJSON results, epoch-second window', async () => {
  let polls = 0;
  mockFetch((url) => {
    if (url.endsWith('/search/jobs')) return { body: { count: 1, items: [{ id: 'job.1' }] } };
    if (url.includes('/status')) return { body: { count: 1, items: [{ status: ++polls < 2 ? 'running' : 'completed' }] } };
    if (url.includes('/results')) return { body: `{"isFinished":true,"totalEventCount":2}\n{"_time":1759000100,"dataset":"fw","dst_ip":"203.0.113.45","src_host":"web-01"}\n{"_time":1759000200,"dataset":"proxy","_raw":"GET http://203.0.113.45/x"}\n` };
    return { status: 404, body: {} };
  });
  const r = await new CriblSearchProvider().search(ip, range, ['fw', 'proxy'], ctx({ searchTimeoutSec: 30 }));
  const create = calls.find((c) => c.method === 'POST' && c.url.endsWith('/m/default_search/search/jobs'))!;
  const body = JSON.parse(create.body!);
  assert.ok(body.query.startsWith('cribl '));
  assert.equal(body.earliest, 1_759_000_000);
  assert.equal(body.latest, 1_759_086_400);
  assert.equal(r.totalEvents, 2);
  assert.deepEqual(r.events[0].matchedFields, ['dst_ip']);
  assert.deepEqual(r.events[1].matchedFields, ['_raw']);
  assert.equal(r.events[0].time, 1_759_000_100_000);
  assert.equal(r.completion, 'completed');
});

test('search: 403 becomes a permission error', async () => {
  mockFetch(() => ({ status: 403, body: { message: 'forbidden' } }));
  await assert.rejects(new CriblSearchProvider().search(ip, range, ['fw'], ctx()), (e: unknown) => e instanceof ProviderFailure && e.error.kind === 'permission');
});

test('search: failed job surfaces a provider error', async () => {
  mockFetch((url) => (url.endsWith('/search/jobs') ? { body: { items: [{ id: 'j' }] } } : { body: { items: [{ status: 'failed' }] } }));
  await assert.rejects(new CriblSearchProvider().search(ip, range, ['fw'], ctx()), (e: unknown) => e instanceof ProviderFailure && e.error.message === 'Search failed.');
});

test('search: timeout cancels the job and keeps partial results', async () => {
  mockFetch((url) => {
    if (url.endsWith('/search/jobs')) return { body: { items: [{ id: 'slow' }] } };
    if (url.includes('/status')) return { body: { items: [{ status: 'running' }] } };
    if (url.includes('/cancel')) return { body: {} };
    return { body: `{"isFinished":false,"totalEventCount":9}\n{"_time":1759000100,"dataset":"fw","dst_ip":"203.0.113.45"}\n` };
  });
  const r = await new CriblSearchProvider().search(ip, range, ['fw'], ctx({ searchTimeoutSec: 0 }));
  assert.equal(r.completion, 'timeout');
  assert.ok(calls.some((c) => c.url.includes('/cancel') && c.method === 'POST'));
  assert.equal(r.events.length, 1);
  assert.equal(r.truncated, true);
});

test('search: empty result is a completed negative', async () => {
  mockFetch((url) => (url.endsWith('/search/jobs') ? { body: { items: [{ id: 'j' }] } } : url.includes('/status') ? { body: { items: [{ status: 'completed' }] } } : { body: '{"isFinished":true,"totalEventCount":0}\n' }));
  const r = await new CriblSearchProvider().search(ip, range, ['fw'], ctx());
  assert.equal(r.totalEvents, 0);
  assert.equal(r.events.length, 0);
});

// ── Cribl Lookups provider ───────────────────────────────────────────
test('lookups: exact cell match only; substring hits do not count', async () => {
  mockFetch((url) => {
    if (url.endsWith('/system/lookups?offset=0&limit=1000')) return { body: { items: [{ id: 'known_c2.csv' }, { id: 'near_miss.csv' }], count: 2 } };
    if (url.includes('known_c2.csv/content')) return { body: { fields: ['__id', 'ip', 'campaign'], items: [[1, '203.0.113.45', 'X']], count: 1 } };
    if (url.includes('near_miss.csv/content')) return { body: { fields: ['__id', 'ip'], items: [[1, '203.0.113.450']], count: 1 } };
    return { status: 404, body: {} };
  });
  const r = await new CriblLookupProvider().check(ip, ctx({ lookupGroupId: 'default' }));
  assert.equal(r.checkedTables, 2);
  assert.equal(r.matchedTables, 1);
  const hit = r.tables.find((t) => t.id === 'known_c2.csv')!;
  assert.deepEqual(hit.matchedColumns, ['ip']);
  assert.deepEqual(hit.rows[0], { ip: '203.0.113.45', campaign: 'X' });
  assert.ok(calls.every((c) => c.method === 'GET'), 'lookups are read-only');
  assert.ok(calls.some((c) => c.url.includes('/m/default/system/lookups/known_c2.csv/content?q=')));
});

test('lookups: 403 on list → unavailable-style provider failure', async () => {
  mockFetch(() => ({ status: 403, body: {} }));
  await assert.rejects(new CriblLookupProvider().check(ip, ctx()), (e: unknown) => e instanceof ProviderFailure && e.error.kind === 'permission');
});

test('lookups: one broken table does not fail the provider', async () => {
  mockFetch((url) => {
    if (url.endsWith('/system/lookups?offset=0&limit=1000')) return { body: { items: [{ id: 'a.csv' }, { id: 'b.csv' }] } };
    if (url.includes('a.csv/content')) return { status: 500, body: {} };
    return { body: { fields: ['__id', 'v'], items: [] } };
  });
  const r = await new CriblLookupProvider().check(ip, ctx());
  assert.equal(r.checkedTables, 1);
  assert.ok(r.tables.find((t) => t.id === 'a.csv')!.error);
});

// ── VirusTotal provider ──────────────────────────────────────────────
test('virustotal: no key in request; parses stats; maps 404/429', async () => {
  mockFetch(() => ({ body: { data: { type: 'ip_address', id: ip.value, attributes: { last_analysis_stats: { malicious: 4, suspicious: 0, harmless: 60, undetected: 20, timeout: 0 } } } } }));
  const v = await new VirusTotalProvider().lookup(ip, ctx());
  assert.equal(v.stats.malicious, 4);
  assert.equal(calls[0].url, 'https://www.virustotal.com/api/v3/ip_addresses/203.0.113.45');
  mockFetch(() => ({ status: 404, body: { error: { code: 'NotFoundError', message: 'x' } } }));
  await assert.rejects(new VirusTotalProvider().lookup(ip, ctx()), (e: unknown) => e instanceof ProviderFailure && e.error.kind === 'not_found');
  mockFetch(() => ({ status: 429, body: { error: { code: 'QuotaExceededError' } } }));
  await assert.rejects(new VirusTotalProvider().lookup(ip, ctx()), (e: unknown) => e instanceof ProviderFailure && e.error.kind === 'rate_limited');
});
