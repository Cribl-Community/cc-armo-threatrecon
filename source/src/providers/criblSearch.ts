import { evidenceQuery } from '../core/query.ts';
import { jobId, jobStatus, parseNdjson, toEvidenceEvents } from '../core/searchParse.ts';
import type { EvidenceEvent, Indicator, ProviderError, SearchResult, TimeRange } from '../core/types.ts';
import { HttpError, apiUrl, criblFetch, isInCribl } from '../platform/cribl.ts';
import { ProviderFailure, type DatasetInfo, type ProviderContext, type SearchProgress, type SearchProvider } from './types.ts';

/** Search endpoints always use the default_search group context (AGENTS.md). */
const BASE = '/m/default_search/search';
const POLL_MS = 1500;
const PAGE = 1000;

const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal.addEventListener('abort', () => {
      clearTimeout(t);
      reject(new DOMException('Aborted', 'AbortError'));
    });
  });

function httpToError(e: unknown, phase: string): ProviderError {
  if (e instanceof HttpError) {
    const msg = typeof e.body === 'object' && e.body && 'message' in e.body ? String((e.body as { message: unknown }).message) : null;
    if (e.status === 401 || e.status === 403) return { kind: 'permission', httpStatus: e.status, message: 'Permission denied.', hint: "Check the App's Search permissions: your role needs Cribl Search access and the App must be shared with you." };
    if (e.status === 404) return { kind: 'unavailable', httpStatus: 404, message: 'Cribl Search is not available in this Workspace.' };
    if (e.status === 429) return { kind: 'rate_limited', httpStatus: 429, message: 'Search limit reached (concurrency or usage guardrail). Try again shortly.' };
    if (e.status === 400) return { kind: 'invalid', httpStatus: 400, message: `Search rejected the query${msg ? `: ${msg}` : '.'}`, hint: 'Check the IOC search fields in Settings.' };
    return { kind: 'server', httpStatus: e.status, message: `Search failed while ${phase} (HTTP ${e.status}).` };
  }
  if (e instanceof TypeError) return { kind: 'network', message: `Network error while ${phase}.` };
  return { kind: 'server', message: `Search failed while ${phase}.` };
}

export class CriblSearchProvider implements SearchProvider {
  readonly kind = 'search';
  readonly demo = false;

  async listDatasets(ctx: ProviderContext): Promise<DatasetInfo[]> {
    if (!isInCribl()) throw new ProviderFailure({ kind: 'unavailable', message: 'Cribl Search is only available inside Cribl.' });
    try {
      // The API requires `offset` whenever `limit` is sent; page until totalCount is reached.
      const out: DatasetInfo[] = [];
      const pageSize = 500;
      for (let offset = 0; offset < 5000; offset += pageSize) {
        const body = await criblFetch<{ items?: { id: string; provider?: string; type?: string; description?: string }[]; totalCount?: number; count?: number }>(`${BASE}/datasets?offset=${offset}&limit=${pageSize}`, { signal: ctx.signal });
        const items = body.items ?? [];
        out.push(...items.map((d) => ({ id: d.id, provider: d.provider ?? null, type: d.type ?? null, description: d.description ?? null })));
        const total = body.totalCount ?? body.count ?? 0;
        if (items.length < pageSize || out.length >= total) break;
      }
      return out.sort((a, b) => a.id.localeCompare(b.id));
    } catch (e) {
      if (e instanceof DOMException) throw e;
      throw new ProviderFailure(httpToError(e, 'listing datasets'));
    }
  }

  async search(ind: Indicator, range: TimeRange, datasets: string[], ctx: ProviderContext, onProgress?: (p: SearchProgress) => void): Promise<SearchResult> {
    if (!isInCribl()) throw new ProviderFailure({ kind: 'unavailable', message: 'Cribl Search is only available inside Cribl.' });
    if (datasets.length === 0) throw new ProviderFailure({ kind: 'invalid', message: 'No datasets selected for Cribl Search.' });
    const { settings, signal } = ctx;
    const limit = settings.resultLimit;
    const query = evidenceQuery(ind, datasets, settings.fields, limit);

    // 1. Create the job. earliest/latest are epoch seconds (documented).
    onProgress?.({ phase: 'submitting' });
    let id: string | null;
    try {
      const created = await criblFetch<unknown>(`${BASE}/jobs`, {
        method: 'POST',
        signal,
        body: JSON.stringify({ query, earliest: Math.floor(range.startMs / 1000), latest: Math.ceil(range.endMs / 1000), timezone: range.timezone }),
      });
      id = jobId(created);
    } catch (e) {
      if (e instanceof DOMException) throw e;
      throw new ProviderFailure(httpToError(e, 'submitting the search'));
    }
    if (!id) throw new ProviderFailure({ kind: 'server', message: 'Search did not return a job id.' });
    const jobPath = `${BASE}/jobs/${encodeURIComponent(id)}`;

    // 2. Poll status until a terminal state or the timeout.
    const deadline = Date.now() + settings.searchTimeoutSec * 1000;
    let completion: SearchResult['completion'] = 'completed';
    const cancel = () => fetch(apiUrl(`${jobPath}/cancel`), { method: 'POST' }).catch(() => undefined);
    signal.addEventListener('abort', () => void cancel(), { once: true });
    for (;;) {
      let status: string | null = null;
      try {
        status = jobStatus(await criblFetch<unknown>(`${jobPath}/status`, { signal }));
      } catch (e) {
        if (e instanceof DOMException) throw e;
        throw new ProviderFailure(httpToError(e, 'checking search status'));
      }
      onProgress?.({ phase: 'running', jobId: id, detail: status ?? undefined });
      if (status === 'completed') break;
      if (status === 'failed') throw new ProviderFailure({ kind: 'server', message: 'Search failed.', hint: 'Open Cribl Search to see the job error.' });
      if (status === 'canceled') throw new ProviderFailure({ kind: 'timeout', message: 'Search was canceled.' });
      if (Date.now() > deadline) {
        await cancel();
        completion = 'timeout';
        break;
      }
      await sleep(POLL_MS, signal);
    }

    // 3. Page through NDJSON results up to the configured cap.
    onProgress?.({ phase: 'fetching', jobId: id });
    const events: EvidenceEvent[] = [];
    let total: number | null = null;
    for (let offset = 0; offset < limit; offset += PAGE) {
      const n = Math.min(PAGE, limit - offset);
      let text: string;
      try {
        const res = await fetch(apiUrl(`${jobPath}/results?limit=${n}&offset=${offset}`), { signal, headers: { accept: 'application/x-ndjson', 'content-type': 'application/x-ndjson' } });
        text = await res.text();
        if (!res.ok) throw new HttpError(res.status, `HTTP ${res.status}`, text);
      } catch (e) {
        if (e instanceof DOMException) throw e;
        if (events.length) {
          completion = 'partial';
          break;
        }
        throw new ProviderFailure(httpToError(e, 'retrieving results'));
      }
      const page = parseNdjson(text);
      if (page.header.totalEventCount !== null) total = page.header.totalEventCount;
      events.push(...toEvidenceEvents(page.rows, ind, settings.fields, id, offset));
      if (page.rows.length < n) break;
    }
    const totalEvents = Math.max(total ?? 0, events.length);
    return { query, jobId: id, datasets, events, totalEvents, truncated: totalEvents > events.length, completion };
  }
}
