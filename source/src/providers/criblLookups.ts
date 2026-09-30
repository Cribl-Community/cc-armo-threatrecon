import { exactMatchColumns, lookupRows } from '../core/searchParse.ts';
import type { Indicator, LookupResult, LookupTableResult, ProviderError } from '../core/types.ts';
import { HttpError, criblFetch, isInCribl } from '../platform/cribl.ts';
import { ProviderFailure, type EvidenceLookupProvider, type LookupInfo, type ProviderContext } from './types.ts';

/** Upper bound on tables checked per investigation (keeps inside proxy rate limits). */
const MAX_TABLES = 40;
const CONCURRENCY = 4;
const ROWS_PER_TABLE = 20;

const toError = (e: unknown): ProviderError => {
  if (e instanceof HttpError) {
    if (e.status === 401 || e.status === 403) return { kind: 'permission', httpStatus: e.status, message: 'Lookup access unavailable.', hint: 'Your role needs read access to lookups in the configured group.' };
    if (e.status === 404) return { kind: 'unavailable', httpStatus: 404, message: 'Lookup integration unavailable in this environment.', hint: 'Check the lookup config group in Settings.' };
    return { kind: 'server', httpStatus: e.status, message: `Lookup request failed (HTTP ${e.status}).` };
  }
  if (e instanceof TypeError) return { kind: 'network', message: 'Network error while reading lookups.' };
  return { kind: 'server', message: 'Lookup request failed.' };
};

/**
 * Read-only lookup check against the documented Stream Lookups API:
 *   GET /m/{group}/system/lookups              (list)
 *   GET /m/{group}/system/lookups/{id}/content (rows; `q` = case-insensitive wildcard row filter)
 * `q` narrows candidates server-side; a row only counts as a match when a cell equals the IOC exactly.
 */
export class CriblLookupProvider implements EvidenceLookupProvider {
  readonly kind = 'lookups';
  readonly demo = false;

  private group(ctx: ProviderContext) {
    const g = ctx.settings.lookupGroupId.trim() || 'default';
    return encodeURIComponent(g);
  }

  async listLookups(ctx: ProviderContext): Promise<LookupInfo[]> {
    if (!isInCribl()) throw new ProviderFailure({ kind: 'unavailable', message: 'Lookup integration unavailable outside Cribl.' });
    try {
      const body = await criblFetch<{ items?: { id: string; size?: number; description?: string }[] }>(`/m/${this.group(ctx)}/system/lookups?offset=0&limit=1000`, { signal: ctx.signal });
      return (body.items ?? []).map((l) => ({ id: l.id, groupId: ctx.settings.lookupGroupId, size: l.size ?? null, description: l.description ?? null }));
    } catch (e) {
      if (e instanceof DOMException) throw e;
      throw new ProviderFailure(toError(e));
    }
  }

  async check(ind: Indicator, ctx: ProviderContext): Promise<LookupResult> {
    const all = await this.listLookups(ctx);
    const wanted = ctx.settings.lookupIds.length ? all.filter((l) => ctx.settings.lookupIds.includes(l.id)) : all;
    const skipped = [
      ...ctx.settings.lookupIds.filter((id) => !all.some((l) => l.id === id)).map((id) => ({ id, reason: 'not found in group' })),
      ...wanted.slice(MAX_TABLES).map((l) => ({ id: l.id, reason: `over the ${MAX_TABLES}-table cap` })),
    ];
    const targets = wanted.slice(0, MAX_TABLES);
    const results: LookupTableResult[] = new Array(targets.length);
    let next = 0;
    const worker = async () => {
      while (next < targets.length) {
        const i = next++;
        const t = targets[i];
        const q = encodeURIComponent(`*${ind.value}*`);
        try {
          const body = await criblFetch<{ totalCount?: number }>(`/m/${this.group(ctx)}/system/lookups/${encodeURIComponent(t.id)}/content?q=${q}&offset=0&limit=${ROWS_PER_TABLE}`, { signal: ctx.signal });
          const rows = lookupRows(body).filter((r) => exactMatchColumns(r, ind.value).length > 0);
          const cols = [...new Set(rows.flatMap((r) => exactMatchColumns(r, ind.value)))];
          results[i] = { id: t.id, groupId: t.groupId, matched: rows.length > 0, matchedColumns: cols, rows: rows.slice(0, 5), rowCount: null };
        } catch (e) {
          if (e instanceof DOMException) throw e;
          results[i] = { id: t.id, groupId: t.groupId, matched: false, matchedColumns: [], rows: [], rowCount: null, error: toError(e).message };
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, targets.length) }, worker));
    const checked = results.filter((r) => !r.error);
    return { tables: results, matchedTables: checked.filter((r) => r.matched).length, checkedTables: checked.length, skipped };
  }
}
