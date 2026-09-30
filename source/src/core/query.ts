/**
 * Cribl Search (KQL-style) query generation — the single place syntax is produced.
 * Syntax used, all documented at docs.cribl.io/search:
 *  - API queries start with the `cribl` operator and are a single line (cribl-as-code/search-results)
 *  - dataset selection `dataset="a" or dataset="b"` inside the cribl scope (search/build-a-search)
 *  - `| where f == "v" or g == "v"`, `_raw has "v"` (search/where)
 *  - `| sort by _time desc`, `| limit N` (search/sort, search/limit)
 *  - `| summarize events=count() by a, b` (search/summarize)
 */
import { iocFields, type FieldStrategy } from './fields.ts';
import type { Indicator } from './types.ts';

/** Double-quoted string literal; backslash escapes per docs.cribl.io/search/string. */
export const quote = (s: string) => `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

/** Field identifiers are restricted so Settings can never inject query syntax. */
export const safeField = (f: string) => /^[A-Za-z_][A-Za-z0-9_.]*$/.test(f);

/** Dataset ids may contain `*` wildcards (documented); anything else unusual is dropped. */
export const safeDataset = (d: string) => /^[A-Za-z0-9_\-.$*]+$/.test(d);

export function datasetScope(datasets: string[]): string {
  const ds = datasets.filter(safeDataset);
  if (ds.length === 0) return '';
  if (ds.length === 1) return `dataset=${quote(ds[0])}`;
  return `(${ds.map((d) => `dataset=${quote(d)}`).join(' or ')})`;
}

export function matchPredicate(ind: Indicator, strategy: FieldStrategy): string {
  const v = quote(ind.value);
  const parts = iocFields(strategy, ind.type)
    .filter(safeField)
    .map((f) => `${f} == ${v}`);
  if (strategy.rawFallback || parts.length === 0) parts.push(`_raw has ${v}`);
  return parts.join(' or ');
}

/** Evidence query sent to the Search jobs API (single line, explicit `cribl`). */
export function evidenceQuery(ind: Indicator, datasets: string[], strategy: FieldStrategy, limit: number): string {
  const n = Math.max(1, Math.min(10_000, Math.floor(limit)));
  return ['cribl', datasetScope(datasets), `| where ${matchPredicate(ind, strategy)}`, '| sort by _time desc', `| limit ${n}`].filter(Boolean).join(' ');
}

/**
 * Detection candidate: narrowed to the fields and datasets that actually matched,
 * counted per dataset and host so it can be reviewed before becoming a detection.
 */
export function detectionQuery(ind: Indicator, datasets: string[], matchedFields: string[], hostField: string | null): string {
  const v = quote(ind.value);
  const fields = matchedFields.filter(safeField);
  const predicate = fields.length ? fields.map((f) => `${f} == ${v}`).join(' or ') : `_raw has ${v}`;
  const by = ['dataset', hostField && safeField(hostField) ? hostField : null].filter(Boolean).join(', ');
  return ['cribl', datasetScope(datasets), `| where ${predicate}`, `| summarize events=count() by ${by}`, '| sort by events desc'].filter(Boolean).join(' ');
}

/** Readable multi-line rendering of a single-line query for display. */
export const prettyQuery = (q: string) => q.replace(/ \| /g, '\n| ');
