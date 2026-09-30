import { iocFields, type FieldStrategy } from './fields.ts';
import type { EvidenceEvent, Indicator } from './types.ts';

export interface ResultsHeader {
  totalEventCount: number | null;
  isFinished: boolean | null;
}

/**
 * Parse a Search results NDJSON page: line 1 is a header object
 * (isFinished, totalEventCount, …); each later line is one event.
 */
export function parseNdjson(text: string): { header: ResultsHeader; rows: Record<string, unknown>[] } {
  const lines = text.split(/\r?\n/).filter((l) => l.trim() !== '');
  const objs: Record<string, unknown>[] = [];
  for (const l of lines) {
    try {
      const o = JSON.parse(l);
      if (o && typeof o === 'object' && !Array.isArray(o)) objs.push(o as Record<string, unknown>);
    } catch {
      /* skip malformed line */
    }
  }
  const first = objs[0];
  const isHeader = !!first && ('totalEventCount' in first || 'isFinished' in first || 'job' in first);
  const header: ResultsHeader = isHeader
    ? { totalEventCount: typeof first.totalEventCount === 'number' ? first.totalEventCount : null, isFinished: typeof first.isFinished === 'boolean' ? first.isFinished : null }
    : { totalEventCount: null, isFinished: null };
  return { header, rows: isHeader ? objs.slice(1) : objs };
}

/**
 * `_time` is documented as epoch seconds in Search results, while the API schema says
 * "typically milliseconds". Values below 1e11 are treated as seconds, others as ms.
 */
export function eventTimeMs(t: unknown): number {
  const n = typeof t === 'number' ? t : typeof t === 'string' ? Number(t) : NaN;
  if (!Number.isFinite(n)) return NaN;
  return n < 1e11 ? Math.round(n * 1000) : Math.round(n);
}

/** Structured fields whose value equals the IOC exactly (case-insensitive for domains/hashes). */
export function matchedFieldsFor(fields: Record<string, unknown>, ind: Indicator, strategy: FieldStrategy): string[] {
  const target = ind.type === 'ipv4' ? ind.value : ind.value.toLowerCase();
  const eq = (v: unknown) => typeof v === 'string' && (ind.type === 'ipv4' ? v : v.toLowerCase()) === target;
  const hits = iocFields(strategy, ind.type).filter((f) => eq(fields[f]));
  if (hits.length) return hits;
  const raw = fields._raw;
  return typeof raw === 'string' && raw.toLowerCase().includes(target) ? ['_raw'] : [];
}

export function toEvidenceEvents(rows: Record<string, unknown>[], ind: Indicator, strategy: FieldStrategy, idPrefix: string, offset = 0): EvidenceEvent[] {
  return rows.map((r, i) => {
    const { _time, dataset, ...rest } = r;
    return {
      id: `${idPrefix}-${offset + i}`,
      time: eventTimeMs(_time),
      dataset: typeof dataset === 'string' ? dataset : 'unknown',
      fields: rest,
      matchedFields: matchedFieldsFor(rest, ind, strategy),
    };
  });
}

/** Search job status: the documented example nests it under items[0], the schema is flat. */
export function jobStatus(body: unknown): string | null {
  const b = (body ?? {}) as { status?: unknown; items?: { status?: unknown }[] };
  const s = b.items?.[0]?.status ?? b.status;
  return typeof s === 'string' ? s : null;
}

export function jobId(body: unknown): string | null {
  const b = (body ?? {}) as { id?: unknown; items?: { id?: unknown }[] };
  const id = b.items?.[0]?.id ?? b.id;
  return typeof id === 'string' ? id : null;
}

/** Lookup content JSON: { fields: ['__id', …], items: [[cells]] } → row objects without __id. */
export function lookupRows(body: unknown): Record<string, string>[] {
  const b = (body ?? {}) as { fields?: unknown; items?: unknown };
  const fields = Array.isArray(b.fields) ? b.fields.map(String) : [];
  const items = Array.isArray(b.items) ? b.items : [];
  return items
    .filter(Array.isArray)
    .map((cells: unknown[]) => {
      const row: Record<string, string> = {};
      fields.forEach((f, i) => {
        if (f !== '__id') row[f] = cells[i] == null ? '' : String(cells[i]);
      });
      return row;
    });
}

/** Columns whose cell equals the IOC exactly (case-insensitive). Substring hits don't count. */
export function exactMatchColumns(row: Record<string, string>, value: string): string[] {
  const v = value.toLowerCase();
  return Object.entries(row)
    .filter(([, c]) => c.trim().toLowerCase() === v)
    .map(([k]) => k);
}
