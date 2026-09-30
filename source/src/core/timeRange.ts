import type { TimePreset, TimeRange } from './types.ts';

export const PRESETS: { value: TimePreset; label: string; ms: number }[] = [
  { value: '15m', label: 'Last 15 minutes', ms: 15 * 60_000 },
  { value: '1h', label: 'Last 1 hour', ms: 3_600_000 },
  { value: '6h', label: 'Last 6 hours', ms: 6 * 3_600_000 },
  { value: '24h', label: 'Last 24 hours', ms: 24 * 3_600_000 },
  { value: '7d', label: 'Last 7 days', ms: 7 * 86_400_000 },
  { value: '30d', label: 'Last 30 days', ms: 30 * 86_400_000 },
  { value: 'custom', label: 'Custom', ms: 0 },
];

/** Hard ceiling for a single investigation window. */
export const MAX_WINDOW_MS = 90 * 86_400_000;
/** Windows longer than this get an explicit "broad search" warning. */
export const BROAD_WINDOW_MS = 7 * 86_400_000;
/** Allowed clock skew between browser and Cribl when checking "end in the future". */
const FUTURE_TOLERANCE_MS = 5 * 60_000;

export const browserTimezone = () => Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';

export function presetRange(preset: Exclude<TimePreset, 'custom'>, now: number = Date.now(), timezone = browserTimezone()): TimeRange {
  const def = PRESETS.find((p) => p.value === preset)!;
  return { preset, startMs: now - def.ms, endMs: now, timezone };
}

/** Re-anchor a relative preset to "now" at run time so a stale form never searches an old window. */
export function resolveRange(range: TimeRange, now: number = Date.now()): TimeRange {
  return range.preset === 'custom' ? range : presetRange(range.preset, now, range.timezone);
}

export type RangeCheck = { ok: true; warning: string | null } | { ok: false; error: string };

export function validateRange(range: TimeRange, now: number = Date.now()): RangeCheck {
  const { startMs, endMs } = range;
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) return { ok: false, error: 'Enter a valid start and end time.' };
  if (startMs >= endMs) return { ok: false, error: 'Start must be before end.' };
  if (endMs > now + FUTURE_TOLERANCE_MS) return { ok: false, error: 'End time is in the future.' };
  const span = endMs - startMs;
  if (span > MAX_WINDOW_MS) return { ok: false, error: `Window is longer than ${MAX_WINDOW_MS / 86_400_000} days. Narrow the time range.` };
  if (span > BROAD_WINDOW_MS) return { ok: true, warning: `Broad search: ${formatSpan(span)}. This may scan a large amount of data and take longer.` };
  return { ok: true, warning: null };
}

export function formatSpan(ms: number): string {
  const h = ms / 3_600_000;
  if (h < 1) return `${Math.round(ms / 60_000)} minutes`;
  if (h < 48) return `${Math.round(h * 10) / 10} hours`;
  return `${Math.round((h / 24) * 10) / 10} days`;
}

export function formatInZone(ms: number, timezone: string, withSeconds = false): string {
  return new Intl.DateTimeFormat('en-US', {
    timeZone: timezone,
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: withSeconds ? '2-digit' : undefined,
    hour12: false,
  }).format(new Date(ms));
}

export function zoneAbbrev(timezone: string, at: number = Date.now()): string {
  const parts = new Intl.DateTimeFormat('en-US', { timeZone: timezone, timeZoneName: 'short' }).formatToParts(new Date(at));
  return parts.find((p) => p.type === 'timeZoneName')?.value ?? timezone;
}

/** Convert a `datetime-local` string interpreted in the browser zone to epoch ms. */
export const fromLocalInput = (s: string) => (s ? new Date(s).getTime() : NaN);

export function toLocalInput(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
