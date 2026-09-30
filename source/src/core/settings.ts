import { DEFAULT_FIELDS, type FieldStrategy } from './fields.ts';
import type { ProviderId, TimePreset } from './types.ts';

export interface AppSettings {
  schemaVersion: 1;
  defaultPreset: Exclude<TimePreset, 'custom'>;
  defaultProviders: ProviderId[];
  /** Search datasets to query. Empty = the user must pick at run time. */
  datasets: string[];
  /** Config group whose lookup files are checked (Stream worker group id). */
  lookupGroupId: string;
  /** Lookup file ids to check. Empty = every lookup in the group (up to the cap). */
  lookupIds: string[];
  fields: FieldStrategy;
  /** Max events pulled into the browser for one investigation. */
  resultLimit: number;
  /** Max seconds to wait for a search job. */
  searchTimeoutSec: number;
  demoMode: boolean;
}

export const DEFAULT_SETTINGS: AppSettings = {
  schemaVersion: 1,
  defaultPreset: '24h',
  defaultProviders: ['lookups', 'search', 'virustotal'],
  datasets: [],
  lookupGroupId: 'default',
  lookupIds: [],
  fields: DEFAULT_FIELDS,
  resultLimit: 500,
  searchTimeoutSec: 120,
  demoMode: false,
};

/** Merge stored settings over defaults so new fields added later never come back undefined. */
export function withDefaults(stored: Partial<AppSettings> | null): AppSettings {
  if (!stored) return DEFAULT_SETTINGS;
  return { ...DEFAULT_SETTINGS, ...stored, fields: { ...DEFAULT_FIELDS, ...(stored.fields ?? {}) } };
}
