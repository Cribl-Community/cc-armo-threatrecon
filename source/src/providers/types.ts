import type { AppSettings } from '../core/settings.ts';
import type { Indicator, LookupResult, ProviderError, SearchResult, TimeRange, VtResult } from '../core/types.ts';

export interface ProviderContext {
  signal: AbortSignal;
  settings: AppSettings;
}

export interface DatasetInfo {
  id: string;
  provider: string | null;
  type: string | null;
  description: string | null;
}

export interface LookupInfo {
  id: string;
  groupId: string;
  size: number | null;
  description: string | null;
}

/** Internal knowledge / watch-list evidence. */
export interface EvidenceLookupProvider {
  readonly kind: 'lookups';
  readonly demo: boolean;
  listLookups(ctx: ProviderContext): Promise<LookupInfo[]>;
  check(ind: Indicator, ctx: ProviderContext): Promise<LookupResult>;
}

export interface SearchProgress {
  phase: 'submitting' | 'running' | 'fetching';
  jobId?: string;
  detail?: string;
}

/** Telemetry evidence from Cribl Search / Cribl Lake. */
export interface SearchProvider {
  readonly kind: 'search';
  readonly demo: boolean;
  listDatasets(ctx: ProviderContext): Promise<DatasetInfo[]>;
  search(ind: Indicator, range: TimeRange, datasets: string[], ctx: ProviderContext, onProgress?: (p: SearchProgress) => void): Promise<SearchResult>;
}

/** External reputation. */
export interface ThreatIntelProvider {
  readonly kind: 'virustotal';
  readonly demo: boolean;
  lookup(ind: Indicator, ctx: ProviderContext): Promise<VtResult>;
}

export interface ProviderSet {
  lookups: EvidenceLookupProvider;
  search: SearchProvider;
  virustotal: ThreatIntelProvider;
}

/** Thrown by providers so the runner can render a provider-specific error without failing the run. */
export class ProviderFailure extends Error {
  readonly error: ProviderError;
  constructor(error: ProviderError) {
    super(error.message);
    this.error = error;
  }
}
