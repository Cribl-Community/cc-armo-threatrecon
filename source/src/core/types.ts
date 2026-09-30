export type IocType = 'ipv4' | 'ipv6' | 'domain' | 'md5' | 'sha1' | 'sha256';

export interface Indicator {
  /** Exactly what the user typed (never sent anywhere). */
  raw: string;
  /** Normalized value used for every query. */
  value: string;
  type: IocType;
}

export type ProviderId = 'lookups' | 'search' | 'virustotal' | 'otherIntel' | 'whois';

export type ProviderStatus = 'idle' | 'skipped' | 'running' | 'complete' | 'unavailable' | 'error';

export type ProviderErrorKind =
  | 'permission'
  | 'not_found'
  | 'rate_limited'
  | 'not_configured'
  | 'unavailable'
  | 'timeout'
  | 'network'
  | 'server'
  | 'invalid';

export interface ProviderError {
  kind: ProviderErrorKind;
  message: string;
  hint?: string;
  httpStatus?: number;
}

export type TimePreset = '15m' | '1h' | '6h' | '24h' | '7d' | '30d' | 'custom';

export interface TimeRange {
  preset: TimePreset;
  startMs: number;
  endMs: number;
  /** IANA zone used for display, e.g. "Europe/Berlin". Queries are always UTC epoch. */
  timezone: string;
}

// ── Lookups ─────────────────────────────────────────────────────────
export interface LookupTableResult {
  id: string;
  groupId: string;
  matched: boolean;
  matchedColumns: string[];
  /** Matching rows only, capped. */
  rows: Record<string, string>[];
  rowCount: number | null;
  error?: string;
}

export interface LookupResult {
  tables: LookupTableResult[];
  matchedTables: number;
  checkedTables: number;
  skipped: { id: string; reason: string }[];
}

// ── Search ──────────────────────────────────────────────────────────
export interface EvidenceEvent {
  id: string;
  /** Epoch milliseconds. */
  time: number;
  dataset: string;
  fields: Record<string, unknown>;
  matchedFields: string[];
}

export interface SearchResult {
  query: string;
  jobId: string | null;
  datasets: string[];
  events: EvidenceEvent[];
  /** Total matches reported by the search job (may exceed events.length). */
  totalEvents: number;
  truncated: boolean;
  completion: 'completed' | 'partial' | 'timeout';
}

// ── VirusTotal ──────────────────────────────────────────────────────
export interface VtStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout: number;
  other: number;
}

export interface VtResult {
  objectType: 'ip_address' | 'domain' | 'file';
  id: string;
  stats: VtStats;
  totalEngines: number;
  /** VirusTotal community reputation score (not a scanner verdict). */
  reputation: number | null;
  tags: string[];
  categories: string[];
  popularThreatLabels: string[];
  asn: number | null;
  asOwner: string | null;
  country: string | null;
  network: string | null;
  registrar: string | null;
  meaningfulName: string | null;
  typeDescription: string | null;
  size: number | null;
  lastAnalysisDate: number | null;
  firstSeenDate: number | null;
  guiUrl: string;
}

export type VtVerdict = 'malicious' | 'suspicious' | 'clean' | 'unknown';

// ── Outcomes & investigation ────────────────────────────────────────
export interface ProviderOutcome<T> {
  status: ProviderStatus;
  data?: T;
  error?: ProviderError;
  startedAt?: number;
  finishedAt?: number;
  demo: boolean;
}

export interface Outcomes {
  lookups: ProviderOutcome<LookupResult>;
  search: ProviderOutcome<SearchResult>;
  virustotal: ProviderOutcome<VtResult>;
}

export type VerdictLevel = 'malicious' | 'suspicious' | 'internal_match' | 'observed' | 'no_evidence' | 'inconclusive';

export interface EvidencePoint {
  provider: ProviderId;
  text: string;
  weight: 'positive' | 'negative' | 'neutral';
}

export interface Verdict {
  level: VerdictLevel;
  label: string;
  /** Qualifier shown next to the label, e.g. "Not observed". */
  qualifier: string | null;
  explanation: string;
  evidence: EvidencePoint[];
  signals: { internalMatch: boolean | null; externalVerdict: VtVerdict | null; observed: boolean | null };
}

export interface InvestigationRequest {
  indicator: Indicator;
  timeRange: TimeRange;
  providers: ProviderId[];
  datasets: string[];
  demo: boolean;
}

export interface SavedInvestigation {
  id: string;
  createdAt: string;
  indicator: Indicator;
  timeRange: TimeRange;
  providers: ProviderId[];
  datasets: string[];
  demo: boolean;
  verdict: { level: VerdictLevel; label: string; qualifier: string | null; explanation: string };
  summary: string;
  counts: { lookupMatches: number | null; events: number | null; hosts: number | null; datasets: number | null; vtMalicious: number | null; vtTotal: number | null };
  providerStatus: Partial<Record<ProviderId, ProviderStatus>>;
}

export type DetectionStatus = 'draft' | 'reviewed' | 'saved';

export interface DetectionCandidate {
  id: string;
  name: string;
  createdAt: string;
  indicator: Indicator;
  why: string;
  query: string;
  datasets: string[];
  fields: string[];
  evidence: { events: number; datasets: number; hosts: number; firstSeen: number | null; lastSeen: number | null };
  status: DetectionStatus;
  demo: boolean;
}
