import type { Indicator, ProviderError, VtResult, VtStats } from './types.ts';

export const VT_API = 'https://www.virustotal.com/api/v3';

export function vtEndpoint(ind: Indicator): string {
  const id = encodeURIComponent(ind.value);
  if (ind.type === 'ipv4' || ind.type === 'ipv6') return `${VT_API}/ip_addresses/${id}`;
  if (ind.type === 'domain') return `${VT_API}/domains/${id}`;
  return `${VT_API}/files/${id}`;
}

export function vtGuiUrl(ind: Indicator): string {
  const id = encodeURIComponent(ind.value);
  if (ind.type === 'ipv4' || ind.type === 'ipv6') return `https://www.virustotal.com/gui/ip-address/${id}`;
  if (ind.type === 'domain') return `https://www.virustotal.com/gui/domain/${id}`;
  return `https://www.virustotal.com/gui/file/${id}`;
}

type Obj = Record<string, unknown>;
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const str = (v: unknown): string | null => (typeof v === 'string' && v.length > 0 ? v : null);
const obj = (v: unknown): Obj => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : {});

/** Parse a VirusTotal v3 object response ({ data: { type, id, attributes } }). */
export function parseVtObject(body: unknown, ind: Indicator): VtResult {
  const data = obj(obj(body).data);
  const a = obj(data.attributes);
  const raw = obj(a.last_analysis_stats);
  const n = (k: string) => num(raw[k]) ?? 0;
  const known = ['malicious', 'suspicious', 'harmless', 'undetected', 'timeout'];
  const other = Object.entries(raw)
    .filter(([k]) => !known.includes(k))
    .reduce((acc, [, v]) => acc + (num(v) ?? 0), 0);
  const stats: VtStats = { malicious: n('malicious'), suspicious: n('suspicious'), harmless: n('harmless'), undetected: n('undetected'), timeout: n('timeout'), other };
  const totalEngines = stats.malicious + stats.suspicious + stats.harmless + stats.undetected + stats.timeout + stats.other;

  const categories = [...new Set(Object.values(obj(a.categories)).filter((v): v is string => typeof v === 'string'))];
  const ptc = obj(a.popular_threat_classification);
  const labels = [
    str(ptc.suggested_threat_label),
    ...[...(Array.isArray(ptc.popular_threat_category) ? ptc.popular_threat_category : []), ...(Array.isArray(ptc.popular_threat_name) ? ptc.popular_threat_name : [])].map((x) => str(obj(x).value)),
  ].filter((x): x is string => !!x);

  const type = str(data.type);
  return {
    objectType: type === 'domain' ? 'domain' : type === 'file' ? 'file' : type === 'ip_address' ? 'ip_address' : ind.type === 'domain' ? 'domain' : ind.type.startsWith('ip') ? 'ip_address' : 'file',
    id: str(data.id) ?? ind.value,
    stats,
    totalEngines,
    reputation: num(a.reputation),
    tags: Array.isArray(a.tags) ? a.tags.filter((t): t is string => typeof t === 'string') : [],
    categories,
    popularThreatLabels: [...new Set(labels)].slice(0, 8),
    asn: num(a.asn),
    asOwner: str(a.as_owner),
    country: str(a.country),
    network: str(a.network),
    registrar: str(a.registrar),
    meaningfulName: str(a.meaningful_name),
    typeDescription: str(a.type_description),
    size: num(a.size),
    lastAnalysisDate: num(a.last_analysis_date) !== null ? num(a.last_analysis_date)! * 1000 : null,
    firstSeenDate: (num(a.first_submission_date) ?? num(a.creation_date) ?? num(a.whois_date)) !== null ? (num(a.first_submission_date) ?? num(a.creation_date) ?? num(a.whois_date))! * 1000 : null,
    guiUrl: vtGuiUrl(ind),
  };
}

/** Map HTTP status + VT error code to a user-facing, key-free message. */
export function vtError(status: number, body?: unknown): ProviderError {
  const code = str(obj(obj(body).error).code) ?? '';
  if (status === 404 || code === 'NotFoundError') return { kind: 'not_found', httpStatus: status, message: 'VirusTotal has no record for this indicator.' };
  if (status === 429 || code === 'QuotaExceededError' || code === 'TooManyRequestsError') return { kind: 'rate_limited', httpStatus: status, message: 'VirusTotal rate limit reached. Try again later.' };
  if (status === 401 || code === 'WrongCredentialsError' || code === 'AuthenticationRequiredError') return { kind: 'not_configured', httpStatus: status, message: 'VirusTotal rejected the API key.', hint: 'Check the VirusTotal API key in Settings.' };
  if (status === 403) return { kind: 'permission', httpStatus: status, message: 'VirusTotal access is not enabled for this App.', hint: 'An admin must authorize www.virustotal.com for this App, or the VirusTotal key lacks access.' };
  if (status >= 500) return { kind: 'server', httpStatus: status, message: 'VirusTotal is unavailable right now.' };
  return { kind: 'server', httpStatus: status, message: `External lookup failed (HTTP ${status}).`, hint: 'Check VirusTotal configuration.' };
}
