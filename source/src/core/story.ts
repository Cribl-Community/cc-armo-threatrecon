import type { EvidenceSummary } from './evidence.ts';
import { IOC_TYPE_LABELS } from './ioc.ts';
import { formatInZone, zoneAbbrev } from './timeRange.ts';
import type { Indicator, Outcomes, ProviderId, TimeRange } from './types.ts';
import { vtVerdict } from './verdict.ts';

const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;

const list = (xs: string[]) => (xs.length <= 1 ? xs.join('') : `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1]}`);

/**
 * Deterministic narrative built only from structured results.
 * Vocabulary is restricted to "was found / was observed / was not observed / returned".
 */
export function incidentStory(ind: Indicator, range: TimeRange, selected: ProviderId[], outcomes: Outcomes, summary: EvidenceSummary | null): string[] {
  const out: string[] = [];
  const tz = range.timezone;
  const label = IOC_TYPE_LABELS[ind.type].replace(/ \(.*\)/, '');
  const window = `${formatInZone(range.startMs, tz)} and ${formatInZone(range.endMs, tz)} ${zoneAbbrev(tz, range.endMs)}`;

  const clauses: string[] = [];
  if (selected.includes('lookups') && outcomes.lookups.status === 'complete' && outcomes.lookups.data) {
    const l = outcomes.lookups.data;
    clauses.push(l.matchedTables > 0 ? `was found in ${plural(l.matchedTables, 'internal lookup table')} (${list(l.tables.filter((t) => t.matched).map((t) => t.id))})` : `was not found in the ${plural(l.checkedTables, 'internal lookup table')} checked`);
  }
  if (selected.includes('search') && outcomes.search.status === 'complete' && summary) {
    if (summary.totalEvents > 0) {
      const first = summary.firstSeen !== null ? formatInZone(summary.firstSeen, tz, true) : null;
      const last = summary.lastSeen !== null ? formatInZone(summary.lastSeen, tz, true) : null;
      clauses.push(`was observed ${plural(summary.totalEvents, 'time')} across ${plural(summary.datasetCount, 'dataset')}${first && last ? ` between ${first} and ${last} ${zoneAbbrev(tz)}` : ''}`);
    } else {
      clauses.push(`was not observed in Cribl telemetry between ${window}`);
    }
  }
  if (clauses.length) out.push(`The ${label} ${ind.value} ${list(clauses)}.`);

  if (summary && summary.totalEvents > 0) {
    const hosts = summary.sourceHosts.slice(0, 2).map((h) => h.value);
    const types = summary.eventTypes.slice(0, 3).map((t) => t.value);
    if (hosts.length) {
      out.push(`Most observations came from ${list(hosts)}${summary.sourceHostCount > hosts.length ? ` (${plural(summary.sourceHostCount, 'source host')} in total)` : ''}${types.length ? ` and were recorded as ${list(types)} events` : ''}.`);
    } else if (types.length) {
      out.push(`Observations were recorded as ${list(types)} events.`);
    }
    if (summary.users.length) out.push(`Associated users in the returned events: ${list(summary.users.slice(0, 3).map((u) => u.value))}.`);
    if (summary.truncated) out.push(`Only the first ${summary.events.toLocaleString()} matching events were retrieved for this view.`);
  }

  if (selected.includes('virustotal') && outcomes.virustotal.status === 'complete' && outcomes.virustotal.data) {
    const v = outcomes.virustotal.data;
    const verdict = vtVerdict(v);
    out.push(
      `VirusTotal returned ${v.stats.malicious} malicious and ${v.stats.suspicious} suspicious detections out of ${v.totalEngines} engines${verdict === 'clean' ? ', with no engine flagging it malicious' : ''}${v.reputation !== null ? `; community reputation score ${v.reputation}` : ''}.`,
    );
  } else if (selected.includes('virustotal') && outcomes.virustotal.error?.kind === 'not_found') {
    out.push('VirusTotal returned no record for this indicator.');
  }

  const failed = (['lookups', 'search', 'virustotal'] as const).filter((p) => selected.includes(p) && (outcomes[p].status === 'error' || outcomes[p].status === 'unavailable') && outcomes[p].error?.kind !== 'not_found');
  if (failed.length) out.push(`Not evaluated: ${list(failed.map((p) => ({ lookups: 'Cribl Lookups', search: 'Cribl Search', virustotal: 'VirusTotal' })[p]))} did not return a result.`);
  return out;
}
