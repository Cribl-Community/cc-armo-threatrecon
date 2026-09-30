import type { EvidencePoint, Outcomes, ProviderId, Verdict, VtResult, VtVerdict } from './types.ts';

/**
 * VirusTotal scanner thresholds. Only engine statistics count — the community
 * `reputation` score never makes an indicator malicious on its own.
 */
export const VT_THRESHOLDS = { maliciousEngines: 3, suspiciousEngines: 3 };

export function vtVerdict(vt: VtResult): VtVerdict {
  const { malicious, suspicious } = vt.stats;
  if (vt.totalEngines === 0) return 'unknown';
  if (malicious >= VT_THRESHOLDS.maliciousEngines) return 'malicious';
  if (malicious > 0 || suspicious >= VT_THRESHOLDS.suspiciousEngines) return 'suspicious';
  return 'clean';
}

const LABELS = {
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  internal_match: 'Internal Match',
  observed: 'Observed',
  no_evidence: 'No Evidence',
  inconclusive: 'Inconclusive',
} as const;

/**
 * Deterministic, explainable verdict. Rules are evaluated top to bottom:
 *
 *  1. No selected provider completed                       → INCONCLUSIVE
 *  2. VirusTotal malicious (≥3 engines)                   → MALICIOUS
 *  3. Internal lookup match AND observed in telemetry      → MALICIOUS
 *  4. VirusTotal suspicious (1–2 malicious or ≥3 susp.)   → SUSPICIOUS
 *  5. Internal lookup match (not observed / not searched)  → INTERNAL MATCH
 *  6. Observed in telemetry, no intel match                → OBSERVED
 *  7. Every selected provider completed with no positive   → NO EVIDENCE
 *  8. Otherwise (some providers failed, rest negative)     → INCONCLUSIVE
 *
 * The qualifier always states whether the IOC was observed. Absence from
 * telemetry is reported as "not observed in the selected window", never as safe.
 */
export function computeVerdict(outcomes: Outcomes, selected: ProviderId[]): Verdict {
  const evidence: EvidencePoint[] = [];
  const sel = (p: ProviderId) => selected.includes(p);
  const done = (p: 'lookups' | 'search' | 'virustotal') => sel(p) && outcomes[p].status === 'complete' && !!outcomes[p].data;

  const internalMatch = done('lookups') ? outcomes.lookups.data!.matchedTables > 0 : null;
  const observed = done('search') ? outcomes.search.data!.events.length > 0 || outcomes.search.data!.totalEvents > 0 : null;
  // A VirusTotal 404 is a completed check with a negative answer ("no record"), not a failure.
  const vtNoRecord = sel('virustotal') && outcomes.virustotal.error?.kind === 'not_found';
  const ext = done('virustotal') ? vtVerdict(outcomes.virustotal.data!) : vtNoRecord ? 'unknown' : null;

  if (internalMatch !== null) {
    const l = outcomes.lookups.data!;
    evidence.push(
      internalMatch
        ? { provider: 'lookups', weight: 'positive', text: `Found in ${l.matchedTables} of ${l.checkedTables} internal lookup table${l.checkedTables === 1 ? '' : 's'}.` }
        : { provider: 'lookups', weight: 'negative', text: `Not found in ${l.checkedTables} internal lookup table${l.checkedTables === 1 ? '' : 's'}.` },
    );
  }
  if (observed !== null) {
    const s = outcomes.search.data!;
    evidence.push(
      observed
        ? { provider: 'search', weight: 'positive', text: `Observed in ${s.totalEvents.toLocaleString()} event${s.totalEvents === 1 ? '' : 's'} in the selected time window.` }
        : { provider: 'search', weight: 'negative', text: 'No matching telemetry was found in the selected time range.' },
    );
  }
  if (vtNoRecord) {
    evidence.push({ provider: 'virustotal', weight: 'negative', text: 'VirusTotal has no record for this indicator.' });
  } else if (ext !== null) {
    const v = outcomes.virustotal.data!;
    const txt = `${v.stats.malicious} of ${v.totalEngines} VirusTotal engines flagged it malicious, ${v.stats.suspicious} suspicious.`;
    evidence.push({ provider: 'virustotal', weight: ext === 'malicious' || ext === 'suspicious' ? 'positive' : 'negative', text: txt });
  }
  for (const p of ['lookups', 'search', 'virustotal'] as const) {
    if (sel(p) && (outcomes[p].status === 'error' || outcomes[p].status === 'unavailable') && !(p === 'virustotal' && vtNoRecord)) {
      evidence.push({ provider: p, weight: 'neutral', text: `${providerName(p)} could not be checked: ${outcomes[p].error?.message ?? 'unavailable'}.` });
    }
  }

  const qualifier = observed === true ? 'Observed' : observed === false ? 'Not observed' : null;
  const signals = { internalMatch, externalVerdict: ext, observed };
  const make = (level: Verdict['level'], explanation: string, q = qualifier): Verdict => ({ level, label: LABELS[level], qualifier: q, explanation, evidence, signals });

  const anyDone = internalMatch !== null || observed !== null || ext !== null;
  if (!anyDone) return make('inconclusive', 'None of the selected sources returned a result, so no conclusion can be drawn.', null);

  const where = observed === true ? ' and was observed in Cribl telemetry during the selected time window' : observed === false ? '; no matching telemetry was found in the selected time window' : '';

  if (ext === 'malicious') {
    const intel = internalMatch ? 'Found in internal lookups and flagged malicious by VirusTotal engines' : 'Flagged malicious by VirusTotal engines';
    return make('malicious', `${intel}${where}.`);
  }
  if (internalMatch && observed) return make('malicious', 'Found in internal threat-intelligence lookup data and observed in Cribl telemetry during the selected time window.');
  if (ext === 'suspicious') return make('suspicious', `Some VirusTotal engines flagged this indicator${where}.`);
  if (internalMatch) return make('internal_match', `Found in internal lookup data${where || '; telemetry was not searched'}.`);
  if (observed) return make('observed', 'Observed in Cribl telemetry, but no selected threat-intelligence source returned a malicious match.');

  const allSelectedDone = (['lookups', 'search', 'virustotal'] as const).filter(sel).every((p) => done(p) || (p === 'virustotal' && vtNoRecord));
  if (allSelectedDone) {
    const parts = [
      observed === false ? 'no matching telemetry was found during the selected time range' : null,
      internalMatch === false ? 'no selected internal lookup matched' : null,
      vtNoRecord ? 'VirusTotal has no record of it' : ext === 'clean' ? 'VirusTotal engines did not flag it' : ext === 'unknown' ? 'VirusTotal returned no scanner results' : null,
    ].filter(Boolean);
    return make('no_evidence', `${capitalize(parts.join(', '))}.`);
  }
  return make('inconclusive', 'Sources that completed found nothing, but at least one selected source failed, so the result is incomplete.');
}

export const providerName = (p: ProviderId) =>
  ({ lookups: 'Cribl Lookups', search: 'Cribl Lake / Search', virustotal: 'VirusTotal', otherIntel: 'Other Threat Intel', whois: 'WHOIS / DNS' })[p];

const capitalize = (s: string) => (s ? s[0].toUpperCase() + s.slice(1) : s);
