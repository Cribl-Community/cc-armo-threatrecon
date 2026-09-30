import { useState, type ReactNode } from 'react';
import { Link, Text } from '@capra/core';
import { Bug, CircleCheckFilled, CircleXFilled, Database, Hashtag } from '@capra/icons';
import type { EvidenceSummary } from '../core/evidence';
import { IOC_TYPE_LABELS } from '../core/ioc';
import { formatInZone } from '../core/timeRange';
import { vtVerdict } from '../core/verdict';
import type { Indicator, LookupResult, Outcomes, TimeRange, VtResult } from '../core/types';
import { DemoBadge, Pill, Running, SectionTitle, StatusIcon } from '../ui/common';

const dateOrNA = (ms: number | null, tz: string) => (ms ? formatInZone(ms, tz) : null);

function Row({ label, children }: { label: string; children: ReactNode | null }) {
  if (children === null || children === undefined || children === '') return null;
  return (
    <>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </>
  );
}

type Tab = 'overview' | 'virustotal' | 'lookups' | 'evidence' | 'related';

export function IndicatorDetails({ ind, outcomes, summary, range, onCopy }: { ind: Indicator; outcomes: Outcomes; summary: EvidenceSummary | null; range: TimeRange; onCopy: () => void }) {
  const [tab, setTab] = useState<Tab>('overview');
  const vt = outcomes.virustotal.data;
  const lk = outcomes.lookups.data;
  const tz = range.timezone;
  const tabs: [Tab, string][] = [
    ['overview', 'Overview'],
    ['virustotal', 'VirusTotal'],
    ['lookups', 'Lookups'],
    ['evidence', 'Cribl Evidence'],
    ['related', 'Related Indicators'],
  ];
  const related = relatedIndicators(ind, outcomes);
  return (
    <section className="panel" aria-label="Indicator details">
      <SectionTitle icon={<Hashtag size="sm" />}>Indicator Details</SectionTitle>
      <div className="tabs" role="tablist">
        {tabs.map(([id, label]) => (
          <button key={id} role="tab" className="tab" aria-selected={tab === id} onClick={() => setTab(id)} type="button">
            {label}
          </button>
        ))}
      </div>
      <div role="tabpanel">
        {tab === 'overview' && (
          <dl className="kv">
            <Row label="Type">
              <Pill tone="brand">{IOC_TYPE_LABELS[ind.type]}</Pill>
            </Row>
            <Row label="Value">
              <span className="row">
                <span className="mono">{ind.value}</span>
                <button className="icon-btn" type="button" onClick={onCopy} aria-label="Copy indicator">
                  ⧉
                </button>
              </span>
            </Row>
            <Row label="Scanner verdict">{vt ? <VtPill vt={vt} /> : null}</Row>
            <Row label="Community reputation">{vt && vt.reputation !== null ? String(vt.reputation) : null}</Row>
            <Row label="Categories">{vt && (vt.categories.length || vt.tags.length) ? <span className="row">{[...vt.categories, ...vt.tags].slice(0, 6).map((c) => <Pill key={c}>{c}</Pill>)}</span> : null}</Row>
            <Row label="First seen (VT)">{vt ? dateOrNA(vt.firstSeenDate, tz) : null}</Row>
            <Row label="Last analysis (VT)">{vt ? dateOrNA(vt.lastAnalysisDate, tz) : null}</Row>
            <Row label="First seen (Cribl)">{summary?.firstSeen ? formatInZone(summary.firstSeen, tz, true) : null}</Row>
            <Row label="Last seen (Cribl)">{summary?.lastSeen ? formatInZone(summary.lastSeen, tz, true) : null}</Row>
            <Row label="Lookup matches">{lk ? `${lk.matchedTables} of ${lk.checkedTables} tables` : null}</Row>
          </dl>
        )}
        {tab === 'virustotal' && (vt ? <VtAttributes vt={vt} tz={tz} /> : <NotAvailable what="VirusTotal data" />)}
        {tab === 'lookups' && (lk ? <LookupTable data={lk} /> : <NotAvailable what="Lookup results" />)}
        {tab === 'evidence' &&
          (summary ? (
            <dl className="kv">
              <Row label="Events">{summary.totalEvents.toLocaleString()}</Row>
              <Row label="Datasets">{summary.datasets.map((d) => d.value).join(', ') || null}</Row>
              <Row label="Matched fields">{summary.matchedFields.map((d) => d.value).join(', ') || null}</Row>
              <Row label="Source hosts">{summary.sourceHostCount ? String(summary.sourceHostCount) : null}</Row>
              <Row label="Users">{summary.userCount ? String(summary.userCount) : null}</Row>
            </dl>
          ) : (
            <NotAvailable what="Cribl Search evidence" />
          ))}
        {tab === 'related' &&
          (related.length ? (
            <ul className="evidence-list">
              {related.map((r) => (
                <li key={`${r.kind}:${r.value}`}>
                  <Pill>{r.kind}</Pill>
                  <span className="mono">{r.value}</span>
                  <Text variant="body-xs-normal" color="secondary">
                    from {r.source}
                  </Text>
                </li>
              ))}
            </ul>
          ) : (
            <NotAvailable what="Related indicators" detail="Only relationships present in returned provider data are shown. None were returned for this indicator." />
          ))}
      </div>
    </section>
  );
}

/** Related indicators come only from returned data (VT network attribute, observed event fields). */
function relatedIndicators(ind: Indicator, outcomes: Outcomes) {
  const out: { kind: string; value: string; source: string }[] = [];
  const vt = outcomes.virustotal.data;
  if (vt?.network && vt.network !== ind.value) out.push({ kind: 'network', value: vt.network, source: 'VirusTotal' });
  const events = outcomes.search.data?.events ?? [];
  const seen = new Set<string>();
  for (const e of events) {
    for (const [k, v] of Object.entries(e.fields)) {
      if (typeof v !== 'string' || v === ind.value || seen.has(v)) continue;
      if ((k === 'query' || k === 'domain' || k === 'fqdn') && ind.type !== 'domain') {
        seen.add(v);
        out.push({ kind: 'domain', value: v, source: `event field ${k}` });
      }
      if ((k === 'dst_ip' || k === 'dest_ip') && ind.type === 'domain') {
        seen.add(v);
        out.push({ kind: 'ip', value: v, source: `event field ${k}` });
      }
    }
    if (out.length >= 8) break;
  }
  return out;
}

function NotAvailable({ what, detail }: { what: string; detail?: string }) {
  return (
    <div className="stack" style={{ padding: '8px 0' }}>
      <Text variant="body-sm-semibold">{what}: not available</Text>
      <Text variant="body-xs-normal" color="secondary">
        {detail ?? 'The source was not selected, did not complete, or returned no data.'}
      </Text>
    </div>
  );
}

function VtPill({ vt }: { vt: VtResult }) {
  const v = vtVerdict(vt);
  return <Pill tone={v === 'malicious' ? 'danger' : v === 'suspicious' ? 'warning' : v === 'clean' ? 'success' : 'neutral'}>{`${v[0].toUpperCase()}${v.slice(1)} · ${vt.stats.malicious}/${vt.totalEngines}`}</Pill>;
}

function VtAttributes({ vt, tz }: { vt: VtResult; tz: string }) {
  return (
    <dl className="kv">
      <Row label="Object">{vt.objectType}</Row>
      <Row label="ASN">{vt.asn !== null ? `AS${vt.asn}` : null}</Row>
      <Row label="AS owner">{vt.asOwner}</Row>
      <Row label="Country">{vt.country}</Row>
      <Row label="Network">{vt.network}</Row>
      <Row label="Registrar">{vt.registrar}</Row>
      <Row label="File name">{vt.meaningfulName}</Row>
      <Row label="File type">{vt.typeDescription}</Row>
      <Row label="Size">{vt.size !== null ? `${vt.size.toLocaleString()} bytes` : null}</Row>
      <Row label="Reputation">{vt.reputation !== null ? `${vt.reputation} (community score, not a scanner verdict)` : null}</Row>
      <Row label="Tags">{vt.tags.length ? vt.tags.join(', ') : null}</Row>
      <Row label="Last analysis">{vt.lastAnalysisDate ? formatInZone(vt.lastAnalysisDate, tz) : null}</Row>
    </dl>
  );
}

// ── VirusTotal panel ─────────────────────────────────────────────────
const SEGMENTS: { key: 'malicious' | 'suspicious' | 'harmless' | 'undetected'; label: string }[] = [
  { key: 'malicious', label: 'Malicious' },
  { key: 'suspicious', label: 'Suspicious' },
  { key: 'harmless', label: 'Harmless' },
  { key: 'undetected', label: 'Undetected' },
];

export function VtPanel({ outcome }: { outcome: Outcomes['virustotal'] }) {
  const vt = outcome.data;
  return (
    <section className="panel" aria-label="Threat intelligence (VirusTotal)">
      <SectionTitle icon={<Bug size="sm" />} extra={outcome.demo && vt ? <DemoBadge /> : undefined}>
        Threat Intelligence (VirusTotal)
      </SectionTitle>
      {outcome.status === 'running' && <Running label="Querying external intelligence…" />}
      {(outcome.status === 'skipped' || outcome.status === 'idle') && <Text variant="body-sm-normal" color="secondary">VirusTotal was not selected for this investigation.</Text>}
      {(outcome.status === 'error' || outcome.status === 'unavailable') && (
        <div className="stack">
          <span className="row">
            <StatusIcon tone={outcome.error?.kind === 'not_found' ? 'neutral' : 'warning'} />
            <Text variant="body-sm-semibold">{outcome.error?.message}</Text>
          </span>
          {outcome.error?.hint && <Text variant="body-xs-normal" color="secondary">{outcome.error.hint}</Text>}
        </div>
      )}
      {vt && (
        <>
          <div className="donut-wrap">
            <Donut vt={vt} />
            <div className="legend">
              {SEGMENTS.map((s) => (
                <FragmentRow key={s.key} dot={`dot-${s.key}`} label={s.label} value={vt.stats[s.key]} />
              ))}
              {vt.stats.timeout + vt.stats.other > 0 && <FragmentRow dot="dot-undetected" label="Timeout / other" value={vt.stats.timeout + vt.stats.other} />}
            </div>
          </div>
          <Text variant="body-xs-normal" color="secondary">
            Scanner statistics from the last analysis{vt.reputation !== null ? ` · Community reputation: ${vt.reputation}` : ''}
          </Text>
          {(vt.popularThreatLabels.length > 0 || vt.tags.length > 0) && (
            <div className="stack">
              <Text variant="body-xs-semibold" color="secondary">
                {vt.popularThreatLabels.length ? 'Popular threat labels' : 'Tags'}
              </Text>
              <div className="row">
                {(vt.popularThreatLabels.length ? vt.popularThreatLabels : vt.tags).map((t) => (
                  <Pill key={t} tone="danger">
                    {t}
                  </Pill>
                ))}
              </div>
            </div>
          )}
          <Link href={vt.guiUrl} target="_blank" isExternal>
            View full VirusTotal report
          </Link>
        </>
      )}
    </section>
  );
}

function FragmentRow({ dot, label, value }: { dot: string; label: string; value: number }) {
  return (
    <>
      <span className={`legend__dot ${dot}`} aria-hidden />
      <Text variant="body-sm-normal">{label}</Text>
      <Text variant="body-sm-semibold">{value}</Text>
    </>
  );
}

function Donut({ vt }: { vt: VtResult }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const total = Math.max(1, vt.totalEngines);
  const lens = SEGMENTS.map((s) => (vt.stats[s.key] / total) * c);
  const offsets = lens.map((_, i) => lens.slice(0, i).reduce((a, b) => a + b, 0));
  return (
    <svg width="140" height="140" viewBox="0 0 140 140" role="img" aria-label={`${vt.stats.malicious} of ${vt.totalEngines} engines flagged malicious`}>
      <circle className="donut__ring" cx="70" cy="70" r={r} strokeWidth="14" fill="none" />
      {SEGMENTS.map((s, i) =>
        lens[i] > 0 ? <circle key={s.key} className={`seg-${s.key}`} cx="70" cy="70" r={r} strokeWidth="14" fill="none" strokeDasharray={`${lens[i]} ${c - lens[i]}`} strokeDashoffset={-offsets[i]} transform="rotate(-90 70 70)" /> : null,
      )}
      <text className="donut__center" x="70" y="68" textAnchor="middle" fontSize="22" fontWeight="700">
        {vt.stats.malicious} / {vt.totalEngines}
      </text>
      <text className="donut__sub" x="70" y="88" textAnchor="middle" fontSize="12">
        malicious
      </text>
    </svg>
  );
}

// ── Lookups panel ────────────────────────────────────────────────────
export function LookupsPanel({ outcome }: { outcome: Outcomes['lookups'] }) {
  return (
    <section className="panel" aria-label="Cribl lookups">
      <SectionTitle icon={<Database size="sm" />} extra={outcome.demo && outcome.data ? <DemoBadge /> : undefined}>
        Cribl Lookups
      </SectionTitle>
      {outcome.status === 'running' && <Running label="Checking internal intelligence…" />}
      {(outcome.status === 'skipped' || outcome.status === 'idle') && <Text variant="body-sm-normal" color="secondary">Cribl Lookups were not selected for this investigation.</Text>}
      {(outcome.status === 'error' || outcome.status === 'unavailable') && (
        <div className="stack">
          <span className="row">
            <StatusIcon tone="warning" />
            <Text variant="body-sm-semibold">{outcome.error?.message ?? 'Lookup access unavailable.'}</Text>
          </span>
          {outcome.error?.hint && <Text variant="body-xs-normal" color="secondary">{outcome.error.hint}</Text>}
        </div>
      )}
      {outcome.data && <LookupTable data={outcome.data} />}
    </section>
  );
}

function LookupTable({ data }: { data: LookupResult }) {
  if (data.tables.length === 0) return <Text variant="body-sm-normal" color="secondary">No lookup tables were available to check.</Text>;
  return (
    <div className="stack">
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Lookup Name</th>
              <th>Match</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {[...data.tables]
              .sort((a, b) => Number(b.matched) - Number(a.matched) || a.id.localeCompare(b.id))
              .map((t) => (
                <tr key={`${t.groupId}/${t.id}`}>
                  <td className="mono">{t.id}</td>
                  <td>
                    {t.error ? (
                      <span className="match tone-warning">Error</span>
                    ) : t.matched ? (
                      <span className="match tone-danger">
                        <CircleXFilled size="xs" /> Yes
                      </span>
                    ) : (
                      <span className="match tone-success">
                        <CircleCheckFilled size="xs" /> No
                      </span>
                    )}
                  </td>
                  <td title={t.error ?? ''}>{t.error ? t.error : t.matched ? describeRow(t.rows[0], t.matchedColumns) : '–'}</td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
      {data.skipped.length > 0 && (
        <Text variant="body-xs-normal" color="secondary">
          Skipped: {data.skipped.map((s) => `${s.id} (${s.reason})`).join(', ')}
        </Text>
      )}
    </div>
  );
}

function describeRow(row: Record<string, string> | undefined, matched: string[]): string {
  if (!row) return 'Matched';
  const rest = Object.entries(row)
    .filter(([k]) => !matched.includes(k))
    .slice(0, 3)
    .map(([k, v]) => `${k}: ${v}`);
  return rest.length ? rest.join(' · ') : `Matched on ${matched.join(', ')}`;
}
