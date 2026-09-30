import { useMemo, useState } from 'react';
import { Button, Drawer, Text } from '@capra/core';
import { Search } from '@capra/icons';
import { evidenceColumns, type EvidenceSummary, type Ranked } from '../core/evidence';
import type { FieldStrategy } from '../core/fields';
import { formatInZone, zoneAbbrev } from '../core/timeRange';
import type { EvidenceEvent, Outcomes, TimeRange } from '../core/types';
import { DemoBadge, Running, SectionTitle, StatusIcon, fmtInt } from '../ui/common';

const INITIAL_ROWS = 10;

export function EvidencePanel({ outcome, summary, range, fields, selectedId, onSelect, progressLabel }: { outcome: Outcomes['search']; summary: EvidenceSummary | null; range: TimeRange; fields: FieldStrategy; selectedId: string | null; onSelect: (id: string | null) => void; progressLabel: string }) {
  const [showAll, setShowAll] = useState(false);
  const events = useMemo(() => outcome.data?.events ?? [], [outcome.data]);
  const cols = useMemo(() => evidenceColumns(events, fields), [events, fields]);
  const tz = range.timezone;
  const rows = showAll ? events : events.slice(0, INITIAL_ROWS);
  const selected = events.find((e) => e.id === selectedId) ?? null;
  const title = summary && summary.totalEvents > 0 ? `Observed in Cribl Lake (${fmtInt(summary.totalEvents)} event${summary.totalEvents === 1 ? '' : 's'})` : 'Observed in Cribl Lake';

  return (
    <section className="panel" aria-label="Cribl Lake evidence">
      <SectionTitle icon={<Search size="sm" />} extra={outcome.demo && outcome.data ? <DemoBadge /> : undefined}>
        {title}
      </SectionTitle>
      {outcome.status === 'running' && <Running label={progressLabel} />}
      {(outcome.status === 'skipped' || outcome.status === 'idle') && <Text variant="body-sm-normal" color="secondary">Cribl Lake / Search was not selected for this investigation.</Text>}
      {(outcome.status === 'error' || outcome.status === 'unavailable') && (
        <div className="stack">
          <span className="row">
            <StatusIcon tone="warning" />
            <Text variant="body-sm-semibold">{outcome.error?.message ?? 'Search failed.'}</Text>
          </span>
          {outcome.error?.hint && <Text variant="body-xs-normal" color="secondary">{outcome.error.hint}</Text>}
        </div>
      )}
      {outcome.data && summary && summary.totalEvents === 0 && (
        <div className="stack">
          <Text variant="body-md-semibold">No evidence found</Text>
          <Text variant="body-sm-normal" color="secondary">
            Nothing matching this indicator was found during the selected time window in {outcome.data.datasets.length ? outcome.data.datasets.join(', ') : 'the searched datasets'}.
          </Text>
        </div>
      )}
      {outcome.data && summary && summary.totalEvents > 0 && (
        <>
          <div className="stats">
            <Stat label="Events" value={fmtInt(summary.totalEvents)} />
            <Stat label="Source hosts" value={fmtInt(summary.sourceHostCount)} />
            <Stat label="Datasets" value={fmtInt(summary.datasetCount)} />
            {summary.userCount > 0 && <Stat label="Users" value={fmtInt(summary.userCount)} />}
            <Stat label="First seen" value={summary.firstSeen ? formatInZone(summary.firstSeen, tz, true).split(', ').slice(-1)[0] : '–'} sub={summary.firstSeen ? formatInZone(summary.firstSeen, tz).split(',')[0] : undefined} />
            <Stat label="Last seen" value={summary.lastSeen ? formatInZone(summary.lastSeen, tz, true).split(', ').slice(-1)[0] : '–'} sub={summary.lastSeen ? `${formatInZone(summary.lastSeen, tz).split(',')[0]} · ${zoneAbbrev(tz)}` : undefined} />
          </div>
          <div className="toplists">
            <TopList title="Top source hosts" items={summary.sourceHosts} />
            <TopList title="Top datasets" items={summary.datasets.slice(0, 5)} />
            <TopList title="Event types" items={summary.eventTypes} />
            {summary.users.length > 0 && <TopList title="Users" items={summary.users} />}
          </div>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Time ({zoneAbbrev(tz)})</th>
                  <th>Dataset</th>
                  {cols.map((c) => (
                    <th key={c.key}>{c.label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.id} className={`clickable ${e.id === selectedId ? 'is-selected' : ''}`} tabIndex={0} onClick={() => onSelect(e.id)} onKeyDown={(k) => k.key === 'Enter' && onSelect(e.id)} aria-label={`Event at ${formatInZone(e.time, tz, true)}`}>
                    <td className="mono">{formatInZone(e.time, tz, true)}</td>
                    <td>{e.dataset}</td>
                    {cols.map((c) => (
                      <td key={c.key} title={c.get(e) ?? ''}>
                        {c.get(e) ?? ''}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="row" style={{ justifyContent: 'space-between' }}>
            <Text variant="body-xs-normal" color="secondary">
              Showing {fmtInt(rows.length)} of {fmtInt(events.length)} retrieved{summary.truncated || summary.totalEvents > events.length ? ` (${fmtInt(summary.totalEvents)} matched; retrieval capped in Settings)` : ''}
              {outcome.data.completion !== 'completed' ? ` · search ${outcome.data.completion}` : ''}
            </Text>
            {events.length > INITIAL_ROWS && (
              <Button variant="tertiary" size="sm" onClick={() => setShowAll((v) => !v)}>
                {showAll ? 'Show fewer' : `View all ${fmtInt(events.length)} results`}
              </Button>
            )}
          </div>
        </>
      )}
      <EventDrawer event={selected} tz={tz} onClose={() => onSelect(null)} />
    </section>
  );
}

function Stat({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="stat">
      <Text variant="body-xs-semibold" color="secondary">
        {label.toUpperCase()}
      </Text>
      <span className="stat__value">{value}</span>
      {sub && (
        <Text variant="body-xs-normal" color="secondary">
          {sub}
        </Text>
      )}
    </div>
  );
}

function TopList({ title, items }: { title: string; items: Ranked[] }) {
  if (!items.length) return null;
  const max = Math.max(...items.map((i) => i.count));
  return (
    <div className="toplist">
      <Text variant="body-xs-semibold" color="secondary">
        {title.toUpperCase()}
      </Text>
      {items.map((i) => (
        <div key={i.value} className="toplist__row">
          <span className="mono" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={i.value}>
            {i.value}
          </span>
          <Text variant="body-xs-semibold">{fmtInt(i.count)}</Text>
          <span className="toplist__bar" aria-hidden>
            <span style={{ width: `${(i.count / max) * 100}%` }} />
          </span>
        </div>
      ))}
    </div>
  );
}

function EventDrawer({ event, tz, onClose }: { event: EvidenceEvent | null; tz: string; onClose: () => void }) {
  return (
    <Drawer isOpen={!!event} onClose={onClose} width={560} title="Evidence details">
      {event && (
        <div className="stack">
          <dl className="kv">
            <dt>Time</dt>
            <dd className="mono">
              {formatInZone(event.time, tz, true)} {zoneAbbrev(tz)} · {new Date(event.time).toISOString()}
            </dd>
            <dt>Dataset</dt>
            <dd>{event.dataset}</dd>
            <dt>Matched on</dt>
            <dd>{event.matchedFields.length ? event.matchedFields.join(', ') : 'raw event text'}</dd>
          </dl>
          <Text variant="body-xs-semibold" color="secondary">
            EVENT FIELDS
          </Text>
          <pre className="code">{JSON.stringify(event.fields, null, 2)}</pre>
        </div>
      )}
    </Drawer>
  );
}
