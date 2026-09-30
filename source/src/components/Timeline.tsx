import { useMemo, useState } from 'react';
import { Button, Text } from '@capra/core';
import { ChartColumn } from '@capra/icons';
import { CATEGORY_ORDER, bucketize, type EventCategory, type EvidenceSummary } from '../core/evidence';
import type { FieldStrategy } from '../core/fields';
import { zoneAbbrev } from '../core/timeRange';
import type { EvidenceEvent, TimeRange } from '../core/types';
import { DemoBadge, SectionTitle } from '../ui/common';

const W = 1000;
const H = 190;
const PAD = { l: 34, r: 12, t: 12, b: 34 };

const tickLabel = (ms: number, tz: string, spanMs: number) =>
  new Intl.DateTimeFormat('en-US', spanMs > 2 * 86_400_000 ? { timeZone: tz, month: 'short', day: 'numeric' } : { timeZone: tz, month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }).format(new Date(ms));

export function Timeline({ events, range, summary, fields, demo, onSelect }: { events: EvidenceEvent[]; range: TimeRange; summary: EvidenceSummary | null; fields: FieldStrategy; demo: boolean; onSelect: (eventId: string) => void }) {
  const [zoom, setZoom] = useState(false);
  const [hover, setHover] = useState<{ i: number; x: number } | null>(null);
  const tz = range.timezone;

  const [start, end] = useMemo(() => {
    if (!zoom || !summary?.firstSeen || !summary.lastSeen) return [range.startMs, range.endMs];
    const pad = Math.max(60_000, (summary.lastSeen - summary.firstSeen) * 0.05);
    return [Math.max(range.startMs, summary.firstSeen - pad), Math.min(range.endMs, summary.lastSeen + pad)];
  }, [zoom, summary, range]);

  const buckets = useMemo(() => bucketize(events, start, end, fields, 96), [events, start, end, fields]);
  const cats: EventCategory[] = summary ? summary.categories.map((c) => c.category) : CATEGORY_ORDER;
  const max = Math.max(1, ...buckets.map((b) => b.total));
  const innerW = W - PAD.l - PAD.r;
  const innerH = H - PAD.t - PAD.b;
  const bw = innerW / buckets.length;
  const ticks = Array.from({ length: 6 }, (_, i) => start + ((end - start) * i) / 5);
  const hb = hover ? buckets[hover.i] : null;

  return (
    <section className="panel" aria-label="Event timeline">
      <div className="panel__head">
        <SectionTitle icon={<ChartColumn size="sm" />} extra={demo && events.length ? <DemoBadge /> : undefined}>
          Event Timeline
        </SectionTitle>
        <div className="row">
          <div className="tl-legend" aria-label="Legend">
            {cats.map((c) => (
              <span key={c} className="tl-legend__item">
                <span className={`tl-legend__sw cat-${c}`} aria-hidden />
                {c}
              </span>
            ))}
          </div>
          {events.length > 0 && (
            <Button variant="tertiary" size="sm" onClick={() => setZoom((z) => !z)}>
              {zoom ? 'Full window' : 'Zoom to activity'}
            </Button>
          )}
        </div>
      </div>
      {events.length === 0 ? (
        <Text variant="body-sm-normal" color="secondary">
          No events to plot for the selected time window.
        </Text>
      ) : (
        <div style={{ position: 'relative' }} onMouseLeave={() => setHover(null)}>
          <svg className="timeline" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img" aria-label={`Timeline of ${events.length} matching events`}>
            {[0.5, 1].map((f) => (
              <line key={f} className="timeline__grid" x1={PAD.l} x2={W - PAD.r} y1={PAD.t + innerH * (1 - f)} y2={PAD.t + innerH * (1 - f)} />
            ))}
            <line className="timeline__axis" x1={PAD.l} x2={W - PAD.r} y1={PAD.t + innerH} y2={PAD.t + innerH} />
            {buckets.map((b, i) => {
              const x = PAD.l + i * bw;
              let y = PAD.t + innerH;
              return (
                <g key={i}>
                  {hover?.i === i && <rect className="timeline__sel" x={x} y={PAD.t} width={bw} height={innerH} />}
                  {CATEGORY_ORDER.map((c) => {
                    const n = b.counts[c] ?? 0;
                    if (!n) return null;
                    const h = (n / max) * innerH;
                    y -= h;
                    return <rect key={c} className={`cat-${c}`} x={x + bw * 0.18} y={y} width={Math.max(1.5, bw * 0.64)} height={h} rx={1.5} />;
                  })}
                  <rect
                    className="timeline__hit"
                    x={x}
                    y={PAD.t}
                    width={bw}
                    height={innerH}
                    onMouseEnter={() => setHover({ i, x: ((x + bw / 2) / W) * 100 })}
                    onClick={() => b.eventIds[0] && onSelect(b.eventIds[0])}
                    aria-label={b.total ? `${b.total} events` : undefined}
                  />
                </g>
              );
            })}
          </svg>
          <span className="tl-ymax" style={{ top: `${(PAD.t / H) * 100}%` }}>
            {max}
          </span>
          {ticks.map((t, i) => (
            <span key={i} className={`tl-xtick tl-xtick--${i === 0 ? 'start' : i === 5 ? 'end' : 'mid'}`} style={{ left: `${((PAD.l + (innerW * i) / 5) / W) * 100}%` }}>
              {tickLabel(t, tz, end - start)}
            </span>
          ))}
          {hb && hb.total > 0 && hover && (
            <div className="tl-tip" style={{ left: `${Math.min(80, Math.max(2, hover.x - 8))}%`, top: 4 }}>
              <div>
                <strong>{hb.total} event{hb.total === 1 ? '' : 's'}</strong> · {tickLabel(hb.start, tz, 0)} – {tickLabel(hb.end, tz, 0)} {zoneAbbrev(tz)}
              </div>
              {CATEGORY_ORDER.filter((c) => hb.counts[c]).map((c) => (
                <div key={c}>
                  {c}: {hb.counts[c]}
                </div>
              ))}
              <div className="muted">Click to open evidence</div>
            </div>
          )}
        </div>
      )}
      <Text variant="body-xs-normal" color="secondary">
        Categories are inferred from dataset and event-type names. Times shown in {zoneAbbrev(tz)} ({tz}).
        {summary && summary.totalEvents > summary.events ? ` Plots the ${summary.events.toLocaleString()} retrieved events of ${summary.totalEvents.toLocaleString()} matched.` : ''}
      </Text>
    </section>
  );
}
