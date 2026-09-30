import { useMemo } from 'react';
import { Text } from '@capra/core';
import { DiagramSankey } from '@capra/icons';
import { relationships, type RelNode } from '../core/evidence';
import type { FieldStrategy } from '../core/fields';
import type { EvidenceEvent, Indicator } from '../core/types';
import { DemoBadge, SectionTitle } from '../ui/common';

const COL_W = 170;
const NODE_H = 30;
const GAP = 12;
const TOP = 30;

const truncate = (s: string, n = 20) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export function Relationships({ ind, events, fields, demo }: { ind: Indicator; events: EvidenceEvent[]; fields: FieldStrategy; demo: boolean }) {
  const rel = useMemo(() => relationships(ind.value, events, fields), [ind.value, events, fields]);
  const columns: { title: string; nodes: RelNode[] }[] = [
    { title: 'INDICATOR', nodes: [{ id: 'ioc', kind: 'ioc' as const, label: ind.value, count: events.length }] },
    { title: 'SOURCE HOSTS', nodes: rel.columns.host },
    { title: 'USERS', nodes: rel.columns.user },
    { title: 'DATASETS', nodes: rel.columns.dataset },
    { title: 'DESTINATIONS', nodes: rel.columns.destination },
  ].filter((c) => c.nodes.length > 0);

  if (events.length === 0 || columns.length < 2) {
    return (
      <section className="panel" aria-label="Evidence relationships">
        <SectionTitle icon={<DiagramSankey size="sm" />}>Evidence Relationships</SectionTitle>
        <Text variant="body-sm-normal" color="secondary">
          Relationships appear once matching events are returned. Only entities present in the events are drawn.
        </Text>
      </section>
    );
  }

  const rows = Math.max(...columns.map((c) => c.nodes.length));
  const width = Math.max(640, columns.length * (COL_W + 60));
  const height = TOP + rows * (NODE_H + GAP) + 10;
  const colX = (i: number) => (columns.length === 1 ? 0 : (i * (width - COL_W)) / (columns.length - 1));
  const pos = new Map<string, { x: number; y: number }>();
  columns.forEach((c, ci) => {
    const offset = ((rows - c.nodes.length) * (NODE_H + GAP)) / 2;
    c.nodes.forEach((n, ni) => pos.set(n.id, { x: colX(ci), y: TOP + offset + ni * (NODE_H + GAP) }));
  });
  const maxEdge = Math.max(1, ...rel.edges.map((e) => e.count));

  return (
    <section className="panel" aria-label="Evidence relationships">
      <SectionTitle icon={<DiagramSankey size="sm" />} extra={demo ? <DemoBadge /> : undefined}>
        Evidence Relationships
      </SectionTitle>
      <div style={{ overflowX: 'auto' }}>
        <svg className="rel" viewBox={`0 0 ${width} ${height}`} style={{ minWidth: 520 }} role="img" aria-label="Indicator related to hosts, users, datasets and destinations seen in the returned events">
          {columns.map((c, ci) => (
            <text key={c.title} className="rel__col" x={colX(ci) + 4} y={14}>
              {c.title}
            </text>
          ))}
          {rel.edges.map((e) => {
            const a = pos.get(e.from);
            const b = pos.get(e.to);
            if (!a || !b) return null;
            const x1 = a.x + COL_W;
            const y1 = a.y + NODE_H / 2;
            const x2 = b.x;
            const y2 = b.y + NODE_H / 2;
            const mx = (x1 + x2) / 2;
            return <path key={`${e.from}-${e.to}`} className={`rel__edge ${e.from === 'ioc' ? 'rel__edge--hot' : ''}`} d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} strokeWidth={1 + (e.count / maxEdge) * 3} opacity={0.75} />;
          })}
          {columns.flatMap((c) =>
            c.nodes.map((n) => {
              const p = pos.get(n.id)!;
              return (
                <g key={n.id} className={`rel__node ${n.kind === 'ioc' ? 'rel__node--ioc' : ''}`}>
                  <title>{`${n.label} — ${n.count} event${n.count === 1 ? '' : 's'}`}</title>
                  <rect x={p.x} y={p.y} width={COL_W} height={NODE_H} rx={6} />
                  <text x={p.x + 10} y={p.y + 19}>
                    {truncate(n.label)}
                  </text>
                  <text className="rel__count" x={p.x + COL_W - 8} y={p.y + 19} textAnchor="end">
                    {n.count}
                  </text>
                </g>
              );
            }),
          )}
        </svg>
      </div>
      <Text variant="body-xs-normal" color="secondary">
        Links show co-occurrence within the same returned event (top 5 per column). They are not inferred.
      </Text>
    </section>
  );
}
