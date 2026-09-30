import { useState } from 'react';
import { Button, EmptyState, Text } from '@capra/core';
import { useNavigate } from 'react-router-dom';
import { IOC_TYPE_LABELS } from '../core/ioc';
import { PRESETS, formatInZone } from '../core/timeRange';
import type { SavedInvestigation, VerdictLevel } from '../core/types';
import { providerName } from '../core/verdict';
import { useApp } from '../state/AppStore';
import { ConfirmDestructive, DemoBadge, Pill, type Tone } from '../ui/common';

export const VERDICT_TONE: Record<VerdictLevel, Tone> = { malicious: 'danger', suspicious: 'warning', internal_match: 'highlight', observed: 'info', no_evidence: 'success', inconclusive: 'neutral' };

export default function SavedPage() {
  const { investigations, deleteInvestigation } = useApp();
  const navigate = useNavigate();
  const [toDelete, setToDelete] = useState<SavedInvestigation | null>(null);

  return (
    <section className="panel">
      <div className="panel__head">
        <div className="stack" style={{ gap: 2 }}>
          <Text as="h2" variant="heading-md">
            Saved Investigations
          </Text>
          <Text variant="body-sm-normal" color="secondary">
            Summaries saved to this App (per user). Raw event data is not stored — open one to re-run it.
          </Text>
        </div>
      </div>
      {investigations.length === 0 ? (
        <EmptyState title="No saved investigations" description="Run an investigation and choose Save investigation to keep its summary here." illustration="EmptyFolder" />
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Indicator</th>
                <th>Type</th>
                <th>Verdict</th>
                <th>Evidence</th>
                <th>Time range</th>
                <th>Sources</th>
                <th>Saved</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {investigations.map((i) => (
                <tr key={i.id}>
                  <td className="mono">
                    {i.indicator.value} {i.demo && <DemoBadge />}
                  </td>
                  <td>{IOC_TYPE_LABELS[i.indicator.type]}</td>
                  <td>
                    <Pill tone={VERDICT_TONE[i.verdict.level]}>
                      {i.verdict.label}
                      {i.verdict.qualifier ? ` · ${i.verdict.qualifier}` : ''}
                    </Pill>
                  </td>
                  <td>
                    {[
                      i.counts.lookupMatches !== null ? `${i.counts.lookupMatches} lookup match${i.counts.lookupMatches === 1 ? '' : 'es'}` : null,
                      i.counts.events !== null ? `${i.counts.events} events` : null,
                      i.counts.vtTotal !== null ? `VT ${i.counts.vtMalicious}/${i.counts.vtTotal}` : null,
                    ]
                      .filter(Boolean)
                      .join(' · ') || '–'}
                  </td>
                  <td>{i.timeRange.preset === 'custom' ? `${formatInZone(i.timeRange.startMs, i.timeRange.timezone)} → ${formatInZone(i.timeRange.endMs, i.timeRange.timezone)}` : PRESETS.find((p) => p.value === i.timeRange.preset)?.label}</td>
                  <td>{i.providers.map(providerName).join(', ')}</td>
                  <td>{new Date(i.createdAt).toLocaleString()}</td>
                  <td>
                    <div className="row">
                      <Button size="sm" variant="secondary" onClick={() => navigate(`/?open=${encodeURIComponent(i.id)}`)}>
                        Open
                      </Button>
                      <Button size="sm" variant="tertiary" appearance="danger" onClick={() => setToDelete(i)}>
                        Delete
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <ConfirmDestructive
        open={!!toDelete}
        title="Delete saved investigation?"
        body={toDelete ? `This permanently deletes the saved summary for ${toDelete.indicator.value} from this App's storage. This cannot be undone. Cribl data is not affected.` : ''}
        confirmText="Delete"
        onConfirm={async () => {
          if (toDelete) await deleteInvestigation(toDelete.id);
          setToDelete(null);
        }}
        onCancel={() => setToDelete(null)}
      />
    </section>
  );
}
