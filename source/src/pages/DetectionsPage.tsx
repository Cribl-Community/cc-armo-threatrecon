import { useState } from 'react';
import { Button, Drawer, EmptyState, Text } from '@capra/core';
import { prettyQuery } from '../core/query';
import type { DetectionCandidate, DetectionStatus } from '../core/types';
import { useApp } from '../state/AppStore';
import { ConfirmDestructive, DemoBadge, Pill, type Tone } from '../ui/common';

const STATUS_TONE: Record<DetectionStatus, Tone> = { draft: 'neutral', reviewed: 'info', saved: 'success' };
const STATUS_LABEL: Record<DetectionStatus, string> = { draft: 'Draft', reviewed: 'Reviewed', saved: 'Saved' };

export default function DetectionsPage() {
  const { detections, saveDetection, deleteDetection } = useApp();
  const [open, setOpen] = useState<DetectionCandidate | null>(null);
  const [toDelete, setToDelete] = useState<DetectionCandidate | null>(null);

  const setStatus = (d: DetectionCandidate, status: DetectionStatus) => {
    const next = { ...d, status };
    void saveDetection(next);
    setOpen(next);
  };

  return (
    <section className="panel">
      <div className="stack" style={{ gap: 2 }}>
        <Text as="h2" variant="heading-md">
          Detection Candidates
        </Text>
        <Text variant="body-sm-normal" color="secondary">
          Candidate queries generated from observed evidence. They live in this App only and are never deployed automatically.
        </Text>
      </div>
      {detections.length === 0 ? (
        <EmptyState title="No detection candidates" description="When an indicator is observed, open Detection Candidate on the results and save it." illustration="Sandcastle" />
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>IOC</th>
                <th>Created</th>
                <th>Evidence</th>
                <th>Status</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {detections.map((d) => (
                <tr key={d.id} className="clickable" onClick={() => setOpen(d)}>
                  <td>
                    {d.name} {d.demo && <DemoBadge />}
                  </td>
                  <td className="mono">{d.indicator.value}</td>
                  <td>{new Date(d.createdAt).toLocaleString()}</td>
                  <td>
                    {d.evidence.events} events · {d.evidence.datasets} datasets · {d.evidence.hosts} hosts
                  </td>
                  <td>
                    <Pill tone={STATUS_TONE[d.status]}>{STATUS_LABEL[d.status]}</Pill>
                  </td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <Button size="sm" variant="tertiary" appearance="danger" onClick={() => setToDelete(d)}>
                      Delete
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Drawer
        isOpen={!!open}
        onClose={() => setOpen(null)}
        width={620}
        title={open?.name ?? 'Detection candidate'}
        footer={
          open && (
            <div className="row" style={{ justifyContent: 'flex-end' }}>
              <Button variant="secondary" onClick={() => setStatus(open, 'reviewed')} disabled={open.status === 'reviewed'}>
                Mark reviewed
              </Button>
              <Button variant="primary" onClick={() => setStatus(open, 'saved')} disabled={open.status === 'saved'}>
                Mark saved
              </Button>
            </div>
          )
        }
      >
        {open && (
          <div className="stack">
            <Text variant="body-sm-normal">{open.why}</Text>
            <dl className="kv">
              <dt>Datasets</dt>
              <dd>{open.datasets.join(', ')}</dd>
              <dt>Fields</dt>
              <dd className="mono">{open.fields.join(', ') || 'raw event text'}</dd>
              <dt>Status</dt>
              <dd>
                <Pill tone={STATUS_TONE[open.status]}>{STATUS_LABEL[open.status]}</Pill>
              </dd>
            </dl>
            <pre className="code">{prettyQuery(open.query)}</pre>
            <Text variant="body-xs-normal" color="secondary">
              Detection creation in Cribl is not enabled in this version.
            </Text>
          </div>
        )}
      </Drawer>
      <ConfirmDestructive
        open={!!toDelete}
        title="Delete detection candidate?"
        body={toDelete ? `This permanently deletes "${toDelete.name}" from this App's storage. This cannot be undone. Nothing in Cribl is changed.` : ''}
        confirmText="Delete"
        onConfirm={async () => {
          if (toDelete) await deleteDetection(toDelete.id);
          setToDelete(null);
        }}
        onCancel={() => setToDelete(null)}
      />
    </section>
  );
}
