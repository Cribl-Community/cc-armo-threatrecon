import { useState } from 'react';
import { Button, Text } from '@capra/core';
import { Bullseye, Copy, Notebook } from '@capra/icons';
import type { EvidenceSummary } from '../core/evidence';
import type { FieldStrategy } from '../core/fields';
import { pick } from '../core/fields';
import { detectionQuery, prettyQuery } from '../core/query';
import { createSavedSearch, savedSearchId } from '../providers/criblSavedSearch';
import { formatInZone } from '../core/timeRange';
import type { DetectionCandidate, Indicator, Outcomes, TimeRange } from '../core/types';
import { newId } from '../state/AppStore';
import { ConfirmDestructive, DemoBadge, Pill, SectionTitle } from '../ui/common';

export function StoryPanel({ lines, demo }: { lines: string[]; demo: boolean }) {
  return (
    <section className="panel" aria-label="Incident story">
      <SectionTitle icon={<Notebook size="sm" />} extra={demo ? <DemoBadge /> : undefined}>
        Incident Story
      </SectionTitle>
      <div className="story">
        {lines.length ? (
          lines.map((l, i) => (
            <Text as="p" key={i} variant="body-md-normal">
              {l}
            </Text>
          ))
        ) : (
          <Text as="p" variant="body-sm-normal" color="secondary">
            The story is generated once sources complete.
          </Text>
        )}
      </div>
      <Text variant="body-xs-normal" color="secondary">
        Generated deterministically from the structured results above. No AI is used and no conclusions are added.
      </Text>
    </section>
  );
}

export function buildCandidate(ind: Indicator, outcomes: Outcomes, summary: EvidenceSummary, fields: FieldStrategy, demo: boolean): DetectionCandidate {
  const events = outcomes.search.data?.events ?? [];
  const matched = summary.matchedFields.map((m) => m.value).filter((f) => f !== '_raw');
  const hostField = fields.sourceHost.find((f) => events.some((e) => pick(e.fields, [f]) !== null)) ?? null;
  const datasets = summary.datasets.map((d) => d.value);
  return {
    id: newId(),
    name: `IOC ${ind.value} observed`,
    createdAt: new Date().toISOString(),
    indicator: ind,
    why: `IOC was observed ${summary.totalEvents.toLocaleString()} time${summary.totalEvents === 1 ? '' : 's'} across ${summary.datasetCount} dataset${summary.datasetCount === 1 ? '' : 's'} in the selected time window.`,
    query: detectionQuery(ind, datasets, matched, hostField),
    datasets,
    fields: matched,
    evidence: { events: summary.totalEvents, datasets: summary.datasetCount, hosts: summary.sourceHostCount, firstSeen: summary.firstSeen, lastSeen: summary.lastSeen },
    status: 'draft',
    demo,
  };
}

export function DetectionPanel({ candidate, range, onSave, saved }: { candidate: DetectionCandidate | null; range: TimeRange; onSave: (c: DetectionCandidate) => void; saved: boolean }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const [confirmSearch, setConfirmSearch] = useState(false);
  const [savedSearch, setSavedSearch] = useState<string | null>(null);
  const [searchMsg, setSearchMsg] = useState<string | null>(null);
  const tz = range.timezone;
  const copy = () => {
    if (!candidate) return;
    navigator.clipboard
      .writeText(candidate.query)
      .then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      })
      .catch(() => undefined);
  };
  return (
    <section className="panel" aria-label="Detection candidate">
      <SectionTitle icon={<Bullseye size="sm" />} extra={<Pill tone="info">Preview</Pill>}>
        Detection Candidate
      </SectionTitle>
      {!candidate ? (
        <Text variant="body-sm-normal" color="secondary">
          A detection candidate becomes available when the indicator is observed in Cribl telemetry.
        </Text>
      ) : !open ? (
        <div className="stack">
          <Text variant="body-sm-normal">{candidate.why}</Text>
          <div>
            <Button variant="primary" leadingIcon={Bullseye} onClick={() => setOpen(true)}>
              Create Detection Candidate
            </Button>
          </div>
        </div>
      ) : (
        <div className="stack">
          {candidate.demo && <DemoBadge />}
          <dl className="kv">
            <dt>Why</dt>
            <dd>{candidate.why}</dd>
            <dt>Datasets</dt>
            <dd>{candidate.datasets.join(', ')}</dd>
            <dt>IOC field(s)</dt>
            <dd className="mono">{candidate.fields.length ? candidate.fields.join(', ') : 'raw event text'}</dd>
            <dt>IOC value</dt>
            <dd className="mono">{candidate.indicator.value}</dd>
            <dt>Observed</dt>
            <dd>{candidate.evidence.firstSeen && candidate.evidence.lastSeen ? `${formatInZone(candidate.evidence.firstSeen, tz)} → ${formatInZone(candidate.evidence.lastSeen, tz)}` : '–'}</dd>
            <dt>Time</dt>
            <dd>Run on a schedule over a short look-back (for example the last 15 minutes) rather than the investigation window.</dd>
          </dl>
          <pre className="code" aria-label="Candidate query">
            {prettyQuery(candidate.query)}
          </pre>
          <div className="row">
            <Button variant="secondary" leadingIcon={Copy} onClick={copy}>
              {copied ? 'Copied' : 'Copy query'}
            </Button>
            <Button variant="primary" onClick={() => onSave(candidate)} disabled={saved}>
              {saved ? 'Saved to Detection Candidates' : 'Save as Candidate'}
            </Button>
            <Button variant="secondary" onClick={() => setConfirmSearch(true)} disabled={candidate.demo || !!savedSearch}>
              {savedSearch ? 'Saved as Search' : 'Save as Search'}
            </Button>
            <Button variant="secondary" disabled>
              Create Detection in Cribl
            </Button>
          </div>
          {searchMsg && <Text variant="body-xs-normal">{searchMsg}</Text>}
          <Text variant="body-xs-normal" color="secondary">
            {candidate.demo ? 'Save as Search is available with live Cribl Search (demo mode never writes to Cribl). ' : ''}Detection creation is not enabled in this version.
          </Text>
        </div>
      )}
      {candidate && (
        <ConfirmDestructive
          open={confirmSearch}
          title="Create a Cribl saved search?"
          body={`This creates a new saved search "${candidate.name}" (id ${savedSearchId(candidate)}) in Cribl Search for this Workspace. It is not scheduled and does not change any other configuration.`}
          confirmText="Create saved search"
          onCancel={() => setConfirmSearch(false)}
          onConfirm={async () => {
            setConfirmSearch(false);
            try {
              const r = await createSavedSearch(candidate);
              setSavedSearch(r.id);
              setSearchMsg(`Saved search "${r.id}" created in Cribl Search.`);
            } catch (e) {
              setSearchMsg(e instanceof Error ? e.message : 'Could not create the saved search.');
            }
          }}
        />
      )}
    </section>
  );
}
