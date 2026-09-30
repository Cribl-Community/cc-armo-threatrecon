import type { ReactNode } from 'react';
import { Text } from '@capra/core';
import { AttentionSolid, Bug, CircleCheckFilled, CircleXFilled, Database, Globe, QuestionCircleOutlined, Search } from '@capra/icons';
import type { EvidenceSummary } from '../core/evidence';
import { vtVerdict } from '../core/verdict';
import type { Outcomes, ProviderId, ProviderOutcome, Verdict } from '../core/types';
import type { SearchProgress } from '../providers/types';
import { DemoBadge, Pill, Running, StatusIcon, fmtInt, type Tone } from '../ui/common';

const VERDICT_ICON = { malicious: CircleXFilled, suspicious: AttentionSolid, internal_match: Database, observed: Search, no_evidence: CircleCheckFilled, inconclusive: QuestionCircleOutlined };

export function VerdictCard({ verdict, pending, demo }: { verdict: Verdict | null; pending: boolean; demo: boolean }) {
  const level = pending || !verdict ? 'pending' : verdict.level;
  const Icon = verdict && !pending ? VERDICT_ICON[verdict.level] : QuestionCircleOutlined;
  return (
    <section className={`panel verdict verdict--${level}`} aria-live="polite" aria-label="Overall verdict">
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <Text variant="body-sm-semibold" color="secondary">
          OVERALL VERDICT
        </Text>
        {demo && <DemoBadge />}
      </div>
      <div className="verdict__main">
        <span className="verdict__icon" aria-hidden>
          <Icon size="md" />
        </span>
        <div className="stack" style={{ gap: 2 }}>
          <span className="verdict__label">{pending ? 'Evaluating…' : verdict?.label}</span>
          {!pending && verdict?.qualifier && (
            <Text variant="body-sm-semibold" color="secondary">
              {verdict.qualifier} in selected window
            </Text>
          )}
        </div>
      </div>
      <Text as="p" variant="body-sm-normal">
        {pending ? 'Waiting for the selected sources to finish. The verdict updates when every source completes.' : verdict?.explanation}
      </Text>
      {!pending && verdict && verdict.evidence.length > 0 && (
        <ul className="evidence-list" aria-label="Why">
          {verdict.evidence.map((e, i) => (
            <li key={i}>
              <StatusIcon tone={e.weight === 'positive' ? 'danger' : e.weight === 'negative' ? 'success' : 'neutral'} size="xs" />
              <Text variant="body-xs-normal">{e.text}</Text>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function Card({ icon, title, children, foot, outcome, runningLabel }: { icon: ReactNode; title: string; children?: ReactNode; foot?: ReactNode; outcome: ProviderOutcome<unknown> | { status: 'soon' }; runningLabel?: string }) {
  let body: ReactNode = children;
  if (outcome.status === 'soon') body = <Status tone="neutral" text="Coming soon" sub="Reserved for a future integration" />;
  else if (outcome.status === 'skipped' || outcome.status === 'idle') body = <Status tone="neutral" text="Not checked" sub="Source not selected" />;
  else if (outcome.status === 'running') body = <div className="stack"><Running label={runningLabel ?? 'Running…'} /><div className="skeleton" style={{ width: '70%' }} /><div className="skeleton" style={{ width: '45%' }} /></div>;
  else if (outcome.status === 'unavailable' || outcome.status === 'error') {
    const e = (outcome as ProviderOutcome<unknown>).error;
    const notFound = e?.kind === 'not_found';
    body = <Status tone={notFound ? 'neutral' : 'warning'} text={notFound ? 'No record' : outcome.status === 'unavailable' ? 'Unavailable' : 'Error'} sub={e?.message} hint={e?.hint} />;
  }
  return (
    <section className="panel pcard" aria-label={title}>
      <div className="pcard__head">
        <span className="tone-info" style={{ display: 'inline-flex' }} aria-hidden>
          {icon}
        </span>
        <Text variant="body-md-semibold">{title}</Text>
        {'demo' in outcome && outcome.demo && outcome.status === 'complete' && (
          <span style={{ marginLeft: 'auto' }}>
            <DemoBadge />
          </span>
        )}
      </div>
      {body}
      {outcome.status === 'complete' && foot && <div className="pcard__foot">{foot}</div>}
    </section>
  );
}

function Status({ tone, text, sub, hint }: { tone: Tone; text: string; sub?: string; hint?: string }) {
  return (
    <div className="stack" style={{ gap: 2 }}>
      <span className={`pcard__status row tone-${tone}`}>
        <StatusIcon tone={tone} size="sm" />
        {text}
      </span>
      {sub && (
        <Text variant="body-xs-normal" color="secondary">
          {sub}
        </Text>
      )}
      {hint && (
        <Text variant="body-xs-normal" color="secondary">
          {hint}
        </Text>
      )}
    </div>
  );
}

const PROGRESS_TEXT: Record<SearchProgress['phase'], string> = { submitting: 'Submitting search…', running: 'Searching telemetry…', fetching: 'Retrieving results…' };

export function ProviderCards({ outcomes, summary, searchProgress, selected }: { outcomes: Outcomes; summary: EvidenceSummary | null; searchProgress: SearchProgress | null; selected: ProviderId[] }) {
  const l = outcomes.lookups;
  const s = outcomes.search;
  const v = outcomes.virustotal;
  const vv = v.data ? vtVerdict(v.data) : null;
  const vtTone: Tone = vv === 'malicious' ? 'danger' : vv === 'suspicious' ? 'warning' : vv === 'clean' ? 'success' : 'neutral';
  const vtText = vv === 'malicious' ? 'Malicious' : vv === 'suspicious' ? 'Suspicious' : vv === 'clean' ? 'Clean' : 'Unknown';
  return (
    <>
      <Card icon={<Database size="md" />} title="Cribl Lookups" outcome={l} runningLabel="Checking internal intelligence…" foot={l.data && <Pill tone={l.data.matchedTables ? 'danger' : 'success'}>{l.data.matchedTables ? 'MATCH' : 'NO MATCH'}</Pill>}>
        {l.data && <Status tone={l.data.matchedTables ? 'danger' : 'success'} text={l.data.matchedTables ? 'Found' : 'Not Found'} sub={l.data.matchedTables ? `In ${l.data.matchedTables} of ${l.data.checkedTables} lookup tables` : `Checked ${l.data.checkedTables} lookup tables`} />}
      </Card>
      <Card
        icon={<Bug size="md" />}
        title="VirusTotal"
        outcome={v}
        runningLabel="Querying external intelligence…"
        foot={v.data && <Pill tone={vtTone}>{`${v.data.stats.malicious} / ${v.data.totalEngines} engines`}</Pill>}
      >
        {v.data && <Status tone={vtTone} text={vtText} sub={`${v.data.stats.malicious} malicious · ${v.data.stats.suspicious} suspicious`} />}
      </Card>
      <Card
        icon={<Search size="md" />}
        title="Cribl Lake / Search"
        outcome={s}
        runningLabel={searchProgress ? PROGRESS_TEXT[searchProgress.phase] : 'Searching telemetry…'}
        foot={summary && <Pill tone={summary.totalEvents ? 'info' : 'success'}>{summary.datasetCount} dataset{summary.datasetCount === 1 ? '' : 's'}</Pill>}
      >
        {summary && <Status tone={summary.totalEvents ? 'info' : 'success'} text={summary.totalEvents ? 'Observed' : 'Not Observed'} sub={summary.totalEvents ? `${fmtInt(summary.totalEvents)} events · ${fmtInt(summary.sourceHostCount)} hosts` : 'No matching telemetry in window'} />}
      </Card>
      <Card icon={<Globe size="md" />} title="Other Intel" outcome={selected.includes('otherIntel') ? { status: 'soon' } : { status: 'soon' }} />
    </>
  );
}
