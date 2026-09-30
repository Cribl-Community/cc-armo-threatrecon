import { useEffect, useMemo, useState } from 'react';
import { Button, Drawer, EmptyState, Text } from '@capra/core';
import { FlagOutlined } from '@capra/icons';
import { useSearchParams } from 'react-router-dom';
import { summarize } from '../core/evidence';
import { parseIndicator } from '../core/ioc';
import { incidentStory } from '../core/story';
import { presetRange, resolveRange, validateRange } from '../core/timeRange';
import { computeVerdict, vtVerdict } from '../core/verdict';
import type { DetectionCandidate, IocType, ProviderId, SavedInvestigation, TimeRange } from '../core/types';
import { ReconControls } from '../components/ReconControls';
import { ProviderCards, VerdictCard } from '../components/ResultCards';
import { IndicatorDetails, LookupsPanel, VtPanel } from '../components/DetailPanels';
import { EvidencePanel } from '../components/EvidencePanel';
import { Timeline } from '../components/Timeline';
import { Relationships } from '../components/Relationships';
import { DetectionPanel, StoryPanel, buildCandidate } from '../components/StoryAndDetection';
import { DEMO_DATASETS, DEMO_SCENARIOS } from '../providers/demo';
import { getProviders } from '../providers';
import type { DatasetInfo } from '../providers/types';
import { newId, useApp } from '../state/AppStore';
import { useInvestigation } from '../state/useInvestigation';
import { DemoBadge, Pill } from '../ui/common';

const PROGRESS = { submitting: 'Submitting search…', running: 'Searching telemetry…', fetching: 'Retrieving results…' } as const;

export default function InvestigationPage() {
  const app = useApp();
  const { settings } = app;
  const demo = settings.demoMode;
  const [params, setParams] = useSearchParams();
  const [iocText, setIocText] = useState('');
  const [manualType, setManualType] = useState<IocType | ''>('');
  const [touched, setTouched] = useState(false);
  const [providers, setProviders] = useState<ProviderId[]>(settings.defaultProviders);
  const [consent, setConsent] = useState(false);
  const [range, setRange] = useState<TimeRange>(() => presetRange(settings.defaultPreset));
  const [blocker, setBlocker] = useState<string | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<string | null>(null);
  const [pickerOpen, setPickerOpen] = useState(false);
  const [savedRunId, setSavedRunId] = useState<number | null>(null);
  const [savedCandidateRun, setSavedCandidateRun] = useState<number | null>(null);
  const [reopened, setReopened] = useState<SavedInvestigation | null>(null);
  const inv = useInvestigation(settings);

  const parsed = useMemo(() => parseIndicator(iocText, manualType || undefined), [iocText, manualType]);
  const rangeCheck = useMemo(() => validateRange(resolveRange(range)), [range]);
  const datasets = settings.datasets.length ? settings.datasets : demo ? DEMO_DATASETS : [];

  // Re-open a saved investigation (form only — raw events are never stored).
  useEffect(() => {
    const id = params.get('open');
    if (!id) return;
    const s = app.investigations.find((i) => i.id === id);
    if (s) {
      setIocText(s.indicator.value);
      setManualType('');
      setProviders(s.providers);
      setRange(s.timeRange.preset === 'custom' ? s.timeRange : presetRange(s.timeRange.preset));
      setReopened(s);
      inv.reset();
    }
    setParams({}, { replace: true });
  }, [params, app.investigations, setParams, inv]);

  const toggle = (p: ProviderId) => setProviders((cur) => (cur.includes(p) ? cur.filter((x) => x !== p) : [...cur, p]));

  const onIocText = (v: string) => {
    setIocText(v);
    setTouched(true);
    setConsent(false);
    setBlocker(null);
  };

  const run = (iocOverride?: string) => {
    const p = iocOverride ? parseIndicator(iocOverride) : parsed;
    setTouched(true);
    if (!p.ok) return setBlocker(p.message);
    if (providers.length === 0) return setBlocker('Select at least one source to check.');
    const r = resolveRange(range);
    const rc = validateRange(r);
    if (providers.includes('search') && !rc.ok) return setBlocker(rc.error);
    if (providers.includes('search') && datasets.length === 0) return setBlocker('Choose at least one dataset for Cribl Search.');
    if (providers.includes('virustotal') && !consent && !(iocOverride && demo)) return setBlocker('Confirm the external lookup notice before querying VirusTotal.');
    setBlocker(null);
    setSelectedEvent(null);
    setReopened(null);
    setRange(r);
    inv.run({ indicator: p.indicator, timeRange: r, providers, datasets, demo });
  };

  const runScenario = (ioc: string) => {
    setIocText(ioc);
    setManualType('');
    setTouched(true);
    setConsent(true);
    run(ioc);
  };

  const req = inv.request;
  const summary = useMemo(() => (inv.outcomes.search.data ? summarize(inv.outcomes.search.data, settings.fields) : null), [inv.outcomes.search.data, settings.fields]);
  const verdict = useMemo(() => (req && !inv.running ? computeVerdict(inv.outcomes, req.providers) : null), [req, inv.running, inv.outcomes]);
  const story = useMemo(() => (req && !inv.running ? incidentStory(req.indicator, req.timeRange, req.providers, inv.outcomes, summary) : []), [req, inv.running, inv.outcomes, summary]);
  const candidate: DetectionCandidate | null = useMemo(() => (req && summary && summary.totalEvents > 0 ? buildCandidate(req.indicator, inv.outcomes, summary, settings.fields, req.demo) : null), [req, summary, inv.outcomes, settings.fields]);

  const save = async () => {
    if (!req || !verdict) return;
    const vt = inv.outcomes.virustotal.data;
    const s: SavedInvestigation = {
      id: newId(),
      createdAt: new Date().toISOString(),
      indicator: req.indicator,
      timeRange: req.timeRange,
      providers: req.providers,
      datasets: req.datasets,
      demo: req.demo,
      verdict: { level: verdict.level, label: verdict.label, qualifier: verdict.qualifier, explanation: verdict.explanation },
      summary: story.join(' '),
      counts: {
        lookupMatches: inv.outcomes.lookups.data?.matchedTables ?? null,
        events: summary?.totalEvents ?? null,
        hosts: summary?.sourceHostCount ?? null,
        datasets: summary?.datasetCount ?? null,
        vtMalicious: vt?.stats.malicious ?? null,
        vtTotal: vt?.totalEngines ?? null,
      },
      providerStatus: { lookups: inv.outcomes.lookups.status, search: inv.outcomes.search.status, virustotal: inv.outcomes.virustotal.status },
    };
    await app.saveInvestigation(s);
    setSavedRunId(inv.runId);
  };

  const hasResults = !!req;
  const vv = inv.outcomes.virustotal.data ? vtVerdict(inv.outcomes.virustotal.data) : null;

  return (
    <>
      <ReconControls
        iocText={iocText}
        onIocText={onIocText}
        manualType={manualType}
        onManualType={setManualType}
        parsed={parsed}
        touched={touched}
        providers={providers}
        onToggleProvider={toggle}
        consent={consent}
        onConsent={setConsent}
        range={range}
        onRange={setRange}
        rangeCheck={rangeCheck}
        datasets={datasets}
        onEditDatasets={() => setPickerOpen(true)}
        onRun={() => run()}
        onReset={() => {
          setIocText('');
          setTouched(false);
          setConsent(false);
          setBlocker(null);
          inv.reset();
        }}
        running={inv.running}
        demo={demo}
        blocker={blocker}
      />

      {demo && (
        <div className="banner" role="note">
          <DemoBadge />
          <Text variant="body-sm-normal">Demo mode is on. Results are synthetic and deterministic; no Cribl or VirusTotal API is called. Turn it off in Settings to investigate real data.</Text>
        </div>
      )}

      {reopened && !hasResults && (
        <div className="banner" role="note">
          <Pill tone="info">Saved {new Date(reopened.createdAt).toLocaleString()}</Pill>
          <Text variant="body-sm-normal">
            {reopened.verdict.label}
            {reopened.verdict.qualifier ? ` (${reopened.verdict.qualifier})` : ''}: {reopened.summary || reopened.verdict.explanation} Run the investigation again to retrieve fresh evidence.
          </Text>
        </div>
      )}

      {!hasResults ? (
        <section className="panel">
          <div className="empty-hero">
            <EmptyState title="Start an investigation" description="Enter an IP, domain, or file hash to begin." illustration="EmptyFolder" size="lg" />
            {demo && (
              <>
                <Text variant="body-sm-semibold">One-click demo scenarios</Text>
                <div className="scenarios">
                  {DEMO_SCENARIOS.map((s) => (
                    <button key={s.id} type="button" className="scenario" onClick={() => runScenario(s.ioc)}>
                      <Text variant="body-md-semibold">{s.title}</Text>
                      <Text variant="body-xs-normal" color="secondary">
                        {s.description}
                      </Text>
                      <span className="mono muted" style={{ fontSize: 12, overflowWrap: 'anywhere' }}>
                        {s.ioc}
                      </span>
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
        </section>
      ) : (
        <>
          <div className="row" style={{ justifyContent: 'space-between' }}>
            <div className="row">
              <Text variant="heading-sm">Results</Text>
              <span className="mono muted">{req.indicator.value}</span>
              {vv === 'malicious' && <Pill tone="danger">VirusTotal: malicious</Pill>}
            </div>
            <div className="row">
              {inv.running && (
                <Button variant="secondary" size="sm" onClick={inv.cancel}>
                  Cancel
                </Button>
              )}
              <Button variant="secondary" size="sm" leadingIcon={FlagOutlined} onClick={() => void save()} disabled={inv.running || savedRunId === inv.runId}>
                {savedRunId === inv.runId ? 'Saved' : 'Save investigation'}
              </Button>
            </div>
          </div>

          <div className="cards">
            <VerdictCard verdict={verdict} pending={inv.running} demo={req.demo} />
            <ProviderCards outcomes={inv.outcomes} summary={summary} searchProgress={inv.searchProgress} selected={req.providers} />
          </div>

          <div className="grid-3">
            <IndicatorDetails ind={req.indicator} outcomes={inv.outcomes} summary={summary} range={req.timeRange} onCopy={() => navigator.clipboard.writeText(req.indicator.value).catch(() => undefined)} />
            <VtPanel outcome={inv.outcomes.virustotal} />
            <LookupsPanel outcome={inv.outcomes.lookups} />
          </div>

          <EvidencePanel
            outcome={inv.outcomes.search}
            summary={summary}
            range={req.timeRange}
            fields={settings.fields}
            selectedId={selectedEvent}
            onSelect={setSelectedEvent}
            progressLabel={inv.searchProgress ? PROGRESS[inv.searchProgress.phase] : 'Searching Cribl Lake…'}
          />

          <div className="grid-2">
            <Timeline events={inv.outcomes.search.data?.events ?? []} range={req.timeRange} summary={summary} fields={settings.fields} demo={req.demo} onSelect={setSelectedEvent} />
            <DetectionPanel
              candidate={candidate}
              range={req.timeRange}
              saved={savedCandidateRun === inv.runId}
              onSave={(c) => {
                void app.saveDetection(c);
                setSavedCandidateRun(inv.runId);
              }}
            />
          </div>

          <div className="grid-2r">
            <StoryPanel lines={story} demo={req.demo} />
            <Relationships ind={req.indicator} events={inv.outcomes.search.data?.events ?? []} fields={settings.fields} demo={req.demo} />
          </div>
        </>
      )}

      <DatasetPicker open={pickerOpen} onClose={() => setPickerOpen(false)} />
    </>
  );
}

function DatasetPicker({ open, onClose }: { open: boolean; onClose: () => void }) {
  const app = useApp();
  const [list, setList] = useState<DatasetInfo[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sel, setSel] = useState<string[]>(app.settings.datasets);
  const demo = app.settings.demoMode;

  useEffect(() => {
    if (!open) return;
    setSel(app.settings.datasets);
    setError(null);
    setList(null);
    const ctl = new AbortController();
    getProviders(demo)
      .search.listDatasets({ signal: ctl.signal, settings: app.settings })
      .then(setList)
      .catch((e) => setError(e?.error?.message ?? e?.message ?? 'Could not list datasets.'));
    return () => ctl.abort();
  }, [open, demo, app.settings]);

  const toggle = (id: string) => setSel((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));

  return (
    <Drawer
      isOpen={open}
      onClose={onClose}
      width={460}
      title="Datasets for Cribl Search"
      footer={
        <div className="row" style={{ justifyContent: 'flex-end' }}>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={() => {
              void app.saveSettings({ ...app.settings, datasets: sel });
              onClose();
            }}
          >
            {`Use ${sel.length} dataset${sel.length === 1 ? '' : 's'}`}
          </Button>
        </div>
      }
    >
      <div className="stack">
        <Text variant="body-sm-normal" color="secondary">
          Only the selected datasets are searched. Choose the ones likely to contain network, DNS, proxy or endpoint telemetry.
        </Text>
        {demo && <DemoBadge />}
        {error && (
          <Text variant="body-sm-normal" color="warning">
            {error}
          </Text>
        )}
        {!list && !error && <Text variant="body-sm-normal">Loading datasets…</Text>}
        {list?.map((d) => (
          <label key={d.id} className={`source ${sel.includes(d.id) ? 'source--on' : ''}`}>
            <input type="checkbox" checked={sel.includes(d.id)} onChange={() => toggle(d.id)} />
            <span className="source__text">
              <Text variant="body-sm-semibold">{d.id}</Text>
              <Text variant="body-xs-normal" color="secondary">
                {[d.provider, d.type, d.description].filter(Boolean).join(' · ') || 'Dataset'}
              </Text>
            </span>
          </label>
        ))}
        {list && list.length === 0 && <Text variant="body-sm-normal">No searchable datasets are visible to this App.</Text>}
      </div>
    </Drawer>
  );
}
