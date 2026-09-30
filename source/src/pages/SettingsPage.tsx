import { useEffect, useState, type ReactNode } from 'react';
import { Button, Text } from '@capra/core';
import { Cog } from '@capra/icons';
import { splitList, type FieldStrategy } from '../core/fields';
import { DEFAULT_SETTINGS, type AppSettings } from '../core/settings';
import { PRESETS } from '../core/timeRange';
import type { ProviderId } from '../core/types';
import { SOURCES } from '../components/ReconControls';
import { getProviders } from '../providers';
import { criblFetch, isInCribl } from '../platform/cribl';
import { useApp } from '../state/AppStore';
import { ConfirmDestructive, Pill, StatusIcon, type Tone } from '../ui/common';

type Probe = { state: 'checking' | 'ok' | 'fail'; detail: string };

function useProbe(kind: 'search' | 'lookups', demo: boolean, settings: AppSettings): Probe {
  const [p, setP] = useState<Probe>({ state: 'checking', detail: 'Checking…' });
  useEffect(() => {
    const ctl = new AbortController();
    setP({ state: 'checking', detail: 'Checking…' });
    const prov = getProviders(demo);
    const task = kind === 'search' ? prov.search.listDatasets({ signal: ctl.signal, settings }).then((d) => `${d.length} dataset${d.length === 1 ? '' : 's'} visible`) : prov.lookups.listLookups({ signal: ctl.signal, settings }).then((l) => `${l.length} lookup${l.length === 1 ? '' : 's'} in group "${settings.lookupGroupId}"`);
    task.then((detail) => setP({ state: 'ok', detail: demo ? `${detail} (demo)` : detail })).catch((e) => setP({ state: 'fail', detail: e?.error?.message ?? e?.message ?? 'Unavailable' }));
    return () => ctl.abort();
  }, [kind, demo, settings]);
  return p;
}

function Status({ label, tone, text, detail }: { label: string; tone: Tone; text: string; detail?: string }) {
  return (
    <div className="stat">
      <Text variant="body-xs-semibold" color="secondary">
        {label.toUpperCase()}
      </Text>
      <span className={`row tone-${tone}`}>
        <StatusIcon tone={tone} size="xs" />
        <Text variant="body-md-semibold">{text}</Text>
      </span>
      {detail && (
        <Text variant="body-xs-normal" color="secondary">
          {detail}
        </Text>
      )}
    </div>
  );
}

function Block({ title, description, children }: { title: string; description?: string; children: ReactNode }) {
  return (
    <section className="panel">
      <div className="stack" style={{ gap: 2 }}>
        <Text as="h2" variant="heading-sm">
          {title}
        </Text>
        {description && (
          <Text variant="body-sm-normal" color="secondary">
            {description}
          </Text>
        )}
      </div>
      {children}
    </section>
  );
}

const FIELD_LABELS: [keyof Omit<FieldStrategy, 'rawFallback'>, string][] = [
  ['ip', 'IP indicator fields'],
  ['domain', 'Domain indicator fields'],
  ['hash', 'Hash indicator fields'],
  ['sourceHost', 'Source host fields'],
  ['destinationHost', 'Destination host fields'],
  ['user', 'User fields'],
  ['eventType', 'Event type fields'],
  ['sourceIp', 'Source IP fields'],
  ['destinationIp', 'Destination IP fields'],
  ['destinationPort', 'Destination port fields'],
  ['details', 'Detail / message fields'],
];

export default function SettingsPage() {
  const app = useApp();
  const [draft, setDraft] = useState<AppSettings>(app.settings);
  const [vtKey, setVtKey] = useState('');
  const [vtBusy, setVtBusy] = useState(false);
  const [vtMsg, setVtMsg] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const [saved, setSaved] = useState(false);
  const connected = isInCribl();
  const search = useProbe('search', app.settings.demoMode, app.settings);
  const lookups = useProbe('lookups', app.settings.demoMode, app.settings);

  const [groups, setGroups] = useState<string[]>([]);
  useEffect(() => setDraft(app.settings), [app.settings]);
  useEffect(() => {
    if (!connected || app.settings.demoMode) return;
    const ctl = new AbortController();
    criblFetch<{ items?: { id: string }[] }>('/products/stream/groups', { signal: ctl.signal })
      .then((b) => setGroups((b.items ?? []).map((g) => g.id)))
      .catch(() => setGroups([]));
    return () => ctl.abort();
  }, [connected, app.settings.demoMode]);
  const dirty = JSON.stringify(draft) !== JSON.stringify(app.settings);
  const set = (patch: Partial<AppSettings>) => {
    setDraft((d) => ({ ...d, ...patch }));
    setSaved(false);
  };
  const toggleDefault = (p: ProviderId) => set({ defaultProviders: draft.defaultProviders.includes(p) ? draft.defaultProviders.filter((x) => x !== p) : [...draft.defaultProviders, p] });

  const saveKey = async () => {
    if (!vtKey.trim()) return;
    setVtBusy(true);
    setVtMsg(null);
    try {
      await app.setVtKey(vtKey);
      setVtKey('');
      setVtMsg('API key stored encrypted. It cannot be read back by the browser.');
    } catch {
      setVtMsg('Could not store the key. Check App KV permissions.');
    } finally {
      setVtBusy(false);
    }
  };

  return (
    <>
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <div className="row">
          <Cog size="md" />
          <Text as="h2" variant="heading-md">
            Settings
          </Text>
        </div>
        <div className="row">
          {saved && <Pill tone="success">Saved</Pill>}
          <Button variant="secondary" onClick={() => set({ ...DEFAULT_SETTINGS, demoMode: draft.demoMode, datasets: draft.datasets })}>
            Reset defaults
          </Button>
          <Button
            variant="primary"
            disabled={!dirty}
            onClick={async () => {
              await app.saveSettings(draft);
              setSaved(true);
            }}
          >
            Save settings
          </Button>
        </div>
      </div>

      <Block title="Environment" description="Live capability checks for this Workspace. Nothing is modified.">
        <div className="stats">
          <Status label="App runtime" tone={connected ? 'success' : 'warning'} text={connected ? 'Inside Cribl' : 'Local preview'} detail={connected ? 'Cribl APIs proxied with your session' : 'Only demo mode works outside Cribl'} />
          <Status label="Cribl Search" tone={search.state === 'ok' ? 'success' : search.state === 'fail' ? 'warning' : 'neutral'} text={search.state === 'ok' ? 'Available' : search.state === 'fail' ? 'Unavailable' : 'Checking'} detail={search.detail} />
          <Status label="Lookup access" tone={lookups.state === 'ok' ? 'success' : lookups.state === 'fail' ? 'warning' : 'neutral'} text={lookups.state === 'ok' ? 'Available' : lookups.state === 'fail' ? 'Unavailable' : 'Checking'} detail={lookups.detail} />
          <Status label="VirusTotal" tone={app.vtStatus.configured ? 'success' : 'neutral'} text={app.vtStatus.configured ? 'Configured' : 'Not configured'} detail={app.vtStatus.updatedAt ? `Key updated ${new Date(app.vtStatus.updatedAt).toLocaleString()}` : 'No API key stored'} />
        </div>
        <label className="source" style={{ maxWidth: 560 }}>
          <input type="checkbox" checked={draft.demoMode} disabled={!connected} onChange={(e) => set({ demoMode: e.target.checked })} />
          <span className="source__text">
            <Text variant="body-sm-semibold">Demo mode</Text>
            <Text variant="body-xs-normal" color="secondary">
              Use deterministic synthetic data (clearly labelled DEMO DATA). No Cribl or VirusTotal API calls are made.{!connected ? ' Always on outside Cribl.' : ''}
            </Text>
          </span>
        </label>
      </Block>

      <Block title="External Intelligence — VirusTotal" description="The key is written to encrypted App KV and injected by the Cribl proxy (config/proxies.yml). The browser never reads it back.">
        <div className="row">
          <Text variant="body-sm-semibold">API key:</Text>
          <Pill tone={app.vtStatus.configured ? 'success' : 'neutral'}>{app.vtStatus.configured ? 'Configured' : 'Not configured'}</Pill>
        </div>
        <div className="row">
          <input className="native-input mono" style={{ minWidth: 380 }} type="password" autoComplete="off" placeholder={app.vtStatus.configured ? 'Enter a new key to replace the stored one' : 'Paste VirusTotal API key'} value={vtKey} onChange={(e) => setVtKey(e.target.value)} aria-label="VirusTotal API key" disabled={!connected} />
          <Button variant="primary" onClick={() => void saveKey()} disabled={!vtKey.trim() || vtBusy || !connected} pending={vtBusy}>
            {app.vtStatus.configured ? 'Replace key' : 'Store key'}
          </Button>
          {app.vtStatus.configured && (
            <Button variant="tertiary" appearance="danger" onClick={() => setConfirmClear(true)} disabled={!connected}>
              Remove key
            </Button>
          )}
        </div>
        {vtMsg && <Text variant="body-xs-normal">{vtMsg}</Text>}
        <Text variant="body-xs-normal" color="secondary">
          Privacy: indicators sent to VirusTotal become part of its dataset and may be visible to the VirusTotal community. Analysts must confirm each external lookup.
        </Text>
      </Block>

      <Block title="Defaults">
        <div className="field-grid">
          <label className="field">
            <Text variant="body-sm-semibold">Default time range</Text>
            <select className="native-select" value={draft.defaultPreset} onChange={(e) => set({ defaultPreset: e.target.value as AppSettings['defaultPreset'] })}>
              {PRESETS.filter((p) => p.value !== 'custom').map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </select>
          </label>
          <div className="field">
            <Text variant="body-sm-semibold">Default providers</Text>
            <div className="row">
              {SOURCES.filter((s) => s.available).map((s) => (
                <label key={s.id} className="row">
                  <input type="checkbox" checked={draft.defaultProviders.includes(s.id)} onChange={() => toggleDefault(s.id)} />
                  <Text variant="body-sm-normal">{s.label}</Text>
                </label>
              ))}
            </div>
          </div>
        </div>
      </Block>

      <Block title="Cribl Search" description="Datasets are chosen from the investigation screen. Limits keep the browser from pulling large result sets.">
        <div className="row">
          <Text variant="body-sm-semibold">Datasets:</Text>
          {draft.datasets.length ? draft.datasets.map((d) => <Pill key={d}>{d}</Pill>) : <Pill tone="warning">None selected</Pill>}
        </div>
        <div className="field-grid">
          <label className="field">
            <Text variant="body-sm-semibold">Max events retrieved</Text>
            <input className="native-input" type="number" min={10} max={5000} value={draft.resultLimit} onChange={(e) => set({ resultLimit: Math.max(10, Math.min(5000, Number(e.target.value) || 500)) })} />
          </label>
          <label className="field">
            <Text variant="body-sm-semibold">Search timeout (seconds)</Text>
            <input className="native-input" type="number" min={15} max={600} value={draft.searchTimeoutSec} onChange={(e) => set({ searchTimeoutSec: Math.max(15, Math.min(600, Number(e.target.value) || 120)) })} />
          </label>
        </div>
      </Block>

      <Block title="Cribl Lookups" description="Lookup files are read-only. Matches are treated as internal threat-intelligence / watch-list hits.">
        <div className="field-grid">
          <label className="field">
            <Text variant="body-sm-semibold">Config group</Text>
            <input className="native-input mono" list="tr-groups" value={draft.lookupGroupId} onChange={(e) => set({ lookupGroupId: e.target.value.trim() })} />
            <datalist id="tr-groups">
              {groups.map((g) => (
                <option key={g} value={g} />
              ))}
            </datalist>
            <Text variant="body-xs-normal" color="secondary">
              {groups.length ? `Stream worker groups: ${groups.join(', ')}` : 'Worker group id that holds the lookup files (e.g. default).'}
            </Text>
          </label>
          <label className="field">
            <Text variant="body-sm-semibold">Lookup files to check (empty = all)</Text>
            <input className="native-input mono" value={draft.lookupIds.join(', ')} onChange={(e) => set({ lookupIds: splitList(e.target.value) })} placeholder="threat_intel.csv, known_c2.csv" />
          </label>
        </div>
      </Block>

      <Block title="IOC search fields" description="Structured fields are matched exactly. Order matters for display fields: the first non-empty field wins.">
        <div className="field-grid">
          {FIELD_LABELS.map(([k, label]) => (
            <label key={k} className="field">
              <Text variant="body-sm-semibold">{label}</Text>
              <textarea className="textarea" value={draft.fields[k].join(', ')} onChange={(e) => set({ fields: { ...draft.fields, [k]: splitList(e.target.value) } })} />
            </label>
          ))}
        </div>
        <label className="row">
          <input type="checkbox" checked={draft.fields.rawFallback} onChange={(e) => set({ fields: { ...draft.fields, rawFallback: e.target.checked } })} />
          <Text variant="body-sm-normal">Also match the indicator in raw event text (fallback)</Text>
        </label>
      </Block>

      <ConfirmDestructive
        open={confirmClear}
        title="Remove the VirusTotal API key?"
        body="This deletes the encrypted key virustotalApiKey from this App's KV store. It cannot be undone; VirusTotal lookups stop working until a new key is stored."
        confirmText="Remove key"
        onConfirm={async () => {
          try {
            await app.clearVtKey();
            setVtMsg('API key removed.');
          } catch {
            setVtMsg('Could not remove the key.');
          }
          setConfirmClear(false);
        }}
        onCancel={() => setConfirmClear(false)}
      />
    </>
  );
}
