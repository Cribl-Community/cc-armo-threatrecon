import { useId } from 'react';
import { Button, Text } from '@capra/core';
import { CloseOutlined, Search } from '@capra/icons';
import { IOC_TYPE_LABELS, type ParseResult } from '../core/ioc';
import { PRESETS, formatInZone, formatSpan, fromLocalInput, toLocalInput, zoneAbbrev, type RangeCheck } from '../core/timeRange';
import type { IocType, ProviderId, TimeRange } from '../core/types';
import { Pill } from '../ui/common';

export interface SourceDef {
  id: ProviderId;
  label: string;
  description: string;
  available: boolean;
  external?: boolean;
}

export const SOURCES: SourceDef[] = [
  { id: 'lookups', label: 'Cribl Lookups', description: 'Check configured internal lookup data', available: true },
  { id: 'search', label: 'Cribl Lake / Search', description: 'Search telemetry for actual observation', available: true },
  { id: 'virustotal', label: 'VirusTotal', description: 'External reputation and enrichment', available: true, external: true },
  { id: 'otherIntel', label: 'Other Threat Intel', description: 'Coming soon', available: false },
  { id: 'whois', label: 'WHOIS / DNS', description: 'Coming soon', available: false },
];

interface Props {
  iocText: string;
  onIocText: (v: string) => void;
  manualType: IocType | '';
  onManualType: (t: IocType | '') => void;
  parsed: ParseResult;
  touched: boolean;
  providers: ProviderId[];
  onToggleProvider: (p: ProviderId) => void;
  consent: boolean;
  onConsent: (v: boolean) => void;
  range: TimeRange;
  onRange: (r: TimeRange) => void;
  rangeCheck: RangeCheck;
  datasets: string[];
  onEditDatasets: () => void;
  onRun: () => void;
  onReset: () => void;
  running: boolean;
  demo: boolean;
  blocker: string | null;
}

export function ReconControls(p: Props) {
  const iocId = useId();
  const typeId = useId();
  const presetId = useId();
  const searchOn = p.providers.includes('search');
  const vtOn = p.providers.includes('virustotal');
  const tz = p.range.timezone;
  const invalid = p.touched && !p.parsed.ok && p.iocText.trim() !== '';

  return (
    <section className="panel recon" aria-label="Investigation controls">
      {/* STEP 1 */}
      <div className="recon__step">
        <label className="recon__label" htmlFor={iocId}>
          <span className="recon__num">1</span>
          <Text variant="body-md-semibold">Enter an Indicator of Compromise (IOC)</Text>
        </label>
        <div className={`ioc-input ${invalid ? 'ioc-input--invalid' : ''}`}>
          <span className="muted" aria-hidden style={{ display: 'inline-flex' }}>
            <Search size="sm" />
          </span>
          <input
            id={iocId}
            value={p.iocText}
            onChange={(e) => p.onIocText(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && p.onRun()}
            placeholder="IP address, domain, MD5, SHA-1 or SHA-256"
            spellCheck={false}
            autoComplete="off"
            aria-invalid={invalid}
            aria-describedby={`${iocId}-hint`}
          />
          {p.iocText && (
            <button type="button" className="icon-btn" onClick={p.onReset} aria-label="Clear indicator">
              <CloseOutlined size="xs" />
            </button>
          )}
        </div>
        <div className="row" id={`${iocId}-hint`} aria-live="polite">
          {p.parsed.ok ? (
            <Pill tone="brand">Type: {IOC_TYPE_LABELS[p.parsed.indicator.type]}</Pill>
          ) : invalid ? (
            <Text variant="body-xs-normal" color="warning">
              {p.parsed.message}
            </Text>
          ) : (
            <Text variant="body-xs-normal" color="secondary">
              Supports IPv4, IPv6, domains, MD5, SHA-1 and SHA-256
            </Text>
          )}
          <label className="row" htmlFor={typeId} style={{ marginLeft: 'auto' }}>
            <Text variant="body-xs-normal" color="secondary">
              Type
            </Text>
            <select id={typeId} className="native-select" style={{ height: 26, fontSize: 12 }} value={p.manualType} onChange={(e) => p.onManualType(e.target.value as IocType | '')}>
              <option value="">Auto-detect</option>
              {(Object.keys(IOC_TYPE_LABELS) as IocType[]).map((t) => (
                <option key={t} value={t}>
                  {IOC_TYPE_LABELS[t]}
                </option>
              ))}
            </select>
          </label>
        </div>
      </div>

      {/* STEP 2 */}
      <div className="recon__step">
        <div className="recon__label">
          <span className="recon__num">2</span>
          <Text variant="body-md-semibold">Select sources to check</Text>
        </div>
        <div className="sources" role="group" aria-label="Sources">
          {SOURCES.map((s) => {
            const on = p.providers.includes(s.id);
            return (
              <label key={s.id} className={`source ${on ? 'source--on' : ''} ${!s.available ? 'source--off' : ''}`} title={s.available ? s.description : 'Coming soon'}>
                <input type="checkbox" checked={on} disabled={!s.available} onChange={() => p.onToggleProvider(s.id)} />
                <span className="source__text">
                  <Text variant="body-sm-semibold">{s.label}</Text>
                  <Text variant="body-xs-normal" color="secondary">
                    {s.available ? s.description : 'Coming soon'}
                  </Text>
                </span>
              </label>
            );
          })}
        </div>
        {vtOn && (
          <label className="consent">
            <input type="checkbox" checked={p.consent} onChange={(e) => p.onConsent(e.target.checked)} />
            <span>
              <Text as="div" variant="body-xs-semibold">
                External lookup{p.demo ? ' (demo mode: nothing is sent)' : ''}
              </Text>
              <Text as="div" variant="body-xs-normal">
                {' '}The selected IOC will be sent to VirusTotal for enrichment. Do not use this option for confidential or sensitive indicators. <strong>I understand.</strong>
              </Text>
            </span>
          </label>
        )}
      </div>

      {/* STEP 3 */}
      <div className="recon__step">
        <label className="recon__label" htmlFor={presetId}>
          <span className="recon__num">3</span>
          <Text variant="body-md-semibold">Set time range for Cribl Lake search</Text>
        </label>
        <select
          id={presetId}
          className="native-select"
          value={p.range.preset}
          disabled={!searchOn}
          onChange={(e) => {
            const v = e.target.value as TimeRange['preset'];
            const def = PRESETS.find((x) => x.value === v)!;
            const now = Date.now();
            p.onRange(v === 'custom' ? { ...p.range, preset: 'custom' } : { preset: v, startMs: now - def.ms, endMs: now, timezone: tz });
          }}
        >
          {PRESETS.map((x) => (
            <option key={x.value} value={x.value}>
              {x.label}
            </option>
          ))}
        </select>
        {p.range.preset === 'custom' && (
          <div className="row">
            <input aria-label="Start" type="datetime-local" className="native-input" value={toLocalInput(p.range.startMs)} onChange={(e) => p.onRange({ ...p.range, startMs: fromLocalInput(e.target.value) })} />
            <span className="muted">→</span>
            <input aria-label="End" type="datetime-local" className="native-input" value={toLocalInput(p.range.endMs)} onChange={(e) => p.onRange({ ...p.range, endMs: fromLocalInput(e.target.value) })} />
          </div>
        )}
        <Text variant="body-xs-normal" color="secondary">
          TIME WINDOW FOR CRIBL SEARCH · {zoneAbbrev(tz)} ({tz})
        </Text>
        {p.rangeCheck.ok ? (
          <Text variant="body-xs-normal">
            {formatInZone(p.range.startMs, tz)} → {formatInZone(p.range.endMs, tz)} · {formatSpan(p.range.endMs - p.range.startMs)}
          </Text>
        ) : (
          <Text variant="body-xs-normal" color="warning">
            {p.rangeCheck.error}
          </Text>
        )}
        {p.rangeCheck.ok && p.rangeCheck.warning && (
          <Text variant="body-xs-normal" color="warning">
            {p.rangeCheck.warning}
          </Text>
        )}
        {searchOn && (
          <div className="row">
            <Text variant="body-xs-normal" color="secondary">
              Datasets:
            </Text>
            {p.datasets.length ? p.datasets.slice(0, 3).map((d) => <Pill key={d}>{d}</Pill>) : <Pill tone="warning">None selected</Pill>}
            {p.datasets.length > 3 && <Pill>+{p.datasets.length - 3}</Pill>}
            <button type="button" className="tab" style={{ padding: '0 4px' }} onClick={p.onEditDatasets}>
              Change
            </button>
          </div>
        )}
      </div>

      {/* RUN */}
      <div className="recon__run">
        <Button variant="primary" size="lg" leadingIcon={Search} onClick={p.onRun} pending={p.running} disabled={p.running} block>
          Run Investigation
        </Button>
        {p.blocker ? (
          <Text variant="body-xs-normal" color="warning">
            {p.blocker}
          </Text>
        ) : (
          <Text variant="body-xs-normal" color="secondary">
            Runs only the selected sources. Nothing runs while typing.
          </Text>
        )}
      </div>
    </section>
  );
}
