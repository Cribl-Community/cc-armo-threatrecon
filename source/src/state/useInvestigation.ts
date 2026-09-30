import { useCallback, useMemo, useRef, useState } from 'react';
import { maskIndicator } from '../core/ioc';
import type { AppSettings } from '../core/settings';
import type { InvestigationRequest, Outcomes, ProviderError, ProviderOutcome } from '../core/types';
import { getProviders } from '../providers';
import { ProviderFailure, type ProviderContext, type SearchProgress } from '../providers/types';

const idle = (): Outcomes => ({
  lookups: { status: 'idle', demo: false },
  search: { status: 'idle', demo: false },
  virustotal: { status: 'idle', demo: false },
});

const toError = (e: unknown): ProviderError => {
  if (e instanceof ProviderFailure) return e.error;
  if (e instanceof DOMException && e.name === 'AbortError') return { kind: 'timeout', message: 'Cancelled.' };
  if (e instanceof TypeError) return { kind: 'network', message: 'Network error while contacting the provider.' };
  return { kind: 'server', message: 'Unexpected provider error.' };
};

export interface RunState {
  request: InvestigationRequest | null;
  outcomes: Outcomes;
  searchProgress: SearchProgress | null;
  runId: number;
  running: boolean;
}

const cacheKey = (r: InvestigationRequest) => JSON.stringify([r.indicator.value, r.indicator.type, r.timeRange.startMs, r.timeRange.endMs, [...r.providers].sort(), [...r.datasets].sort(), r.demo]);

export function useInvestigation(settings: AppSettings) {
  const [state, setState] = useState<RunState>({ request: null, outcomes: idle(), searchProgress: null, runId: 0, running: false });
  const abortRef = useRef<AbortController | null>(null);
  const cache = useRef(new Map<string, Outcomes>());

  const run = useCallback(
    (request: InvestigationRequest) => {
      abortRef.current?.abort();
      const key = cacheKey(request);
      const cached = cache.current.get(key);
      if (cached) {
        setState((s) => ({ request, outcomes: cached, searchProgress: null, runId: s.runId + 1, running: false }));
        return;
      }
      const ctl = new AbortController();
      abortRef.current = ctl;
      const providers = getProviders(request.demo);
      const ctx: ProviderContext = { signal: ctl.signal, settings };
      const initial = idle();
      for (const p of ['lookups', 'search', 'virustotal'] as const) initial[p] = { status: request.providers.includes(p) ? 'running' : 'skipped', demo: request.demo, startedAt: Date.now() };
      const live: Outcomes = { ...initial };
      setState((s) => ({ request, outcomes: initial, searchProgress: null, runId: s.runId + 1, running: true }));

      const settle = <K extends keyof Outcomes>(p: K, outcome: Outcomes[K]) => {
        if (ctl.signal.aborted && outcome.error?.message === 'Cancelled.') return;
        live[p] = outcome;
        setState((s) => (s.request === request ? { ...s, outcomes: { ...s.outcomes, [p]: outcome } } : s));
      };
      const exec = async <K extends keyof Outcomes>(p: K, fn: () => Promise<NonNullable<Outcomes[K]['data']>>) => {
        if (!request.providers.includes(p)) return;
        const startedAt = Date.now();
        try {
          const data = await fn();
          settle(p, { status: 'complete', data, demo: request.demo, startedAt, finishedAt: Date.now() } as Outcomes[K]);
        } catch (e) {
          // A superseded or cancelled run is not a provider failure.
          if (ctl.signal.aborted) return;
          const error = toError(e);
          // Diagnostics never include the full IOC value or any secret.
          console.warn(`[threat-recon] ${p} failed for ${maskIndicator(request.indicator.value)}: ${error.kind}${error.httpStatus ? ` (${error.httpStatus})` : ''}`);
          const status = error.kind === 'unavailable' || error.kind === 'permission' || error.kind === 'not_configured' ? 'unavailable' : 'error';
          settle(p, { status, error, demo: request.demo, startedAt, finishedAt: Date.now() } as ProviderOutcome<never> as Outcomes[K]);
        }
      };

      void Promise.all([
        exec('lookups', () => providers.lookups.check(request.indicator, ctx)),
        exec('virustotal', () => providers.virustotal.lookup(request.indicator, ctx)),
        exec('search', () =>
          providers.search.search(request.indicator, request.timeRange, request.datasets, ctx, (progress) =>
            setState((s) => (s.request === request ? { ...s, searchProgress: progress } : s)),
          ),
        ),
      ]).then(() => {
        if (ctl.signal.aborted) return;
        cache.current.set(key, { ...live });
        setState((s) => (s.request === request ? { ...s, running: false, searchProgress: null } : s));
      });
    },
    [settings],
  );

  const cancel = useCallback(() => {
    abortRef.current?.abort();
    setState((s) => {
      const o = { ...s.outcomes };
      for (const p of ['lookups', 'search', 'virustotal'] as const) if (o[p].status === 'running') o[p] = { status: 'error', error: { kind: 'timeout', message: 'Cancelled by user.' }, demo: o[p].demo };
      return { ...s, outcomes: o, running: false, searchProgress: null };
    });
  }, []);

  const reset = useCallback(() => {
    abortRef.current?.abort();
    setState((s) => ({ request: null, outcomes: idle(), searchProgress: null, runId: s.runId + 1, running: false }));
  }, []);

  return useMemo(() => ({ ...state, run, cancel, reset }), [state, run, cancel, reset]);
}
