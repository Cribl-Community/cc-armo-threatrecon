# ArMo - Threat Recon — Architecture

ArMo - Threat Recon is a frontend-only **Cribl App**: a React + TypeScript SPA (Vite, scaffolded with
`@cribl/apps` 1.2.0) that runs in Cribl's sandboxed App iframe and uses the **Capra** design system.

```
            ┌──────────────────────── Cribl App iframe (browser) ────────────────────────┐
 Analyst ─▶ │ ReconControls ─▶ useInvestigation (runner) ─▶ ProviderSet (live | demo)     │
            │                                   │                                        │
            │         core/ (pure, unit-tested) ◀┘  verdict · story · evidence · query   │
            └───────────┬──────────────────────────────┬───────────────────────────────┬─┘
                        │ fetch(CRIBL_API_URL + …)      │ fetch(https://www.virustotal…)│ KV
                        ▼                               ▼                               ▼
              Cribl API (user's session,     Cribl App external proxy         App KV store
              RBAC + policies.yml)           injects x-apikey from            (settings, saved
              Search jobs · datasets ·       encrypted KV (proxies.yml)       investigations,
              lookups (read-only)                                              candidates)
```

## Frontend layers

| Layer | Path | Responsibility |
|---|---|---|
| Core (pure) | `src/core/` | IOC parsing/normalization, time ranges, verdict rules, evidence aggregation, incident story, query generation, VirusTotal parsing. No React, no I/O — covered by `tests/core.test.ts`. |
| Providers | `src/providers/` | `EvidenceLookupProvider`, `SearchProvider`, `ThreatIntelProvider` interfaces (`types.ts`). Live implementations (`criblLookups.ts`, `criblSearch.ts`, `virustotal.ts`) and a clearly separated demo set (`demo.ts`). `index.ts` is the only switch. |
| State | `src/state/` | `useInvestigation` runs selected providers independently (per-provider status, abort, per-run cache). `AppStore` persists settings / investigations / candidates in App KV. |
| UI | `src/components/`, `src/pages/` | Capra-based screens. Every color comes from Capra tokens, so the App follows Cribl's light/dark theme. |

## Provider execution model

`useInvestigation.run(request)` starts only the providers the analyst selected, in parallel. Each
reports `running → complete | error | unavailable` on its own, so a failing provider never blanks the
page. Provider failures are thrown as `ProviderFailure { kind, message, hint, httpStatus }` and shown
per card. Results are cached per `(IOC, type, window, providers, datasets, demo)` key for the session.

## Deterministic verdict

`src/core/verdict.ts` documents and implements the rules, evaluated top to bottom:

1. No selected provider completed → **Inconclusive**
2. VirusTotal ≥ 3 malicious engines → **Malicious** (qualified *Observed / Not observed*)
3. Internal lookup match **and** observed in telemetry → **Malicious**
4. VirusTotal 1–2 malicious or ≥ 3 suspicious engines → **Suspicious**
5. Internal lookup match only → **Internal Match**
6. Observed, no intel match → **Observed**
7. Every selected provider completed negative (VirusTotal "no record" counts as completed) → **No Evidence**
8. Otherwise → **Inconclusive**

The VirusTotal community `reputation` score never makes an indicator malicious by itself. Absence from
telemetry is always worded "No matching telemetry was found in the selected time range", never "safe".

## Cribl APIs

All Cribl calls use the documented REST API through the App fetch proxy (the user's session and RBAC
apply) and are declared in `config/policies.yml`. They are **read-only**; the App never creates,
updates or deletes Cribl configuration. See `README.md → Permissions` for the exact list.

## External API — VirusTotal

- `GET https://www.virustotal.com/api/v3/{ip_addresses|domains|files}/{id}` from the browser; the Cribl
  App proxy rewrites it to the App-scoped proxy endpoint.
- `config/proxies.yml` restricts the host to those three path prefixes and injects
  `x-apikey: kv.virustotalApiKey`.
- The key is written once from Settings with an **encrypted** KV write (write-only: the browser can
  never read it back). A separate plain KV record `virustotal/status` only says *configured / when / by whom*.
- VirusTotal runs only after the analyst ticks the external-lookup consent for that indicator.

## KV layout (App-scoped, per Workspace)

| Key | Content |
|---|---|
| `settings/v1` | App settings: defaults, datasets, lookup group/files, field strategy, limits, demo mode |
| `virustotal/status` | `{ configured, updatedAt, updatedBy }` — never the key |
| `virustotalApiKey` | **Encrypted** VirusTotal key (write-only) |
| `users/{userId}/investigations/index` | Saved investigation summaries (no raw events) |
| `users/{userId}/detections/index` | Detection candidates |

## Data flow for one investigation

1. Input is validated and normalized client-side (`core/ioc.ts`); invalid values are never sent.
2. The time window is re-anchored to "now" at run time and validated (`core/timeRange.ts`).
3. Selected providers run in parallel; results are normalized into `LookupResult`, `SearchResult`, `VtResult`.
4. `core/evidence.ts` aggregates only returned events (counts, first/last seen, top entities, timeline buckets, relationships).
5. `core/verdict.ts` and `core/story.ts` produce the verdict and narrative deterministically.
6. `core/query.ts` builds the detection-candidate query from the fields and datasets that actually matched.

## Security notes

- No browser storage (localStorage, sessionStorage, IndexedDB, cookies). App KV only.
- No secrets in source, bundle, logs or network payloads to the browser.
- Diagnostics mask IOC values (`maskIndicator`) and never log raw events.
- Query generation escapes string literals and rejects field names outside `[A-Za-z_][A-Za-z0-9_.]*`,
  so settings cannot inject query syntax.
- Destructive actions (deleting a saved item or the VirusTotal key) require explicit confirmation that
  names the exact item, and only touch App-owned KV.
