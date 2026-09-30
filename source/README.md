# ArMo - Threat Recon

From Indicator → Evidence → Detection: one IOC, the sources you choose, the time window you choose, and deterministic, auditable evidence from Cribl Lookups, Cribl Search and VirusTotal.

This README uses fixed section names and a fixed metadata table so it can be rendered as normal Markdown today and parsed into App Gallery components later.

## Summary

ArMo - Threat Recon is a Cribl app for IOC investigation. It helps SOC analysts check whether an indicator is in internal lookup data, prove whether it was actually observed in Cribl telemetry (when, where, how often), and turn the evidence into a reviewable detection-candidate query — without an AI black box.

## What This App Does

* Primary purpose: a focused, fast investigation workflow for a single Indicator of Compromise (IPv4, IPv6, domain, MD5, SHA-1, SHA-256).
* Key capabilities:
  * Client-side IOC validation, normalization and type detection (invalid values are never sent anywhere)
  * **Cribl Lookups** — read-only exact matches in Stream lookup files
  * **Cribl Search / Cribl Lake** — a search job over the datasets and time window you select, with first/last seen, counts, top hosts, users, event types, an evidence table, timeline and relationship view
  * **VirusTotal** (optional, consent-gated) — scanner statistics kept separate from community reputation
  * A deterministic, explainable verdict: *Malicious · Suspicious · Internal Match · Observed · No Evidence · Inconclusive*
  * A deterministic incident story and a detection-candidate query built from the fields and datasets that actually matched
  * Saved investigations and detection candidates; optional **Save as Search** in Cribl Search
  * Demo mode with clearly labelled synthetic data for presentations
* Intended users:
  * Analyst, Admin
* Works with:
  * Cribl.Cloud · Cribl Search / Lake · Cribl Stream (lookups)

ArMo - Threat Recon is not an AI investigator. It answers one question precisely: *is this IOC known, did we see it, when and where, and what evidence supports that?*

## When To Use This App

* An alert, threat-intel feed or colleague hands you an IP, domain or hash and you need to know "did we see this?" fast.
* You want an auditable answer limited to specific datasets and an exact time window.
* You want to check internal watch lists and (optionally) external reputation in the same place.
* You want a starting query for a detection once an indicator is confirmed in your telemetry.

## Before You Install

* Required Cribl product or deployment type: Cribl.Cloud with Cribl Search (Cribl Lake datasets or any searchable dataset); Stream worker group with lookup files for the Lookups source.
* Required permissions or roles: users need their normal Cribl Search access, read access to lookups in the configured group, and the **App user** role on this App.
* Required external systems or APIs: VirusTotal v3 (optional) — an admin must approve `www.virustotal.com` at install time and store an API key in Settings.
* Required configuration values: datasets to search (picked on first run); lookup config group (default `default`).
* Known limits or prerequisites: VirusTotal public API: 4 requests/minute, 500/day, not for commercial use. Cribl Search `earliest` can be at most 90 days back; the App caps a window at 90 days and warns above 7 days.

## Installation

### Install From Marketplace or URL
1. Go to Apps in your Cribl environment.
2. Choose the Marketplace or import from URL option.
3. If the app is available in the Cribl Marketplace, install it directly from there.
4. If the app is distributed as a Marketplace-hosted URL, use the URL to import it.
5. Review the app details and complete installation.

### If The App Is Not Yet In The Cribl Marketplace
1. Build the package: `npm install && npm run package` (produces the `.tgz`).
2. In Cribl, go to Apps and choose import from file.
3. Upload the `.tgz` file.
4. Review the declared permissions (`policies.yml`) and external endpoint (`proxies.yml`), then complete installation.
5. Share the App with the users or teams who need it (**App user**).

## Configuration

| Setting | Required | Description | Example | Scope |
|---|---|---|---|---|
| Datasets | Yes (for Search) | Cribl Search datasets to query. Only these are searched. | `firewall_logs, proxy_logs, dns_logs` | shared |
| Lookup config group | No | Stream worker group holding the lookup files. | `default` | shared |
| Lookup files | No | Files to check; empty = all in the group (max 40). | `threat_intel.csv, known_c2.csv` | shared |
| VirusTotal API key | No | Stored **encrypted** and write-only; injected by the Cribl proxy. | — | shared |
| Default time range | No | Preselected window. | Last 24 hours | shared |
| Default providers | No | Preselected sources. | Lookups, Search, VirusTotal | shared |
| Max events retrieved | No | Cap on events pulled into the browser. | 500 | shared |
| Search timeout | No | Seconds to wait; on timeout the job is cancelled and partial results shown. | 120 | shared |
| IOC search fields | No | Field names for IPs, domains, hashes, hosts, users…; exact match, optional raw-text fallback. | `src_ip, dst_ip` | shared |
| Demo mode | No | Deterministic synthetic data labelled DEMO DATA; no API calls. | Off | shared |

Blank datasets block a Search run with a clear message. Blank VirusTotal key → VirusTotal shows *Not configured*; other sources still run.

## How To Use

### Typical Workflow
1. Open **ArMo - Threat Recon** from the Apps page.
2. **Enter an IOC** — the type is detected automatically (override if needed).
3. **Select sources** — Cribl Lookups, Cribl Lake / Search, VirusTotal. Confirm the external-lookup notice if VirusTotal is selected.
4. **Set the time range** (presets or custom; timezone shown) and datasets.
5. **Run Investigation** — each source reports independently.
6. Review the **Overall Verdict**, provider cards, evidence table, timeline, relationships and incident story.
7. Open **Detection Candidate** → copy, save as candidate, or save as a Cribl saved search.

### First-Run Checklist
* Settings → check that *Cribl Search* and *Lookup access* show **Available**.
* Pick datasets (**Datasets → Change** on the investigation screen).
* Optionally store a VirusTotal API key in Settings.

## Permissions

Everything is read-only except creating/cancelling the App's own search jobs and the optional, explicitly confirmed creation of a saved search. The App never creates, updates or deletes pipelines, routes, sources, destinations, workers, datasets or lookup tables. The App cannot do anything the signed-in user cannot do in the Cribl UI. If an API is denied, that source shows *Permission denied* and the other sources still complete.

### Cribl API Endpoints Used

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v1/m/default_search/search/datasets` | List searchable datasets for the dataset picker and Settings status |
| POST | `/api/v1/m/default_search/search/jobs` | Create the IOC search job (`cribl …` single-line query, epoch-second window) |
| GET | `/api/v1/m/default_search/search/jobs/{id}/status` | Poll job status |
| GET | `/api/v1/m/default_search/search/jobs/{id}/results` | Page NDJSON results (`limit`, `offset`) |
| POST | `/api/v1/m/default_search/search/jobs/{id}/cancel` | Cancel the App's own job on timeout or user cancel |
| POST | `/api/v1/m/default_search/search/saved` | Optional: create a saved search from a detection candidate (after confirmation) |
| GET | `/api/v1/m/{group}/system/lookups` | List lookup files in the configured group |
| GET | `/api/v1/m/{group}/system/lookups/{id}/content` | Read candidate rows via the `q` row filter; the App then requires an exact cell match |
| GET | `/api/v1/products/stream/groups` | Suggest lookup config groups in Settings |
| GET/PUT/DELETE | `/api/v1/kvstore/*` (App-scoped) | Settings, saved investigations, candidates, encrypted VirusTotal key |

Example generated query:

```
cribl (dataset="firewall" or dataset="proxy") | where src_ip == "203.0.113.45" or dst_ip == "203.0.113.45" or _raw has "203.0.113.45" | sort by _time desc | limit 500
```

## External API Access

### Default Configuration
* `default/proxies.yml` — `www.virustotal.com`, paths `/api/v3/ip_addresses/`, `/api/v3/domains/`, `/api/v3/files/` only; injects `x-apikey` from the encrypted KV value `virustotalApiKey`.
* `default/policies.yml` — the Cribl API paths listed above.

### External Endpoints
* VirusTotal v3 — reputation and scanner statistics for IPs, domains and file hashes.

**⚠️ Privacy:** VirusTotal states that indicators queried via its API are added to the VirusTotal dataset and may become visible to its community. ArMo - Threat Recon never queries VirusTotal automatically; the analyst must confirm the external-lookup notice for each indicator. Do not use this option for confidential or sensitive indicators.

## Data And Storage

* KV keys (App-scoped, per Workspace):
  * `settings/v1` — app settings (shared)
  * `virustotal/status` — whether a key is configured, when, by whom (never the key)
  * `virustotalApiKey` — **encrypted**, write-only VirusTotal key
  * `users/{userId}/investigations/index` — saved investigation summaries (per user; no raw events)
  * `users/{userId}/detections/index` — detection candidates (per user)
* No browser storage is used. Uninstalling the App deletes its KV data.

## Support

### Community Built
This app is a hackathon community contribution. It may be useful for learning, experimentation, or shared workflows, but it does not carry an official support commitment from Cribl. Contact the author, Arno Arzumanyan, for questions and fixes.

## Known Limitations

* Lookup matching reads Stream lookup files in one config group; Cribl Search-native lookups (`$vt_lookups`) are not yet queried.
* Results are capped (default 500 events); totals come from the search job and the timeline plots retrieved events.
* `_time` is treated as epoch seconds below 1e11, otherwise milliseconds (the documentation describes both).
* "Other Threat Intel" and "WHOIS / DNS" are placeholders for future providers; "Create Detection in Cribl" is intentionally disabled.
* Live Preview is not supported in Safari.

## Troubleshooting

### The App Opens But Some Features Do Not Work
Possible causes:
* Missing permissions — the affected card shows *Permission denied*
* No datasets selected — Search is blocked with a message
* VirusTotal not configured or not approved by an admin
* Running outside Cribl — only demo mode works

### The App Cannot Connect To An API Or Service
Check:
* Settings → Environment status
* `www.virustotal.com` is approved for this App
* The VirusTotal key is stored (Settings shows *Configured*)
* The lookup config group id

### The App Works Locally But Not In Cribl
Check:
* Packaging and deployment version
* That the App is shared with you (**App user**)
* Your Cribl Search and lookup permissions

## Development

```bash
npm install
npm run dev       # then Apps → Create App → Live Preview in Cribl (Chrome, Edge or Firefox)
npm test          # unit + provider integration tests (Node test runner)
npm run lint
npm run build     # tsc + vite build + apps build
npm run package
```

* Core logic is pure and tested in `src/core/`; providers in `src/providers/`; UI in `src/components/` and `src/pages/`.
* Outside Cribl the App runs in demo mode only.
* See `ARCHITECTURE.md` for design and data flow, `DEMO.md` for a 2-minute demo script.

## Project Layout

```text
src/
  App.tsx, main.tsx
  core/        IOC, time range, verdict, evidence, story, query, parsers (pure, tested)
  providers/   live Cribl Search / Lookups / VirusTotal + demo providers
  state/       investigation runner, App KV store
  components/  investigation UI
  pages/       Investigation, Saved Investigations, Detection Candidates, Settings
  styles/      token-based CSS (light + dark)
tests/         node:test suites
config/
  policies.yml   Cribl API access grants
  proxies.yml    VirusTotal endpoint + key injection
README.md, ARCHITECTURE.md, DEMO.md
```

## Versioning And Releases

* Semantic versioning; `npm run package` bumps the patch version.
* Upgrading keeps App KV data (settings, saved items, the encrypted key).

## Contributing

Open an issue or contact the author. Keep all Cribl API usage to documented endpoints and add tests for new providers.

## License

This app is licensed under the Apache License 2.0 — see [LICENSE](./LICENSE).

## App Metadata

| Field | Value |
|---|---|
| App Name | ArMo - Threat Recon |
| App ID | threat-recon |
| Version | 0.1.0 |
| Author | Arno Arzumanyan |
| Support Model | community-built |
| Support Label | Community Built |
| Support Contact | App author (Arno Arzumanyan) |
| License | Apache-2.0 |
| License File | [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.txt) |
| Product Tags | search, lake |
| Category | Security investigation |
| Audience | analyst, admin |
| Availability | preview |
| Requires External Access | yes |
| Repository | — |
| Documentation | ARCHITECTURE.md, DEMO.md |
| README Schema Version | 1.0 |
