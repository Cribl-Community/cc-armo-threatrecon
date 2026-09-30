# ArMo - Threat Recon — 2-minute demo script

**Setup (before you present)**
- Open ArMo - Threat Recon from **Apps** in Cribl. Switch Cribl to the **dark theme** (account menu); the App follows it.
- Demo path: **Settings → Demo mode** on. Every synthetic result is labelled **DEMO DATA**.
- Live path: Demo mode off, pick datasets once (**Datasets → Change**), and store a VirusTotal key in Settings.

The demo scenarios use IETF documentation addresses (RFC 5737 `203.0.113.0/24`, `198.51.100.0/24`, and
`example.net`) so the demo never labels a real third party's infrastructure as malicious.

---

**0:00 — "Give me an IOC."**
Paste `203.0.113.45` (or click the **Malicious IP** scenario card). The field shows **Type: IP Address (IPv4)**. Invalid input never leaves the browser.

**0:10 — "Tell me where I want to look."**
Cribl Lookups, Cribl Lake / Search, VirusTotal are checked. Point at **Other Threat Intel** and **WHOIS / DNS**: disabled, *Coming soon*. Nothing is faked.
Tick the external-lookup notice: *the IOC will be sent to VirusTotal* — nothing external runs without that consent.

**0:20 — "Tell me when."**
**Last 24 hours**. The exact window and timezone are shown. This window drives the Cribl Search job.

**0:25 — Run Investigation.**
Each provider reports independently (*Checking internal intelligence… / Querying external intelligence… / Searching telemetry…*). A failing provider never blanks the page.

**0:35 — Overall Verdict: MALICIOUS — Observed in selected window.**
Read the "why" list: found in 2 of 4 internal lookups · observed in 47 events · N/M VirusTotal engines.
"This is deterministic. The rules are in `src/core/verdict.ts` — no AI, no black box."

**0:50 — Intelligence + evidence.**
- VirusTotal donut: scanner statistics, kept separate from community reputation.
- Cribl Lookups: which tables matched, with the matching row.
- **Observed in Cribl Lake**: events, hosts, datasets, first/last seen, top hosts, event types, and the evidence table (only columns that have data).

**1:15 — Event Timeline.** Hover a spike, click it → the exact event opens with every field and the field that matched.

**1:30 — Evidence Relationships + Incident Story.**
The graph only draws entities that co-occur in returned events. The story is generated from structured results: "was found / was observed / returned".

**1:40 — Detection Candidate.**
**Create Detection Candidate** → the Cribl Search query narrowed to the fields and datasets that actually matched, summarised per host. **Save as Candidate** → it appears under *Detection Candidates*.
"Create Detection in Cribl" is deliberately disabled: this version never writes production config.

**1:55 — Close.**
"One IOC, the sources I chose, the window I chose, deterministic evidence I can audit, and a detection I can review. Intelligence + observability + investigation + action — on data Cribl already has."

---

Contrast scenarios if time allows: **Clean IP** → *No Evidence* (never "safe"), **Observed, not malicious** → *Observed*, **No evidence** hash → VirusTotal *no record*.
