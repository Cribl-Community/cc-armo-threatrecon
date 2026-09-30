# ArMo - Threat Recon

**From Indicator → Evidence → Detection — inside Cribl.**

ArMo - Threat Recon is a Cribl App that answers the first question every SOC analyst asks about a suspicious
IP, domain or file hash:

> **"Do we know this indicator, did we actually see it, when and where — and what's the proof?"**

Paste one indicator, choose the sources to check and the time window, press **Run Investigation**. In seconds
you get one clear verdict, backed by evidence you can audit, and a ready-made detection query.

**Enter IOC → Select sources → Set time range → Run → Verdict · Evidence · Timeline · Detection candidate**

---

## Why it matters

| Without Threat Recon | With Threat Recon |
|---|---|
| Jump between lookup tables, Cribl Search, and VirusTotal in separate tabs | One screen, one click, all selected sources in parallel |
| Hand-write a search query for every IOC and every dataset | Queries are generated for you from the IOC type and configurable field names |
| "It's in a threat feed" ≠ "it hit our network" | Internal intel, external reputation **and** real telemetry evidence, side by side |
| Opaque scores and AI summaries that are hard to defend | A deterministic, rule-based verdict with the exact reasons listed |
| Findings stay in a chat or ticket | Save the investigation, and turn the evidence into a detection candidate or a Cribl saved search |

**Benefits at a glance**

- ⏱️ **Faster triage** — minutes of copy-paste become one run.
- 🔍 **Proof, not guesses** — first seen, last seen, event counts, hosts, users, datasets and the raw events.
- 🧾 **Auditable** — every verdict shows *why*; the same inputs always give the same answer.
- 🛡️ **Safe by design** — read-only, no secrets in the browser, external lookups only with explicit consent.
- 🎯 **Actionable** — a detection-candidate query built from what actually matched.
- 💸 **Uses what you already have** — your Cribl Lake / Search datasets and Stream lookup files. No new infrastructure.

> Threat Recon is deliberately **not** an AI investigator. It complements Cribl's AI features by giving
> analysts a precise, repeatable, evidence-first workflow for a single indicator.

---

## What it does

**1. Enter an Indicator of Compromise.** IPv4, IPv6, domain, MD5, SHA-1 or SHA-256. The type is detected
automatically and validated in the browser — invalid values are never sent anywhere.

**2. Select the sources to check.**
- **Cribl Lookups** — is the indicator in your internal watch lists / threat-intel lookup files?
- **Cribl Lake / Search** — was it actually observed in your telemetry?
- **VirusTotal** *(optional)* — external reputation and engine statistics.

**3. Set the time window** for the Cribl Search — presets from 15 minutes to 30 days, or a custom range, with the
timezone shown clearly.

**4. Get the answer.** Each source reports on its own, so one slow or failing source never blocks the others.

| You see | What it tells you |
|---|---|
| **Overall Verdict** | *Malicious · Suspicious · Internal Match · Observed · No Evidence · Inconclusive* — plus the reasons |
| **Provider cards** | Found / not found, malicious / clean, observed / not observed — at a glance |
| **Observed in Cribl Lake** | Events, hosts, users, datasets, first & last seen, top hosts and event types, and the evidence table |
| **Event Timeline** | When the activity happened; click any spike to open the exact event |
| **Evidence Relationships** | Which hosts, users, datasets and destinations were connected to the indicator |
| **Incident Story** | A short, plain-English summary written only from the results — no speculation |
| **Detection Candidate** | A Cribl Search query narrowed to the fields and datasets that matched — copy it, save it, or save it as a Cribl saved search |

**5. Keep the work.** *Saved Investigations* and *Detection Candidates* pages keep summaries for later
(stored in the App's own storage — never raw events).

---

## Install

The installable package is in this repository: **`threat-recon-0.1.2.tgz`**.

1. In Cribl, go to **Apps → Add App → Import from File**.
2. Upload `threat-recon-0.1.2.tgz`.
3. Review the declared permissions and the external endpoint (`www.virustotal.com`) and confirm.
4. **Share** the App with the users or teams who should use it (**App user** role).

### First run (2 minutes)

1. Open **ArMo - Threat Recon** from **Apps**.
2. Go to **Settings** — check that *Cribl Search* and *Lookup access* show **Available**.
3. On the investigation screen, click **Datasets → Change** and pick the datasets to search (firewall, proxy, DNS, endpoint…).
4. *(Optional)* Paste a VirusTotal API key in **Settings**. It is stored encrypted and can never be read back.
5. Enter an indicator and click **Run Investigation**.

**Just want to see it?** Turn on **Settings → Demo mode** and click one of the four one-click scenarios.
All demo results are clearly labelled **DEMO DATA** and use reserved documentation addresses, so no real
organisation is ever labelled malicious.

---

## Trust & safety

- **Read-only.** Threat Recon never changes pipelines, routes, sources, destinations, workers, datasets or
  lookup tables. The only thing it can create is a Cribl saved search — and only after you confirm it by name.
- **Respects your permissions.** It can only see what your Cribl role allows. If something is not permitted,
  that source shows *Permission denied* and everything else still works.
- **External lookups need consent.** VirusTotal adds queried indicators to its dataset, so Threat Recon never
  queries it automatically — the analyst must tick an explicit notice every time.
- **No secrets in the browser.** The VirusTotal key lives in encrypted App storage and is injected by the Cribl
  proxy. No browser storage, no keys in code, IOC values masked in diagnostics.
- **Honest results.** No evidence is reported as *"no matching telemetry in the selected time range"* — never as
  "safe". Unsupported sources are shown as *Coming soon*, not faked.

---

## Requirements

- Cribl.Cloud with **Cribl Search** (Cribl Lake or any searchable dataset).
- For lookups: a Stream worker group with lookup files (default group `default`).
- For VirusTotal: an API key and admin approval of `www.virustotal.com` at install time.
- A modern browser (Chrome, Edge or Firefox recommended).

## Good to know

- Up to 500 events are retrieved per investigation by default (configurable); totals come from the search job.
- Lookup files are checked in one worker group; matches must be exact (no partial matches).
- "Other Threat Intel", "WHOIS / DNS" and "Create Detection in Cribl" are reserved for future versions.

---

**Author:** Arno Arzumanyan · **App ID:** `threat-recon` · **Version:** 0.1.2 · Community-built for the Cribl App Hackathon.
