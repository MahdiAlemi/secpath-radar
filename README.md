# SecPath Radar

SecPath Radar is a local-first Persian cybersecurity intelligence brief generator. It collects public RSS items, NVD CVEs, CISA KEV, and EPSS signals, ranks them locally, and optionally asks Gemini for a Persian editorial display layer.

Current phase: **v0.4.27-poc-watch-metadata**

## What changed in v0.4.8

- Full UI redesign into a modern SOC / command-center style dashboard.
- Removed **Tools & Techniques**, **Tip of the Day**, and **Today Action Items** from UI and generation code.
- Expanded RSS source coverage from a small list to a wider threat-intelligence/news set.
- Added news lanes: active exploitation, vulnerabilities, malware/incidents, AI security.
- Footer rewritten as product/help text instead of build-log text.
- Original source text remains available in each card while Persian editorial fields are shown first.
- No deployment, GitHub Pages, or DNS changes in this phase.

## Run locally

```bash
cargo run -- --offline --ai
```

With fresh network/cache:

```bash
cargo run -- --full --ai
```

With Gemini refresh:

```bash
cargo run -- --offline --ai --refresh-ai
```

When using a SOCKS proxy in WSL:

```bash
export ALL_PROXY="socks5h://127.0.0.1:9090"
```

Preview:

```bash
python3 -m http.server 8000 --directory site
```

Open:

```text
http://localhost:8000
```

## Privacy and cost controls

- Gemini is used only with `--ai`.
- API key is loaded from `.env` or environment and sent via `x-goog-api-key` header.
- AI results are cached in `data/cache/ai`.
- HTTP responses are cached in `data/cache/http`.
- `.env`, caches, generated HTML, and latest JSON are ignored by Git.

## Current source set

Configured RSS sources include CISA, BleepingComputer, SecurityWeek, KrebsOnSecurity, The Hacker News, Zero Day Initiative, SANS ISC, Cisco advisories, Cisco Talos, Microsoft Security Blog, Google Online Security Blog, ProjectDiscovery Blog, Cloudflare Security, Unit 42, Rapid7, CERT/CC, Infosecurity Magazine, and PortSwigger Research.

NVD, CISA KEV, EPSS, CISA Vulnrichment, Feodo Tracker, and SSLBL are used by the intelligence engine. Botnet C2 and TLS indicators are metadata-only; no malware samples or dangerous links are downloaded or rendered.



## v0.4.27 — CVE PoC Watch Metadata

Adds a passive metadata-only watch for public GitHub repositories that mention selected dashboard CVEs. This is a defensive triage signal only. The UI does **not** render raw exploit links, clone/download commands, payloads, or exploit code.

- Searches GitHub Repository Search API for selected CVE IDs.
- Uses `GITHUB_TOKEN` if present, but works with unauthenticated/rate-limited public metadata when available.
- Caches GitHub search responses under the intel cache and supports offline reuse.
- Correlates each repository metadata hit with severity, KEV, EPSS momentum, and CISA priority from the local CVE engine.
- Writes `poc_watch`, `stats.poc_watch`, `stats.poc_watch_high`, and `stats.poc_watch_cves`.
- Excludes CVE database mirrors, advisory databases, nuclei template collections, scanners, and generic roundup/index repositories.

Quick checks:

```bash
cargo run -- --full --refresh-cache
jq '.version, .stats.poc_watch, .stats.poc_watch_high, .stats.poc_watch_cves, .poc_watch.totals, .poc_watch.repos[:5]' data/latest_brief.json
```

## v0.4.26.2 — Independent Writeup Feeds

Adds a dedicated writeup/research feed layer beside Daily News. Writeups are no longer inferred from the regular news panel; they are fetched from `writeup_sources` such as The DFIR Report, PortSwigger Research, Unit 42, Cisco Talos, ProjectDiscovery, ZDI, Securelist, Google Cloud Threat Intelligence, Microsoft Security Blog, and Cloudflare Security Research.

- Uses independent RSS/Atom sources configured under `writeup_sources`.
- Keeps raw English title/summary while adding Persian display fields.
- Filters out news-like posts, weekly roundups, patch summaries, webinars, and product updates.
- Shows compact source/type charts and up to 12 writeup cards in the UI.
- Writes `writeups_pulse`, `stats.writeups`, `stats.writeup_sources`, `stats.writeup_feed_sources`, and `stats.failed_writeup_sources` to `data/latest_brief.json`.
- Metadata-only: no exploit steps, no code snippets, no clone/download, no scan, and no operational workflow.

Quick checks:

```bash
cargo run -- --offline
jq '.version, .stats.writeups, .stats.writeup_sources, .stats.writeup_feed_sources, .stats.failed_writeup_sources, .writeups_pulse.totals, .writeups_pulse.writeups[:5]' data/latest_brief.json
```


## v0.4.8.1 Frontend split

This release keeps SecPath Radar as a static, observational dashboard:

- `templates/index.html.j2` contains markup only.
- `assets/css/radar.css` contains the dashboard styling.
- `assets/js/radar.js` is passive only and must not add user-input workflows.
- `site/assets/` is copied automatically during render.
- Internal navigation links and collapsible cards were removed to keep the output read-only.
- Tools, tips, and action-item sections remain removed.

No deployment, GitHub Pages, or DNS changes are included in this phase.


## v0.4.10 — IOC Radar

This phase adds a read-only IOC telemetry layer from abuse.ch URLhaus and ThreatFox static CSV exports. Indicators are cached under `data/cache/intel`, defanged before display, and rendered as passive charts/lists. There are no forms, search boxes, filters, or user input workflows.

## v0.4.9 — Attack Pressure Radar chart

This phase adds a read-only DShield/SANS telemetry layer. It fetches static DShield top-port feeds, stores them in `data/cache/intel`, and renders passive attack-pressure charts. There are no forms, search boxes, filters, or user input workflows.

Telemetry sources:

- `topports.txt` — top firewall-log ports
- `topports_source.txt` — ports sorted by source IP scanning pressure
- `topports_reports.txt` — ports sorted by report volume
- `topports_targets.txt` — ports sorted by target exposure

DShield/SANS recommends using static feeds where possible and not downloading them more than once per hour. The default `intel.refresh_hours` is `1`.


### UI preference locked

- Black/orange SOC-console theme.
- No border radius.
- Attack Pressure must render as static charts, not statistic-only cards.
- IOC Radar must defang URLs/domains/IPs and never make malware/phishing URLs clickable.
- Radar remains read-only: no forms, inputs, filters, or user workflows.


## v0.4.11 — Suspicious Infrastructure Radar

Adds a passive infrastructure enrichment layer. SecPath Radar extracts public IPs from the current IOC Radar output and enriches a small capped set through Shodan InternetDB. InternetDB is used as a lightweight, no-key lookup source for open ports, hostnames, tags, CPEs, and vulnerability hints. The dashboard remains static/read-only: no forms, no search, no filters, and no active scanning.


## v0.4.11.1 infra fallback

- Adds DShield top source IPs as passive infrastructure candidates.
- Keeps candidate-only infrastructure rows when Shodan InternetDB has no record, so the radar does not render empty.
- Tightens the Gemini JSON prompt and reduces AI payload size to reduce truncated JSON.


## Supply Chain Radar

This local, static radar adds passive open-source package advisory awareness from GitHub Global Security Advisories and OSV vulnerability reference pages. It does not accept package input, does not scan dependencies, and does not perform any user-driven workflow.


## v0.4.14 — Source Hygiene + Reliability

Replaces unreliable RSS sources with current feeds, adds a static SVG favicon, surfaces RSS source-health details in the JSON/UI, and adds a Gemini JSON repair pass for malformed AI responses. The dashboard remains a static observational radar with no user input or deployment changes.

## v0.4.14.1 — AI Offline Guard

When `--offline --ai` is used and there is no matching Gemini cache for the current compact brief, SecPath Radar no longer attempts a network call. It records a local AI-status fallback and renders the site from deterministic local polish.


## v0.4.14.4 — SANS ISC Title Feed

- Switches SANS ISC from the full-text feed to the official title-only diary RSS feed to avoid malformed/empty full-text responses from producing RSS parse failures.
- Keeps SANS ISC as a public RSS source while improving Source Health reliability.

## v0.4.14.3 — AI Status Consistency

- Keeps offline AI guard fully network-free.
- Reports `ai_status.ok=false` when no matching Gemini cache exists in offline mode.
- Keeps `calls_used=0` and renders with local fallback.


## v0.4.15 — Static Executive Snapshot

Adds a static, read-only executive snapshot near the top of the dashboard. It derives a 60-second management summary, three risk cards, rising signals, and impact-weighted source groups from the current radar data only. It adds no new external source, no user input, no deployment, and no interactive workflow.

## v0.4.16 — Production Glass UI

This phase is a production UI redesign, not a data-source expansion.

- Three-column desktop layout for one-glance scanning.
- Compact cards and charts with reduced debug/metadata noise.
- Dark glass/acrylic visual language with square Windows-style surfaces and no rounded corners.
- News presentation uses local Persian display fields and does not depend on AI being available.
- AI status is no longer a prominent production UI element.
- Source health is reduced to compact operational counts.
- The dashboard remains static/read-only: no forms, no user inputs, and no workflow controls.

## v0.4.18 — Botnet C2 Pulse

This phase adds a compact, read-only botnet telemetry layer from abuse.ch Feodo Tracker and SSLBL. It fetches C2 IP metadata plus SSLBL JA3/certificate fingerprint metadata, caches it under `data/cache/intel`, defangs IPs before display, and renders only aggregate charts and short metadata rows. It does not download malware samples, render dangerous links, expose onion/leak data, or add user-input workflows.


## v0.4.17.1 — Vulnrichment No-Data Polish

- Treat missing CISA Vulnrichment records as normal no-data instead of noisy warnings.
- Add EPSS tracked/stable/falling counters and Vulnrichment checked/missing counters.
- Keep the production UI compact when enrichment has no hits.

## v0.4.17 — EPSS Momentum + CISA Vulnrichment

This release adds passive CVE enrichment without changing the production UI model:

- Historical EPSS lookups for 7-day and 30-day momentum.
- CISA Vulnrichment lookups for selected CVEs.
- Compact production badges for rising EPSS and CISA SSVC priority.
- No active scanning, no exploit links, no new user inputs.


### v0.4.19.1 — GreyNoise Offline Aggregate Cache

GreyNoise Context now writes a compact aggregate cache after successful online/full runs. Offline production runs reuse that aggregate first, so the dashboard stays stable even when per-IP Community API cache entries do not line up with the latest candidate set.

### v0.4.19 — GreyNoise Infrastructure Context

Adds passive GreyNoise Community API context for selected suspicious infrastructure and Botnet C2 IPs. The dashboard uses only high-level metadata (`noise`, `riot`, `classification`, `last_seen`, and owner/name) and does not scan, probe, or expose operational actions. Unauthenticated Community lookups are limited, so the default max lookup count is intentionally small. Set `GREYNOISE_API_KEY` locally for a higher allowance; never commit it.

### v0.4.20 — Phishing Pulse

Adds a compact, read-only phishing telemetry layer from the OpenPhish community feed. The dashboard stores only defanged URLs and host metadata, derives TLD/brand/risk charts locally, and never renders clickable phishing links or any submission/scanning workflow.


### v0.4.21 — Static Interactivity

Adds local-only viewing interactions for the production dashboard:

- Collapsible panels by clicking each card header.
- Dense mode stored in localStorage.
- Focus mode for one selected panel with `F`; `Esc` returns to the overview.
- Local section jump links and keyboard hints.
- No forms, no scanners, no submissions, no backend workflow, and no operational security actions.


## v0.4.22 — Snapshot History

This phase adds a local, read-only snapshot history layer. Before writing `data/latest_brief.json`, the generator reads the previous brief if present, compares key operational counters, attaches `history_snapshot` to the current JSON, and writes compact runtime snapshots under `snapshots/history/`.

The comparison is local only. It does not add network sources, forms, inputs, backend workflows, scanning, submission, or operational security actions.




### v0.4.25.1 — Daily News fallback polish

- Keeps the requested local-day model for news: 00:00–23:59 local time.
- If the current local day has no timestamped RSS items in cache, the dashboard falls back to the latest available feed day instead of showing an empty news panel.
- Marks the fallback in `news_window.mode = latest-feed-day-fallback` and explains it in `news_window.note_fa`.
- Breaking News is still selected from the effective news window and remains read-only.

## v0.4.25 — Daily News Freshness + Breaking News

This phase keeps the same UI but changes news behavior:

- RSS still fetches and dedupes all source items.
- The user-facing news window is the current local day, 00:00–23:59.
- Daily news is sorted newest-first instead of only risk/top-score first.
- High-risk daily items are separated into a compact **Breaking News** panel.
- `news_window`, `breaking_news`, and daily news counters are written to `data/latest_brief.json`.
- Older or undated RSS items are counted but hidden from the daily news panel.
- No new external data source, no scan, no submit workflow, and no backend.

Quick checks:

```bash
cargo run -- --offline
jq '.version, .news_window, .stats.daily_news, .stats.breaking_news, .breaking_news[:3], .global_news[:3] | .' data/latest_brief.json
```

## v0.4.24 — Production UX Triage Polish

This phase keeps the existing dark glass production UI and improves triage UX without adding active capabilities.

- Reduces the top KPI strip to the core decision metrics.
- Adds a **Top Signals Today** triage strip above the three-column dashboard.
- Makes Snapshot History quiet when there is no meaningful delta.
- Improves visual hierarchy for high / medium / watch cards.
- Cleans ICS/OT vendor and product extraction so vendor charts do not show long `Product Version:` strings.
- Keeps all interactions local/client-side only: collapse, dense mode, focus mode, and local anchors.
- No input, form, select, operational button, scan, submit, backend workflow, exploit content, or dangerous links.

## v0.4.23 — ICS/OT Advisory Pulse

Adds a passive industrial-control advisory layer from the CISA ICS Advisories feed. The module extracts advisory title, vendor, equipment, CVSS, CVE count, sector hints and compact risk buckets for defensive OT/ICS triage. It is metadata-only: no scanning, no exploit content, no submission workflow and no dangerous links in the dashboard.

Quick checks:

```bash
cargo run -- --full --refresh-cache
jq '.version, .stats.ics_advisories, .stats.ics_high, .stats.ics_vendors, .ics_ot_pulse.totals, .ics_ot_pulse.vendor_chart[:5]' data/latest_brief.json

cargo run -- --offline
jq '.version, .stats.ics_advisories, .stats.ics_high, .stats.ics_vendors, .ics_ot_pulse.totals, .stats.failed_rss_sources' data/latest_brief.json
```
