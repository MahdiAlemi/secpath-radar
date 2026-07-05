# SecPath Radar

SecPath Radar is a local-first Persian cybersecurity intelligence brief generator. It collects public RSS items, NVD CVEs, CISA KEV, and EPSS signals, ranks them locally, and optionally asks Gemini for a Persian editorial display layer.

Current phase: **v0.4.16-production-glass-ui**

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

NVD, CISA KEV, and EPSS are still used by the CVE engine.


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
