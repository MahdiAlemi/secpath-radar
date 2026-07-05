# SecPath Radar

SecPath Radar is a local-first Persian cybersecurity intelligence brief generator. It collects public RSS items, NVD CVEs, CISA KEV, and EPSS signals, ranks them locally, and optionally asks Gemini for a Persian editorial display layer.

Current phase: **v0.4.8-redesign-sources**

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

Configured RSS sources include CISA, BleepingComputer, SecurityWeek, KrebsOnSecurity, The Hacker News, Dark Reading, SANS ISC, Cisco advisories, Cisco Talos, Microsoft Security Blog, Google security blogs, Cloudflare Security, Unit 42, Rapid7, CERT/CC, Infosecurity Magazine, and PortSwigger Research.

NVD, CISA KEV, and EPSS are still used by the CVE engine.
