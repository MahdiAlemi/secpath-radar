<div align="center">
  <img src="assets/logo.svg" width="88" alt="SecPath Radar" />

# SecPath Radar

**Passive cyber threat monitoring** — a static, read-only intelligence dashboard built in Rust

`Rust` · `Static HTML/CSS/JS` · `No framework` · `MIT`

</div>

---

## What is it?

SecPath Radar is an observation-first radar for the daily threat landscape: vulnerabilities, security news, IOCs, and public threat telemetry — rendered into a single static page. No active scanning, no visitor tracking, no server-side code.

Every run collects from public sources, scores and aggregates the results, optionally polishes the top items with an AI editorial layer, and renders everything to plain HTML/CSS/JS plus a small JSON API and RSS feed.

## Highlights

- **~185 public sources** — security news RSS, research write-ups, NVD, CISA KEV, EPSS, CISA Vulnrichment, and 15 threat-intel feeds (DShield, URLhaus, ThreatFox, Shodan InternetDB, GitHub Advisories, ransomware.live, Feodo Tracker, SSLBL, GreyNoise, OpenPhish, CISA ICS, MalwareBazaar, Spamhaus DROP, Red Hat CSAF, nuclei templates, PoC watch)
- **CVE triage engine** — CVSS + EPSS + KEV-aware risk scoring with layered fallbacks when a source is down
- **AI editorial layer (optional)** — Gemini rewrites the top news/CVE items into concise, defensive editorial notes and produces a daily **Executive Briefing** panel; everything is schema-locked, sanitized, and cached per item
- **Resilient by design** — explicit cache timestamps, validated stale fallback, pre-cache RSS/Atom validation, `--offline` mode, concurrent feed collection, and publication quality gates that preserve the last known-good output when essential news data is unusable
- **Static output** — `site/index.html`, `feed.xml`, and JSON endpoints under `site/api/`; host it anywhere (GitHub Pages, any static host, or just open the file)

## Quick start

```bash
# 1. Full pipeline: fetch news + CVEs + intel, then render into site/
cargo run --release -- --full

# 2. Same, with the Gemini editorial layer
#    (needs GEMINI_API_KEY in the environment or in .env)
cargo run --release -- --full --ai

# 3. Run the full pipeline from cached/stale source responses only (no network)
cargo run --release -- --offline
```

Open `site/index.html` directly in a browser — no server needed.

## CLI flags

| Flag | Effect |
| --- | --- |
| `--full` | Fetch news + CVEs + intel sources, then render |
| `--fetch` | Fetch news only |
| `--cves` | Fetch CVE data only |
| `--offline` | No network; use cached/stale data only |
| `--refresh-cache` | Ignore HTTP cache TTLs and refetch |
| `--ai` | Enable the Gemini editorial layer |
| `--refresh-ai` | Regenerate AI output even when cached |
| `--no-ai` | Force-disable AI for this run |
| `--input <file>` | Render from a specific brief JSON |
| `--template <file>` | Override the Minijinja template file |
| `--out <file>` | Override the rendered HTML path (default `site/index.html`) |
| `--config <file>` | Override the config file (default `config.yaml`) |

## Configuration

Everything lives in `config.yaml`:

- **Feeds** — news and write-up sources with per-feed tags
- **HTTP** — connection/request timeouts, bounded feed concurrency, a 90-minute cache TTL for the two-hour schedule, feed validation before cache replacement, fallback/source-health reporting, publication thresholds, and an optional proxy
- **Gemini** — model, API URL, temperature, cache directory, and how many top items get editorial treatment (`max_global_news`, `max_cves`)

Secrets are read from the environment first, then from a local `.env` file (which is git-ignored):

```bash
GEMINI_API_KEY=...      # required only for --ai
GREYNOISE_API_KEY=...   # optional, enriches GreyNoise context
GITHUB_TOKEN=...        # optional, raises GitHub API rate limits
```

## The AI layer

The AI layer is an *editor*, not an author. With `--ai`, the pipeline makes at most **three batched Gemini calls per run**:

1. **News batch** — rewrites the top news items (title, summary, why it matters, ops note) and the priority alert
2. **CVE batch** — same treatment for the top CVEs, plus a recommended action
3. **Executive briefing** — one schema-locked call that turns the day's top items into a headline, a short narrative, key takeaways, and 24-hour watch items, rendered as a dedicated dashboard panel and exposed in the JSON API

Safety and cost controls:

- **Schema-locked responses** — Gemini must return JSON matching a strict response schema; a single repair pass fixes truncated output
- **Sanitized merge** — only whitelisted editorial fields are accepted; URLs, CVE IDs, scores, and sources can never be overwritten by the model
- **Per-item content cache** — each item's editorial output is cached by content hash under `data/cache/ai/`; unchanged items never trigger a new call, so steady-state runs use zero to three calls
- **Graceful degradation** — if the AI call fails or the key is missing, the dashboard renders fully without AI content and records the reason in `ai_status`

## Outputs

| Path | Contents |
| --- | --- |
| `site/index.html` | The dashboard |
| `site/feed.xml` | RSS feed of the day's items |
| `site/api/summary.json` | Compact machine-readable summary |
| `site/api/brief.json` | Full brief (news, CVEs, intel, weekly, trend, AI briefing) |
| `data/latest_brief.json` | Last validated full pipeline state used for history comparison and state restoration |
| `snapshots/` | Daily archive and history snapshots |

## CI

`.github/workflows/radar.yml` runs every two hours at minute 17 and can also be started with `workflow_dispatch`. The build job has read-only repository access, restores the previous cache/day/history state from an encrypted GitHub Actions artifact, runs formatting and tests with a pinned Rust toolchain, collects and renders the radar, and applies publication quality gates. Only validated, state-free site files are passed to the write-scoped `radar-output` job and the GitHub Pages deployment. Failed or empty-news builds never replace the last known-good published output.

Runtime state is packed after validation and encrypted with the repository secret `RADAR_STATE_KEY` before upload. The workflow keeps the three newest encrypted artifacts for rollback and can perform a one-time migration from the legacy `radar-output/state` directory. The public `radar-output` branch and Pages artifact contain no cache, day state, snapshots, `.env`, or `data` directory. HTTP cache freshness remains stored in `.meta.json` sidecars rather than filesystem mtimes.

## Design principles

1. **Passive only** — collect from public feeds and APIs; never scan, probe, or touch third-party systems
2. **Read-only output** — a static page with no forms, no accounts, no analytics, and no visitor data collection
3. **Fail soft, publish hard** — optional sources may degrade to cached or empty panels, but missing/invalid essential news blocks publication and preserves the previous output
4. **Defensive language** — AI output is constrained to defensive guidance; no exploit detail ever ships to the page

## Project structure

```
src/            # Rust pipeline (fetch, score, aggregate, render)
src/intel/      # 15 threat-intel source modules
templates/      # minijinja HTML templates
assets/         # CSS/JS/logo copied into site/ at render time
config.yaml     # feeds, HTTP, and AI configuration
site/           # generated static output
data/           # runtime state and caches (git-ignored)
snapshots/      # daily JSON archives
```

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

Design & development: <strong>Mahdi Alemi</strong>

</div>
