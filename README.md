# SecPath Radar

Local Rust generator for a Persian daily cybersecurity radar.

### v0.4.7 AI JSON guard

This checkpoint hardens the Gemini editorial layer:

- Adds a shallow JSON response schema to the Gemini request.
- Keeps `responseMimeType: application/json`.
- Validates the returned AI JSON shape before merging it into the brief.
- Uses smaller default AI edit windows for more reliable JSON output.
- Preserves the safe API-key header flow and SOCKS proxy support.


Current checkpoint: `v0.4.7-ai-json-guard`

Highlights:

- RSS + NVD + CISA KEV + EPSS
- HTTP cache and offline mode
- Gemini editorial polish with AI cache
- SOCKS proxy support for WSL/VPN setups
- Safer API key handling via `x-goog-api-key` header
- Persian UI polish and better daily action items

## Modes

```bash
cargo run                    # render sample JSON only
cargo run -- --full          # RSS + CVE/KEV/EPSS, no Gemini
cargo run -- --offline       # build from HTTP cache only
cargo run -- --full --ai     # one Gemini call max, with AI cache
cargo run -- --full --ai --refresh-ai
cargo run -- --full --refresh-cache
```

For WSL + local SOCKS proxy:

```bash
export ALL_PROXY="socks5h://127.0.0.1:9090"
cargo run -- --offline --ai
```

## Gemini

Create `.env` locally:

```env
GEMINI_API_KEY=your_google_ai_studio_key
```

The key is sent in the `x-goog-api-key` header and is never written to `site/` or JSON output. Keep `.env` out of git.

## Output

- `site/index.html`
- `data/latest_brief.json`
- `site/CNAME` -> `radar.secpath.space`


## v0.4.7 — Persian content quality layer

This phase keeps deployment untouched and improves only local content quality:

- Adds Persian display fields (`title_fa`, `summary_fa`, `why_it_matters`, `ops_note`) without replacing source fields.
- Protects immutable fields during Gemini merge (`url`, `source`, `cve_id`, `cvss`, `epss`, `kev`, `severity`, `risk_score`, `published`, `summary`, `title`, `tags`).
- Shows Persian editorial text in the UI while keeping the original source text in a collapsible block.
- Adds template guards for missing CVSS/EPSS values.
- Keeps the one-call AI policy and AI cache behavior unchanged.
