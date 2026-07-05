# SecPath Radar

Local Rust generator for a Persian daily cybersecurity radar.

Current checkpoint: `v0.4.5-polish`

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
