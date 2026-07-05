# SecPath Radar

Local Rust generator for a Persian daily cybersecurity radar.

## Modes

```bash
cargo run                    # render sample JSON only
cargo run -- --full          # RSS + CVE/KEV/EPSS, no Gemini
cargo run -- --offline       # build from HTTP cache only
cargo run -- --full --ai     # one Gemini call max, with AI cache
cargo run -- --full --ai --refresh-ai
cargo run -- --full --refresh-cache
```

## Gemini

Create `.env` locally:

```env
GEMINI_API_KEY=your_google_ai_studio_key
```

The key is never written to `site/` or JSON output. Keep `.env` out of git.

## Output

- `site/index.html`
- `data/latest_brief.json`
- `site/CNAME` -> `radar.secpath.space`
