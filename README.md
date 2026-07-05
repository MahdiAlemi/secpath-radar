# SecPath Radar

رادار روزانه امنیت سایبری، CVEها و تهدیدهای مهم.

## Run modes

```bash
cargo run                 # sample mode: no network calls
cargo run -- --fetch      # RSS only
cargo run -- --cves       # NVD + CISA KEV + EPSS only
cargo run -- --full       # RSS + CVE engine
cargo run -- --offline    # same as --full but cache only
cargo run -- --offline --full
cargo run -- --full --refresh-cache
```

## Cache

HTTP responses are cached under `data/cache/http` by default. This keeps local tests fast and reduces unnecessary calls to RSS, NVD, CISA KEV and EPSS.

- `--offline` uses cached responses only.
- `--refresh-cache` ignores fresh cache and refetches.
- If a network request fails, the app falls back to stale cache when available.

Gemini is not called in this phase.
