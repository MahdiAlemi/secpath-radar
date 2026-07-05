# SecPath Radar Local - Phase 3

Phase 3 adds a local CVE engine:

- `cargo run` renders the sample JSON only.
- `cargo run -- --fetch` fetches RSS news only.
- `cargo run -- --cves` fetches NVD CVEs + CISA KEV + EPSS only.
- `cargo run -- --full` fetches RSS + CVE data.

Gemini calls used: 0.
