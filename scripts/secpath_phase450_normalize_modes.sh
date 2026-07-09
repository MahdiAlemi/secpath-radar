#!/usr/bin/env bash
set -euo pipefail

# Normalize accidental executable bits on source/config/frontend files.
# Keep scripts executable.
find src templates assets -type f -exec chmod 0644 {} +
find .github -type f -exec chmod 0644 {} + 2>/dev/null || true
[ -f Cargo.toml ] && chmod 0644 Cargo.toml
[ -f Cargo.lock ] && chmod 0644 Cargo.lock
[ -f README.md ] && chmod 0644 README.md
[ -f config.yaml ] && chmod 0644 config.yaml
find scripts -type f -name '*.sh' -exec chmod 0755 {} + 2>/dev/null || true

echo "Mode cleanup done. Source/frontend files are non-executable; scripts remain executable."
