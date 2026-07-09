#!/usr/bin/env bash
set -euo pipefail
# Keep project sources/templates/assets non-executable; scripts remain executable.
find src templates assets -type f -exec chmod 0644 {} + 2>/dev/null || true
find scripts -type f -name '*.sh' -exec chmod 0755 {} + 2>/dev/null || true
echo "Mode cleanup done. Source, template, and asset files are non-executable; shell scripts remain executable."
