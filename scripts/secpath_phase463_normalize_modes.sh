#!/usr/bin/env bash
set -euo pipefail
find src templates assets -type f -exec chmod 0644 {} + 2>/dev/null || true
find scripts -type f -name "*.sh" -exec chmod 0755 {} + 2>/dev/null || true
echo "Mode cleanup done."
