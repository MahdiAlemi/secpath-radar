#!/usr/bin/env bash
set -euo pipefail
find src templates assets -type f -exec chmod 0644 {} +
find scripts -type f -name "*.sh" -exec chmod 0755 {} +
echo "Mode cleanup done. Source/templates/assets are non-executable; scripts remain executable."
