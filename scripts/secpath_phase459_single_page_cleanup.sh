#!/usr/bin/env bash
set -euo pipefail

rm -f templates/weekly.html.j2
rm -f site/weekly.html

# The dashboard is now single-page. Weekly data is still built into
# data/latest_brief.json and rendered inside site/index.html.
echo "Single-page cleanup done: removed legacy weekly template/output if present."
