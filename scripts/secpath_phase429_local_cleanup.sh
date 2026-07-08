#!/usr/bin/env bash
set -euo pipefail

# SecPath Radar phase 4.29 local cleanup.
# This script performs local-only repository cleanup. It does not deploy, publish,
# push, or contact any remote service.

# Files left from the previous deploy-oriented/local-debug state.
# A ZIP overlay can overwrite files but cannot reliably delete tracked/untracked files.
rm -f site/CNAME
rm -f check_cves.py

# Normalize accidental executable bits introduced by archive/Windows round-trips.
# Keep shell scripts executable; most project files should be plain 0644.
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  while IFS= read -r -d '' path; do
    [ -f "$path" ] || continue
    case "$path" in
      scripts/*.sh)
        chmod 755 "$path"
        ;;
      *)
        chmod 644 "$path"
        ;;
    esac
  done < <(git ls-files -z)
fi

find scripts -type f -name '*.sh' -exec chmod 755 {} + 2>/dev/null || true

cat <<'MSG'
Cleanup done.

What changed locally:
- Removed leftover deploy/debug files when present: site/CNAME, check_cves.py
- Normalized accidental executable file modes
- Kept .env in place for local-only use; do not commit or share it
- GitHub Actions is manual CI/render-check only and does not publish/deploy
MSG
