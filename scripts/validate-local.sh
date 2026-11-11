#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_command="${PYTHON_COMMAND:-python3.12}"
"$python_command" -m pytest
if find "$root" -path "$root/.git" -prune -o -path '*/.github/workflows/*' -type f -print | grep -q .; then
  echo "GitHub Actions workflows are prohibited." >&2
  exit 1
fi
if rg -n --hidden --glob '!.git/**' --glob '!.venv/**' --glob '!**/.venv/**' '(?i)(password[[:space:]]*[:=]|client[_-]?secret[[:space:]]*[:=]|api[_-]?key[[:space:]]*[:=]|connectionstring[[:space:]]*[:=])' "$root"; then
  echo "Potential credential pattern found." >&2
  exit 1
fi
echo "Local validation completed. No telemetry source, cloud service, or remediation integration was contacted."
