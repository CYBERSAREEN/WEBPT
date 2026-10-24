#!/usr/bin/env bash
# tools/refresh.sh   Logger++ CSV -> 04-notes/endpoints.md, tests.md and 05-report/dashboard.html
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd); . "$ROOT/tools/.config"
CSV=$ROOT/02-burp/LoggerPlusPlus_Autosave.csv
[ -s "$CSV" ] || { echo "no Logger++ CSV yet: $CSV"; exit 1; }
python3 -I "$ROOT/tools/logger_to_notes.py" "$CSV" --out-dir "$ROOT/04-notes"
python3 -I "$ROOT/converter.py" "$CSV" -o "$ROOT/05-report/dashboard.html" ${PREFIX:+--scope-prefix "$PREFIX"}
python3 -I "$ROOT/tools/redact.py" "$CSV" "$ROOT/02-burp/redacted/LoggerPlusPlus_redacted.csv"
echo "Share ONLY 02-burp/redacted/ with any AI or Copilot. Never the raw CSV."
