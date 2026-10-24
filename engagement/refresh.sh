#!/usr/bin/env bash
# tools/refresh.sh   SAFE Logger++ CSV -> 04-notes/endpoints.md, tests.md and 05-report/dashboard.html
# Refuses a full export: the log must never contain cookies/tokens (see README, SAFE preset).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd); . "$ROOT/tools/.config"
CSV=$ROOT/02-burp/LoggerPlusPlus_Autosave.csv
[ -s "$CSV" ] || { echo "no Logger++ CSV yet: $CSV"; exit 1; }
COLS=$(python3 -I -c 'import csv,sys; csv.field_size_limit(10**9); r=[x for x in csv.reader(open(sys.argv[1], newline="", encoding="utf-8", errors="replace")) if x]; print(len(r[0]) if r else 0)' "$CSV")
if [ "$COLS" != 29 ]; then
  echo "REFUSED: $CSV has $COLS columns, the SAFE preset has 29."
  echo "Full exports carry cookies/tokens. Re-export with the SAFE preset (README) and delete this file."
  exit 2
fi
python3 -I "$ROOT/tools/logger_to_notes.py" "$CSV" --out-dir "$ROOT/04-notes"
python3 -I "$ROOT/converter.py" "$CSV" -o "$ROOT/05-report/dashboard.html" ${PREFIX:+--scope-prefix "$PREFIX"}
