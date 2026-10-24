#!/usr/bin/env bash
# tools/log.sh "<what I did>" "<why>"   -> appends a timestamped row to 04-notes/command-log.md
ROOT=$(cd "$(dirname "$0")/.." && pwd)
printf -- '- %s | %s | why: %s\n' "$(date '+%F %T')" "${1:?what}" "${2:-}" >> "$ROOT/04-notes/command-log.md"
tail -1 "$ROOT/04-notes/command-log.md"
