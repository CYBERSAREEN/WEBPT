#!/usr/bin/env bash
# tools/shot.sh <finding-id> <short-description>   region screenshot -> 03-evidence/screenshots/
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
ID=${1:?finding id e.g. F-01}; WHAT=${2:?short description}
OUT=$ROOT/03-evidence/screenshots/${ID}_${WHAT// /-}_$(date +%Y%m%d-%H%M%S).png
if command -v flameshot >/dev/null; then flameshot gui -p "$OUT"; else xfce4-screenshooter -r -s "$OUT"; fi
echo "$OUT"
