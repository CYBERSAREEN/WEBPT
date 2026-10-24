#!/usr/bin/env python3
"""Redact a Logger++ full CSV export so it is safe to share with an external AI/Copilot.

    python3 -I tools/redact.py 02-burp/LoggerPlusPlus_Autosave.csv 02-burp/redacted/LoggerPlusPlus_redacted.csv

Rule (mentor, 2026-10-24): no cookies, tokens, session IDs, role/permission/tenant data
leave the machine. Column positions match the default Logger++ 3.x field order
(Select All). The raw CSV stays local; only the redacted copy may be shared.
"""
import csv, os, re, sys

csv.field_size_limit(10**9)
# whole-cell blanking: raw base64 request/response, cookie string, parameters, response cookies
BLANK = {5, 33, 35, 37, 54}
# regex redaction inside: req headers, req body, url, query, pathquery, referrer, resp headers, resp body
SCRUB = {6, 7, 14, 17, 18, 28, 38, 39}
PATTERNS = [
    (re.compile(r"(?im)^(cookie|set-cookie|authorization|proxy-authorization|x-api-key|x-auth-token|x-csrf-token)\s*:.*$"), r"\1: [REDACTED]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), "[REDACTED-JWT]"),
    (re.compile(r"(?i)([\"']?(?:token|access_token|refresh_token|session|sessionid|sid|jwt|password|passwd|pwd|secret|api_?key|role|roles|permissions?|tenant(?:_?id)?|org(?:_?id)?)[\"']?\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^&\s,;}]+)"), r"\1[REDACTED]"),
]

def scrub(s):
    for rx, rep in PATTERNS:
        s = rx.sub(rep, s)
    return s

def main(src, dst):
    os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
    n = 0
    with open(src, newline="", encoding="utf-8", errors="replace") as f, \
         open(dst, "w", newline="", encoding="utf-8") as o:
        w = csv.writer(o)
        for row in csv.reader(f):
            for i in range(len(row)):
                if i in BLANK:
                    row[i] = "[REDACTED]" if row[i] else ""
                elif i in SCRUB:
                    row[i] = scrub(row[i])
            w.writerow(row); n += 1
    print(f"{dst}: {n} rows redacted")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
