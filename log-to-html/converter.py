#!/usr/bin/env python3
"""One-command wrapper: Logger++ auto-export CSV -> output.html dashboard.

    python3 converter.py LoggerPlusPlus_Autosave.csv
    python3 converter.py burp/LoggerPlusPlus_Autosave.csv -o report/output.html

Uses tools/logger_to_notes.py (parser) and tools/dashboard_template.html (page).
Keep both in the tools/ folder next to this file.
"""
import argparse, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "tools"))
import logger_to_notes as L  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", help="Logger++ auto-export CSV")
    ap.add_argument("-o", "--output", default="output.html")
    ap.add_argument("--scope-prefix", default="", help="only paths starting with this, e.g. /labs/parcelpoint")
    ap.add_argument("--ignore-param", action="append", default=["fcbz"], help="parameter names to ignore (repeatable)")
    a = ap.parse_args()
    if not os.path.isfile(a.csv):
        sys.exit(f"not a file: {a.csv}")
    rows = [r for r in L.read_rows(a.csv) if r[L.PATH].startswith(a.scope_prefix)]
    eps, tests = L.build(rows, set(a.ignore_param))
    L.write_html(eps, tests, a.output, a.csv)
    real = sum(1 for v in eps.values() if set(v["status"]) != {"404"})
    print(f"{a.output}: {len(rows)} rows, {real} endpoints, {len(tests)} test cases")


if __name__ == "__main__":
    main()
