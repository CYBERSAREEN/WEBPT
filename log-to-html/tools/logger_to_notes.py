#!/usr/bin/env python3
"""Parse a Logger++ auto-export CSV into endpoints.md and tests.md.

    python3 -I tools/logger_to_notes.py burp/LoggerPlusPlus_Autosave.csv --out-dir notes

Add  --html report/dashboard.html  for a self-contained offline dashboard (template: dashboard_template.html).

Endpoints: only what Logger++ actually logged (nothing guessed), `_rsc` prefetch rows
dropped, one row per METHOD + path. Endpoints that only ever returned 404 are listed
separately as "probed, not found" so they do not look like real routes.

Tests: any request (Proxy, Repeater, Intruder, ...) that carries a marker is a test case.
    X-Test: passed
    X-Test: failed; id=TC02; cat=XSS; note=img onerror reads cookie
  results: passed | failed | info   (passed = app defended, failed = vulnerability found)
  Fallback when you do not want a custom header on the wire: put the same text in the
  Logger++ Comment column, e.g.  TEST: failed; id=TC02; cat=XSS
The marker is never copied into the output. Intruder runs that share one marker are
collapsed into a single test row with a request count and status spread.

Logger++ autosave has no header row, so columns are read by position (Logger++ 3.x).
"""
import argparse, csv, collections, datetime, json, os, re, sys, urllib.parse

csv.field_size_limit(10**9)

# column positions in the headerless autosave
TOOL, REQ_HEADERS, REQ_BODY, TIME, COMMENT, URL, METHOD, PATH, QUERY, STATUS = 0, 6, 7, 9, 12, 14, 15, 16, 17, 45
KNOWN_TOOLS = {"Proxy", "Repeater", "Intruder", "Scanner", "Target", "Spider", "Sequencer", "Extender"}
MIN_COLS = STATUS + 1

HEADER_RE = re.compile(r"^X-Test:[ \t]*(.*?)\s*$", re.I | re.M)
COMMENT_RE = re.compile(r"^\s*TEST:\s*(.*?)\s*$", re.I)
RESULTS = {"passed": "PASS", "pass": "PASS", "failed": "FAIL", "fail": "FAIL", "info": "INFO"}


def read_rows(path):
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        for r in csv.reader(f):
            if len(r) >= MIN_COLS and r[TOOL] in KNOWN_TOOLS:
                yield r


def parse_marker(text):
    """'failed; id=TC02; cat=XSS; note=...' -> dict, or None if no valid result word."""
    parts = [p.strip() for p in text.split(";") if p.strip()]
    if not parts or parts[0].lower() not in RESULTS:
        return None
    m = {"result": RESULTS[parts[0].lower()], "id": "", "cat": "", "note": ""}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        if k.strip().lower() in m:
            m[k.strip().lower()] = v.strip()
    return m


def find_marker(row):
    h = HEADER_RE.search(row[REQ_HEADERS])
    if h:
        return parse_marker(h.group(1))
    c = COMMENT_RE.match(row[COMMENT])
    return parse_marker(c.group(1)) if c else None


def parsed_params(row, ignore):
    """Query parameters plus form-encoded body parameters, noise names removed."""
    pairs = urllib.parse.parse_qsl(row[QUERY], keep_blank_values=True)
    body = row[REQ_BODY]
    if body and "=" in body and not body.lstrip().startswith(("{", "[", "<")):
        pairs += urllib.parse.parse_qsl(body, keep_blank_values=True)
    return [(k, v) for k, v in pairs if k not in ignore]


def esc(s):
    return str(s).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def load_manual(path, ncols):
    """Keep hand-edited Tested?/Notes cells across runs, keyed by the first column."""
    keep = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            if line.startswith("|") and not line.startswith(("| ---", "| Endpoint")):
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                if len(cells) == ncols:
                    keep[cells[0]] = cells[-2:]
    return keep


def build(rows, ignore):
    eps = collections.OrderedDict()
    tests = collections.OrderedDict()
    for r in rows:
        if "_rsc" in r[QUERY]:  # Next.js prefetch noise: not an endpoint, not a test
            continue
        params = parsed_params(r, ignore)
        key = f"{r[METHOD]} {r[PATH].rstrip('/') or '/'}"
        e = eps.setdefault(key, {"params": set(), "status": collections.Counter(), "tools": set()})
        e["params"].update(k for k, _ in params)
        e["status"][r[STATUS]] += 1
        e["tools"].add(r[TOOL])

        m = find_marker(r)
        if m:
            sig = (m["id"] or m["result"] + m["cat"] + m["note"], key, r[TOOL])
            if r[TOOL] != "Intruder":  # every manual send is its own test unless it shares an id
                sig += (r[QUERY], r[REQ_BODY]) if not m["id"] else ()
            t = tests.setdefault(sig, {**m, "endpoint": key, "tool": r[TOOL], "n": 0,
                                       "status": collections.Counter(), "params": params, "time": r[TIME]})
            t["n"] += 1
            t["status"][r[STATUS]] += 1
    return eps, tests


def write_endpoints(eps, path):
    cols = ["Endpoint", "Params", "Status seen", "Requests", "Tools", "Tested?", "Notes"]
    keep = load_manual(path, len(cols))
    found = {k: v for k, v in eps.items() if set(v["status"]) != {"404"}}
    probed = {k: v for k, v in eps.items() if set(v["status"]) == {"404"}}
    out = ["# Endpoints (generated from Logger++ log; edit only Tested? and Notes)", "",
           "| " + " | ".join(cols) + " |", "|" + " --- |" * len(cols)]
    for key, e in sorted(found.items()):
        tested, notes = keep.get(key, ["no", ""])
        out.append("| " + " | ".join(esc(x) for x in [
            key, ", ".join(sorted(e["params"])) or "-",
            ", ".join(f"{s}x{n}" for s, n in sorted(e["status"].items())),
            sum(e["status"].values()), ", ".join(sorted(e["tools"])), tested, notes]) + " |")
    if probed:
        out += ["", "## Probed, returned only 404 (not real routes)", ""]
        out += [f"- {k}" for k in sorted(probed)]
    open(path, "w", encoding="utf-8").write("\n".join(out) + "\n")
    return len(found), len(probed)


def write_tests(tests, path):
    cols = ["ID", "Cat", "Result", "Test", "Endpoint", "Parsed params", "Tool", "Requests", "Status", "Time"]
    out = ["# Test cases (generated from X-Test markers / TEST: comments in the Logger++ log)", "",
           "| " + " | ".join(cols) + " |", "|" + " --- |" * len(cols)]
    totals = collections.Counter()
    for i, t in enumerate(tests.values(), 1):
        totals[t["result"]] += 1
        params = "; ".join(f"{k}={v[:60]}" for k, v in t["params"]) or "-"
        out.append("| " + " | ".join(esc(x) for x in [
            t["id"] or f"T{i:02d}", t["cat"] or "-", t["result"], t["note"] or "-", t["endpoint"], params,
            t["tool"], t["n"], ", ".join(f"{s}x{n}" for s, n in sorted(t["status"].items())), t["time"]]) + " |")
    out += ["", f"Totals: PASS {totals['PASS']}, FAIL {totals['FAIL']}, INFO {totals['INFO']}"]
    open(path, "w", encoding="utf-8").write("\n".join(out) + "\n")
    return sum(totals.values())


TEMPLATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard_template.html")


def safe_json(obj):
    """JSON for a <script type=application/json> block: payloads in the data cannot close the tag."""
    return (json.dumps(obj).replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def write_html(eps, tests, path, source):
    """Self-contained offline dashboard. The page renders log data with textContent only."""
    per_ep = collections.defaultdict(collections.Counter)
    for t in tests.values():
        per_ep[t["endpoint"]][t["result"]] += 1
    data = {
        "generated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "source": os.path.basename(source),
        "endpoints": [
            {"key": k, "params": sorted(v["params"]), "status": dict(v["status"]),
             "requests": sum(v["status"].values()), "tools": sorted(v["tools"]),
             "tests": dict(per_ep.get(k, {})), "probed": set(v["status"]) == {"404"}}
            for k, v in sorted(eps.items())],
        "tests": [
            {"id": t["id"] or f"T{i:02d}", "cat": t["cat"] or "-", "result": t["result"], "note": t["note"],
             "endpoint": t["endpoint"], "params": [[k, v[:200]] for k, v in t["params"]], "tool": t["tool"],
             "n": t["n"], "status": dict(t["status"]), "time": t["time"]}
            for i, t in enumerate(tests.values(), 1)],
    }
    with open(TEMPLATE, encoding="utf-8") as f:
        page = f.read().replace("__DATA__", safe_json(data))
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", help="Logger++ auto-export CSV")
    ap.add_argument("--out-dir", default=".", help="where endpoints.md and tests.md go")
    ap.add_argument("--scope-prefix", default="", help="only keep paths starting with this, e.g. /labs/parcelpoint")
    ap.add_argument("--ignore-param", action="append", default=["fcbz"],
                    help="parameter names to drop from parsed params (repeatable; default fcbz)")
    ap.add_argument("--html", metavar="FILE", help="also write a self-contained dashboard, e.g. report/dashboard.html")
    a = ap.parse_args()
    if not os.path.isfile(a.csv):
        sys.exit(f"not a file: {a.csv}")
    rows = [r for r in read_rows(a.csv) if r[PATH].startswith(a.scope_prefix)]
    eps, tests = build(rows, set(a.ignore_param))
    os.makedirs(a.out_dir, exist_ok=True)
    n_found, n_probed = write_endpoints(eps, os.path.join(a.out_dir, "endpoints.md"))
    n_tests = write_tests(tests, os.path.join(a.out_dir, "tests.md"))
    if a.html:
        os.makedirs(os.path.dirname(os.path.abspath(a.html)), exist_ok=True)
        write_html(eps, tests, a.html, a.csv)
        print(f"dashboard: {a.html}")
    print(f"{len(rows)} rows | endpoints {n_found} (+{n_probed} probed 404) | test cases {n_tests}")


if __name__ == "__main__":
    main()
