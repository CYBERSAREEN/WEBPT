from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .core.http import HttpClient
from .core.scope import ScopeGuard
from .pipeline import Analyzer, Engagement

BANNER = "arsenal {v} - only test systems you are authorised to test.".format(v=__version__)


def _client(a) -> HttpClient:
    headers = {}
    for h in a.header or []:
        if ":" not in h:
            raise SystemExit(f"bad header (need 'Name: value'): {h}")
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    if a.cookie:
        headers["Cookie"] = a.cookie
    return HttpClient(proxy=a.proxy, timeout=a.timeout, delay=a.delay, retries=a.retries,
                      max_bytes=a.max_bytes, insecure=a.insecure, headers=headers)


def _common(p: argparse.ArgumentParser):
    p.add_argument("-o", "--out", default="arsenal-out", help="output directory (default: arsenal-out)")
    p.add_argument("--proxy", help="e.g. http://127.0.0.1:8080 to route through Burp")
    p.add_argument("-H", "--header", action="append", help="extra header 'Name: value' (repeatable)")
    p.add_argument("--cookie", help="Cookie header value for authenticated crawling")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification (Burp CA not trusted)")
    p.add_argument("--timeout", type=float, default=15)
    p.add_argument("--delay", type=float, default=0, help="seconds between requests")
    p.add_argument("--retries", type=int, default=2)
    p.add_argument("--max-bytes", type=int, default=5_000_000, help="per-file size cap")
    p.add_argument("--depth", type=int, default=1, help="page crawl depth (0 = only the given URLs)")
    p.add_argument("--max-pages", type=int, default=10)
    p.add_argument("--max-files", type=int, default=500)
    p.add_argument("--scope", action="append", default=[], help="additional in-scope host (repeatable)")
    p.add_argument("--subdomains", action="store_true", help="treat subdomains of scope hosts as in scope")
    p.add_argument("--third-party", action="store_true", help="also download out-of-scope scripts (CDNs)")
    p.add_argument("--reveal", action="store_true", help="show full secret values (default masked)")
    p.add_argument("-q", "--quiet", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="arsenal", description=BANNER)
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, helptext in (("dump", "download all JS only"), ("full", "dump + sourcemaps + endpoints/secrets/wordlist + report")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("urls", nargs="+")
        _common(p)
    p = sub.add_parser("analyze", help="analyse an existing dump directory")
    p.add_argument("dir")
    p.add_argument("-o", "--out", default="arsenal-out")
    p.add_argument("--reveal", action="store_true")
    return ap


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    log = (lambda *_: None) if getattr(a, "quiet", False) else print
    print(BANNER, file=sys.stderr)
    if a.cmd == "analyze":
        d = Path(a.dir)
        if not d.is_dir():
            print(f"not a directory: {d}", file=sys.stderr)
            return 2
        res = Analyzer(a.reveal).run(d)
        Analyzer.write_reports(Path(a.out), res)
        print(f"secrets={len(res['secrets'])} endpoints={len(res['endpoints'])} -> {a.out}/report.md")
        return 0
    urls = [u if "://" in u else "https://" + u for u in a.urls]
    scope = ScopeGuard.from_targets(urls, a.scope, a.subdomains)
    eng = Engagement(urls, Path(a.out), _client(a), scope, depth=a.depth, max_pages=a.max_pages,
                     max_files=a.max_files, third_party=a.third_party)
    if a.cmd == "dump":
        res = eng.dump(log)
    else:
        res, findings = eng.full(a.reveal, log)
        print(f"secrets={len(findings['secrets'])} endpoints={len(findings['endpoints'])} params={len(findings['params'])} -> {a.out}/report.md")
    uniq = sum(1 for s in res.saved if not s.duplicate_of)
    print(f"saved={uniq} skipped={len(res.skipped)} errors={len(res.errors)} third_party={len(set(res.third_party))}")
    return 0 if (uniq or not res.errors) else 1
