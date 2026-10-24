# Arsenal

OOP, stdlib-only (Python 3.10+) CLI for web-pentest recon. Authorised targets only.

```
./arsenal.py full https://target.tld -o out --proxy http://127.0.0.1:8080 --insecure
```

## Layout (one class per job)
| Class | File | Job |
|---|---|---|
| `HttpClient` | core/http.py | requests: proxy, delay, retries, size cap, headers/cookies |
| `ScopeGuard` | core/scope.py | refuses out-of-scope hosts (exact host by default) |
| `OutputStore` | core/storage.py | safe paths, query-aware names, sha256 dedupe, manifest |
| `PageParser` / `JSDumper` | modules/jsdump.py | finds + downloads every reachable JS file and sourcemap |
| `SourceMapRecovery` | modules/sourcemaps.py | rebuilds original source from `.map` / inline maps |
| `Module` -> `EndpointExtractor`, `SecretScanner`, `ParamHarvester` | modules/*.py | analysers (add yours by subclassing `Module`) |
| `Analyzer`, `Engagement` | pipeline.py | orchestration + reports |

## Commands
- `dump URL...`  download JS only
- `full URL...`  dump + sourcemaps + endpoints + secrets + params + `report.md`
- `analyze DIR`  re-run analysis on an existing dump (e.g. files saved from Burp)

Outputs in `-o DIR`: `js/` (raw files), `sources/` (recovered originals), `report.md`, `findings.json`, `endpoints.txt`, `wordlist.txt`, `js/manifest.json`.

See `docs/USAGE.md` for how to use it efficiently. Tests: `python3 -m unittest discover -s tests`.

## Quick JS extract (any URL format, full crawl)
```
python3 arsenal.py --js-extract <url> <output-folder> [--cookie "N=V"] [--analyse] [--delay S] [--stay-in-path] [--proxy URL]
python3 arsenal.py --js-extract www.example.com ~/recon/example
python3 arsenal.py --js-extract "https://example.com:8443/app?x=1" ~/recon/example --analyse --delay 0.5
```
- Target can be `example.com`, `www.example.com`, `http(s)://...`, `host:port`, an IP, `localhost:3000`, `//host/path`, or a pasted/defanged form like `hxxps://example[.]com`. With no scheme it tries https, then http.
- Crawl depth is always maximum: every in-scope page reachable by links is visited and all its JS is saved (safety ceilings: 5,000 pages, 50,000 files). Scope is the target's host only; other hosts and CDNs are listed, not fetched.
- Never followed: logout/delete/remove/reset-style links (so an authenticated crawl keeps its session) and binary/media links.
- `--stay-in-path` limits which *pages* are crawled to the URL's path (for engagements scoped to e.g. `/labs/harbor`); JS is still downloaded from anywhere on the host.
- JS goes to `<output-folder>/js/`; `--analyse` also writes `endpoints.txt`, `wordlist.txt`, `findings.json`, `report.md`.
