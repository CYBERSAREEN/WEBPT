# Using Arsenal efficiently

Maps to the *Web Hacking Arsenal* recon stage (Ch.2) and `Desktop/Web-Hacking-Arsenal-Methodology/attack-matrix.md` section 0.

## Workflow (do in this order)
1. **Unauthenticated sweep**: `./arsenal.py full https://t.tld -o t1`
   Read `t1/report.md` first: secrets, "interesting endpoints" (admin/internal/debug...), third-party scripts.
2. **Authenticated sweep** (different JS ships to logged-in users, admin links hide in role-gated bundles):
   `./arsenal.py full https://t.tld/dashboard --cookie "session=..." -o t2`
   `diff <(sort t1/endpoints.txt) <(sort t2/endpoints.txt)` -> endpoints that only appear after login.
   Repeat with a low-priv and a high-priv cookie: gaps are access-control test cases (use Autorize).
3. **Through Burp** so everything lands in Logger++/sitemap: `--proxy http://127.0.0.1:8080 --insecure`
4. **Feed results onward**
   - `endpoints.txt` -> Burp (Pentest Coverage Tracker) / `ffuf`/`httpx` for liveness
   - `wordlist.txt` -> Param Miner / ffuf as the target-specific parameter list
   - `sources/` -> `grep -rn "dangerouslySetInnerHTML\|innerHTML\|eval(\|postMessage\|localStorage" sources/`
5. Pick findings, then walk WHAT/WHICH/PRE/PAY in the attack matrix for each.

## Flags that matter
| Flag | When |
|---|---|
| `--depth N --max-pages M` | follow same-scope links to reach more page-specific bundles (default depth 1) |
| `--scope host` / `--subdomains` | target spans hosts (static.t.tld, app.t.tld); default is exact host only |
| `--third-party` | also pull CDN scripts (vendor libs: check versions for known CVEs). Off by default to stay in scope |
| `--cookie` / `-H` | auth, `Authorization: Bearer ...`, custom headers |
| `--delay 0.5` | gentle on fragile / WAF-protected targets |
| `--max-bytes` | raise for giant bundles; truncated files are reported |
| `--reveal` | print secret values in full (default masked so reports are shareable) |

## Reading the report
- `secrets` severity high = well-known token formats; medium = generic `key: "value"` with entropy filter. **Verify before reporting**: many keys (Google Maps, Sentry DSN) are public by design.
- `skipped: ... soft-404` = server returned HTML for a .js URL (SPA fallback). Not a file.
- `guess failed` = harmless; bundlers add a runtime path prefix so the tool tries `/_next/` and root variants.
- `truncated at max_bytes` = file cut; raise `--max-bytes`.

## Edge cases the tests cover
duplicate script tags, `<base href>`, protocol-relative CDN URLs, `data:` scripts, inline JSON `<script>`, soft-404 HTML,
missing files, same bytes under two URLs (dedupe), same path with different query (separate files), path traversal in URLs and
sourcemap `sources`, invalid/empty sourcemaps, inline base64 maps, redirects, size cap, unreachable host, out-of-scope pages, `--max-files`.

## Try it on a lab
Run the two sweeps from the workflow above against your own lab target, authenticated with your own cookie. Do not write lab-specific answers (cookie names, hidden routes) into docs.

## Extend it
Subclass `Module`, implement `scan_text(text, file) -> list[Finding]`, add it to `Analyzer`. Ideas: DOM-sink finder, postMessage handler finder, GraphQL schema grabber, hidden-parameter fuzzer, JWT decoder.
