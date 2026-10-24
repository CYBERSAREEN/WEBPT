"""One-shot JS extraction used by `arsenal.py --js-extract URL OUT_DIR`."""
from __future__ import annotations

from pathlib import Path

from .core.http import HttpClient
from .core.scope import ScopeGuard
from .core.urlnorm import normalize_target
from .pipeline import Engagement


def run_extract(target_text: str, out_dir: str, log=print, cookie: str = "", depth: int = 1,
                analyse: bool = False, proxy: str | None = None, insecure: bool = False) -> dict:
    """Normalise the target, try each candidate URL (https then http), save JS, optionally analyse."""
    candidates = normalize_target(target_text)
    out = Path(out_dir).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    headers = {"Cookie": cookie} if cookie else {}
    last = None
    for url in candidates:
        log(f"-> trying {url}")
        host = url.split("//", 1)[1].split("/", 1)[0]
        local = host.startswith(("localhost", "127.", "10.", "192.168.", "[::1]"))
        client = HttpClient(proxy=proxy, timeout=15, retries=2, insecure=insecure or local, headers=headers)
        scope = ScopeGuard.from_targets([url], [], False)
        eng = Engagement([url], out, client, scope, depth=depth, max_pages=10, max_files=500, third_party=False)
        try:
            if analyse:
                res, findings = eng.full(False, log)
                extra = {"endpoints": len(findings["endpoints"]), "secrets": len(findings["secrets"])}
            else:
                res, extra = eng.dump(log), {}
        except Exception as e:  # network failure etc.: try the next candidate scheme
            log(f"   failed: {e}")
            last = e
            continue
        saved = sum(1 for s in res.saved if not s.duplicate_of)
        if saved or not res.errors:
            return {"url": url, "saved": saved, "skipped": len(res.skipped), "errors": len(res.errors),
                    "third_party": len(set(res.third_party)), "out": str(out), **extra}
        first = str(res.errors[0])[:160] if res.errors else "no files found"
        last = RuntimeError(f"no files saved ({first})")
        log(f"   {last}")
    raise RuntimeError(f"could not extract from any candidate ({last})")
