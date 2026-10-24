from __future__ import annotations

import re
from collections import deque
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlsplit

from ..core.http import FetchError, HttpClient
from ..core.models import DumpResult, JsAsset
from ..core.scope import ScopeGuard
from ..core.storage import OutputStore

JS_CT = ("javascript", "ecmascript")
# quoted strings that look like a JS file reference, e.g. "/_next/static/chunks/app.js?v=3"
STRING_REF = re.compile(r"""["'`]((?:https?:)?//[^"'`\s<>]+?\.m?js(?:\?[^"'`\s<>]*)?|[./A-Za-z0-9_@~-][^"'`\s<>]*?\.m?js(?:\?[^"'`\s<>]*)?)["'`]""")
# links a crawler must not follow: binaries (wasteful) and state-changing/session-ending URLs
SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif", ".pdf", ".zip", ".gz", ".tar",
            ".7z", ".rar", ".mp3", ".mp4", ".webm", ".mov", ".avi", ".woff", ".woff2", ".ttf", ".otf", ".eot",
            ".css", ".xml", ".csv", ".xls", ".xlsx", ".doc", ".docx", ".exe", ".dmg", ".apk", ".iso")
UNSAFE_LINK = re.compile(r"(log[-_]?out|sign[-_]?out|signoff|delete|remove|destroy|unsubscribe|revoke|reset[-_]?password)", re.I)
STATIC_IMPORT = re.compile(r"""(?:\bimport\s*(?:[^'"()]*?\bfrom\s*)?|\bexport\s[^'"()]*?\bfrom\s*|\bimport\s*\(\s*)["']([^"']+)["']""")
SOURCEMAP = re.compile(r"""[#@]\s*sourceMappingURL=([^\s'"]+)""")


class PageParser(HTMLParser):
    """Collects script sources, inline scripts, preloads, <base>, and same-site links."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts: list[str] = []
        self.preloads: list[str] = []
        self.links: list[str] = []
        self.inline: list[str] = []
        self.base: str | None = None
        self._in_script = False
        self._buf: list[str] = []
        self._inline_ok = True

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "base" and a.get("href") and self.base is None:
            self.base = a["href"]
        elif tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"].strip())
            else:
                self._in_script = True
                t = a.get("type", "").lower()
                self._inline_ok = t in ("", "module", "text/javascript", "application/javascript")
                self._buf = []
        elif tag == "link":
            rel = a.get("rel", "").lower()
            if ("preload" in rel or "modulepreload" in rel) and a.get("href"):
                if a.get("as", "script") == "script" or "modulepreload" in rel:
                    self.preloads.append(a["href"].strip())
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"].strip())

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            code = "".join(self._buf).strip()
            if code and self._inline_ok:
                self.inline.append(code)
            self._in_script = False


class JSDumper:
    """Crawl pages, download every reachable JS file (src, preload, imports, string refs, sourcemaps)."""

    def __init__(
        self,
        client: HttpClient,
        store: OutputStore,
        scope: ScopeGuard,
        depth: int = 1,
        max_pages: int = 10,
        max_files: int = 500,
        third_party: bool = False,
        log=print,
        page_prefix: str = "",
    ):
        self.client, self.store, self.scope = client, store, scope
        self.depth, self.max_pages, self.max_files = depth, max_pages, max_files
        self.third_party = third_party
        self.page_prefix = page_prefix
        self.log = log
        self.result = DumpResult()
        self._seen_js: set[str] = set()
        self._seen_pages: set[str] = set()
        self._inline_n = 0

    # ---- public ----
    def run(self, targets: list[str]) -> DumpResult:
        queue = deque((u, 0) for u in targets)
        pages = 0
        while queue and pages < self.max_pages:
            url, d = queue.popleft()
            url = urldefrag(url)[0]
            if url in self._seen_pages:
                continue
            self._seen_pages.add(url)
            if not self.scope.allows(url):
                self.result.skipped.append((url, "page out of scope"))
                continue
            pages += 1
            try:
                resp = self.client.get(url)
            except FetchError as e:
                self.result.errors.append((url, str(e)))
                continue
            self.log(f"[page] {resp.status} {url}")
            ct = resp.content_type
            if any(k in ct for k in JS_CT):  # target itself is a JS file
                self._handle_js(JsAsset(url, "script-src", url), resp)
                continue
            if resp.status >= 400 and not resp.body:
                self.result.errors.append((url, f"HTTP {resp.status}"))
                continue
            page = PageParser()
            try:
                page.feed(resp.text())
            except Exception as e:  # malformed HTML must not stop the run
                self.result.errors.append((url, f"html parse: {e}"))
            base = urljoin(resp.final_url, page.base) if page.base else resp.final_url
            self._from_page(page, base, url)
            if d < self.depth:
                for href in page.links:
                    nxt = urldefrag(urljoin(base, href))[0]
                    if nxt not in self._seen_pages and self.scope.allows(nxt) and not self._skip_link(nxt):
                        queue.append((nxt, d + 1))
        self.store.write_manifest()
        return self.result

    # ---- internals ----
    def _skip_link(self, url: str) -> bool:
        path = urlsplit(url).path
        if path.lower().endswith(SKIP_EXT):
            return True
        if self.page_prefix and not path.startswith(self.page_prefix):
            return True
        if UNSAFE_LINK.search(path):
            self.result.skipped.append((url, "state-changing/logout link not followed"))
            return True
        return False

    def _from_page(self, page: PageParser, base: str, page_url: str):
        for i, code in enumerate(page.inline):
            self._inline_n += 1
            fake = f"{page_url.split('#')[0].split('?')[0].rstrip('/')}/__inline_{self._inline_n}.js"
            rec = self.store.save(fake, code.encode(), "inline")
            self.result.saved.append(rec)
            self._discover(code, base, page_url)
        for src in page.scripts:
            self._queue_js(JsAsset(urljoin(base, src), "script-src", page_url))
        for src in page.preloads:
            self._queue_js(JsAsset(urljoin(base, src), "preload", page_url))

    def _queue_js(self, asset: JsAsset):
        url = urldefrag(asset.url)[0]
        if url in self._seen_js or url.startswith(("data:", "blob:", "javascript:")):
            return
        self._seen_js.add(url)
        if len(self._seen_js) > self.max_files:
            self.result.skipped.append((url, "max-files reached"))
            return
        if not self.scope.allows(url):
            if urlsplit(url).scheme in ("http", "https"):
                self.result.third_party.append(url)
            if not self.third_party:
                self.result.skipped.append((url, "third-party (use --third-party)"))
                return
        try:
            resp = self.client.get(url)
        except FetchError as e:
            self.result.errors.append((url, str(e)))
            return
        self._handle_js(JsAsset(url, asset.origin, asset.found_on), resp)

    def _handle_js(self, asset: JsAsset, resp):
        if resp.status >= 400:
            if asset.origin == "guess":  # speculative URL, a 404 is expected
                self.result.skipped.append((asset.url, f"guess failed: HTTP {resp.status}"))
            else:
                self.result.errors.append((asset.url, f"HTTP {resp.status}"))
            return
        if "text/html" in resp.content_type:  # SPA fallback served HTML for a missing .js
            self.result.skipped.append((asset.url, "got HTML, not JS (soft-404)"))
            return
        if not resp.body:
            self.result.skipped.append((asset.url, "empty body"))
            return
        if resp.truncated:
            self.result.errors.append((asset.url, "truncated at max_bytes"))
        rec = self.store.save(asset.url, resp.body, asset.origin)
        self.result.saved.append(rec)
        self.log(f"[js]   {resp.status} {asset.url}" + (" (dup)" if rec.duplicate_of else ""))
        if not rec.duplicate_of:
            self._discover(resp.text(), resp.final_url, asset.url)

    def _discover(self, code: str, base: str, found_on: str):
        for m in STATIC_IMPORT.finditer(code):
            ref = m.group(1)
            if ref.split("?")[0].endswith((".js", ".mjs")):
                self._queue_js(JsAsset(urljoin(base, ref), "import", found_on))
        for m in STRING_REF.finditer(code):
            ref = m.group(1)
            bare = not ref.startswith(("/", "./", "../", "http", "//"))
            self._queue_js(JsAsset(urljoin(base, ref), "guess" if bare else "string-ref", found_on))
            if bare:
                # bundlers prepend a publicPath at runtime (Next: /_next/), so bare refs resolve wrong; guess
                root = "{0.scheme}://{0.netloc}".format(urlsplit(base))
                self._queue_js(JsAsset(f"{root}/{ref}", "guess", found_on))
                if ref.startswith("static/"):
                    self._queue_js(JsAsset(f"{root}/_next/{ref}", "guess", found_on))
        for m in SOURCEMAP.finditer(code):
            ref = m.group(1)
            if ref.startswith("data:"):
                continue  # inline maps handled by SourceMapRecovery
            self._queue_map(urljoin(base, ref), found_on)

    def _queue_map(self, url: str, found_on: str):
        if url in self._seen_js or not self.scope.allows(url):
            return
        self._seen_js.add(url)
        try:
            resp = self.client.get(url)
        except FetchError as e:
            self.result.errors.append((url, str(e)))
            return
        if resp.status == 200 and resp.body.lstrip()[:1] == b"{":
            self.result.saved.append(self.store.save(url, resp.body, "sourcemap", ".map"))
            self.log(f"[map]  200 {url}")
