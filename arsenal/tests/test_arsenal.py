import base64
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from arsenal.core.http import FetchError, HttpClient
from arsenal.core.scope import ScopeGuard
from arsenal.core.storage import OutputStore
from arsenal.modules.endpoints import EndpointExtractor
from arsenal.modules.jsdump import JSDumper
from arsenal.modules.secrets import SecretScanner
from arsenal.modules.sourcemaps import SourceMapRecovery
from arsenal.pipeline import Engagement

MAP = json.dumps({"version": 3, "sources": ["webpack://app/./src/../../etc/passwd", "webpack://app/src/api.ts"],
                  "sourcesContent": ["root:x", "export const k='https://api.internal.example/v2/users'"]})
INLINE_MAP = base64.b64encode(MAP.encode()).decode()

ROUTES = {
    "/": ("text/html", b"""<html><head><base href="/app/"><script src="main.js"></script>
        <script src="main.js"></script><script src="//cdn.other.test/x.js"></script>
        <link rel="modulepreload" href="chunk-a.mjs"><script src="missing.js"></script>
        <script src="soft404.js"></script><script src="data:text/javascript,alert(1)"></script>
        <script type="application/json">{"a":1}</script>
        <script>var k="/inline/endpoint/one";</script></head>
        <body><a href="/second">next</a><a href="mailto:a@b.c">m</a><a href="javascript:void(0)">j</a></body></html>"""),
    "/second": ("text/html", b"<script src='/app/second.js'></script>"),
    "/app/main.js": ("application/javascript", b"""import('./lazy.js'); fetch("/api/v1/users"); var s="/app/dyn/abc.js?v=2";
        var AWS="AKIAABCDEFGHIJKLMNOP"; const cfg={apiKey:"9f8e7d6c5b4a3b2c1d0e"}; //# sourceMappingURL=main.js.map"""),
    "/app/main.js.map": ("application/json", MAP.encode()),
    "/app/lazy.js": ("application/javascript", b"export default 'https://t.example/admin/export?format=csv'"),
    "/app/chunk-a.mjs": ("application/javascript", b"console.log('a')"),
    "/app/dyn/abc.js": ("application/javascript", b"//# sourceMappingURL=data:application/json;base64," + INLINE_MAP.encode()),
    "/app/second.js": ("application/javascript", b"console.log('a')"),  # same bytes as chunk-a => dedupe
    "/app/soft404.js": ("text/html", b"<html>not found</html>"),
    "/app/big.js": ("application/javascript", b"x" * 3000),
}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        route = ROUTES.get(self.path.split("?")[0])
        if self.path.startswith("/redir"):
            self.send_response(302)
            self.send_header("Location", "/app/main.js")
            self.end_headers()
            return
        if not route:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", route[0])
        self.end_headers()
        self.wfile.write(route[1])

    def log_message(self, *a):
        pass


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()


class TestDump(Base):
    def run_dump(self, **kw):
        d = tempfile.mkdtemp()
        store = OutputStore(d)
        scope = ScopeGuard.from_targets([self.base])
        res = JSDumper(HttpClient(retries=0, timeout=3), store, scope, log=lambda *_: None, **kw).run([self.base + "/"])
        return d, res

    def names(self, res):
        return sorted(Path(s.path).name for s in res.saved if not s.duplicate_of)

    def test_discovery_and_edge_cases(self):
        d, res = self.run_dump(depth=1)
        n = self.names(res)
        for expect in ("main.js", "lazy.js", "chunk-a.mjs", "abc__qf67bbdbf.js", "main.js.map"):
            self.assertIn(expect, n)
        self.assertEqual(sum(1 for x in n if x.startswith("__inline")), 1)  # json script ignored, inline kept
        self.assertTrue(any("soft-404" in r for _, r in res.skipped))      # HTML masquerading as JS
        self.assertTrue(any(u.endswith("missing.js") for u, _ in res.errors))
        self.assertIn("http://cdn.other.test/x.js", res.third_party)         # protocol-relative CDN
        self.assertFalse(any("data:" in s.url for s in res.saved))
        self.assertTrue(any(s.duplicate_of for s in res.saved))              # second.js == chunk-a.mjs
        self.assertEqual(sum(1 for s in res.saved if s.url.endswith("main.js")), 1)  # listed twice, fetched once
        self.assertTrue((Path(d) / "manifest.json").exists())

    def test_depth_zero_skips_linked_pages(self):
        _, res = self.run_dump(depth=0)
        self.assertNotIn("second.js", self.names(res))

    def test_max_files(self):
        _, res = self.run_dump(max_files=2)
        self.assertTrue(any("max-files" in r for _, r in res.skipped))

    def test_out_of_scope_page(self):
        d = tempfile.mkdtemp()
        res = JSDumper(HttpClient(retries=0), OutputStore(d), ScopeGuard(["example.org"]), log=lambda *_: None).run([self.base + "/"])
        self.assertEqual(res.saved, [])

    def test_unreachable_host(self):
        d = tempfile.mkdtemp()
        url = "http://127.0.0.1:9/"
        res = JSDumper(HttpClient(retries=0, timeout=1), OutputStore(d), ScopeGuard.from_targets([url]), log=lambda *_: None).run([url])
        self.assertTrue(res.errors)


class TestHttp(Base):
    def test_redirect_and_cap(self):
        c = HttpClient(retries=0, max_bytes=10)
        r = c.get(self.base + "/redir")
        self.assertEqual(r.status, 200)
        self.assertTrue(r.truncated)
        self.assertEqual(len(r.body), 10)

    def test_404_returns_response(self):
        self.assertEqual(HttpClient(retries=0).get(self.base + "/nope").status, 404)

    def test_connection_failure(self):
        with self.assertRaises(FetchError):
            HttpClient(retries=0, timeout=1).get("http://127.0.0.1:9/")


class TestStorage(unittest.TestCase):
    def test_traversal_and_query(self):
        s = OutputStore(tempfile.mkdtemp())
        p = s.path_for("https://a.test/../../etc/passwd.js?x=1")
        self.assertIn(s.root, p.resolve().parents)
        self.assertNotEqual(s.path_for("https://a.test/a.js?v=1"), s.path_for("https://a.test/a.js?v=2"))
        self.assertTrue(s.path_for("https://a.test/").name.endswith(".js"))

    def test_long_name(self):
        s = OutputStore(tempfile.mkdtemp())
        s.save("https://a.test/" + "a" * 400 + ".js", b"x", "t")


class TestScope(unittest.TestCase):
    def test_rules(self):
        g = ScopeGuard(["a.test"])
        self.assertTrue(g.allows("https://a.test/x"))
        self.assertFalse(g.allows("https://evil-a.test/x"))
        self.assertFalse(g.allows("https://sub.a.test/x"))
        self.assertFalse(g.allows("ftp://a.test/x"))
        self.assertTrue(ScopeGuard(["a.test"], True).allows("https://sub.a.test/x"))
        self.assertFalse(ScopeGuard(["a.test"], True).allows("https://nota.test/x"))


class TestAnalysis(unittest.TestCase):
    def test_endpoints(self):
        js = 'fetch("/api/v1/users"); x="image/png"; y="https://www.w3.org/2000/svg"; axios.post("/admin/delete"); z="/a.png"'
        vals = {f.value for f in EndpointExtractor().scan_text(js, "f")}
        self.assertIn("/api/v1/users", vals)
        self.assertIn("/admin/delete", vals)
        self.assertNotIn("image/png", vals)
        self.assertFalse(any("w3.org" in v for v in vals))
        self.assertNotIn("/a.png", vals)

    def test_secrets_masking_and_placeholders(self):
        js = 'a="AKIAABCDEFGHIJKLMNOP"; password: "changeme"; secret="xK9#mQ2$vL8nZ4pR"; token="${TOKEN}"'
        masked = SecretScanner().scan_text(js, "f")
        self.assertTrue(all("AKIAABCDEFGHIJKLMNOP" not in f.value for f in masked))
        kinds = {f.note for f in masked}
        self.assertIn("aws-access-key", kinds)
        self.assertEqual(sum(f.note.startswith("generic") for f in masked), 1)  # placeholder ignored
        self.assertIn("AKIAABCDEFGHIJKLMNOP", {f.value for f in SecretScanner(reveal=True).scan_text(js, "f")})

    def test_empty_and_binaryish(self):
        self.assertEqual(EndpointExtractor().scan_text("", "f"), [])
        self.assertEqual(SecretScanner().scan_text("\x00\x01\xff" * 100, "f"), [])


class TestSourceMaps(unittest.TestCase):
    def test_traversal_blocked_and_invalid(self):
        out = Path(tempfile.mkdtemp())
        r = SourceMapRecovery(out)
        self.assertEqual(r.recover_map(MAP.encode(), "m.map"), 2)
        self.assertTrue(all(out in p.resolve().parents for p in out.rglob("*") if p.is_file()))
        self.assertEqual(r.recover_map(b"{not json", "bad.map"), 0)
        self.assertEqual(r.recover_map(b'{"sources":["a"]}', "names.map"), 0)


class TestFull(Base):
    def test_full_pipeline(self):
        out = Path(tempfile.mkdtemp())
        eng = Engagement([self.base + "/"], out, HttpClient(retries=0, timeout=3), ScopeGuard.from_targets([self.base]), depth=1)
        res, f = eng.full(log=lambda *_: None)
        report = (out / "report.md").read_text()
        self.assertIn("aws-access-key", report)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", report)
        self.assertTrue(any("api.internal.example" in x.value for x in f["endpoints"]))  # from recovered source
        self.assertTrue((out / "wordlist.txt").read_text().strip())


if __name__ == "__main__":
    unittest.main()
