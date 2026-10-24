import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from arsenal.extract import run_extract  # noqa: E402

HITS: list[str] = []


def page(n, extra=""):
    return f'<html><body><script src="/js/p{n}.js"></script><a href="/p{n + 1}">next</a>{extra}</body></html>'


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        HITS.append(self.path)
        p = self.path
        if p.startswith("/js/"):
            body, ct = ("var a=%r;" % p).encode(), "application/javascript"
        elif p == "/":
            body, ct = page(0, '<a href="/logout">out</a><a href="/pic.png">i</a><a href="http://other.invalid/x">o</a>').encode(), "text/html"
        elif p.startswith("/p") and p[2:].isdigit():
            n = int(p[2:])
            body, ct = (page(n) if n < 5 else '<html><script src="/js/last.js"></script></html>').encode(), "text/html"
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200); self.send_header("Content-Type", ct); self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)


class ExtractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), H)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_full_depth_skips_unsafe(self):
        HITS.clear()
        with tempfile.TemporaryDirectory() as d:
            r = run_extract(f"127.0.0.1:{self.port}", d, lambda *_: None)
            names = {p.name for p in Path(d, "js").rglob("*.js")}
        self.assertEqual({"p0.js", "p1.js", "p2.js", "p3.js", "p4.js", "last.js"} & names, {"p0.js", "p1.js", "p2.js", "p3.js", "p4.js", "last.js"})
        self.assertEqual(r["saved"], 6)
        self.assertNotIn("/logout", HITS)       # session-ending link never requested
        self.assertNotIn("/pic.png", HITS)      # binary link never requested
        self.assertTrue(all("other.invalid" not in h for h in HITS))

    def test_stay_in_path(self):
        HITS.clear()
        with tempfile.TemporaryDirectory() as d:
            run_extract(f"127.0.0.1:{self.port}/p3", d, lambda *_: None, stay_in_path=True)
        self.assertIn("/p3", HITS)
        self.assertNotIn("/p4", HITS)


if __name__ == "__main__":
    unittest.main()
