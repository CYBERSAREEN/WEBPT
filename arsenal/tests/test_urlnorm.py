import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from arsenal.core.urlnorm import TargetError, normalize_target as n  # noqa: E402


class UrlNormTests(unittest.TestCase):
    def first(self, s):
        return n(s)[0]

    def test_plain_and_www(self):
        self.assertEqual(n("example.com"), ["https://example.com", "http://example.com"])
        self.assertEqual(self.first("www.example.com"), "https://www.example.com")

    def test_schemes_and_case(self):
        self.assertEqual(n("http://example.com"), ["http://example.com"])
        self.assertEqual(n("HTTPS://EXAMPLE.COM/A"), ["https://example.com/A"])
        self.assertEqual(self.first("//example.com/x"), "https://example.com/x")
        self.assertEqual(self.first("http:/example.com"), "http://example.com")
        self.assertEqual(self.first("https:\\\\example.com\\a"), "https://example.com/a")

    def test_port_path_query_fragment(self):
        self.assertEqual(self.first("example.com:8443/app?x=1#frag"), "https://example.com:8443/app?x=1")
        self.assertEqual(self.first("https://a.b.example.co.uk/p/q/"), "https://a.b.example.co.uk/p/q/")

    def test_local_and_ip(self):
        self.assertEqual(n("localhost:3000"), ["http://localhost:3000", "https://localhost:3000"])
        self.assertEqual(self.first("127.0.0.1:8080/app"), "http://127.0.0.1:8080/app")
        self.assertEqual(self.first("8.8.8.8"), "https://8.8.8.8")
        self.assertEqual(self.first("[::1]:3000"), "http://[::1]:3000")

    def test_userinfo_dropped(self):
        self.assertEqual(self.first("https://user:pw@example.com/x"), "https://example.com/x")

    def test_pasted_noise(self):
        self.assertEqual(self.first('  "https://example.com/a",  '), "https://example.com/a")
        self.assertEqual(self.first("see https://example.com/a, thanks"), "https://example.com/a")
        self.assertEqual(self.first("<https://example.com>"), "https://example.com")
        self.assertEqual(self.first("(https://example.com/x)."), "https://example.com/x")
        self.assertEqual(self.first("view-source:https://example.com"), "https://example.com")
        self.assertEqual(self.first("​example.com\n"), "https://example.com")

    def test_defanged(self):
        self.assertEqual(self.first("hxxps://example[.]com/a"), "https://example.com/a")
        self.assertEqual(self.first("example(.)com"), "https://example.com")

    def test_idn(self):
        self.assertEqual(self.first("тест.рф"), "https://xn--e1aybc.xn--p1ai")

    def test_rejects(self):
        for bad in ("", "   ", "ftp://example.com", "file:///etc/passwd", "javascript:alert(1)",
                    "mailto:a@b.com", "justaword", "http://", "example.com:99999", "-bad-.com"):
            with self.assertRaises(TargetError, msg=bad):
                n(bad)


if __name__ == "__main__":
    unittest.main()
