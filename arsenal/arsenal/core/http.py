from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field


class FetchError(Exception):
    """Network-level failure (DNS, TLS, timeout, connection reset)."""


@dataclass
class Response:
    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    body: bytes
    truncated: bool = False
    elapsed: float = 0.0

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    def text(self) -> str:
        charset = "utf-8"
        ct = self.headers.get("content-type", "")
        if "charset=" in ct:
            charset = ct.split("charset=")[-1].split(";")[0].strip() or "utf-8"
        try:
            return self.body.decode(charset)
        except (UnicodeDecodeError, LookupError):
            return self.body.decode("utf-8", errors="replace")


@dataclass
class HttpClient:
    """Thin urllib wrapper: proxy (Burp), delay, retries, size cap, custom headers. Stdlib only."""

    proxy: str | None = None
    timeout: float = 15.0
    delay: float = 0.0
    retries: int = 2
    max_bytes: int = 5_000_000
    insecure: bool = False
    headers: dict[str, str] = field(default_factory=dict)
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) Arsenal/0.1"
    _last: float = field(default=0.0, init=False, repr=False)
    requests_made: int = field(default=0, init=False)

    def __post_init__(self):
        handlers: list[urllib.request.BaseHandler] = []
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy}))
        ctx = ssl.create_default_context()
        if self.insecure:  # needed when Burp's CA is not trusted
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self._opener = urllib.request.build_opener(*handlers)

    def _throttle(self):
        wait = self.delay - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def get(self, url: str) -> Response:
        hdrs = {"User-Agent": self.user_agent, "Accept": "*/*", "Accept-Encoding": "identity", **self.headers}
        last_err: Exception | None = None
        for attempt in range(self.retries + 1):
            self._throttle()
            self.requests_made += 1
            started = time.monotonic()
            try:
                req = urllib.request.Request(url, headers=hdrs)
                with self._opener.open(req, timeout=self.timeout) as r:
                    return self._build(url, r, r.status, started)
            except urllib.error.HTTPError as e:  # 4xx/5xx still carry a body worth reading
                if e.code in (429, 502, 503, 504) and attempt < self.retries:
                    time.sleep(min(2**attempt, 5))
                    continue
                try:
                    return self._build(url, e, e.code, started)
                finally:
                    e.close()
            except (urllib.error.URLError, TimeoutError, ssl.SSLError, ConnectionError, OSError, ValueError) as e:
                last_err = e
                time.sleep(min(2**attempt * 0.3, 2))
        raise FetchError(f"{url}: {last_err}")

    def _build(self, url: str, r, status: int, started: float) -> Response:
        body = r.read(self.max_bytes + 1)
        truncated = len(body) > self.max_bytes
        return Response(
            url=url,
            final_url=getattr(r, "url", None) or r.geturl(),
            status=status,
            headers={k.lower(): v for k, v in r.headers.items()},
            body=body[: self.max_bytes],
            truncated=truncated,
            elapsed=time.monotonic() - started,
        )
