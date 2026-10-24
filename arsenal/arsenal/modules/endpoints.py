from __future__ import annotations

import re

from ..core.models import Finding
from .base import Module

# absolute URLs, rooted/relative paths with a slash, and API-ish calls. Written for recall, tuned to cut noise.
ABS_URL = re.compile(r"""["'`](https?://[^\s"'`<>\\]{4,300}|wss?://[^\s"'`<>\\]{4,300})["'`]""")
PATH = re.compile(r"""["'`]((?:/|\.{1,2}/)[A-Za-z0-9_\-./{}:$@%~=?&+,;]{2,200})["'`]""")
REL_API = re.compile(r"""["'`]((?:api|v\d|graphql|rest|internal|admin|auth|oauth|rpc)/[A-Za-z0-9_\-./{}:$@%~=?&+,;]{1,200})["'`]""")
CALL = re.compile(r"""\b(?:fetch|axios(?:\.\w+)?|\$\.(?:get|post|ajax)|\.open)\(\s*(?:["'`]([A-Z]+)["'`]\s*,\s*)?["'`]([^"'`]{2,200})["'`]""")

NOISE_PREFIX = ("text/", "image/", "application/", "audio/", "video/", "font/", "multipart/")
NOISE_HOSTS = ("w3.org", "schema.org", "reactjs.org", "react.dev", "nextjs.org", "mozilla.org", "github.com/facebook")
NOISE_EXT = (".png", ".jpg", ".jpeg", ".svg", ".gif", ".woff", ".woff2", ".ttf", ".ico", ".css", ".webp")
SENSITIVE = ("admin", "internal", "debug", "token", "password", "reset", "upload", "export", "graphql", "swagger", "actuator", "backup", "config")


class EndpointExtractor(Module):
    """LinkFinder-style extraction of URLs and API paths from JS."""

    name = "endpoints"

    def scan_text(self, text: str, file: str) -> list[Finding]:
        found: dict[str, Finding] = {}

        def add(val: str, pos: int, note: str):
            val = val.strip()
            low = val.lower()
            if (
                len(val) < 3
                or low.startswith(NOISE_PREFIX)
                or any(h in low for h in NOISE_HOSTS)
                or low.split("?")[0].endswith(NOISE_EXT)
                or low in ("/", "./", "../")
                or "//" == val[:2] and "." not in val
                or len(re.sub(r"\$\{[^}]*\}|[/._\-]", "", val)) < 3  # template-only or too short ("/a/i")
                or "node_modules" in low
            ):
                return
            sev = "low" if any(s in low for s in SENSITIVE) else "info"
            if val not in found:
                found[val] = Finding("endpoint", val, file, self.line_of(text, pos), sev, note)

        for rx, note in ((ABS_URL, "absolute-url"), (PATH, "path"), (REL_API, "relative-api")):
            for m in rx.finditer(text):
                add(m.group(1), m.start(1), note)
        for m in CALL.finditer(text):
            method, url = m.group(1), m.group(2)
            add(url, m.start(2), f"call{(' ' + method) if method else ''}")
        return list(found.values())
