from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from ..core.models import Finding
from .base import Module

QUERY_KEY = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_\-.]{0,40})=")
OBJ_KEY = re.compile(r"""[{,]\s*["']?([A-Za-z_][A-Za-z0-9_]{2,30})["']?\s*:""")
JS_NOISE = {"function", "return", "default", "const", "this", "true", "false", "null", "undefined", "length", "prototype", "constructor", "style", "class", "children", "props", "type", "key", "ref"}


class ParamHarvester(Module):
    """Harvest candidate parameter names + path words for Param Miner / ffuf style wordlists."""

    name = "params"

    def __init__(self, wide: bool = False):
        self.wide = wide  # wide=True also harvests object keys (very noisy on minified bundles)

    def scan_text(self, text: str, file: str) -> list[Finding]:
        seen: dict[str, Finding] = {}
        for m in QUERY_KEY.finditer(text):
            seen.setdefault(m.group(1), Finding("param", m.group(1), file, self.line_of(text, m.start()), "info", "query-key"))
        for m in (OBJ_KEY.finditer(text) if self.wide else ()):
            k = m.group(1)
            if k.lower() not in JS_NOISE:
                seen.setdefault(k, Finding("param", k, file, self.line_of(text, m.start()), "info", "object-key"))
        return list(seen.values())

    @staticmethod
    def from_endpoints(endpoints: list[Finding]) -> set[str]:
        words: set[str] = set()
        for f in endpoints:
            p = urlsplit(f.value)
            words.update(k for k, _ in parse_qsl(p.query))
            words.update(s for s in p.path.split("/") if s and not s.startswith(("{", ":")) and "." not in s)
        return words
