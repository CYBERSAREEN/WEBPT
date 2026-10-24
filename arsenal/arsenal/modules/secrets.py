from __future__ import annotations

import math
import re
from collections import Counter

from ..core.models import Finding
from .base import Module

PATTERNS: list[tuple[str, str, str]] = [
    ("aws-access-key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "high"),
    ("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "medium"),
    ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "high"),
    ("slack-token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", "high"),
    ("stripe-secret", r"\b[sr]k_live_[A-Za-z0-9]{16,}\b", "high"),
    ("private-key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "high"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*", "medium"),
    ("sentry-dsn", r"https://[0-9a-f]{16,}@[\w.-]+/\d+", "low"),
    ("firebase-url", r"https://[\w-]+\.firebaseio\.com", "medium"),
    ("s3-bucket", r"\b[\w.-]+\.s3[.-](?:[\w-]+\.)?amazonaws\.com\b", "low"),
    ("basic-auth-url", r"https?://[^/\s:@\"']+:[^/\s@\"']+@[\w.-]+", "high"),
    ("flag-like", r"\bBL\{[^}\s]{4,80}\}", "high"),
]
GENERIC = re.compile(
    r"""(?i)["']?(api[_-]?key|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|passwd|password|private[_-]?key)["']?\s*[:=]\s*["']([^"'\s]{8,})["']"""
)
PLACEHOLDER = re.compile(r"(?i)^(x+|\*+|your[_-].*|<.*>|\$\{.*\}|process\.env.*|example|changeme|password|null|undefined)$")


def entropy(s: str) -> float:
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def mask(v: str) -> str:
    return v if len(v) <= 8 else v[:4] + "..." + v[-2:]


class SecretScanner(Module):
    """Regex + entropy secret finder. Values masked unless reveal=True."""

    name = "secrets"

    def __init__(self, reveal: bool = False):
        self.reveal = reveal
        self._compiled = [(n, re.compile(p), s) for n, p, s in PATTERNS]

    def _val(self, v: str) -> str:
        return v if self.reveal else mask(v)

    def scan_text(self, text: str, file: str) -> list[Finding]:
        out: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for name, rx, sev in self._compiled:
            for m in rx.finditer(text):
                key = (name, m.group(0))
                if key in seen:
                    continue
                seen.add(key)
                out.append(Finding("secret", self._val(m.group(0)), file, self.line_of(text, m.start()), sev, name))
        for m in GENERIC.finditer(text):
            v = m.group(2)
            if PLACEHOLDER.match(v) or entropy(v) < 2.5 or ("generic", v) in seen:
                continue
            seen.add(("generic", v))
            out.append(Finding("secret", self._val(v), file, self.line_of(text, m.start()), "medium", f"generic:{m.group(1).lower()}"))
        return out
