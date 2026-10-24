"""Turn whatever a human types or pastes into fetchable URLs.

Accepts: example.com, www.example.com, http(s)://..., //example.com/a, HTTPS://EXAMPLE.COM,
example.com:8443/path?x=1#frag, localhost:3000, 127.0.0.1:8080/app, [::1]:3000, user:pw@host,
defanged hxxps://example[.]com, view-source:https://..., surrounding quotes/brackets/trailing
punctuation, text such as "see https://x.com/a, thanks", and non-ASCII (IDN) hosts.
Rejects other schemes (ftp, file, javascript, mailto, ...) and hosts with no dot / not an IP / not localhost.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)
_BAD_SCHEMES = ("ftp", "ftps", "file", "javascript", "mailto", "data", "tel", "ssh", "sftp", "ws", "wss", "about", "chrome")
_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$", re.I)


class TargetError(ValueError):
    """Raised with a short human-readable reason."""


def _defang(s: str) -> str:
    s = re.sub(r"^hxxp", "http", s, flags=re.I)
    s = re.sub(r"\[?\(?\bdot\b\)?\]?", ".", s, flags=re.I) if re.search(r"[\[(]dot[\])]", s, re.I) else s
    s = s.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[://]", "://").replace("[/]", "/")
    return s


def _pick_token(text: str) -> str:
    text = text.translate(_ZERO_WIDTH).strip()
    if not text:
        raise TargetError("enter a target")
    tokens = text.split()
    for t in tokens:
        t2 = t.strip("\"'`<>()[]{},;")
        if "." in t2 or "://" in t2 or t2.lower().startswith(("localhost", "[")) or ":" in t2:
            return t
    return tokens[0]


def _clean_token(tok: str) -> str:
    tok = tok.strip().strip("\"'`<>")
    # strip wrapping ( ) { } and trailing punctuation, but keep IPv6 [..] brackets
    while tok and tok[-1] in ".,;:)}!?\"'" and not tok.endswith("]"):
        tok = tok[:-1]
    while tok and tok[0] in "({\"'`<":
        tok = tok[1:]
    return tok.replace("\\", "/")


def _valid_host(host: str) -> str:
    host = host.strip().rstrip(".")
    if not host:
        raise TargetError("no host found")
    if host.lower() == "localhost":
        return "localhost"
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if "." not in host:
        raise TargetError(f"'{host}' is not a domain, IP, or localhost (needs a dot)")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise TargetError("host has invalid characters")
    host = host.lower()
    if not all(_LABEL.match(p) for p in host.split(".")):
        raise TargetError(f"'{host}' is not a valid hostname")
    return host


def _is_local(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def normalize_target(text: str) -> list[str]:
    """Return candidate URLs, best first. Raises TargetError if nothing usable."""
    tok = _defang(_clean_token(_pick_token(text)))
    tok = re.sub(r"^(view-source|url):", "", tok, flags=re.I)

    m = re.match(r"^([a-z][a-z0-9+.-]*):", tok, re.I)
    scheme = None
    rest = tok
    if m and not re.match(r"^[^/]*\.[^/]*:\d", tok) and not re.match(r"^(localhost|\[)", tok, re.I):
        cand = m.group(1).lower()
        after = tok[m.end():]
        if cand in ("http", "https"):
            scheme, rest = cand, after.lstrip("/")
        elif cand in _BAD_SCHEMES or after.startswith("//"):
            raise TargetError(f"'{cand}:' is not supported, only http/https")
        elif not re.match(r"^\d+(/|$)", after):  # not "host:port"
            raise TargetError(f"'{cand}:' is not supported, only http/https")
    elif tok.startswith("//"):
        rest = tok.lstrip("/")

    try:
        parts = urlsplit("//" + rest)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        raise TargetError("invalid port or address")
    host = _valid_host(host)
    hostpart = f"[{host}]" if ":" in host else host
    netloc = hostpart + (f":{port}" if port else "")
    path = parts.path or ""
    query = f"?{parts.query}" if parts.query else ""
    tail = f"{netloc}{path}{query}"

    if scheme:
        return [f"{scheme}://{tail}"]
    order = ("http", "https") if _is_local(host) else ("https", "http")
    return [f"{s}://{tail}" for s in order]
