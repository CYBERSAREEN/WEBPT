from __future__ import annotations

from urllib.parse import urlsplit


class ScopeGuard:
    """Decides whether a URL may be requested. Default: only the hosts you name."""

    def __init__(self, hosts: list[str], include_subdomains: bool = False):
        self.hosts = {self._host(h) for h in hosts if h.strip()}
        self.include_subdomains = include_subdomains

    @staticmethod
    def _host(value: str) -> str:
        """Accept 'host', 'host:port' or a full URL and return the bare lowercase hostname."""
        value = value.strip()
        parts = urlsplit(value if "://" in value else "//" + value)
        return (parts.hostname or value).lower()

    @classmethod
    def from_targets(cls, urls: list[str], extra: list[str] | None = None, include_subdomains: bool = False):
        hosts = [urlsplit(u).hostname or "" for u in urls] + list(extra or [])
        return cls(hosts, include_subdomains)

    def allows(self, url: str) -> bool:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            return False
        host = (parts.hostname or "").lower()
        if host in self.hosts:
            return True
        return self.include_subdomains and any(host.endswith("." + h) for h in self.hosts)
