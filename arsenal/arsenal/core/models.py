from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class JsAsset:
    """A JavaScript resource found during discovery."""

    url: str
    origin: str  # script-src | inline | preload | import | string-ref | sourcemap
    found_on: str


@dataclass
class SavedFile:
    url: str
    path: str
    sha256: str
    size: int
    origin: str
    duplicate_of: str | None = None


@dataclass(frozen=True)
class Finding:
    kind: str  # endpoint | secret | param
    value: str
    file: str
    line: int
    severity: str = "info"  # info | low | medium | high
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DumpResult:
    saved: list[SavedFile] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (url, reason)
    third_party: list[str] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
