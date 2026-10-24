from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from ..core.models import Finding


class Module(ABC):
    """Every analysis module implements scan_text; shared helpers live here."""

    name = "module"

    @abstractmethod
    def scan_text(self, text: str, file: str) -> list[Finding]: ...

    def scan_file(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return self.scan_text(text, str(path))

    def scan_dir(self, root: Path, suffixes=(".js", ".mjs", ".html", ".map", ".json")) -> list[Finding]:
        out: list[Finding] = []
        for p in sorted(root.rglob("*")):
            if p.is_file() and p.suffix in suffixes and p.name != "manifest.json":
                out.extend(self.scan_file(p))
        return out

    @staticmethod
    def line_of(text: str, pos: int) -> int:
        return text.count("\n", 0, pos) + 1
