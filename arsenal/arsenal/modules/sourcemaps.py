from __future__ import annotations

import base64
import json
import re
from pathlib import Path

INLINE_MAP = re.compile(r"sourceMappingURL=data:application/json;(?:charset=[^;]+;)?base64,([A-Za-z0-9+/=]+)")


class SourceMapRecovery:
    """Rebuild original source files from .map files (and inline data: maps) via sourcesContent."""

    def __init__(self, out_dir: str | Path):
        self.out = Path(out_dir).resolve()
        self.recovered = 0
        self.errors: list[str] = []

    @staticmethod
    def _clean(src: str) -> Path:
        src = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", src)  # webpack://, file://
        parts = [p for p in re.split(r"[\\/]+", src) if p and p not in (".", "..")]
        parts = [re.sub(r"[^A-Za-z0-9._@=+() -]", "_", p)[:100] for p in parts]
        return Path(*parts) if parts else Path("unnamed")

    def recover_map(self, raw: bytes, label: str) -> int:
        try:
            data = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as e:
            self.errors.append(f"{label}: invalid JSON ({e})")
            return 0
        sources, contents = data.get("sources") or [], data.get("sourcesContent") or []
        if not contents:
            self.errors.append(f"{label}: no sourcesContent (names only: {len(sources)} sources)")
        n = 0
        for i, src in enumerate(sources):
            if i >= len(contents) or contents[i] is None:
                continue
            dest = (self.out / re.sub(r"[^A-Za-z0-9._-]", "_", label)[:60] / self._clean(src)).resolve()
            if self.out not in dest.parents:
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(contents[i], encoding="utf-8")
            n += 1
        self.recovered += n
        return n

    def recover_dir(self, dump_dir: str | Path) -> int:
        root = Path(dump_dir)
        for p in root.rglob("*.map"):
            self.recover_map(p.read_bytes(), p.name)
        for p in root.rglob("*.js"):
            text = p.read_text(encoding="utf-8", errors="replace")
            for m in INLINE_MAP.finditer(text):
                try:
                    self.recover_map(base64.b64decode(m.group(1)), p.name + ".inline")
                except ValueError:
                    self.errors.append(f"{p.name}: bad base64 in inline map")
        return self.recovered
