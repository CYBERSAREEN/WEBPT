from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .models import SavedFile

_BAD = re.compile(r"[^A-Za-z0-9._@=+-]")


class OutputStore:
    """Writes files under root/<host>/<path>, safe against traversal, dedupes by content hash."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._by_hash: dict[str, str] = {}
        self.manifest: list[SavedFile] = []

    def path_for(self, url: str, default_ext: str = ".js") -> Path:
        p = urlsplit(url)
        host = _BAD.sub("_", (p.hostname or "unknown") + (f"_{p.port}" if p.port else ""))
        segs = [s for s in unquote(p.path).split("/") if s and s not in (".", "..")]
        segs = [_BAD.sub("_", s)[:100] for s in segs] or ["index"]
        name = segs[-1]
        if "." not in name:
            name += default_ext
        if p.query:  # same path, different query => different file; keep extension last
            stem, dot, ext = name.rpartition(".")
            tag = "__q" + hashlib.sha1(p.query.encode()).hexdigest()[:8]
            name = f"{stem}{tag}.{ext}" if dot else name + tag
        out = self.root.joinpath(host, *segs[:-1], name[:140])
        if self.root not in out.resolve().parents:
            raise ValueError(f"path escapes output dir: {url}")
        return out

    def save(self, url: str, body: bytes, origin: str, ext: str = ".js") -> SavedFile:
        digest = hashlib.sha256(body).hexdigest()
        if digest in self._by_hash:
            rec = SavedFile(url, self._by_hash[digest], digest, len(body), origin, duplicate_of=self._by_hash[digest])
            self.manifest.append(rec)
            return rec
        path = self.path_for(url, ext)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        self._by_hash[digest] = str(path)
        rec = SavedFile(url, str(path), digest, len(body), origin)
        self.manifest.append(rec)
        return rec

    def write_manifest(self) -> Path:
        out = self.root / "manifest.json"
        out.write_text(json.dumps([r.__dict__ for r in self.manifest], indent=2))
        return out
