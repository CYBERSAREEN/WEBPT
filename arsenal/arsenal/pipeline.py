from __future__ import annotations

import json
from pathlib import Path

from .core.http import HttpClient
from .core.models import DumpResult, Finding
from .core.scope import ScopeGuard
from .core.storage import OutputStore
from .modules.endpoints import EndpointExtractor
from .modules.jsdump import JSDumper
from .modules.secrets import SecretScanner
from .modules.sourcemaps import SourceMapRecovery
from .modules.wordlist import ParamHarvester


class Analyzer:
    """Runs analysis modules over a dump directory and writes reports."""

    def __init__(self, reveal: bool = False):
        self.endpoints = EndpointExtractor()
        self.secrets = SecretScanner(reveal=reveal)
        self.params = ParamHarvester()

    def run(self, dump_dir: Path) -> dict[str, list[Finding]]:
        return {
            "endpoints": self.endpoints.scan_dir(dump_dir),
            "secrets": self.secrets.scan_dir(dump_dir),
            "params": self.params.scan_dir(dump_dir),
        }

    @staticmethod
    def write_reports(out: Path, results: dict[str, list[Finding]], dump: DumpResult | None = None) -> None:
        out.mkdir(parents=True, exist_ok=True)
        (out / "findings.json").write_text(json.dumps({k: [f.to_dict() for f in v] for k, v in results.items()}, indent=2))
        eps = sorted({f.value for f in results["endpoints"]})
        (out / "endpoints.txt").write_text("\n".join(eps) + ("\n" if eps else ""))
        words = sorted({f.value for f in results["params"]} | ParamHarvester.from_endpoints(results["endpoints"]))
        (out / "wordlist.txt").write_text("\n".join(words) + ("\n" if words else ""))
        lines = ["# Arsenal report", ""]
        if dump:
            lines += [
                f"- JS files saved: {sum(1 for s in dump.saved if not s.duplicate_of)} (duplicates: {sum(1 for s in dump.saved if s.duplicate_of)})",
                f"- Third-party scripts seen: {len(set(dump.third_party))}",
                f"- Skipped: {len(dump.skipped)}  Errors: {len(dump.errors)}",
                "",
            ]
        sec = [f for f in results["secrets"]]
        lines.append(f"## Secrets ({len(sec)})")
        lines += [f"- [{f.severity}] {f.note}: `{f.value}` ({Path(f.file).name}:{f.line})" for f in sec] or ["- none"]
        low = [f for f in results["endpoints"] if f.severity != "info"]
        lines += ["", f"## Interesting endpoints ({len(low)})"]
        lines += [f"- `{f.value}` ({Path(f.file).name}:{f.line})" for f in low] or ["- none"]
        lines += ["", f"Total endpoints: {len(eps)} -> endpoints.txt. Wordlist: {len(words)} -> wordlist.txt"]
        if dump and dump.third_party:
            lines += ["", "## Third-party scripts"] + [f"- {u}" for u in sorted(set(dump.third_party))]
        (out / "report.md").write_text("\n".join(lines) + "\n")


class Engagement:
    """Orchestrates dump -> sourcemap recovery -> analysis for one target set."""

    def __init__(self, targets: list[str], out: Path, client: HttpClient, scope: ScopeGuard, **dump_opts):
        self.targets, self.out = targets, Path(out)
        self.client, self.scope, self.dump_opts = client, scope, dump_opts

    def dump(self, log=print) -> DumpResult:
        store = OutputStore(self.out / "js")
        return JSDumper(self.client, store, self.scope, log=log, **self.dump_opts).run(self.targets)

    def full(self, reveal: bool = False, log=print):
        res = self.dump(log)
        rec = SourceMapRecovery(self.out / "sources")
        n = rec.recover_dir(self.out / "js")
        log(f"[maps] recovered {n} original source files")
        findings = Analyzer(reveal).run(self.out / "js")
        if n:
            sources = Analyzer(reveal).run(self.out / "sources")
            for k in findings:
                findings[k] += sources[k]
        Analyzer.write_reports(self.out, findings, res)
        return res, findings
