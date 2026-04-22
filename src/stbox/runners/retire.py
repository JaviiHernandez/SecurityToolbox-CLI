"""retire.js — outdated JS library scanner.

Runs against a URL and produces a list of detected JS libraries with CVEs.
Pure passive: downloads JS files and checks hashes/version regex against
RetireJS's offline database. No payloads sent.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

from stbox.models import Finding, Severity
from stbox.runners.base import BaseRunner


_SEV = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class RetireRunner(BaseRunner):
    name = "retire"
    binary = "retire"

    def build_cmd(self, target: str, **kwargs) -> Sequence[str]:
        out_file = self.log_dir / f"retire-{abs(hash(target))}.json"
        self._out_file = out_file
        return [
            self.binary,
            "--outputformat", "json",
            "--outputpath", str(out_file),
            "--exitwith", "0",
            "--url", target,
        ]

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        out: list[Finding] = []
        p: Path | None = getattr(self, "_out_file", None)
        if not p or not p.exists():
            return out
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            return out

        # retire-cli emits: { "data": [ { "file": ..., "results": [...] } ] }
        records = data.get("data") if isinstance(data, dict) else data
        if not isinstance(records, list):
            return out

        for rec in records:
            for comp in rec.get("results", []) or []:
                name = comp.get("component", "unknown")
                version = comp.get("version", "?")
                for v in comp.get("vulnerabilities", []) or []:
                    sev = _SEV.get((v.get("severity") or "medium").lower(), Severity.MEDIUM)
                    cves = []
                    identifiers = v.get("identifiers") or {}
                    if isinstance(identifiers.get("CVE"), list):
                        cves = identifiers["CVE"]
                    summary = (
                        identifiers.get("summary")
                        or v.get("info", [""])[0]
                        or f"{name} {version}"
                    )
                    out.append(
                        Finding(
                            tool="retire",
                            severity=sev,
                            title=f"Outdated JS library: {name} {version} — {summary}"[:200],
                            description=summary,
                            target=rec.get("file") or target,
                            cve=cves,
                            references=v.get("info") or [],
                            tags=["js-library", "outdated"],
                            evidence={
                                "component": name,
                                "version": version,
                                "file": rec.get("file"),
                                "below": v.get("below"),
                                "atOrAbove": v.get("atOrAbove"),
                            },
                        )
                    )
        return out
