"""Nikto — legacy web server scanner. Noisy but still surfaces real issues
on older Apache/IIS/CGI stacks that modern scanners miss.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

from stbox.models import Finding, Severity
from stbox.runners.base import BaseRunner


_SEVERITY_KEYWORDS = [
    ("critical", Severity.CRITICAL),
    ("remote code", Severity.CRITICAL),
    ("sql injection", Severity.HIGH),
    ("xss", Severity.MEDIUM),
    ("directory traversal", Severity.HIGH),
    ("default", Severity.MEDIUM),
    ("disclosure", Severity.MEDIUM),
    ("outdated", Severity.MEDIUM),
    ("vulnerable", Severity.MEDIUM),
]


def _severity_from_text(text: str) -> Severity:
    lower = text.lower()
    for kw, sev in _SEVERITY_KEYWORDS:
        if kw in lower:
            return sev
    return Severity.LOW


class NiktoRunner(BaseRunner):
    name = "nikto"
    binary = "nikto"

    def build_cmd(self, target: str, **kwargs) -> Sequence[str]:
        out_file = self.log_dir / f"nikto-{abs(hash(target))}.json"
        self._out_file = out_file  # stash for parse()
        return [
            self.binary,
            "-h", target,
            "-Format", "json",
            "-output", str(out_file),
            "-ask", "no",
            "-maxtime", str(self.cfg.tool_timeout - 10),
            "-Tuning", "x 6",    # skip DoS category
            "-nointeractive",
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

        for host in (data if isinstance(data, list) else [data]):
            for v in host.get("vulnerabilities", []) or []:
                title = v.get("msg") or v.get("description") or "Nikto finding"
                out.append(
                    Finding(
                        tool="nikto",
                        severity=_severity_from_text(title),
                        title=title[:200],
                        description=v.get("description", "") or "",
                        target=host.get("host") or target,
                        references=[v.get("references", "")] if v.get("references") else [],
                        tags=["nikto", "legacy"],
                        evidence={
                            "method": v.get("method"),
                            "url": v.get("url"),
                            "id": v.get("id"),
                            "osvdb": v.get("OSVDB"),
                        },
                    )
                )
        return out
