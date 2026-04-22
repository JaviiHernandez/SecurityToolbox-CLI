"""Nuclei — ProjectDiscovery template-based scanner.

Passive mode: only exposure / tech / misconfiguration templates, no bruteforce
or fuzzing. `-severity info,low,medium,high,critical` is kept wide so the user
sees what's there; the mode gate restricts tags, not severity.
"""

from __future__ import annotations

import json
from typing import Sequence

from stbox.models import Finding, Severity
from stbox.runners.base import BaseRunner


_SEVERITY_MAP = {
    "info": Severity.INFO,
    "unknown": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class NucleiRunner(BaseRunner):
    name = "nuclei"
    binary = "nuclei"

    def __init__(self, cfg, mode: str = "passive"):
        super().__init__(cfg)
        self.mode = mode

    def build_cmd(self, target: str, **kwargs) -> Sequence[str]:
        cmd: list[str] = [
            self.binary,
            "-target", target,
            "-jsonl",
            "-silent",
            "-no-color",
            "-disable-update-check",
            "-rate-limit", str(int(self.cfg.rate_limit_rps)),
            "-timeout", "10",
            "-retries", "1",
        ]

        if self.mode == "passive":
            # Passive tag selection — no fuzzing, no bruteforce, no intrusive.
            cmd += [
                "-tags", "exposure,tech,misconfig,cve,default-login,panel,oast",
                "-severity", "info,low,medium,high,critical",
                "-exclude-tags", "fuzz,intrusive,dos,bruteforce,intrude",
            ]
        elif self.mode == "standard":
            cmd += [
                "-tags", "exposure,tech,misconfig,cve,default-login,panel,oast,seclists",
                "-severity", "low,medium,high,critical",
                "-exclude-tags", "fuzz,dos,bruteforce",
            ]
        else:  # active
            cmd += [
                "-severity", "low,medium,high,critical",
                # No tag restrictions. User explicitly asked for active.
            ]

        return cmd

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        out: list[Finding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = ev.get("info", {}) or {}
            severity_raw = (info.get("severity") or "info").lower()
            severity = _SEVERITY_MAP.get(severity_raw, Severity.INFO)

            cls = info.get("classification", {}) or {}
            cves = cls.get("cve-id") or []
            if isinstance(cves, str):
                cves = [cves]
            cwes = cls.get("cwe-id") or []
            if isinstance(cwes, str):
                cwes = [cwes]

            cvss = cls.get("cvss-score")
            if isinstance(cvss, str):
                try:
                    cvss = float(cvss)
                except ValueError:
                    cvss = None

            refs = info.get("reference") or []
            if isinstance(refs, str):
                refs = [refs]

            matched = ev.get("matched-at") or ev.get("host") or target

            out.append(
                Finding(
                    tool="nuclei",
                    severity=severity,
                    title=info.get("name") or ev.get("template-id") or "nuclei finding",
                    description=info.get("description") or "",
                    target=matched,
                    cve=cves,
                    cwe=cwes,
                    cvss=cvss,
                    references=refs,
                    tags=info.get("tags", []) if isinstance(info.get("tags"), list) else [],
                    evidence={
                        "template-id": ev.get("template-id"),
                        "template-path": ev.get("template-path"),
                        "matcher-name": ev.get("matcher-name"),
                        "extracted-results": ev.get("extracted-results"),
                        "request": ev.get("request"),
                        "response": ev.get("response"),
                    },
                )
            )
        return out
