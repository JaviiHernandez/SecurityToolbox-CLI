"""Dalfox — XSS scanner. ACTIVE ONLY.

Dalfox injects payloads by design; it cannot be run passively. The
orchestrator refuses to instantiate this runner unless --i-have-permission
was passed.
"""

from __future__ import annotations

import json
from typing import Sequence

from stbox.models import Finding, Severity
from stbox.runners.base import BaseRunner


class DalfoxRunner(BaseRunner):
    name = "dalfox"
    binary = "dalfox"

    def build_cmd(self, target: str, **kwargs) -> Sequence[str]:
        return [
            self.binary,
            "url", target,
            "--format", "json",
            "--silence",
            "--timeout", "10",
            "--delay", str(int(1000 / max(self.cfg.rate_limit_rps, 1))),
            "--worker", "5",
            "--skip-bav",            # skip basic auth vuln checks
            "--skip-mining-dict",    # already handled by arjun
        ]

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        out: list[Finding] = []
        # Dalfox emits JSON-lines. Each finding is one JSON object.
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            severity_raw = (rec.get("severity") or "medium").lower()
            sev_map = {
                "info": Severity.INFO,
                "low": Severity.LOW,
                "medium": Severity.MEDIUM,
                "high": Severity.HIGH,
                "critical": Severity.CRITICAL,
            }
            out.append(
                Finding(
                    tool="dalfox",
                    severity=sev_map.get(severity_raw, Severity.MEDIUM),
                    title=f"XSS: {rec.get('type', 'reflected')} via {rec.get('param', '?')}",
                    description=rec.get("message_str", "") or rec.get("message", ""),
                    target=rec.get("data") or rec.get("url") or target,
                    cwe=["CWE-79"],
                    tags=["xss", "active"],
                    evidence={
                        "payload": rec.get("payload"),
                        "param": rec.get("param"),
                        "type": rec.get("type"),
                        "poc": rec.get("poc") or rec.get("poc-type"),
                    },
                )
            )
        return out
