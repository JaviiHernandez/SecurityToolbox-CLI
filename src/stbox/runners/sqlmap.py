"""SQLmap — SQL injection scanner. ACTIVE ONLY.

We invoke sqlmap with `--batch --level=3 --risk=2` on a specific URL (not a
blind crawl). The orchestrator only instantiates this runner when
--i-have-permission is passed AND Arjun surfaced parameters worth testing.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Sequence

from stbox.models import Finding, Severity
from stbox.runners.base import BaseRunner


class SqlmapRunner(BaseRunner):
    name = "sqlmap"
    binary = "sqlmap"

    def build_cmd(self, target: str, **kwargs) -> Sequence[str]:
        out_dir = self.log_dir / f"sqlmap-{abs(hash(target))}"
        self._out_dir = out_dir
        return [
            self.binary,
            "-u", target,
            "--batch",
            "--level=3",
            "--risk=2",
            "--random-agent",
            "--output-dir", str(out_dir),
            "--timeout", "15",
            "--retries", "1",
            "--flush-session",
            "--disable-coloring",
            # Keep it reasonably quiet so we don't get banned.
            "--threads=2",
            "--delay=1",
        ]

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        out: list[Finding] = []
        blob = stdout + "\n" + stderr

        # SQLmap's friendly text output — look for the "is vulnerable" banner.
        m = re.search(
            r"Parameter:\s*(\S+).*?Type:\s*([^\n]+).*?Title:\s*([^\n]+)",
            blob, re.DOTALL,
        )
        if m:
            param, typ, title = m.group(1), m.group(2).strip(), m.group(3).strip()
            out.append(
                Finding(
                    tool="sqlmap",
                    severity=Severity.CRITICAL,
                    title=f"SQL injection: {title}",
                    description=f"Parameter {param!r} is injectable ({typ})",
                    target=target,
                    cwe=["CWE-89"],
                    tags=["sqli", "active"],
                    evidence={"parameter": param, "technique": typ, "title": title},
                )
            )

        # Also flag any "back-end DBMS:" disclosure even without confirmed SQLi.
        m2 = re.search(r"back-end DBMS:\s*([^\n]+)", blob)
        if m2 and not out:
            out.append(
                Finding(
                    tool="sqlmap",
                    severity=Severity.INFO,
                    title=f"Back-end DBMS fingerprint: {m2.group(1).strip()}",
                    target=target,
                    tags=["sqli", "fingerprint"],
                    evidence={"dbms": m2.group(1).strip()},
                )
            )
        return out
