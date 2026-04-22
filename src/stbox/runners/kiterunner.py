"""kiterunner (`kr`) — API endpoint brute force.

Kiterunner uses `.kite` wordlists (compiled bundles of Swagger/OpenAPI
routes harvested from public API specs) to discover HTTP API endpoints
that wouldn't be found by regular directory brute force. The killer
feature: it sends the correct method + Content-Type + sample body per
route, so an API expecting `POST /api/v1/users` with JSON gets a JSON
body instead of an empty GET.

Output is tab-separated:
   GET     200     [123,     45,    2]  https://target/api/v1/healthz
"""

from __future__ import annotations

import re
from typing import Sequence
from urllib.parse import urlparse

from stbox.models import Finding, Severity
from stbox.runners.base import BaseRunner


# Line format: METHOD  STATUS  [LEN, WORDS, LINES]  URL
_ROW_RE = re.compile(
    r"^\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+"
    r"(\d{3})\s+"
    r"\[[^\]]+\]\s+"
    r"(https?://\S+)",
    re.IGNORECASE,
)


class KiterunnerRunner(BaseRunner):
    name = "kiterunner"
    binary = "kr"

    def build_cmd(
        self,
        target: str,
        *,
        kite_file: str | None = None,
        **kwargs,
    ) -> Sequence[str]:
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"kiterunner: only HTTP(S), got {target!r}")

        kite = kite_file or str(self.cfg.wl_kite)
        return [
            self.binary,
            "scan",
            target,
            "-w", kite,
            "--fail-status-codes", "400,401,403,404,405,500,502,503",
            "-j", "10",              # 10 concurrent targets (we only give 1)
            "--max-timeout", "5s",
            "-o", "text",
        ]

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        out: list[Finding] = []
        for line in stdout.splitlines():
            m = _ROW_RE.match(line)
            if not m:
                continue
            method, status_str, url = m.group(1).upper(), m.group(2), m.group(3)
            status = int(status_str)
            # A 200 on an API route is the golden hit. 3xx + 2xx-other also
            # interesting. Kiterunner's --fail-status-codes should have
            # filtered out 404/401 etc., so anything left is a candidate.
            if status in (200, 201):
                severity = Severity.MEDIUM
            elif 300 <= status < 400:
                severity = Severity.LOW
            else:
                severity = Severity.INFO
            out.append(
                Finding(
                    tool="kiterunner",
                    severity=severity,
                    title=f"API route: {method} {url} → HTTP {status}",
                    description=(
                        f"kiterunner found an undocumented API route. "
                        f"Method {method}, status {status}. These come from "
                        f"public OpenAPI/Swagger collections — if it hits "
                        f"here and isn't in your API docs, you have forgotten "
                        f"endpoints."
                    ),
                    target=url,
                    tags=["api", "discovery", method.lower(), f"status-{status}"],
                    evidence={"method": method, "status": status, "url": url},
                )
            )
        return out
