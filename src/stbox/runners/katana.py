"""katana — ProjectDiscovery next-gen crawler.

Used in `standard` mode to discover endpoints. Depth is capped to keep
scans bounded; JS parsing is enabled so SPA routes are surfaced.
"""

from __future__ import annotations

import json
from typing import Sequence

from stbox.models import Finding, Severity
from stbox.runners.base import BaseRunner


class KatanaRunner(BaseRunner):
    name = "katana"
    binary = "katana"

    def build_cmd(self, target: str, **kwargs) -> Sequence[str]:
        return [
            self.binary,
            "-u", target,
            "-jc",                        # parse JS for endpoints
            "-silent",
            "-jsonl",
            "-depth", "3",
            "-timeout", "10",
            "-rate-limit", str(int(self.cfg.rate_limit_rps)),
            "-concurrency", "10",
            "-headless=false",
        ]

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        out: list[Finding] = []
        seen: set[str] = set()
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            req = rec.get("request") or {}
            endpoint = req.get("endpoint") or req.get("url") or rec.get("endpoint")
            if not endpoint or endpoint in seen:
                continue
            seen.add(endpoint)
            out.append(
                Finding(
                    tool="katana",
                    severity=Severity.INFO,
                    title=f"Endpoint: {endpoint}",
                    target=endpoint,
                    tags=["recon", "crawl"],
                    evidence={
                        "method": req.get("method"),
                        "source": req.get("source"),
                        "status_code": (rec.get("response") or {}).get("status_code"),
                    },
                )
            )
        return out
