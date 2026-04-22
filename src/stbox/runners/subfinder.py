"""subfinder — passive subdomain enumeration via 30+ public sources.

Pure passive: no DNS bruteforce, no active probing. Only queries public
aggregators (crt.sh, certspotter, anubis, hackertarget, etc.). No API keys
needed for the free sources.
"""

from __future__ import annotations

import json
from typing import Sequence

from stbox.models import Finding, Severity
from stbox.runners.base import BaseRunner
from stbox.scope import extract_host


class SubfinderRunner(BaseRunner):
    name = "subfinder"
    binary = "subfinder"

    def build_cmd(self, target: str, **kwargs) -> Sequence[str]:
        host = extract_host(target)
        return [
            self.binary,
            "-d", host,
            "-silent",
            "-all",       # query all free sources
            "-json",
            "-timeout", "30",
        ]

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        """subfinder emits one JSON record per subdomain. We return an INFO
        finding per unique host — the orchestrator consumes these into
        scan_result.subdomains.
        """
        seen: set[str] = set()
        out: list[Finding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                # Legacy non-JSON lines — plain hostnames.
                host = line
            else:
                try:
                    rec = json.loads(line)
                    host = (rec.get("host") or "").strip()
                except json.JSONDecodeError:
                    continue
            if not host or host in seen:
                continue
            seen.add(host)
            out.append(
                Finding(
                    tool="subfinder",
                    severity=Severity.INFO,
                    title=f"Subdomain discovered: {host}",
                    target=host,
                    tags=["recon", "subdomain"],
                    evidence={"source": "subfinder-passive"},
                )
            )
        return out
