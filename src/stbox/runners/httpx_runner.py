"""httpx — ProjectDiscovery liveness / fingerprinting probe.

Given a list of hosts (from subfinder or passive sources), returns which
ones respond and what tech headers they expose. Pure HEAD/GET probes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

from stbox.models import Finding, Severity
from stbox.runners.base import BaseRunner


class HttpxRunner(BaseRunner):
    name = "httpx"
    binary = "httpx"

    async def run_list(self, hosts: list[str]) -> tuple[list[str], dict[str, dict]]:
        """Probe every host, return (live_hosts, per_host_metadata)."""
        if not hosts:
            return [], {}

        # Write hosts to a temp file so we don't hit command-line length limits.
        inp = self.log_dir / "httpx-input.txt"
        inp.write_text("\n".join(hosts) + "\n", encoding="utf-8")

        run, findings = await self.run(str(inp))

        live: list[str] = []
        meta: dict[str, dict] = {}
        for f in findings:
            live.append(f.target)
            meta[f.target] = f.evidence
        return live, meta

    def build_cmd(self, target: str, **kwargs) -> Sequence[str]:
        return [
            self.binary,
            "-l", target,                 # target here is path to file
            "-json",
            "-silent",
            "-no-color",
            "-timeout", "10",
            "-rate-limit", str(int(self.cfg.rate_limit_rps)),
            "-follow-redirects",
            "-tech-detect",
            "-title",
            "-status-code",
            "-server",
            "-ip",
            "-cname",
            "-web-server",
        ]

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        out: list[Finding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = rec.get("url") or rec.get("input") or ""
            out.append(
                Finding(
                    tool="httpx",
                    severity=Severity.INFO,
                    title=f"Live host: {url} [{rec.get('status_code')}] {rec.get('title', '')}".strip(),
                    target=url,
                    tags=["recon", "httpx"],
                    evidence={
                        "status_code": rec.get("status_code"),
                        "title": rec.get("title"),
                        "tech": rec.get("tech") or rec.get("technologies"),
                        "server": rec.get("server") or rec.get("webserver"),
                        "ip": rec.get("host") or rec.get("a"),
                        "cname": rec.get("cname"),
                        "content_length": rec.get("content_length"),
                        "content_type": rec.get("content_type"),
                    },
                )
            )
        return out
