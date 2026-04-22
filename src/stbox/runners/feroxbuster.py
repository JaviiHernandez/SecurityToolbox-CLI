"""feroxbuster — fast recursive content discovery.

Only used in `active` mode with a reasonably sized wordlist. We cap depth
+ requests to avoid getting banned and to keep scans bounded.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

from stbox.models import Finding, Severity
from stbox.runners.base import BaseRunner


class FeroxbusterRunner(BaseRunner):
    name = "feroxbuster"
    binary = "feroxbuster"

    def __init__(self, cfg, wordlist: str | None = None):
        super().__init__(cfg)
        self.wordlist = wordlist or "/usr/share/seclists/Discovery/Web-Content/common.txt"

    def build_cmd(self, target: str, **kwargs) -> Sequence[str]:
        out_file = self.log_dir / f"ferox-{abs(hash(target))}.json"
        self._out_file = out_file
        return [
            self.binary,
            "--url", target,
            "--wordlist", self.wordlist,
            "--depth", "2",
            "--threads", "10",
            "--rate-limit", str(int(self.cfg.rate_limit_rps * 10)),  # it's per-thread
            "--json",
            "--output", str(out_file),
            "--silent",
            "--no-state",
            "--status-codes", "200,204,301,302,307,401,403",
            "--timeout", "10",
            "--quiet",
        ]

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        out: list[Finding] = []
        p: Path | None = getattr(self, "_out_file", None)
        if not p or not p.exists():
            return out
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("type") != "response":
                continue
            url = rec.get("url") or ""
            status = rec.get("status", 0)
            if not url:
                continue

            sev = Severity.INFO
            if status == 401 or status == 403:
                sev = Severity.LOW
            if any(k in url.lower() for k in (".git", ".env", "backup", "phpinfo", "adminer")):
                sev = Severity.HIGH

            out.append(
                Finding(
                    tool="feroxbuster",
                    severity=sev,
                    title=f"Discovered path [{status}]: {url}",
                    target=url,
                    tags=["content-discovery"],
                    evidence={
                        "status": status,
                        "size": rec.get("content_length"),
                        "wildcard": rec.get("wildcard"),
                    },
                )
            )
        return out
