"""Arjun — HTTP parameter discovery.

Semi-active: sends a curated wordlist of parameter names at each endpoint
and diffs the response. Only used in `standard` or `active` mode.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

from stbox.models import Finding, Severity
from stbox.runners.base import BaseRunner


class ArjunRunner(BaseRunner):
    name = "arjun"
    binary = "arjun"

    def build_cmd(self, target: str, **kwargs) -> Sequence[str]:
        out_file = self.log_dir / f"arjun-{abs(hash(target))}.json"
        self._out_file = out_file
        return [
            self.binary,
            "-u", target,
            "-oJ", str(out_file),
            "-t", "5",                 # threads
            "--stable",                # conservative, fewer false positives
            "-m", "GET",
            "--rate-limit", str(int(self.cfg.rate_limit_rps)),
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

        # arjun output format: { "<url>": { "params": [...], "method": "..." } }
        for url, info in (data.items() if isinstance(data, dict) else []):
            params = info.get("params", []) if isinstance(info, dict) else []
            for p_name in params:
                out.append(
                    Finding(
                        tool="arjun",
                        severity=Severity.INFO,
                        title=f"Hidden parameter discovered: {p_name}",
                        target=url,
                        tags=["param-discovery"],
                        evidence={"parameter": p_name, "method": info.get("method")},
                    )
                )
        return out
