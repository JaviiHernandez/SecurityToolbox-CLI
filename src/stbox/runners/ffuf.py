"""ffuf — fast generic web fuzzer.

Three modes supported by this runner:

  mode="path"   → fuzz the path segment:   https://host/FUZZ
  mode="param"  → fuzz a query-string key: https://host/?FUZZ=test
  mode="vhost"  → virtual-host fuzzing:    Host: FUZZ.domain.tld

All modes emit JSONL via `-of json -o - `. We parse stdout and convert
hits (non-baseline status codes) into Findings.

ACTIVE ONLY (fires many requests per second to the target).
"""

from __future__ import annotations

import json
from typing import Sequence
from urllib.parse import urlparse

from stbox.models import Finding, Severity
from stbox.runners.base import BaseRunner


_SEV_BY_STATUS = {
    200: Severity.LOW,     # interesting path
    301: Severity.LOW,
    302: Severity.LOW,
    401: Severity.LOW,     # auth-protected path discovered
    403: Severity.LOW,     # forbidden but exists
}


class FfufRunner(BaseRunner):
    name = "ffuf"
    binary = "ffuf"

    def build_cmd(
        self,
        target: str,
        *,
        mode: str = "path",
        wordlist: str | None = None,
        **kwargs,
    ) -> Sequence[str]:
        if mode not in ("path", "param", "vhost"):
            raise ValueError(f"ffuf: unsupported mode {mode!r}")
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"ffuf: only HTTP(S), got {target!r}")

        wl = wordlist or (
            str(self.cfg.wl_params) if mode == "param" else str(self.cfg.wl_content_small)
        )

        # Build the FUZZ URL depending on mode.
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if mode == "path":
            fuzz_url = f"{origin}/FUZZ"
        elif mode == "param":
            fuzz_url = f"{origin}{parsed.path or '/'}?FUZZ=test"
        else:  # vhost
            fuzz_url = origin + (parsed.path or "/")

        cmd: list[str] = [
            self.binary,
            "-u", fuzz_url,
            "-w", wl,
            "-mc", "200,204,301,302,307,401,403,405",  # interesting statuses
            "-t", "25",
            "-rate", str(int(self.cfg.rate_limit_rps * 10)),   # per-second cap
            "-maxtime", str(self.cfg.tool_timeout - 30),
            "-o", "-", "-of", "json",
            "-s",                      # silent: JSON only on stdout
        ]
        if mode == "vhost":
            cmd += ["-H", f"Host: FUZZ.{parsed.hostname or ''}"]
        return cmd

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            # ffuf in some versions prints non-JSON before/after — try to
            # locate the first "{" and parse from there.
            try:
                start = stdout.index("{")
                data = json.loads(stdout[start:])
            except (ValueError, json.JSONDecodeError):
                return []
        results = data.get("results") or []
        out: list[Finding] = []
        for r in results:
            status = r.get("status", 0)
            url = r.get("url", target)
            input_val = (r.get("input") or {}).get("FUZZ", "?")
            out.append(
                Finding(
                    tool="ffuf",
                    severity=_SEV_BY_STATUS.get(status, Severity.INFO),
                    title=f"ffuf hit: {input_val!r} → HTTP {status}",
                    description=(
                        f"ffuf discovered {url} returning HTTP {status}. "
                        "Investigate manually — interesting paths may be "
                        "admin panels, staging endpoints, or leftover dev "
                        "artefacts."
                    ),
                    target=url,
                    tags=["ffuf", "discovery", f"status-{status}"],
                    evidence={
                        "status": status,
                        "length": r.get("length"),
                        "words": r.get("words"),
                        "lines": r.get("lines"),
                        "input": input_val,
                    },
                )
            )
        return out
