"""wfuzz — older-school web fuzzer, kept as a secondary to ffuf.

Useful when the target fingerprints ffuf's User-Agent specifically or
when you want wfuzz's recursive mode. We only wrap path fuzzing here;
parameter fuzzing belongs to ffuf + arjun in this pipeline.
"""

from __future__ import annotations

import re
from typing import Sequence
from urllib.parse import urlparse

from stbox.models import Finding, Severity
from stbox.runners.base import BaseRunner


# Output row looks like:
#   000000034:   200      3 L      12 W       234 Ch      "admin"
_ROW_RE = re.compile(
    r"^\s*\d+:\s+(\d{3})\s+\d+\s+L\s+\d+\s+W\s+\d+\s+Ch\s+\"(.+?)\"\s*$"
)


class WfuzzRunner(BaseRunner):
    name = "wfuzz"
    binary = "wfuzz"

    def build_cmd(
        self,
        target: str,
        *,
        mode: str = "path",
        wordlist: str | None = None,
        **kwargs,
    ) -> Sequence[str]:
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"wfuzz: only HTTP(S), got {target!r}")

        wl = wordlist or str(self.cfg.wl_content_small)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if mode == "path":
            fuzz_url = f"{origin}/FUZZ"
        elif mode == "param":
            fuzz_url = f"{origin}{parsed.path or '/'}?FUZZ=test"
        else:
            raise ValueError(f"wfuzz: unsupported mode {mode!r}")

        return [
            self.binary,
            "-z", f"file,{wl}",
            "--hc", "404,500,503",      # hide noise status codes
            "-t", "20",
            "-s", str(1.0 / max(self.cfg.rate_limit_rps, 1)),  # per-req sleep
            fuzz_url,
        ]

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        out: list[Finding] = []
        for line in stdout.splitlines():
            m = _ROW_RE.match(line)
            if not m:
                continue
            status, value = int(m.group(1)), m.group(2)
            severity = Severity.LOW if status in (200, 301, 302, 401, 403) else Severity.INFO
            out.append(
                Finding(
                    tool="wfuzz",
                    severity=severity,
                    title=f"wfuzz hit: {value!r} → HTTP {status}",
                    target=target.rstrip("/") + "/" + value.lstrip("/"),
                    tags=["wfuzz", "discovery", f"status-{status}"],
                    evidence={"status": status, "value": value},
                )
            )
        return out
