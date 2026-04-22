"""Medusa — alternative credential brute force on HTTP forms.

Similar to hydra but with different threading model and occasionally
more reliable on tricky WAF-fronted forms. Same safety story: requires
--i-have-permission AND explicit form parameters.

For HTTP-POST forms Medusa uses the `web-form` module with syntax:
  -M web-form -m FORM:<path> -m DENY-SIGNAL:<failure_text> -m FORM-DATA:post?<body>

Note: Medusa is less configurable than hydra for web forms — we use it
as a secondary when hydra gets blocked/fingerprinted.
"""

from __future__ import annotations

import re
from typing import Sequence
from urllib.parse import urlparse

from stbox.models import Finding, Severity
from stbox.runners.base import BaseRunner


class MedusaRunner(BaseRunner):
    name = "medusa"
    binary = "medusa"

    def build_cmd(
        self,
        target: str,
        *,
        form_path: str | None = None,
        form_body: str | None = None,
        failure_text: str | None = None,
        user_field: str = "user",
        pass_field: str = "pass",
        **kwargs,
    ) -> Sequence[str]:
        if not (form_path and form_body and failure_text):
            raise ValueError(
                "medusa runner needs form_path, form_body, failure_text"
            )
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"medusa: only HTTP(S), got {target!r}")

        module = "web-form"
        # Medusa wants the body with markers, and a "USER-AGENT"
        # style replacement for user/pass positions.
        body_with_markers = (
            form_body
            .replace("^USER^", f"^USER^")
            .replace("^PASS^", f"^PASS^")
        )

        return [
            self.binary,
            "-h", parsed.hostname or "",
            "-n", str(parsed.port or (443 if parsed.scheme == "https" else 80)),
            "-s" if parsed.scheme == "https" else "-S",  # -s = SSL
            "-U", str(self.cfg.wl_usernames),
            "-P", str(self.cfg.wl_passwords),
            "-M", module,
            "-m", f"FORM:{form_path}",
            "-m", f"DENY-SIGNAL:{failure_text}",
            "-m", f"FORM-DATA:post?{body_with_markers}",
            "-t", "4",
            "-f",              # stop after first success per host
            "-O", "/dev/stdout",
        ]

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        out: list[Finding] = []
        # Medusa success lines:
        #   ACCOUNT FOUND: [web-form] Host: host User: admin Password: hunter2 [SUCCESS]
        line_re = re.compile(
            r"ACCOUNT FOUND.*?Host:\s*(\S+)\s+User:\s*(\S+)\s+Password:\s*(\S+)",
            re.IGNORECASE,
        )
        for line in stdout.splitlines():
            m = line_re.search(line)
            if not m:
                continue
            host, user, passwd = m.group(1), m.group(2), m.group(3)
            out.append(
                Finding(
                    tool="medusa",
                    severity=Severity.CRITICAL,
                    title=f"Weak login credentials: {user}:{passwd} @ {host}",
                    description=(
                        "Medusa confirmed valid credentials. Rotate the "
                        "password, enforce minimum-length policy and add "
                        "2FA or login rate-limiting."
                    ),
                    target=target,
                    cwe=["CWE-521", "CWE-798"],
                    tags=["brute-force", "weak-creds", "auth"],
                    evidence={"host": host, "username": user, "password": passwd},
                )
            )
        return out
