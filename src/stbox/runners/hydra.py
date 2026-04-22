"""Hydra — credential brute force on HTTP forms. ACTIVE ONLY.

Hydra fires a real login payload per iteration. It's a textbook "active"
tool and the orchestrator only instantiates it when --i-have-permission
was explicitly passed.

We focus on the `http-post-form` / `https-post-form` modules, which is
99% of what users actually need (login.php-style endpoints). Other
Hydra targets (SSH, FTP, SMB, POP3, …) are out of scope for a WEB
security scanner — that's network penetration, not our remit.

The caller must provide:
  - form_path: "/login.php"     path with the login form
  - form_body: "user=^USER^&pass=^PASS^"  post body with hydra markers
  - failure_text: e.g. "Invalid credentials" — success is "marker NOT present"

If form_path / form_body / failure_text are omitted we SKIP the run
(we refuse to guess because a bad guess generates hundreds of spurious
login attempts against the target).
"""

from __future__ import annotations

import re
from typing import Sequence
from urllib.parse import urlparse

from stbox.models import Finding, Severity
from stbox.runners.base import BaseRunner


class HydraRunner(BaseRunner):
    name = "hydra"
    binary = "hydra"

    def build_cmd(
        self,
        target: str,
        *,
        form_path: str | None = None,
        form_body: str | None = None,
        failure_text: str | None = None,
        **kwargs,
    ) -> Sequence[str]:
        if not (form_path and form_body and failure_text):
            raise ValueError(
                "hydra runner needs form_path, form_body, failure_text — "
                "refusing to fire blind."
            )
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"hydra: only HTTP(S) supported, got {target!r}")
        host = parsed.netloc
        module = "https-post-form" if parsed.scheme == "https" else "http-post-form"

        # Hydra's form string: <path>:<body>:F=<failure_needle>
        form_string = f"{form_path}:{form_body}:F={failure_text}"

        return [
            self.binary,
            "-L", str(self.cfg.wl_usernames),
            "-P", str(self.cfg.wl_passwords),
            "-s", str(parsed.port or (443 if parsed.scheme == "https" else 80)),
            "-t", "4",                 # 4 concurrent (not 16+ — we're polite)
            "-W", "2",                 # 2s wait between req per thread
            "-I",                      # ignore existing restore file
            "-o", "/dev/stdout",
            host,
            module,
            form_string,
        ]

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        out: list[Finding] = []
        # Hydra success lines look like:
        #   [80][http-post-form] host: example.com   login: admin   password: hunter2
        line_re = re.compile(
            r"\[\d+\]\[[^\]]+\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)",
            re.IGNORECASE,
        )
        for line in stdout.splitlines():
            m = line_re.search(line)
            if not m:
                continue
            host, user, passwd = m.group(1), m.group(2), m.group(3)
            out.append(
                Finding(
                    tool="hydra",
                    severity=Severity.CRITICAL,
                    title=f"Weak login credentials: {user}:{passwd} @ {host}",
                    description=(
                        "Hydra confirmed valid credentials against this login "
                        "form. These credentials are either from the "
                        "top-10k-most-common list (weak) or a known default. "
                        "Rotate the password, enforce a minimum length "
                        "policy, and add 2FA or rate-limiting on the login "
                        "endpoint."
                    ),
                    target=target,
                    cwe=["CWE-521", "CWE-798"],  # weak password / hardcoded creds
                    tags=["brute-force", "weak-creds", "auth"],
                    evidence={
                        "host": host,
                        "username": user,
                        "password": passwd,
                    },
                )
            )
        return out
