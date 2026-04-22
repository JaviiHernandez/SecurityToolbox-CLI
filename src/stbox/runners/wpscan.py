"""wpscan — WordPress scanner. Only invoked when tech fingerprint detects WP.

Default flags keep it passive: version + users + plugins enumeration, no
password bruteforce. Active mode can add `--enumerate u --passwords ...` if
the caller explicitly allows it.
"""

from __future__ import annotations

import json
import os
from typing import Sequence

from stbox.models import Finding, Severity
from stbox.runners.base import BaseRunner


_SEV = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class WpscanRunner(BaseRunner):
    name = "wpscan"
    binary = "wpscan"

    def __init__(self, cfg, active: bool = False):
        super().__init__(cfg)
        self.active = active

    def build_cmd(self, target: str, **kwargs) -> Sequence[str]:
        cmd: list[str] = [
            self.binary,
            "--url", target,
            "--format", "json",
            "--no-banner",
            "--disable-tls-checks",
            "--random-user-agent",
            "--max-threads", "5",
        ]

        api_token = os.getenv("WPSCAN_API_TOKEN")
        if api_token:
            cmd += ["--api-token", api_token]

        # Enumeration: versions, plugins popular, themes popular, users
        cmd += ["--enumerate", "vp,vt,u,dbe"]

        if self.active:
            cmd += ["--plugins-detection", "aggressive"]
        else:
            cmd += ["--plugins-detection", "passive"]

        return cmd

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return []
        out: list[Finding] = []

        wp = (data.get("version") or {})
        if wp.get("vulnerabilities"):
            for vuln in wp["vulnerabilities"]:
                out.append(self._vuln_to_finding("WordPress core", vuln, target))

        for plugin_slug, pdata in (data.get("plugins") or {}).items():
            for vuln in pdata.get("vulnerabilities", []) or []:
                out.append(self._vuln_to_finding(f"plugin {plugin_slug}", vuln, target))

        for theme_slug, tdata in (data.get("themes") or {}).items():
            for vuln in tdata.get("vulnerabilities", []) or []:
                out.append(self._vuln_to_finding(f"theme {theme_slug}", vuln, target))

        for user in (data.get("users") or {}):
            out.append(
                Finding(
                    tool="wpscan",
                    severity=Severity.LOW,
                    title=f"WordPress user enumerated: {user}",
                    target=target,
                    tags=["wordpress", "enum", "user"],
                    evidence={"user": user},
                )
            )
        return out

    @staticmethod
    def _vuln_to_finding(prefix: str, vuln: dict, target: str) -> Finding:
        refs = []
        for k in ("cve", "secunia", "exploitdb", "metasploit", "url"):
            v = (vuln.get("references") or {}).get(k)
            if isinstance(v, list):
                refs.extend(v)
            elif isinstance(v, str):
                refs.append(v)
        cves = [r for r in refs if str(r).startswith("CVE-")]
        return Finding(
            tool="wpscan",
            severity=_SEV.get((vuln.get("severity") or "medium").lower(), Severity.MEDIUM),
            title=f"[{prefix}] {vuln.get('title', 'WP vulnerability')}",
            description=vuln.get("fixed_in", "") or "",
            target=target,
            cve=cves,
            references=[r for r in refs if not str(r).startswith("CVE-")],
            tags=["wordpress"],
            evidence=vuln,
        )
