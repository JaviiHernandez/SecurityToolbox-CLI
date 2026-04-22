"""Nuclei workflows runner — runs curated workflow YAMLs that CHAIN
templates together for classic exploit chains (SSRF → cloud metadata →
credentials, LFI → /etc/passwd → SSH key theft, etc.).

Workflows live in $STBOX_NUCLEI_WORKFLOWS (default /opt/stbox-workflows/)
and are shipped with the Docker image. Users can drop their own .yaml
files there.

A nuclei workflow looks like:
    workflows:
      - template: http/vulnerabilities/generic/ssrf-blind.yaml
        subtemplates:
          - template: http/exposures/tokens/generic/aws-access-key.yaml
          - template: http/exposures/tokens/generic/gcp-api-key.yaml

Only the subtemplates of the first matching parent run — drastically
cutting noise compared to "nuclei -t all/".
"""

from __future__ import annotations

import json
import os
from typing import Sequence

from stbox.models import Finding, Severity
from stbox.runners.base import BaseRunner


_SEV_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": Severity.INFO,
}


class NucleiWorkflowsRunner(BaseRunner):
    name = "nuclei-workflows"
    binary = "nuclei"

    def build_cmd(self, target: str, **kwargs) -> Sequence[str]:
        wf_dir = self.cfg.nuclei_workflows_dir
        if not wf_dir.exists():
            raise RuntimeError(
                f"nuclei workflows dir {wf_dir} does not exist — "
                "install stbox-workflows or set STBOX_NUCLEI_WORKFLOWS"
            )
        return [
            self.binary,
            "-target", target,
            "-w", str(wf_dir),            # -w loads workflows (not -t)
            "-jsonl", "-silent",
            "-timeout", "10",
            "-rate-limit", str(int(self.cfg.rate_limit_rps * 10)),
            "-severity", "low,medium,high,critical",
            "-no-color",
            "-stats-json",
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
            if not rec.get("template-id"):
                continue

            info = rec.get("info") or {}
            severity = _SEV_MAP.get((info.get("severity") or "info").lower(), Severity.INFO)
            name = info.get("name") or rec.get("template-id")
            classification = info.get("classification") or {}

            out.append(
                Finding(
                    tool="nuclei-workflows",
                    severity=severity,
                    title=f"[workflow] {name}",
                    description=info.get("description") or "",
                    target=rec.get("matched-at") or rec.get("host") or target,
                    cve=classification.get("cve-id") or [],
                    cwe=classification.get("cwe-id") or [],
                    cvss=classification.get("cvss-score"),
                    references=info.get("reference") or [],
                    tags=["nuclei", "workflow"] + (info.get("tags") or []),
                    evidence={
                        "template_id": rec.get("template-id"),
                        "workflow_path": rec.get("template-path"),
                        "matcher_name": rec.get("matcher-name"),
                        "extracted_results": rec.get("extracted-results"),
                        "request": rec.get("request"),
                    },
                )
            )
        return out
