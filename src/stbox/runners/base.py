"""Base class + shared subprocess helpers for every binary-backed runner."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from stbox.config import Config, which
from stbox.models import Finding, ToolRun
from stbox.utils import ensure_dir, run_cmd, safe_filename


logger = logging.getLogger("stbox.runner")


class BaseRunner:
    """Template for every tool wrapper.

    Subclasses set `name` + `binary` and override `build_cmd` + `parse`.
    If the binary is missing from $PATH the runner short-circuits with a
    skipped ToolRun (unless Config.strict_binaries is True).
    """

    name: str = ""
    binary: str = ""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.log_dir = ensure_dir(cfg.workdir / "logs")

    # ------------------------------------------------------------------ API

    def available(self) -> bool:
        return which(self.binary) is not None

    def build_cmd(self, target: str, **kwargs) -> Sequence[str]:
        raise NotImplementedError

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        raise NotImplementedError

    async def run(self, target: str, **kwargs) -> tuple[ToolRun, list[Finding]]:
        run = ToolRun(tool=self.name)

        if not self.available():
            run.status = "skipped"
            run.error = f"{self.binary!r} not found on PATH"
            if self.cfg.strict_binaries:
                raise RuntimeError(run.error)
            logger.warning("%s — %s", self.name, run.error)
            return run, []

        cmd = list(self.build_cmd(target, **kwargs))
        run.command = " ".join(cmd)
        run.status = "running"
        t0 = time.monotonic()

        exit_code, stdout, stderr = await run_cmd(
            cmd, timeout=self.cfg.tool_timeout
        )

        run.exit_code = exit_code
        run.duration_seconds = time.monotonic() - t0
        run.finished_at = datetime.now(timezone.utc)

        # Dump raw output for forensic review.
        base = safe_filename(f"{self.name}-{target}")
        run.stdout_path = self.log_dir / f"{base}.stdout.log"
        run.stderr_path = self.log_dir / f"{base}.stderr.log"
        run.stdout_path.write_text(stdout, encoding="utf-8")
        run.stderr_path.write_text(stderr, encoding="utf-8")

        if exit_code in (0, 1):  # many scanners exit 1 when findings exist
            try:
                findings = self.parse(stdout, stderr, target)
                run.findings_count = len(findings)
                run.status = "done"
                return run, findings
            except Exception as e:  # noqa: BLE001
                run.status = "failed"
                run.error = f"parser error: {e}"
                logger.exception("%s parser crashed", self.name)
                return run, []
        else:
            run.status = "failed"
            run.error = f"exit={exit_code}: {stderr.strip()[:500]}"
            return run, []
