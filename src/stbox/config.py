"""Runtime configuration: timeouts, rate limits, paths, env overrides."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    """Global runtime configuration.

    All knobs can be overridden via environment variables prefixed STBOX_*.
    """

    # Per-tool timeout (seconds). Tools that exceed this are killed.
    tool_timeout: int = 300

    # Concurrency cap for parallel async tasks (HTTP probes etc.).
    max_concurrency: int = 25

    # Max requests per second when we do our own HTTP probing.
    rate_limit_rps: float = 10.0

    # User-Agent for our own HTTP probes.
    user_agent: str = (
        "Mozilla/5.0 (X11; Linux x86_64) SecurityToolbox-CLI/0.1 "
        "(+https://github.com/JaviiHernandez/SecurityToolbox-CLI)"
    )

    # Where to dump raw tool outputs.
    workdir: Path = Path.cwd() / "stbox-runs"

    # If False, tools that cannot find their binary on $PATH are skipped
    # with a warning instead of aborting the scan.
    strict_binaries: bool = False

    @classmethod
    def from_env(cls) -> Config:
        return cls(
            tool_timeout=int(os.getenv("STBOX_TOOL_TIMEOUT", "300")),
            max_concurrency=int(os.getenv("STBOX_MAX_CONCURRENCY", "25")),
            rate_limit_rps=float(os.getenv("STBOX_RATE_LIMIT_RPS", "10")),
            user_agent=os.getenv("STBOX_USER_AGENT", cls.user_agent),
            workdir=Path(os.getenv("STBOX_WORKDIR", str(cls.workdir))),
            strict_binaries=os.getenv("STBOX_STRICT_BINARIES", "0") == "1",
        )


def which(binary: str) -> str | None:
    """Return absolute path to `binary` on $PATH, or None."""
    return shutil.which(binary)


# Canonical names we look for on $PATH. Kept in one place so the install
# scripts and the runners agree.
TOOL_BINARIES = {
    "nuclei": "nuclei",
    "katana": "katana",
    "subfinder": "subfinder",
    "httpx": "httpx",
    "nikto": "nikto",
    "wpscan": "wpscan",
    "arjun": "arjun",
    "dalfox": "dalfox",
    "sqlmap": "sqlmap",
    "feroxbuster": "feroxbuster",
    "retire": "retire",
}
