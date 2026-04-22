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

    # --- Wordlists (SecLists layout under /usr/share/seclists) ---------------
    # Default locations inside the Docker image. Overridable via env vars when
    # running natively with SecLists at a different path (e.g. Kali ships it
    # at /usr/share/seclists too; Homebrew at /opt/homebrew/share/seclists).
    seclists_root: Path = Path("/usr/share/seclists")

    # Content / path brute force (ffuf, feroxbuster).
    wl_content_small: Path = Path("/usr/share/seclists/Discovery/Web-Content/common.txt")
    wl_content_big:   Path = Path("/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt")

    # Parameter fuzzing (ffuf, wfuzz).
    wl_params: Path = Path("/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt")

    # Credentials brute force (hydra, medusa).
    wl_usernames: Path = Path("/usr/share/seclists/Usernames/top-usernames-shortlist.txt")
    wl_passwords: Path = Path("/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt")

    # Kiterunner "kite" routes. Shipped as .kite file (not in SecLists).
    wl_kite: Path = Path("/opt/kiterunner/routes-large.kite")

    # Nuclei workflows directory (our curated .yaml workflows).
    nuclei_workflows_dir: Path = Path("/opt/stbox-workflows")

    @classmethod
    def from_env(cls) -> Config:
        return cls(
            tool_timeout=int(os.getenv("STBOX_TOOL_TIMEOUT", "300")),
            max_concurrency=int(os.getenv("STBOX_MAX_CONCURRENCY", "25")),
            rate_limit_rps=float(os.getenv("STBOX_RATE_LIMIT_RPS", "10")),
            user_agent=os.getenv("STBOX_USER_AGENT", cls.user_agent),
            workdir=Path(os.getenv("STBOX_WORKDIR", str(cls.workdir))),
            strict_binaries=os.getenv("STBOX_STRICT_BINARIES", "0") == "1",
            seclists_root=Path(os.getenv("STBOX_SECLISTS", str(cls.seclists_root))),
            wl_content_small=Path(os.getenv("STBOX_WL_CONTENT_SMALL", str(cls.wl_content_small))),
            wl_content_big=Path(os.getenv("STBOX_WL_CONTENT_BIG", str(cls.wl_content_big))),
            wl_params=Path(os.getenv("STBOX_WL_PARAMS", str(cls.wl_params))),
            wl_usernames=Path(os.getenv("STBOX_WL_USERNAMES", str(cls.wl_usernames))),
            wl_passwords=Path(os.getenv("STBOX_WL_PASSWORDS", str(cls.wl_passwords))),
            wl_kite=Path(os.getenv("STBOX_WL_KITE", str(cls.wl_kite))),
            nuclei_workflows_dir=Path(os.getenv("STBOX_NUCLEI_WORKFLOWS",
                                                 str(cls.nuclei_workflows_dir))),
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
    "hydra": "hydra",
    "medusa": "medusa",
    "ffuf": "ffuf",
    "wfuzz": "wfuzz",
    "kiterunner": "kr",
}
