"""Cross-cutting helpers: subprocess wrapper, logging, path helpers."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Sequence


logger = logging.getLogger("stbox")


async def run_cmd(
    cmd: Sequence[str],
    *,
    timeout: int = 300,
    stdin: bytes | None = None,
    cwd: Path | None = None,
    env: dict | None = None,
) -> tuple[int, str, str]:
    """Run a subprocess asynchronously.

    Returns (exit_code, stdout, stderr). Raises asyncio.TimeoutError
    (translated to a (-1, "", "timeout") tuple below) if it runs too long.
    """
    logger.debug("exec: %s", " ".join(cmd))
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
        )
    except FileNotFoundError:
        return (127, "", f"binary not found on PATH: {cmd[0]}")

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(input=stdin), timeout=timeout
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        await proc.wait()
        return (-1, "", f"timeout after {timeout}s")

    return (
        proc.returncode or 0,
        stdout_b.decode("utf-8", errors="replace"),
        stderr_b.decode("utf-8", errors="replace"),
    )


def ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p


def safe_filename(s: str) -> str:
    """Sanitize a string for use as a filename component."""
    keep = "-_.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(c if c in keep else "_" for c in s)[:120] or "out"
