"""Exposures scanner — probes ~40 well-known sensitive paths.

Native Python port of the web /api/exposures-check route. Catch-all
detection upfront (random 404 probe) so SPA sites that return 200 for
every unknown path don't generate false positives.
"""

from __future__ import annotations

import asyncio
import random
import re
import string
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

import httpx

from stbox.config import Config
from stbox.models import Finding, Severity


_PAGE_TIMEOUT = 4.0
_CONCURRENCY = 12
_MAX_BYTES = 8 * 1024


# ----------------------------------------------------------------------------
# Validators — each returns True iff the response body proves the path is
# a real hit (not just a catch-all HTML error page).
# ----------------------------------------------------------------------------

def _body_starts_with(*markers: str) -> Callable[[str, str], bool]:
    def _check(body: str, _ct: str) -> bool:
        head = body.lstrip()
        return any(head.startswith(m) for m in markers)
    return _check


def _body_contains(*markers: str) -> Callable[[str, str], bool]:
    def _check(body: str, _ct: str) -> bool:
        return any(m in body for m in markers)
    return _check


def _looks_like_json(body: str, ct: str) -> bool:
    head = body.lstrip()
    if not (head.startswith("{") or head.startswith("[")):
        return False
    head_low = head[:500].lower()
    if "<html" in head_low or "<!doctype" in head_low:
        return False
    if "html" in ct.lower():
        return False
    return True


def _looks_like_env(body: str, _ct: str) -> bool:
    return re.search(r"^\s*[A-Z][A-Z0-9_]{1,}\s*=", body, re.M) is not None


def _looks_like_sql(body: str, _ct: str) -> bool:
    return re.search(
        r"(CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL dump|PostgreSQL database dump)",
        body, re.I,
    ) is not None


@dataclass(frozen=True)
class _Check:
    path: str
    severity: Severity
    name: str
    category: str
    validate: Callable[[str, str], bool] | None = None
    informational: bool = False
    require_content_type: tuple[str, ...] | None = None


EXPOSURE_CHECKS: tuple[_Check, ...] = (
    # VCS
    _Check("/.git/HEAD",  Severity.CRITICAL, "Git repository exposed (/.git/HEAD)", "vcs", _body_starts_with("ref:")),
    _Check("/.git/config",Severity.CRITICAL, "Git config exposed (/.git/config)", "vcs", _body_contains("[core]", "[remote ")),
    _Check("/.svn/entries",Severity.CRITICAL, "Subversion repo exposed", "vcs"),
    _Check("/.hg/hgrc",   Severity.CRITICAL, "Mercurial repo exposed", "vcs"),
    # Secrets
    _Check("/.env",            Severity.CRITICAL, ".env file exposed (secrets)", "secrets", _looks_like_env),
    _Check("/.env.local",      Severity.CRITICAL, ".env.local exposed", "secrets", _looks_like_env),
    _Check("/.env.production", Severity.CRITICAL, ".env.production exposed", "secrets", _looks_like_env),
    _Check("/.env.backup",     Severity.CRITICAL, ".env.backup exposed", "secrets", _looks_like_env),
    _Check("/.aws/credentials",Severity.CRITICAL, "AWS credentials file exposed", "secrets",
           _body_contains("aws_access_key_id", "[default]")),
    _Check("/.htpasswd",       Severity.CRITICAL, ".htpasswd exposed (hashed creds)", "secrets",
           lambda b, _: re.search(r"^[A-Za-z_][A-Za-z0-9_.-]*:\$[0-9a-z]+\$", b, re.M) is not None),
    _Check("/.npmrc", Severity.HIGH, ".npmrc may contain auth tokens", "secrets",
           lambda b, _: re.search(r"(registry\s*=|_authToken\s*=|always-auth\s*=)", b, re.I) is not None),
    # Backups
    _Check("/backup.sql",   Severity.CRITICAL, "SQL dump exposed", "backup", _looks_like_sql),
    _Check("/db.sql",       Severity.CRITICAL, "Database dump exposed", "backup", _looks_like_sql),
    _Check("/dump.sql",     Severity.CRITICAL, "Database dump exposed", "backup", _looks_like_sql),
    _Check("/database.sql", Severity.CRITICAL, "Database dump exposed", "backup", _looks_like_sql),
    _Check("/backup.zip",   Severity.HIGH,     "Backup .zip exposed", "backup", _body_starts_with("PK\x03\x04")),
    _Check("/backup.tar.gz",Severity.HIGH,     "Backup .tar.gz exposed", "backup", _body_starts_with("\x1f\x8b")),
    # Config
    _Check("/config.php.bak",     Severity.CRITICAL, "PHP config backup exposed", "config", _body_contains("<?php", "<?=")),
    _Check("/wp-config.php.bak",  Severity.CRITICAL, "WP config backup exposed", "config",
           _body_contains("DB_NAME", "DB_PASSWORD", "AUTH_KEY")),
    _Check("/wp-config.old",      Severity.CRITICAL, "WP config .old exposed", "config",
           _body_contains("DB_NAME", "DB_PASSWORD", "AUTH_KEY")),
    _Check("/web.config.bak",     Severity.HIGH,     "IIS web.config backup exposed", "config",
           _body_contains("<configuration", "<system.webServer")),
    _Check("/config.json", Severity.MEDIUM, "config.json exposed", "config", _looks_like_json),
    # Build artifacts
    _Check("/package.json",  Severity.LOW, "package.json exposed", "build",
           lambda b, ct: _looks_like_json(b, ct) and ("\"dependencies\"" in b or "\"name\"" in b)),
    _Check("/composer.json", Severity.LOW, "composer.json exposed", "build",
           lambda b, ct: _looks_like_json(b, ct) and ("\"require\"" in b or "\"name\"" in b)),
    _Check("/yarn.lock",     Severity.LOW, "yarn.lock exposed", "build",
           _body_contains("# yarn lockfile", "__metadata:")),
    # IDE
    _Check("/.vscode/settings.json", Severity.MEDIUM, "VS Code settings exposed", "ide", _looks_like_json),
    _Check("/.idea/workspace.xml",   Severity.MEDIUM, "IntelliJ workspace exposed", "ide",
           _body_contains("<project", "<?xml")),
    _Check("/.DS_Store",             Severity.LOW,    ".DS_Store exposed", "ide", _body_contains("Bud1")),
    # Server info
    _Check("/server-status", Severity.HIGH, "Apache server-status exposed", "server",
           _body_contains("Apache Server Status")),
    _Check("/server-info",   Severity.HIGH, "Apache server-info exposed", "server",
           _body_contains("Apache Server Information")),
    _Check("/phpinfo.php",   Severity.HIGH, "phpinfo() output exposed", "server",
           _body_contains("PHP Version", "phpinfo()")),
    _Check("/info.php",      Severity.HIGH, "phpinfo() output exposed (info.php)", "server",
           _body_contains("PHP Version", "phpinfo()")),
    # Admin
    _Check("/phpmyadmin/", Severity.MEDIUM, "phpMyAdmin accessible", "admin",
           _body_contains("phpMyAdmin")),
    # Informational (positives)
    _Check("/.well-known/security.txt", Severity.INFO, "security.txt published", "info",
           lambda b, _: re.search(r"^\s*(Contact|Expires|Encryption|Policy|Acknowledgments)\s*:",
                                  b, re.I | re.M) is not None,
           informational=True, require_content_type=("text/plain", "text/")),
    _Check("/robots.txt", Severity.INFO, "robots.txt present", "info",
           lambda b, _: re.search(r"^\s*(User-agent|Disallow|Allow|Sitemap)\s*:", b, re.I | re.M) is not None,
           informational=True, require_content_type=("text/plain",)),
    _Check("/sitemap.xml", Severity.INFO, "sitemap.xml present", "info",
           _body_contains("<urlset", "<sitemapindex"),
           informational=True, require_content_type=("application/xml", "text/xml")),
)


# ----------------------------------------------------------------------------
# Catch-all detection + real hit check (mirrors the TS implementation).
# ----------------------------------------------------------------------------

def _looks_like_html(body: str, content_type: str) -> bool:
    ct = content_type.lower()
    if ct.startswith("text/html") or ct.startswith("application/xhtml"):
        return True
    head = body.lstrip()[:512].lower()
    if (
        head.startswith("<!doctype") or head.startswith("<html") or
        (("<head" in head) and ("<body" in head))
    ):
        return True
    return False


def _is_real_hit(check: _Check, body: str, ct: str, catch_all: bool) -> bool:
    if check.require_content_type:
        ct_low = ct.lower()
        if not any(ct_low.startswith(p) for p in check.require_content_type):
            return False
    if _looks_like_html(body, ct):
        return False
    if catch_all and not check.validate:
        return False
    if check.validate:
        return check.validate(body, ct)
    return True


async def _probe_path(client: httpx.AsyncClient, base: str, path: str,
                      timeout: float = _PAGE_TIMEOUT) -> tuple[int, str, str]:
    try:
        r = await client.get(base + path, timeout=timeout,
                             headers={"Range": f"bytes=0-{_MAX_BYTES - 1}"})
        # Read at most _MAX_BYTES.
        body = r.content.decode("utf-8", errors="ignore")[:_MAX_BYTES]
        return r.status_code, r.headers.get("content-type", ""), body
    except httpx.HTTPError:
        return 0, "", ""


async def _detect_catch_all(client: httpx.AsyncClient, base: str) -> bool:
    slug = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    path = f"/stbox-404-probe-{slug}-xyz.bogus"
    status, ct, body = await _probe_path(client, base, path)
    if status in (404, 410) or status >= 400:
        return False
    if status in (200, 206):
        return _looks_like_html(body, ct) or len(body) > 0
    return False


async def scan_exposures(url: str, cfg: Config) -> list[Finding]:
    parsed = urlparse(url)
    if not parsed.scheme.startswith("http"):
        return []
    origin = f"{parsed.scheme}://{parsed.netloc}"

    findings: list[Finding] = []

    async with httpx.AsyncClient(
        headers={
            "User-Agent": cfg.user_agent,
            "Accept": "*/*",
            "Referer": origin + "/",
        },
        follow_redirects=False,
        timeout=_PAGE_TIMEOUT,
    ) as client:
        catch_all = await _detect_catch_all(client, origin)
        sem = asyncio.Semaphore(_CONCURRENCY)

        async def _run_check(ch: _Check) -> Finding | None:
            async with sem:
                status, ct, body = await _probe_path(client, origin, ch.path)
                if status not in (200, 206):
                    return None
                if not _is_real_hit(ch, body, ct, catch_all):
                    return None
                sev = Severity.INFO if ch.informational else ch.severity
                return Finding(
                    tool="exposures",
                    severity=sev,
                    title=f"{ch.name} — {ch.path}",
                    description=(
                        f"Path {ch.path} returned HTTP {status} with validated "
                        f"content. Category: {ch.category}. "
                        + ("Positive signal (good hygiene)." if ch.informational
                           else "Remove from webroot or block in server config.")
                    ),
                    target=origin + ch.path,
                    tags=["exposures", ch.category, ch.path.lstrip("/").replace("/", "_")],
                    evidence={
                        "path": ch.path,
                        "status": status,
                        "content_type": ct[:100],
                        "informational": ch.informational,
                        "catch_all_detected": catch_all,
                    },
                )

        results = await asyncio.gather(*[_run_check(ch) for ch in EXPOSURE_CHECKS])

    for f in results:
        if f is not None:
            findings.append(f)

    # Summary finding — always emit, even if empty.
    non_info = [f for f in findings if f.severity != Severity.INFO]
    findings.append(
        Finding(
            tool="exposures",
            severity=Severity.INFO,
            title=(
                f"Exposures scan: {len(non_info)} findings "
                f"({len(EXPOSURE_CHECKS)} paths probed"
                + (", catch-all filter active" if catch_all else "")
                + ")"
            ),
            target=origin,
            tags=["exposures", "summary"],
            evidence={
                "paths_checked": len(EXPOSURE_CHECKS),
                "findings_count": len(non_info),
                "catch_all_detected": catch_all,
            },
        )
    )

    return findings
