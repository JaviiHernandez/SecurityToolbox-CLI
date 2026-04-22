"""JavaScript library vulnerability scanner — native Python port of the
VULN_DB used in the web /report endpoint and the SecLens extension.

Fetches the page, extracts every <script src=...>, downloads each script,
and fingerprints the library + version using URL and body regex. Matches
versions against a curated CVE database and emits findings per
vulnerable instance.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urljoin

import httpx

from stbox.config import Config
from stbox.models import Finding, Severity


# -----------------------------------------------------------------------------
# Vulnerability database. Mirror of the TypeScript VULN_DB in
# securitytoolbox/src/lib/js-vuln-db.ts — keep in sync.
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class _VulnRange:
    below: str
    severity: Severity
    cve: tuple[str, ...]
    summary: str
    above: str | None = None


VULN_DB: dict[str, list[_VulnRange]] = {
    "jQuery": [
        _VulnRange("1.12.0",  Severity.MEDIUM,  ("CVE-2015-9251",), "XSS via 3rd-party text/script responses"),
        _VulnRange("3.0.0",   Severity.MEDIUM,  ("CVE-2015-9251",), "XSS via cross-domain ajax"),
        _VulnRange("3.4.0",   Severity.MEDIUM,  ("CVE-2019-11358",), "Prototype pollution via $.extend"),
        _VulnRange("3.5.0",   Severity.MEDIUM,  ("CVE-2020-11022", "CVE-2020-11023"), "XSS via HTML containing </option> or <style>"),
    ],
    "jQuery UI": [
        _VulnRange("1.12.0",  Severity.MEDIUM,  ("CVE-2016-7103",), "XSS in dialog closeText"),
        _VulnRange("1.13.2",  Severity.LOW,     ("CVE-2022-31160",), "XSS in checkboxradio icon"),
    ],
    "Lodash": [
        _VulnRange("4.17.5",  Severity.HIGH,    ("CVE-2018-3721",),  "Prototype pollution via merge/mergeWith/defaultsDeep"),
        _VulnRange("4.17.12", Severity.HIGH,    ("CVE-2019-10744",), "Prototype pollution in defaultsDeep"),
        _VulnRange("4.17.15", Severity.MEDIUM,  ("CVE-2019-19771",), "ReDoS in toNumber/trim/trimEnd"),
        _VulnRange("4.17.19", Severity.MEDIUM,  ("CVE-2020-8203",),  "Prototype pollution in zipObjectDeep"),
        _VulnRange("4.17.21", Severity.HIGH,    ("CVE-2021-23337",), "Command injection via _.template"),
    ],
    "Underscore.js": [
        _VulnRange("1.12.1", Severity.HIGH, ("CVE-2021-23358",), "Arbitrary code execution via _.template"),
    ],
    "Moment.js": [
        _VulnRange("2.19.3", Severity.MEDIUM, ("CVE-2017-18214",), "ReDoS in moment()"),
        _VulnRange("2.29.2", Severity.HIGH,   ("CVE-2022-24785",), "Path traversal via untrusted locale"),
        _VulnRange("2.29.4", Severity.HIGH,   ("CVE-2022-31129",), "ReDoS in rfc2822 date parsing"),
    ],
    "AngularJS": [
        _VulnRange("1.6.9",   Severity.HIGH,     ("CVE-2018-1000004",), "XSS in ngSanitize"),
        _VulnRange("1.7.9",   Severity.MEDIUM,   ("CVE-2019-10768",),   "Prototype pollution via merge"),
        _VulnRange("1.8.0",   Severity.MEDIUM,   ("CVE-2020-7676",),    "XSS in ngSanitize under SVG"),
        _VulnRange("999.0.0", Severity.CRITICAL, (),                    "AngularJS is end-of-life (Dec 2021) — migrate to Angular 2+"),
    ],
    "Bootstrap": [
        _VulnRange("3.4.0", Severity.MEDIUM, ("CVE-2018-14041", "CVE-2018-14042"), "XSS in data-target, tooltip, popover, scrollspy"),
        _VulnRange("4.3.1", Severity.MEDIUM, ("CVE-2019-8331",), "XSS in tooltip data-template"),
    ],
    "Handlebars": [
        _VulnRange("4.0.14", Severity.HIGH, ("CVE-2015-8861",),  "Arbitrary file access on server"),
        _VulnRange("4.3.0",  Severity.HIGH, ("CVE-2019-19919",), "Prototype pollution in parseHelpers"),
        _VulnRange("4.6.0",  Severity.HIGH, ("CVE-2019-20920",), "Arbitrary code execution via template"),
        _VulnRange("4.7.7",  Severity.HIGH, ("CVE-2021-23369", "CVE-2021-23383"), "Prototype pollution / RCE"),
    ],
    "Vue.js": [
        _VulnRange("2.6.14", Severity.MEDIUM, ("CVE-2021-32723",), "XSS via dev-mode render"),
    ],
    "D3.js": [
        _VulnRange("5.8.0", Severity.MEDIUM, ("CVE-2020-7746",), "Prototype pollution via d3.set"),
    ],
    "React": [
        _VulnRange("16.4.2", Severity.MEDIUM, ("CVE-2018-6341",), "XSS via dangerouslySetInnerHTML in older SSR apps"),
    ],
    "Next.js": [
        _VulnRange("11.1.1",  Severity.MEDIUM,   ("CVE-2021-37693",), "Open redirect via malformed URL"),
        _VulnRange("12.0.5",  Severity.MEDIUM,   ("CVE-2021-43803",), "SSRF via next/image component"),
        _VulnRange("12.1.0",  Severity.HIGH,     ("CVE-2022-21717",), "DoS via malformed Accept-Language"),
        _VulnRange("13.5.1",  Severity.HIGH,     ("CVE-2024-34351",), "SSRF in Server Actions redirect"),
        _VulnRange("14.2.15", Severity.HIGH,     ("CVE-2024-51479",), "Authorization bypass in Next.js middleware"),
        _VulnRange("14.2.25", Severity.CRITICAL, ("CVE-2025-29927",), "Middleware authz bypass via x-middleware-subrequest header", above="13.0.0"),
        _VulnRange("15.2.3",  Severity.CRITICAL, ("CVE-2025-29927",), "Middleware authz bypass via x-middleware-subrequest header", above="15.0.0"),
    ],
    "Axios": [
        _VulnRange("0.21.1", Severity.HIGH,   ("CVE-2020-28168",), "SSRF via follow redirects"),
        _VulnRange("0.21.2", Severity.MEDIUM, ("CVE-2021-3749",),  "ReDoS in trim"),
        _VulnRange("1.6.0",  Severity.MEDIUM, ("CVE-2023-45857",), "CSRF via XSRF token exposure"),
        _VulnRange("1.7.4",  Severity.HIGH,   ("CVE-2024-39338",), "SSRF via protocol-relative URL"),
    ],
    "DOMPurify": [
        _VulnRange("2.0.17", Severity.HIGH,   ("CVE-2020-26870",), "XSS bypass via nested template"),
        _VulnRange("2.3.0",  Severity.MEDIUM, ("CVE-2021-33623",), "Mutation XSS via mXSS"),
        _VulnRange("3.0.9",  Severity.MEDIUM, ("CVE-2024-45801",), "XSS via trusted types bypass"),
    ],
    "CKEditor": [
        _VulnRange("4.16.0", Severity.MEDIUM, ("CVE-2021-32808",), "XSS in widget plugin"),
        _VulnRange("4.22.0", Severity.MEDIUM, ("CVE-2023-28439",), "XSS in HTML parser"),
    ],
    "TinyMCE": [
        _VulnRange("5.10.0", Severity.MEDIUM, ("CVE-2021-32755",), "XSS via paste plugin"),
        _VulnRange("6.7.3",  Severity.MEDIUM, ("CVE-2024-21908",), "XSS via URL protocol"),
    ],
    "GSAP": [
        _VulnRange("3.11.4", Severity.MEDIUM, ("CVE-2022-46164",), "XSS via URL params in animation plugin"),
    ],
}


# -----------------------------------------------------------------------------
# URL + body detection patterns.
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class _Pattern:
    name: str
    url: re.Pattern | None = None
    body: re.Pattern | None = None


_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern("jQuery",        body=re.compile(r"[*!]\s*jQuery\s+v?(\d+\.\d+\.\d+)", re.I)),
    _Pattern("jQuery",        url=re.compile(r"jquery[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", re.I)),
    _Pattern("jQuery UI",     body=re.compile(r"[*!]\s*jQuery UI[\s\-]+v?(\d+\.\d+\.\d+)", re.I)),
    _Pattern("jQuery UI",     url=re.compile(r"jquery-ui[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", re.I)),
    _Pattern("Lodash",        body=re.compile(r"[*!]\s*(?:lodash|Lo-Dash)\s+(?:<https?:[^>]+>\s+)?(\d+\.\d+\.\d+)", re.I)),
    _Pattern("Lodash",        url=re.compile(r"lodash[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", re.I)),
    _Pattern("Underscore.js", body=re.compile(r"[*!]\s*Underscore\.js\s+(\d+\.\d+\.\d+)", re.I)),
    _Pattern("Moment.js",     body=re.compile(r"moment\.version\s*=\s*['\"](\d+\.\d+\.\d+)['\"]", re.I)),
    _Pattern("Moment.js",     url=re.compile(r"moment[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", re.I)),
    _Pattern("AngularJS",     body=re.compile(r"AngularJS\s+v?(\d+\.\d+\.\d+)", re.I)),
    _Pattern("AngularJS",     url=re.compile(r"angular[-.]?(1\.\d+(?:\.\d+)?)(?:\.min)?\.js", re.I)),
    _Pattern("Bootstrap",     body=re.compile(r"[*!]\s*Bootstrap\s+v?(\d+\.\d+\.\d+)", re.I)),
    _Pattern("Bootstrap",     url=re.compile(r"bootstrap[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", re.I)),
    _Pattern("Handlebars",    body=re.compile(r"Handlebars\.VERSION\s*=\s*['\"](\d+\.\d+\.\d+)['\"]", re.I)),
    _Pattern("Vue.js",        body=re.compile(r"[*!]\s*Vue\.js\s+v?(\d+\.\d+\.\d+)", re.I)),
    _Pattern("D3.js",         body=re.compile(r"d3\s+v(\d+\.\d+\.\d+)", re.I)),
    _Pattern("React",         body=re.compile(r"\breact\.version\s*=\s*['\"](\d+\.\d+\.\d+)['\"]", re.I)),
    _Pattern("Axios",         body=re.compile(r"axios/(\d+\.\d+\.\d+)", re.I)),
    _Pattern("DOMPurify",     body=re.compile(r"DOMPurify\.version\s*=\s*['\"](\d+\.\d+\.\d+)['\"]", re.I)),
    _Pattern("CKEditor",      body=re.compile(r"CKEDITOR\.version\s*=\s*['\"](\d+\.\d+(?:\.\d+)?)['\"]", re.I)),
    _Pattern("GSAP",          body=re.compile(r"GSAP\s+(\d+\.\d+\.\d+)", re.I)),
)


# -----------------------------------------------------------------------------
# Version comparison — mirror of the TS compareVersions.
# -----------------------------------------------------------------------------

def _cmp_versions(a: str | None, b: str | None) -> int:
    if not a:
        return -1
    if not b:
        return 1
    def _norm(s: str) -> list[int]:
        s = re.sub(r"^v", "", s, flags=re.I)
        s = re.sub(r"[^0-9.\-]", "", s)
        parts = re.split(r"[.\-]", s)
        out = []
        for p in parts:
            try:
                out.append(int(p))
            except ValueError:
                out.append(0)
        return out
    pa, pb = _norm(a), _norm(b)
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    for i in range(n):
        if pa[i] < pb[i]:
            return -1
        if pa[i] > pb[i]:
            return 1
    return 0


# -----------------------------------------------------------------------------
# Main entrypoint
# -----------------------------------------------------------------------------

_SCRIPT_RE = re.compile(
    r'<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\'][^>]*>', re.I
)
_MAX_SCRIPTS = 30
_MAX_CONCURRENT = 8
_PER_SCRIPT_TIMEOUT = 8.0
_PAGE_TIMEOUT = 15.0
_MAX_SCRIPT_BYTES = 2 * 1024 * 1024  # 2 MB


async def _fetch_text(client: httpx.AsyncClient, url: str,
                      timeout: float, max_bytes: int = _MAX_SCRIPT_BYTES) -> str:
    try:
        async with client.stream("GET", url, timeout=timeout) as r:
            if r.status_code >= 400:
                return ""
            total = 0
            chunks: list[bytes] = []
            async for chunk in r.aiter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    break
                chunks.append(chunk)
            try:
                return b"".join(chunks).decode("utf-8", errors="ignore")
            except UnicodeDecodeError:
                return ""
    except httpx.HTTPError:
        return ""


def _detect_in(script_url: str, body: str) -> list[tuple[str, str, str]]:
    """Return list of (lib_name, version, source) from one script."""
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for p in _PATTERNS:
        if p.url:
            m = p.url.search(script_url)
            if m and m.group(1):
                key = f"{p.name}@{m.group(1)}"
                if key not in seen:
                    seen.add(key)
                    out.append((p.name, m.group(1), "url"))
        if p.body and body:
            m = p.body.search(body)
            if m and m.group(1):
                key = f"{p.name}@{m.group(1)}"
                if key not in seen:
                    seen.add(key)
                    out.append((p.name, m.group(1), "body"))
    return out


def _find_vulns(libs: Iterable[tuple[str, str, str, str]]) -> list[Finding]:
    """libs: iterable of (name, version, source, script_url)."""
    findings: list[Finding] = []
    for name, version, source, script_url in libs:
        ranges = VULN_DB.get(name)
        if not ranges or not version:
            continue
        for r in ranges:
            if _cmp_versions(version, r.below) >= 0:
                continue
            if r.above and _cmp_versions(version, r.above) < 0:
                continue
            findings.append(
                Finding(
                    tool="js-libs",
                    severity=r.severity,
                    title=f"{name} {version} — {r.summary}",
                    description=(
                        f"{name} @ {version} is vulnerable. Fixed in {r.below}. "
                        f"Detected via {source} pattern in {script_url or 'inline HTML'}."
                    ),
                    target=script_url or name,
                    tags=["js-libs", name.lower().replace(".", "-"), "cve"],
                    cve=list(r.cve),
                    evidence={
                        "library": name,
                        "detected_version": version,
                        "fixed_in": r.below,
                        "source": source,
                        "script_url": script_url,
                    },
                )
            )
    return findings


async def scan_js_libs(page_url: str, cfg: Config) -> list[Finding]:
    """Fetch the page + every <script src>, detect libraries, match CVEs."""
    async with httpx.AsyncClient(
        timeout=_PAGE_TIMEOUT,
        follow_redirects=True,
        headers={
            "User-Agent": cfg.user_agent,
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        },
    ) as client:
        try:
            r = await client.get(page_url)
        except httpx.HTTPError:
            return []

        if r.status_code >= 400:
            return []
        html = r.text or ""

        # Inline detection (Next.js __NEXT_DATA__, inline banners).
        inline = _detect_in("", html)

        # Extract script URLs and resolve relatives.
        srcs = []
        for m in _SCRIPT_RE.finditer(html):
            raw = m.group(1).strip()
            if not raw:
                continue
            absolute = urljoin(str(r.url), raw)
            if absolute.startswith(("http://", "https://")):
                srcs.append(absolute)
        # Dedupe preserving order, cap count.
        seen_urls: set[str] = set()
        unique_srcs: list[str] = []
        for s in srcs:
            if s in seen_urls:
                continue
            seen_urls.add(s)
            unique_srcs.append(s)
        unique_srcs = unique_srcs[:_MAX_SCRIPTS]

        # Parallel fetch with concurrency cap.
        sem = asyncio.Semaphore(_MAX_CONCURRENT)
        async def _one(u: str) -> tuple[str, str]:
            async with sem:
                body = await _fetch_text(client, u, _PER_SCRIPT_TIMEOUT)
                return u, body
        results = await asyncio.gather(*[_one(u) for u in unique_srcs])

    all_libs: list[tuple[str, str, str, str]] = [
        (n, v, s, "") for (n, v, s) in inline
    ]
    detected_lib_set: set[tuple[str, str]] = {(n, v) for n, v, _ in inline}
    for url, body in results:
        for (n, v, src) in _detect_in(url, body):
            if (n, v) in detected_lib_set:
                continue
            detected_lib_set.add((n, v))
            all_libs.append((n, v, src, url))

    findings = _find_vulns(all_libs)

    # Add a summary informational finding.
    findings.append(
        Finding(
            tool="js-libs",
            severity=Severity.INFO,
            title=(
                f"JS libraries: {len(detected_lib_set)} detected, "
                f"{len(findings)} known CVE(s)"
            ),
            target=page_url,
            tags=["js-libs", "summary"],
            evidence={
                "libraries": [{"name": n, "version": v} for n, v in sorted(detected_lib_set)],
                "scripts_scanned": len(unique_srcs),
                "scripts_total": len(unique_srcs),
            },
        )
    )
    return findings
