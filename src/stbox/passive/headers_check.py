"""HTTP security headers + Set-Cookie flag analysis.

Fetches the target URL with a browser-like UA, then runs two checks:
  1. Recommended security header coverage (HSTS, CSP, X-Frame-Options, ...)
  2. Set-Cookie flags (Secure, HttpOnly, SameSite)

Both checks are pure observation — no payloads, no auth. Safe to run
against any public URL.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from stbox.config import Config
from stbox.models import Finding, Severity


# -----------------------------------------------------------------------------
# Recommended security headers with short per-header risk explanations.
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class HeaderDef:
    key: str
    name: str
    severity_if_missing: Severity
    good_values: tuple[str, ...] | None   # case-insensitive substring match
    explain: str


HEADER_DEFS: tuple[HeaderDef, ...] = (
    HeaderDef(
        key="strict-transport-security",
        name="Strict-Transport-Security",
        severity_if_missing=Severity.MEDIUM,
        good_values=None,
        explain=(
            "Forces browsers to use HTTPS on subsequent visits. Without HSTS, "
            "a first-visit attacker on the network can SSL-strip."
        ),
    ),
    HeaderDef(
        key="content-security-policy",
        name="Content-Security-Policy",
        severity_if_missing=Severity.MEDIUM,
        good_values=None,
        explain=(
            "The single most effective defence against reflected / stored "
            "XSS. Without CSP, injected <script> tags run unrestricted."
        ),
    ),
    HeaderDef(
        key="x-frame-options",
        name="X-Frame-Options",
        severity_if_missing=Severity.LOW,
        good_values=("DENY", "SAMEORIGIN"),
        explain=(
            "Prevents the page from being embedded in a malicious "
            "<iframe> (clickjacking foundation)."
        ),
    ),
    HeaderDef(
        key="x-content-type-options",
        name="X-Content-Type-Options",
        severity_if_missing=Severity.LOW,
        good_values=("nosniff",),
        explain=(
            "Disables MIME-sniffing. Without it, a user-uploaded file with a "
            "misleading extension can be executed as script."
        ),
    ),
    HeaderDef(
        key="referrer-policy",
        name="Referrer-Policy",
        severity_if_missing=Severity.LOW,
        good_values=None,
        explain=(
            "Controls how much URL info leaks in the Referer header. Without "
            "a strict policy, tokens in the query string leak to 3rd parties."
        ),
    ),
    HeaderDef(
        key="permissions-policy",
        name="Permissions-Policy",
        severity_if_missing=Severity.LOW,
        good_values=None,
        explain=(
            "Restricts which browser features (camera, geolocation, mic, USB) "
            "your pages and third-party frames can use."
        ),
    ),
    HeaderDef(
        key="cross-origin-opener-policy",
        name="Cross-Origin-Opener-Policy",
        severity_if_missing=Severity.LOW,
        good_values=None,
        explain=(
            "Isolates the top-level browsing context from cross-origin popups "
            "(mitigates Spectre-class side channels)."
        ),
    ),
)


# -----------------------------------------------------------------------------
# Fetch helper
# -----------------------------------------------------------------------------

async def _fetch(url: str, cfg: Config) -> httpx.Response | None:
    try:
        async with httpx.AsyncClient(
            timeout=15,
            follow_redirects=True,
            headers={
                "User-Agent": cfg.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
        ) as client:
            return await client.get(url)
    except httpx.HTTPError:
        return None


# -----------------------------------------------------------------------------
# Main entrypoint
# -----------------------------------------------------------------------------

async def analyze_headers_and_cookies(
    url: str, cfg: Config,
) -> list[Finding]:
    """Fetch `url` once and produce findings for security headers + cookies."""
    r = await _fetch(url, cfg)
    if r is None:
        return []

    # Lowercase header keys for consistent lookup.
    headers = {k.lower(): v for k, v in r.headers.items()}

    findings: list[Finding] = []

    # ---- Security headers ----
    present_count = 0
    for h in HEADER_DEFS:
        val = headers.get(h.key)
        if not val:
            findings.append(
                Finding(
                    tool="headers",
                    severity=h.severity_if_missing,
                    title=f"Missing security header: {h.name}",
                    description=h.explain,
                    target=url,
                    tags=["headers", "missing-header", h.key],
                    evidence={"header": h.name, "present": False},
                )
            )
            continue
        present_count += 1
        # Some headers have a "good" set of values. If the header is present
        # but with a value that doesn't clearly protect, flag as LOW.
        if h.good_values:
            if not any(gv.lower() in val.lower() for gv in h.good_values):
                findings.append(
                    Finding(
                        tool="headers",
                        severity=Severity.LOW,
                        title=f"{h.name} misconfigured",
                        description=(
                            f"{h.name}={val!r} does not set a clearly "
                            f"protective value. Expected one of: "
                            f"{', '.join(h.good_values)}."
                        ),
                        target=url,
                        tags=["headers", "misconfigured", h.key],
                        evidence={"header": h.name, "value": val},
                    )
                )

    # HSTS deep-check: max-age must be reasonable.
    hsts = headers.get("strict-transport-security")
    if hsts:
        import re
        m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        if m:
            age = int(m.group(1))
            if age < 31536000:  # one year
                findings.append(
                    Finding(
                        tool="headers",
                        severity=Severity.LOW,
                        title=f"HSTS max-age is too short ({age}s)",
                        description=(
                            "HSTS max-age is below the one-year minimum. "
                            "Browsers may forget the HTTPS-only setting; use "
                            "max-age=31536000 with includeSubDomains."
                        ),
                        target=url,
                        tags=["headers", "hsts", "short-max-age"],
                        evidence={"max_age_seconds": age, "value": hsts},
                    )
                )

    # Summary finding.
    total = len(HEADER_DEFS)
    findings.append(
        Finding(
            tool="headers",
            severity=Severity.INFO,
            title=f"Security headers: {present_count}/{total} present",
            target=url,
            tags=["headers", "summary"],
            evidence={
                "present": present_count,
                "total": total,
                "status_code": r.status_code,
                "final_url": str(r.url),
                "server": headers.get("server"),
            },
        )
    )

    # ---- Cookies ----
    # httpx exposes Set-Cookie via response.cookies but we want the RAW
    # attributes (Secure / HttpOnly / SameSite) which aren't surfaced there.
    # Parse the Set-Cookie headers manually instead.
    raw_cookies = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []
    if not raw_cookies:
        # httpx < 0.28 compat
        sc = r.headers.get("set-cookie")
        if sc:
            raw_cookies = [sc]

    for cookie_line in raw_cookies:
        parts = [p.strip() for p in cookie_line.split(";")]
        name_val = parts[0] if parts else ""
        name = name_val.split("=", 1)[0] if "=" in name_val else name_val
        attrs = {}
        for p in parts[1:]:
            if "=" in p:
                k, v = p.split("=", 1)
                attrs[k.strip().lower()] = v.strip()
            else:
                attrs[p.lower()] = True

        issues: list[str] = []
        if not attrs.get("secure"):
            issues.append("missing Secure")
        if not attrs.get("httponly"):
            issues.append("missing HttpOnly")
        samesite = str(attrs.get("samesite") or "").lower()
        if not samesite:
            issues.append("missing SameSite")
        elif samesite == "none" and not attrs.get("secure"):
            issues.append("SameSite=None without Secure (browsers reject this)")

        if issues:
            # Severity: missing Secure on a cookie that's clearly session-like
            # (name contains session/auth/jwt/sid/token) is MEDIUM; otherwise LOW.
            session_like = any(
                s in name.lower() for s in ("session", "auth", "jwt", "sid", "token", "csrf")
            )
            sev = Severity.MEDIUM if session_like else Severity.LOW
            findings.append(
                Finding(
                    tool="cookies",
                    severity=sev,
                    title=f"Cookie {name!r} lacks hardening: {', '.join(issues)}",
                    description=(
                        f"Set-Cookie attributes observed: Secure="
                        f"{bool(attrs.get('secure'))}, HttpOnly="
                        f"{bool(attrs.get('httponly'))}, "
                        f"SameSite={samesite or 'unset'}. "
                        f"All session/auth cookies should have Secure + "
                        f"HttpOnly + SameSite=Lax (or Strict)."
                    ),
                    target=url,
                    tags=["cookies", "hardening", name],
                    evidence={"cookie_name": name, "attributes": attrs, "issues": issues},
                )
            )

    return findings
