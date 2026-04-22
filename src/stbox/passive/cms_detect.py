"""CMS fingerprinting + lightweight passive checks (WordPress, Drupal,
Joomla, Ghost, Shopify, Webflow, Wix, Magento, WooCommerce, PrestaShop).

For WordPress specifically — the most targeted CMS on the internet — we
also run a handful of passive probes (no brute force, no exploitation):
  - /readme.html (version disclosure)
  - /wp-json/wp/v2/users (REST API user enumeration)
  - /xmlrpc.php reachability

For Drupal + Joomla we emit a single detection finding; deep auditing is
left to dedicated tools.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from stbox.config import Config
from stbox.models import Finding, Severity


@dataclass(frozen=True)
class _CmsSignature:
    name: str
    body_markers: tuple[str, ...] = ()
    body_regexes: tuple[re.Pattern, ...] = ()
    header_markers: tuple[tuple[str, str], ...] = ()   # (header, substring)

    def detect(self, body: str, headers: dict[str, str]) -> tuple[bool, str | None]:
        """Return (matched, version)."""
        for m in self.body_markers:
            if m in body:
                return True, None
        for r in self.body_regexes:
            m = r.search(body)
            if m:
                return True, m.group(1) if m.groups() else None
        for k, needle in self.header_markers:
            v = headers.get(k.lower(), "")
            if needle.lower() in v.lower():
                return True, None
        return False, None


CMS_SIGNATURES: tuple[_CmsSignature, ...] = (
    _CmsSignature(
        "WordPress",
        body_markers=("/wp-content/", "/wp-includes/"),
        body_regexes=(
            re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([\d.]+)', re.I),
        ),
        header_markers=(("link", "wp-json"),),
    ),
    _CmsSignature(
        "Drupal",
        body_markers=("/sites/default/files/", "drupalSettings"),
        body_regexes=(
            re.compile(r'<meta[^>]+name=["\']Generator["\'][^>]+content=["\']Drupal\s+(\d+)', re.I),
        ),
        header_markers=(("x-generator", "drupal"),),
    ),
    _CmsSignature(
        "Joomla",
        body_markers=("/media/jui/", "/components/com_content/"),
        body_regexes=(
            re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla!?\s*([\d.]*)', re.I),
        ),
    ),
    _CmsSignature(
        "Ghost",
        body_regexes=(
            re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Ghost\s*([\d.]*)', re.I),
        ),
    ),
    _CmsSignature(
        "Webflow",
        body_regexes=(
            re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Webflow', re.I),
        ),
    ),
    _CmsSignature(
        "Wix",
        body_markers=("static.wixstatic.com",),
        header_markers=(("x-wix-request-id", ""),),
    ),
    _CmsSignature(
        "Squarespace",
        body_markers=("static.squarespace.com",),
        header_markers=(("server", "Squarespace"),),
    ),
    _CmsSignature(
        "Shopify",
        body_markers=("cdn.shopify.com",),
        header_markers=(("x-shopify-stage", ""), ("x-shopid", ""), ("x-sorting-hat-shopid", "")),
    ),
    _CmsSignature(
        "WooCommerce",
        body_markers=("woocommerce-",),
    ),
    _CmsSignature(
        "Magento",
        body_markers=("Mage.Cookies", "/mage/"),
    ),
    _CmsSignature(
        "PrestaShop",
        body_markers=("prestashop",),
    ),
)


async def detect_cms(url: str, cfg: Config) -> list[Finding]:
    parsed = urlparse(url)
    if not parsed.scheme.startswith("http"):
        return []
    origin = f"{parsed.scheme}://{parsed.netloc}"

    findings: list[Finding] = []

    async with httpx.AsyncClient(
        headers={
            "User-Agent": cfg.user_agent,
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        },
        follow_redirects=True,
        timeout=15,
    ) as client:
        try:
            r = await client.get(url)
        except httpx.HTTPError:
            return []
        body = r.text or ""
        headers = {k.lower(): v for k, v in r.headers.items()}

        # Run every signature.
        detected: list[tuple[str, str | None]] = []
        for sig in CMS_SIGNATURES:
            matched, version = sig.detect(body, headers)
            if matched:
                detected.append((sig.name, version))

        if not detected:
            return findings

        # Deduplicate — a site can match both WordPress + WooCommerce legitimately.
        for name, version in detected:
            findings.append(
                Finding(
                    tool="cms",
                    severity=Severity.INFO,
                    title=f"CMS detected: {name}" + (f" {version}" if version else ""),
                    target=url,
                    tags=["cms", name.lower().replace(" ", "-"), "detection"],
                    evidence={"cms": name, "version": version},
                )
            )

        # WordPress-specific passive checks.
        if any(n == "WordPress" for n, _ in detected):
            findings.extend(await _wordpress_passive_checks(client, origin, body))

    return findings


async def _wordpress_passive_checks(
    client: httpx.AsyncClient,
    origin: str,
    home_body: str,
) -> list[Finding]:
    out: list[Finding] = []

    async def _probe(path: str) -> tuple[int, str, str]:
        try:
            r = await client.get(origin + path, timeout=5)
            body = r.text[:8192] if r.text else ""
            ct = r.headers.get("content-type", "")
            return r.status_code, ct, body
        except httpx.HTTPError:
            return 0, "", ""

    # readme.html — version disclosure that most teams forget to delete.
    status, ct, body = await _probe("/readme.html")
    if status == 200 and "wordpress" in body.lower():
        out.append(
            Finding(
                tool="wordpress",
                severity=Severity.MEDIUM,
                title="WordPress /readme.html accessible",
                description=(
                    "The default /readme.html ships with every WP install and "
                    "discloses the exact version. Delete it or block via "
                    ".htaccess — removes a free reconnaissance win for attackers."
                ),
                target=origin + "/readme.html",
                tags=["wordpress", "version-disclosure"],
            )
        )

    # REST API user enumeration.
    status, ct, body = await _probe("/wp-json/wp/v2/users")
    if status == 200 and "application/json" in ct:
        try:
            users = json.loads(body)
            if isinstance(users, list) and users:
                slugs = [str(u.get("slug")) for u in users[:10] if u.get("slug")]
                out.append(
                    Finding(
                        tool="wordpress",
                        severity=Severity.HIGH,
                        title=f"WordPress REST API user enumeration ({len(users)} users)",
                        description=(
                            "/wp-json/wp/v2/users returns author slugs without "
                            "authentication. Attackers feed these directly into "
                            "wp-login brute force. Filter the endpoint in "
                            "functions.php or install 'Disable REST API'. "
                            f"Leaked slugs: {', '.join(slugs)}"
                        ),
                        target=origin + "/wp-json/wp/v2/users",
                        tags=["wordpress", "user-enum", "rest-api"],
                        evidence={"user_count": len(users), "sample_slugs": slugs},
                    )
                )
        except (json.JSONDecodeError, ValueError):
            pass

    # xmlrpc.php
    status, ct, body = await _probe("/xmlrpc.php")
    if status in (200, 405):   # 405 is what GET returns — confirms endpoint exists
        out.append(
            Finding(
                tool="wordpress",
                severity=Severity.MEDIUM,
                title="WordPress /xmlrpc.php is reachable",
                description=(
                    "xmlrpc.php enables credential brute-force amplification "
                    "(100 accounts per request) and pingback-based DDoS "
                    "reflection. Disable via .htaccess or a security plugin."
                ),
                target=origin + "/xmlrpc.php",
                tags=["wordpress", "xmlrpc"],
            )
        )

    # Version from generator meta tag.
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([\d.]+)',
                  home_body, re.I)
    if m:
        version = m.group(1)
        out.append(
            Finding(
                tool="wordpress",
                severity=Severity.LOW,
                title=f"WordPress version disclosed in generator meta tag: {version}",
                description=(
                    "The <meta name=\"generator\"> tag announces the exact WP "
                    "version to every scanner. Remove it in functions.php:\n"
                    "  remove_action('wp_head', 'wp_generator');"
                ),
                target=origin,
                tags=["wordpress", "version-disclosure"],
                evidence={"version": version},
            )
        )

    return out
