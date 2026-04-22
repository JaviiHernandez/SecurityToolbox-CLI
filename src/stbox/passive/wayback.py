"""Wayback Machine CDX lookup — historical URLs + parameter mining.

Useful to find old endpoints / parameters that may still be live or
reveal technology that was once deployed. 100% passive: only reads from
web.archive.org.

Output philosophy: ONE summary finding with counts + a ranked parameter
list, NOT one finding per URL. A big domain can have 100 000+ archived
URLs — listing every single one drowns the real findings in noise.
The raw URL list is attached as evidence so the HTML/JSON report can
expose it on demand.
"""

from __future__ import annotations

from urllib.parse import urlparse, parse_qs

import httpx

from stbox.config import Config
from stbox.models import Finding, Severity


# Hard caps to keep memory sane on very old / noisy domains.
_MAX_URLS_COLLECTED = 2000
_MAX_URLS_IN_EVIDENCE = 200  # only the first N URLs are kept for the report


async def query_wayback(domain: str, cfg: Config, limit: int = 1000) -> list[Finding]:
    url = (
        f"https://web.archive.org/cdx/search/cdx?"
        f"url={domain}/*&output=json&fl=original&collapse=urlkey&limit={limit}"
    )
    async with httpx.AsyncClient(
        timeout=45, headers={"User-Agent": cfg.user_agent}
    ) as client:
        try:
            r = await client.get(url)
        except httpx.HTTPError as e:
            return [
                Finding(
                    tool="wayback",
                    severity=Severity.INFO,
                    title=f"Wayback query failed: {e}",
                    target=domain,
                    tags=["recon", "passive", "error"],
                )
            ]

    if r.status_code != 200:
        return []
    try:
        data = r.json()
    except Exception:  # noqa: BLE001
        return []

    rows = data[1:] if len(data) > 1 else []  # first row is header
    urls: list[str] = []
    param_freq: dict[str, int] = {}

    for row in rows:
        orig = row[0] if isinstance(row, list) and row else ""
        if not orig:
            continue
        if len(urls) < _MAX_URLS_COLLECTED:
            urls.append(orig)
        # Param frequency across ALL captured URLs — this is the interesting
        # signal (names that keep reappearing are likely still handled by
        # the backend and worth fuzzing with arjun/ffuf later).
        try:
            parsed = urlparse(orig)
            for k in parse_qs(parsed.query).keys():
                param_freq[k] = param_freq.get(k, 0) + 1
        except Exception:  # noqa: BLE001
            continue

    if not urls:
        return []

    # Rank parameters by frequency, truncate the long tail.
    ranked_params = sorted(param_freq.items(), key=lambda kv: kv[1], reverse=True)[:50]

    # Build a single summary finding.
    return [
        Finding(
            tool="wayback",
            severity=Severity.INFO,
            title=(
                f"Wayback Machine: {len(urls)} historical URLs, "
                f"{len(param_freq)} unique parameters"
            ),
            description=(
                "Historical URL enumeration from web.archive.org's CDX API. "
                "Useful for discovering legacy endpoints that may still be "
                "live, and parameter names to feed into active fuzzing tools."
            ),
            target=domain,
            tags=["recon", "passive", "wayback", "summary"],
            evidence={
                "url_count": len(urls),
                "param_count": len(param_freq),
                "top_params": ranked_params[:20],  # [(name, count), ...]
                "sample_urls": urls[:_MAX_URLS_IN_EVIDENCE],
            },
        )
    ]
