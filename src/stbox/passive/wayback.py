"""Wayback Machine CDX lookup — historical URLs for a domain.

Useful to find old endpoints / parameters that may still be live or
reveal technology that was once deployed. 100% passive: only reads from
web.archive.org.
"""

from __future__ import annotations

from urllib.parse import urlparse, parse_qs

import httpx

from stbox.config import Config
from stbox.models import Finding, Severity


async def query_wayback(domain: str, cfg: Config, limit: int = 500) -> list[Finding]:
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

    out: list[Finding] = []
    params_seen: set[str] = set()
    for row in data[1:] if len(data) > 1 else []:  # first row is header
        orig = row[0] if isinstance(row, list) and row else ""
        if not orig:
            continue
        parsed = urlparse(orig)
        # One finding per unique URL
        out.append(
            Finding(
                tool="wayback",
                severity=Severity.INFO,
                title=f"Historical URL: {orig}",
                target=orig,
                tags=["recon", "passive", "wayback"],
                evidence={"path": parsed.path, "query": parsed.query},
            )
        )
        # Extract parameter names for param-mining
        for k in parse_qs(parsed.query).keys():
            if k not in params_seen:
                params_seen.add(k)
                out.append(
                    Finding(
                        tool="wayback",
                        severity=Severity.INFO,
                        title=f"Historical parameter: {k}",
                        target=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                        tags=["recon", "passive", "param"],
                        evidence={"parameter": k},
                    )
                )
    return out
