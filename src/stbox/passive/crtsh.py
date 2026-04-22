"""Certificate Transparency lookup via crt.sh. Pure passive subdomain recon."""

from __future__ import annotations

import asyncio

import httpx

from stbox.config import Config
from stbox.models import Finding, Severity


async def query_crtsh(domain: str, cfg: Config) -> list[Finding]:
    """Query crt.sh for certificates mentioning `domain` and extract unique
    subdomains. Returns a list of INFO findings, one per unique hostname.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    async with httpx.AsyncClient(
        timeout=30, headers={"User-Agent": cfg.user_agent}
    ) as client:
        try:
            r = await client.get(url)
        except httpx.HTTPError as e:
            return [
                Finding(
                    tool="crtsh",
                    severity=Severity.INFO,
                    title=f"crt.sh query failed: {e}",
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

    hosts: set[str] = set()
    for entry in data if isinstance(data, list) else []:
        name_value = entry.get("name_value", "")
        for line in name_value.split("\n"):
            h = line.strip().lstrip("*.").lower()
            if not h or h == domain:
                continue
            if h.endswith(f".{domain}") or h == domain:
                hosts.add(h)

    return [
        Finding(
            tool="crtsh",
            severity=Severity.INFO,
            title=f"Subdomain (CT log): {h}",
            target=h,
            tags=["recon", "passive", "ct-log"],
            evidence={"source": "crt.sh"},
        )
        for h in sorted(hosts)
    ]
