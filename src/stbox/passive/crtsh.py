"""Certificate Transparency lookup via crt.sh. Pure passive subdomain recon.

Returns ONE summary finding with the full deduplicated subdomain list in
evidence. A single INFO per unique hostname (the old behaviour) made a
big org like webpagetest.org produce 500+ findings of no individual
importance — the value of CT enumeration is the list, not each entry.
"""

from __future__ import annotations

import httpx

from stbox.config import Config
from stbox.models import Finding, Severity


async def query_crtsh(domain: str, cfg: Config) -> list[Finding]:
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

    sorted_hosts = sorted(hosts)
    if not sorted_hosts:
        return []

    return [
        Finding(
            tool="crtsh",
            severity=Severity.INFO,
            title=f"Certificate Transparency: {len(sorted_hosts)} subdomains discovered",
            description=(
                "Subdomain enumeration via crt.sh's Certificate Transparency "
                "log search. Every name returned was at some point certified "
                "by a public CA and is permanently discoverable. The target "
                "domain saw zero traffic — purely passive reconnaissance."
            ),
            target=domain,
            tags=["recon", "passive", "ct-log", "summary"],
            evidence={
                "source": "crt.sh",
                "count": len(sorted_hosts),
                "subdomains": sorted_hosts,
            },
        )
    ]
