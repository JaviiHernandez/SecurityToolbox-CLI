"""Async DNS recon — A/AAAA/MX/NS/TXT/SOA/CAA."""

from __future__ import annotations

import dns.asyncresolver
import dns.exception

from stbox.config import Config
from stbox.models import Finding, Severity


RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA")


async def dns_recon(domain: str, cfg: Config) -> list[Finding]:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    findings: list[Finding] = []
    has_spf = False
    has_dmarc = False

    for rtype in RECORD_TYPES:
        try:
            answers = await resolver.resolve(domain, rtype)
        except (dns.exception.DNSException, Exception):  # noqa: BLE001
            continue
        for rr in answers:
            value = rr.to_text().strip('"')
            if rtype == "TXT" and value.lower().startswith("v=spf1"):
                has_spf = True
            findings.append(
                Finding(
                    tool="dns",
                    severity=Severity.INFO,
                    title=f"DNS {rtype}: {value}",
                    target=domain,
                    tags=["dns", rtype.lower()],
                    evidence={"type": rtype, "value": value, "ttl": answers.rrset.ttl},
                )
            )

    # DMARC lives at _dmarc.<domain>
    try:
        dmarc = await resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rr in dmarc:
            has_dmarc = True
            findings.append(
                Finding(
                    tool="dns",
                    severity=Severity.INFO,
                    title=f"DMARC: {rr.to_text().strip(chr(34))}",
                    target=domain,
                    tags=["dns", "dmarc"],
                )
            )
    except (dns.exception.DNSException, Exception):  # noqa: BLE001
        pass

    if not has_spf:
        findings.append(
            Finding(
                tool="dns",
                severity=Severity.LOW,
                title="No SPF record — domain may be spoofable",
                target=domain,
                tags=["dns", "email-security", "missing-spf"],
            )
        )
    if not has_dmarc:
        findings.append(
            Finding(
                tool="dns",
                severity=Severity.LOW,
                title="No DMARC record — email auth not enforced",
                target=domain,
                tags=["dns", "email-security", "missing-dmarc"],
            )
        )
    return findings
