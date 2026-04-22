"""Async DNS recon — A/AAAA/MX/NS/TXT/SOA/CAA with actionable findings only.

Emits ONE summary finding with every record in evidence, plus LOW findings
for missing SPF/DMARC (real email-security issues). The old behaviour of
one INFO per DNS record flooded the report with 10-15 near-useless rows.
"""

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

    records: dict[str, list[str]] = {rtype: [] for rtype in RECORD_TYPES}
    has_spf = False
    has_dmarc = False
    dmarc_value: str | None = None

    for rtype in RECORD_TYPES:
        try:
            answers = await resolver.resolve(domain, rtype)
        except (dns.exception.DNSException, Exception):  # noqa: BLE001
            continue
        for rr in answers:
            value = rr.to_text().strip('"')
            records[rtype].append(value)
            if rtype == "TXT" and value.lower().startswith("v=spf1"):
                has_spf = True

    # DMARC lives at _dmarc.<domain>
    try:
        dmarc_answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rr in dmarc_answers:
            val = rr.to_text().strip('"')
            if val.lower().startswith("v=dmarc1"):
                has_dmarc = True
                dmarc_value = val
                break
    except (dns.exception.DNSException, Exception):  # noqa: BLE001
        pass

    # Filter empty record types out of the evidence dict.
    records_present = {k: v for k, v in records.items() if v}

    findings: list[Finding] = []

    # Single summary finding with every record attached.
    if records_present:
        summary_bits = []
        for rt in ("A", "AAAA", "MX", "NS", "TXT"):
            n = len(records.get(rt) or [])
            if n:
                summary_bits.append(f"{n} {rt}")
        findings.append(
            Finding(
                tool="dns",
                severity=Severity.INFO,
                title=f"DNS records ({', '.join(summary_bits)})",
                description=(
                    "Authoritative DNS records resolved for this domain. "
                    "Individual record values are attached as evidence."
                ),
                target=domain,
                tags=["dns", "summary"],
                evidence={
                    "records": records_present,
                    "has_dmarc": has_dmarc,
                    "dmarc_record": dmarc_value,
                    "has_spf": has_spf,
                },
            )
        )

    # Real issues — email spoofing prevention.
    has_mx = bool(records.get("MX"))
    if has_mx and not has_spf:
        findings.append(
            Finding(
                tool="dns",
                severity=Severity.MEDIUM,
                title="No SPF record — domain is spoofable as an email sender",
                description=(
                    "The domain accepts email (MX is configured) but publishes "
                    "no SPF record. Any internet host can send mail claiming "
                    "to be @{0} and no gateway will reject it on SPF grounds. "
                    "Publish a strict SPF (-all) that covers your actual "
                    "sending infrastructure.".format(domain)
                ),
                target=domain,
                tags=["dns", "email-security", "missing-spf"],
            )
        )
    if has_mx and not has_dmarc:
        findings.append(
            Finding(
                tool="dns",
                severity=Severity.MEDIUM,
                title="No DMARC record — receiver policy unknown",
                description=(
                    "Without DMARC, mail receivers (Gmail, Outlook) have no "
                    "instruction for what to do when SPF/DKIM fail. Start "
                    "with 'v=DMARC1; p=none; rua=mailto:dmarc@{0}' to collect "
                    "reports, then ramp up to p=quarantine and p=reject."
                    .format(domain)
                ),
                target=domain,
                tags=["dns", "email-security", "missing-dmarc"],
            )
        )

    # AAAA/IPv6: informational, but only if A exists (i.e., domain IS live).
    if records.get("A") and not records.get("AAAA"):
        findings.append(
            Finding(
                tool="dns",
                severity=Severity.LOW,
                title="IPv6 (AAAA) record missing",
                description=(
                    "The domain resolves over IPv4 but publishes no AAAA "
                    "record. Not critical in 2025, but ~45% of internet "
                    "users reach sites over IPv6 when available."
                ),
                target=domain,
                tags=["dns", "ipv6", "missing-aaaa"],
            )
        )

    return findings
