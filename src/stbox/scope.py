"""Scope validation — reject targets we must not scan without explicit opt-in.

Hard blocks:
  * .mil and .gov / .gob TLDs (never, even with --i-have-permission)
  * localhost, 127.0.0.0/8, ::1, link-local
  * RFC1918 private IPs (10/8, 172.16/12, 192.168/16) unless --allow-internal
  * Common SaaS control planes (aws.amazon.com, azure.com, gcp...) unless opted-in
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

import tldextract


BLOCKED_TLDS = {"mil", "gov", "gob"}

# Hosts we refuse to touch even with --i-have-permission, because blasting them
# will flag abuse reports for entire cloud providers.
BLOCKED_SAAS_HOSTS = {
    "console.aws.amazon.com",
    "portal.azure.com",
    "console.cloud.google.com",
}


class ScopeError(Exception):
    """Raised when a target is out of scope and must be refused."""


def normalize_target(target: str) -> str:
    """Accept a URL or bare hostname and return `scheme://host[:port]`."""
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    if not parsed.hostname:
        raise ScopeError(f"invalid target: {target!r}")
    return target


def extract_host(target: str) -> str:
    return urlparse(normalize_target(target)).hostname or ""


def is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
    )


def check_target(
    target: str,
    *,
    allow_internal: bool = False,
    force: bool = False,
) -> tuple[str, list[str]]:
    """Return (normalized_target, notes). Raise ScopeError if blocked.

    `force=True` silences soft warnings but cannot bypass BLOCKED_TLDS or
    BLOCKED_SAAS_HOSTS — those are hard refusals.
    """
    normalized = normalize_target(target)
    host = extract_host(normalized).lower()
    notes: list[str] = []

    # Hard blocks — never overridable. Check every label of the suffix so
    # both `foo.mil` (suffix="mil") and `foo.gob.es` (suffix="gob.es") match.
    ext = tldextract.extract(host)
    suffix_labels = set(ext.suffix.split(".")) if ext.suffix else set()
    if suffix_labels & BLOCKED_TLDS:
        raise ScopeError(
            f"refusing to scan {host!r}: .{ext.suffix} is in the hard-block TLD list"
        )
    if host in BLOCKED_SAAS_HOSTS:
        raise ScopeError(f"refusing to scan {host!r}: SaaS control-plane host")

    # Private / loopback / reserved IPs.
    if is_private_ip(host):
        if not allow_internal:
            raise ScopeError(
                f"refusing to scan internal/private address {host!r}. "
                "Pass --allow-internal if this is your own lab."
            )
        notes.append(f"internal target {host} allowed via --allow-internal")

    # Soft warnings
    if host.endswith((".edu", ".edu.es", ".ac.uk", ".ac.jp")):
        notes.append(
            f"{host} is an academic TLD — make sure you have written authorization"
        )

    if not force and ext.suffix == "":
        notes.append(f"{host} has no public suffix — may be internal; proceed with care")

    return normalized, notes
