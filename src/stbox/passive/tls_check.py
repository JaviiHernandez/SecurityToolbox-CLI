"""TLS certificate + protocol analyzer.

Opens a TCP+TLS connection to the target host, grabs the peer certificate
and negotiated protocol/cipher, and produces findings on expiry, weak
protocol, self-signed, etc. No payloads.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from stbox.config import Config
from stbox.models import Finding, Severity


def _parse_host_port(target: str) -> tuple[str, int]:
    """Accept a URL (https://host[:port]) or bare host[:port]."""
    if "://" in target:
        p = urlparse(target)
        host = p.hostname or ""
        port = p.port or (443 if p.scheme == "https" else 80)
    else:
        if ":" in target:
            host, port_s = target.rsplit(":", 1)
            port = int(port_s)
        else:
            host = target
            port = 443
    return host, port


def _probe_tls(host: str, port: int, timeout: float = 8.0) -> dict | None:
    """Synchronous TLS probe. Returns a dict of {cert, protocol, cipher}
    or None if unreachable / handshake failed."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # we want info even for self-signed

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (OSError, socket.gaierror):
        return None

    try:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert(binary_form=False)
            # getpeercert with verify_mode=CERT_NONE returns an empty dict on
            # some Python versions — fall back to the DER and parse it.
            if not cert:
                der = ssock.getpeercert(binary_form=True)
                if der:
                    cert = _parse_der_cert(der)
            return {
                "protocol": ssock.version(),
                "cipher": ssock.cipher(),  # (name, version, bits)
                "cert": cert,
            }
    except (ssl.SSLError, OSError, socket.timeout):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _parse_der_cert(der: bytes) -> dict:
    """Extract subject/issuer/notAfter/notBefore from a DER cert.
    Falls back to best-effort parsing with cryptography if available."""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        return {"raw_der_length": len(der)}

    try:
        c = x509.load_der_x509_certificate(der, default_backend())
        return {
            "subject": [(a.oid._name, a.value) for a in c.subject],
            "issuer": [(a.oid._name, a.value) for a in c.issuer],
            "notBefore": c.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y GMT")
                if hasattr(c, "not_valid_before_utc") else c.not_valid_before.strftime("%b %d %H:%M:%S %Y GMT"),
            "notAfter": c.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT")
                if hasattr(c, "not_valid_after_utc") else c.not_valid_after.strftime("%b %d %H:%M:%S %Y GMT"),
            "serialNumber": format(c.serial_number, "x"),
        }
    except Exception:  # noqa: BLE001
        return {"raw_der_length": len(der)}


def _tuple_list_get(seq: list[tuple[str, str]] | list[list[tuple[str, str]]] | None,
                    key: str) -> str | None:
    """getpeercert returns subject/issuer as either a list of tuples or a
    list-of-lists-of-tuples depending on how many RDN components there are.
    Normalise to a simple key -> value lookup."""
    if not seq:
        return None
    for item in seq:
        if isinstance(item, (list, tuple)) and item and isinstance(item[0], (list, tuple)):
            for k, v in item:
                if k == key:
                    return v
        elif isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[0], str):
            k, v = item
            if k == key:
                return v
    return None


async def analyze_tls(target: str, cfg: Config) -> list[Finding]:
    host, port = _parse_host_port(target)
    if port == 80:
        # Plain HTTP — nothing to analyse.
        return []

    # Run the synchronous probe in a worker thread so we don't block.
    info = await asyncio.to_thread(_probe_tls, host, port)
    if info is None:
        return [
            Finding(
                tool="tls",
                severity=Severity.INFO,
                title=f"TLS handshake failed against {host}:{port}",
                target=target,
                tags=["tls", "unreachable"],
            )
        ]

    findings: list[Finding] = []
    cert = info.get("cert") or {}
    protocol = info.get("protocol") or ""
    cipher = info.get("cipher") or ()

    # Common name / issuer
    subject_cn = _tuple_list_get(cert.get("subject"), "commonName") or \
                 _tuple_list_get(cert.get("subject"), "CN") or ""
    issuer_cn = _tuple_list_get(cert.get("issuer"), "commonName") or \
                _tuple_list_get(cert.get("issuer"), "CN") or ""
    issuer_o  = _tuple_list_get(cert.get("issuer"), "organizationName") or \
                _tuple_list_get(cert.get("issuer"), "O") or ""

    # Expiry
    not_after_str = cert.get("notAfter")
    days_left: int | None = None
    if not_after_str:
        try:
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            not_after = not_after.replace(tzinfo=timezone.utc)
            delta = (not_after - datetime.now(timezone.utc)).total_seconds()
            days_left = int(delta // 86400)
        except ValueError:
            pass

    if days_left is not None:
        if days_left < 0:
            findings.append(
                Finding(
                    tool="tls",
                    severity=Severity.HIGH,
                    title=f"TLS certificate EXPIRED {abs(days_left)} days ago",
                    description=(
                        "The origin's TLS certificate has expired. Modern "
                        "browsers show a full-page security warning; the site "
                        "is effectively unreachable. Renew immediately."
                    ),
                    target=target,
                    tags=["tls", "cert-expired"],
                    evidence={"notAfter": not_after_str, "days_left": days_left},
                )
            )
        elif days_left < 15:
            findings.append(
                Finding(
                    tool="tls",
                    severity=Severity.MEDIUM,
                    title=f"TLS certificate expires in {days_left} days",
                    description=(
                        "Renew the certificate now. If it's Let's Encrypt, "
                        "verify the auto-renewal cron / systemd timer is "
                        "actually running."
                    ),
                    target=target,
                    tags=["tls", "cert-expiring"],
                    evidence={"notAfter": not_after_str, "days_left": days_left},
                )
            )
        elif days_left < 30:
            findings.append(
                Finding(
                    tool="tls",
                    severity=Severity.LOW,
                    title=f"TLS certificate expires in {days_left} days",
                    target=target,
                    tags=["tls", "cert-renewing-soon"],
                    evidence={"notAfter": not_after_str, "days_left": days_left},
                )
            )

    # Protocol: below TLS 1.2 is outright bad.
    bad_protocols = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
    if protocol in bad_protocols:
        findings.append(
            Finding(
                tool="tls",
                severity=Severity.HIGH,
                title=f"Weak TLS protocol negotiated: {protocol}",
                description=(
                    "The server accepted a legacy TLS/SSL version that is "
                    "considered broken (POODLE, BEAST, etc.). Disable all "
                    "versions below TLS 1.2 in the server config."
                ),
                target=target,
                tags=["tls", "weak-protocol", protocol.lower()],
                evidence={"protocol": protocol, "cipher": list(cipher) if cipher else []},
            )
        )
    elif protocol == "TLSv1.2":
        findings.append(
            Finding(
                tool="tls",
                severity=Severity.LOW,
                title="TLS 1.2 in use — consider upgrading to TLS 1.3",
                description=(
                    "TLS 1.3 is faster (1 RTT vs 2), has forward secrecy "
                    "mandatory, and removes every broken cipher. Enable it "
                    "in your web server — every modern browser supports it."
                ),
                target=target,
                tags=["tls", "tls-1.2"],
                evidence={"protocol": protocol, "cipher": list(cipher) if cipher else []},
            )
        )

    # Summary finding with everything attached (INFO).
    findings.append(
        Finding(
            tool="tls",
            severity=Severity.INFO,
            title=f"TLS: {protocol or '?'} via {issuer_o or issuer_cn or '?'}",
            target=target,
            tags=["tls", "summary"],
            evidence={
                "protocol": protocol,
                "cipher": list(cipher) if cipher else [],
                "subject_cn": subject_cn,
                "issuer_cn": issuer_cn,
                "issuer_o": issuer_o,
                "notBefore": cert.get("notBefore"),
                "notAfter": cert.get("notAfter"),
                "days_left": days_left,
            },
        )
    )

    return findings
