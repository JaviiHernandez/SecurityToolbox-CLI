"""Orchestrator — runs the pipeline of phases based on scan mode.

Phases (passive → standard → active):
  1. Recon passive          crt.sh, wayback, DNS              every mode
  2. Subdomain enumeration  subfinder                         every mode (if binary)
  3. Live-host filter       httpx                             every mode (if binary)
  4. Content discovery      katana                            standard, active
  5. Vuln scan              nuclei (+tech detect)             every mode
  6. JS libs                retire.js                         every mode
  7. Legacy web scan        nikto                             standard, active
  8. WordPress detect+scan  wpscan (if WP fingerprint)        every mode
  9. Param discovery        arjun                             standard, active
 10. Content brute          feroxbuster                       active only
 11. XSS scan               dalfox                            active only
 12. SQLi scan              sqlmap on arjun-discovered params active only
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from stbox.config import Config
from stbox.models import Finding, Mode, ScanResult, ToolRun
from stbox.passive.crtsh import query_crtsh
from stbox.passive.dns_lookup import dns_recon
from stbox.passive.wayback import query_wayback
from stbox.runners.arjun import ArjunRunner
from stbox.runners.dalfox import DalfoxRunner
from stbox.runners.feroxbuster import FeroxbusterRunner
from stbox.runners.httpx_runner import HttpxRunner
from stbox.runners.katana import KatanaRunner
from stbox.runners.nikto import NiktoRunner
from stbox.runners.nuclei import NucleiRunner
from stbox.runners.retire import RetireRunner
from stbox.runners.sqlmap import SqlmapRunner
from stbox.runners.subfinder import SubfinderRunner
from stbox.runners.wpscan import WpscanRunner
from stbox.scope import check_target, extract_host


logger = logging.getLogger("stbox.orchestrator")


def detect_wordpress(tech_stack: dict[str, list[str]], evidence_blobs: list[dict]) -> bool:
    """Very simple WP detection: look at httpx tech tags + any known WP path."""
    for tags in tech_stack.values():
        for t in tags or []:
            if "wordpress" in str(t).lower():
                return True
    for blob in evidence_blobs:
        tech = blob.get("tech") or []
        if isinstance(tech, list) and any("wordpress" in str(x).lower() for x in tech):
            return True
    return False


async def run_scan(
    target: str,
    mode: Mode,
    cfg: Config,
    *,
    allow_internal: bool = False,
    permission_ack: bool = False,
    console: Console | None = None,
) -> ScanResult:
    console = console or Console()

    # Scope check first — may raise ScopeError.
    normalized, scope_notes = check_target(target, allow_internal=allow_internal)
    host = extract_host(normalized)

    result = ScanResult(
        target=normalized,
        mode=mode,
        scope_notes=scope_notes,
        permission_ack=permission_ack,
    )
    cfg.workdir.mkdir(parents=True, exist_ok=True)

    if mode == Mode.ACTIVE and not permission_ack:
        raise PermissionError(
            "Active mode requires --i-have-permission. Aborting."
        )

    phases: list[tuple[str, callable]] = [
        ("passive: crt.sh", lambda: query_crtsh(host, cfg)),
        ("passive: wayback", lambda: query_wayback(host, cfg)),
        ("passive: DNS", lambda: dns_recon(host, cfg)),
    ]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:

        # ---- Phase 1: pure-python passive recon ----
        task = progress.add_task("Passive recon (crt.sh, wayback, DNS)", total=len(phases))
        passive_results = await asyncio.gather(
            *(coro() for _, coro in phases), return_exceptions=True
        )
        for phase_name, res in zip([p[0] for p in phases], passive_results, strict=False):
            progress.update(task, advance=1)
            if isinstance(res, Exception):
                logger.warning("%s failed: %s", phase_name, res)
                continue
            result.findings.extend(res)

        # Collect subdomains for next phase
        subdomains = {
            f.target for f in result.findings
            if f.tool in {"crtsh"} and "." in f.target
        }
        subdomains.add(host)
        result.subdomains = sorted(subdomains)

        # ---- Phase 2: subfinder (if available) ----
        subfinder = SubfinderRunner(cfg)
        if subfinder.available():
            progress.update(task, description="subfinder")
            run, finds = await subfinder.run(normalized)
            result.tool_runs.append(run)
            result.findings.extend(finds)
            for f in finds:
                subdomains.add(f.target)
            result.subdomains = sorted(subdomains)

        # ---- Phase 3: httpx liveness + tech ----
        httpx_runner = HttpxRunner(cfg)
        if httpx_runner.available() and subdomains:
            progress.add_task("httpx liveness probe", total=None)
            live, meta = await httpx_runner.run_list(sorted(subdomains))
            result.live_hosts = live
            for host_url, md in meta.items():
                tech = md.get("tech") or []
                if isinstance(tech, list) and tech:
                    result.tech_stack[host_url] = list(tech)
                result.findings.append(
                    Finding(
                        tool="httpx",
                        severity="info",  # type: ignore[arg-type]
                        title=f"Live: {host_url} [{md.get('status_code')}]",
                        target=host_url,
                        tags=["recon", "httpx"],
                        evidence=md,
                    )
                )
        else:
            # If httpx binary isn't available, just assume the primary target is live.
            result.live_hosts = [normalized]

        # ---- Phase 4: katana (standard + active) ----
        if mode in (Mode.STANDARD, Mode.ACTIVE):
            katana = KatanaRunner(cfg)
            if katana.available():
                progress.add_task("katana crawler", total=None)
                for lh in result.live_hosts[:5]:    # cap: don't crawl 100 hosts
                    run, finds = await katana.run(lh)
                    result.tool_runs.append(run)
                    result.findings.extend(finds)

        # ---- Phase 5: nuclei ----
        nuclei = NucleiRunner(cfg, mode=mode.value)
        if nuclei.available():
            progress.add_task("nuclei templates", total=None)
            for lh in result.live_hosts[:10]:
                run, finds = await nuclei.run(lh)
                result.tool_runs.append(run)
                result.findings.extend(finds)

        # ---- Phase 6: retire.js ----
        retire = RetireRunner(cfg)
        if retire.available():
            progress.add_task("retire.js (JS libraries)", total=None)
            for lh in result.live_hosts[:5]:
                run, finds = await retire.run(lh)
                result.tool_runs.append(run)
                result.findings.extend(finds)

        # ---- Phase 7: nikto (standard, active) ----
        if mode in (Mode.STANDARD, Mode.ACTIVE):
            nikto = NiktoRunner(cfg)
            if nikto.available():
                progress.add_task("nikto (legacy checks)", total=None)
                for lh in result.live_hosts[:3]:
                    run, finds = await nikto.run(lh)
                    result.tool_runs.append(run)
                    result.findings.extend(finds)

        # ---- Phase 8: wpscan (if WP detected) ----
        evidence_blobs = [f.evidence for f in result.findings if f.tool == "httpx"]
        if detect_wordpress(result.tech_stack, evidence_blobs):
            wp = WpscanRunner(cfg, active=(mode == Mode.ACTIVE))
            if wp.available():
                progress.add_task("wpscan (WordPress detected)", total=None)
                run, finds = await wp.run(normalized)
                result.tool_runs.append(run)
                result.findings.extend(finds)

        # ---- Phase 9: arjun (standard, active) ----
        arjun_targets: list[str] = []
        if mode in (Mode.STANDARD, Mode.ACTIVE):
            arjun = ArjunRunner(cfg)
            if arjun.available():
                progress.add_task("arjun param discovery", total=None)
                for lh in result.live_hosts[:3]:
                    run, finds = await arjun.run(lh)
                    result.tool_runs.append(run)
                    result.findings.extend(finds)
                    # Build sqlmap targets from arjun's findings.
                    for f in finds:
                        p = f.evidence.get("parameter")
                        if p:
                            arjun_targets.append(f"{lh}{'&' if '?' in lh else '?'}{p}=1")

        # ---- Phase 10-12: active only ----
        if mode == Mode.ACTIVE:
            ferox = FeroxbusterRunner(cfg)
            if ferox.available():
                progress.add_task("feroxbuster", total=None)
                for lh in result.live_hosts[:2]:
                    run, finds = await ferox.run(lh)
                    result.tool_runs.append(run)
                    result.findings.extend(finds)

            dalfox = DalfoxRunner(cfg)
            if dalfox.available():
                progress.add_task("dalfox XSS", total=None)
                for lh in result.live_hosts[:2]:
                    run, finds = await dalfox.run(lh)
                    result.tool_runs.append(run)
                    result.findings.extend(finds)

            sqlmap = SqlmapRunner(cfg)
            if sqlmap.available() and arjun_targets:
                progress.add_task("sqlmap (on arjun-discovered params)", total=None)
                for t in arjun_targets[:5]:
                    run, finds = await sqlmap.run(t)
                    result.tool_runs.append(run)
                    result.findings.extend(finds)

    result.finished_at = datetime.now(timezone.utc)
    return result
