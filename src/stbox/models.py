"""Domain models — unified representation of scan findings across every tool."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field, HttpUrl


class Severity(str, Enum):
    """Severity levels, aligned with CVSS-style buckets."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Mode(str, Enum):
    """Scan aggressiveness."""

    PASSIVE = "passive"
    STANDARD = "standard"
    ACTIVE = "active"


class Finding(BaseModel):
    """Unified vulnerability / exposure / informational finding."""

    tool: str
    severity: Severity
    title: str
    description: str = ""
    target: str  # URL, host, or domain
    evidence: dict = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    cvss: float | None = None
    references: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def __str__(self) -> str:
        tag = f"[{self.severity.value.upper()}]"
        return f"{tag} {self.tool}: {self.title} — {self.target}"


class ToolRun(BaseModel):
    """Metadata about a single tool execution."""

    tool: str
    command: str = ""
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    exit_code: int | None = None
    findings_count: int = 0
    status: str = "pending"  # pending | running | done | failed | skipped
    error: str | None = None
    stdout_path: Path | None = None
    stderr_path: Path | None = None


class ScanResult(BaseModel):
    """Top-level scan output. Rendered to HTML / JSON / Markdown."""

    target: str
    mode: Mode
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    subdomains: list[str] = Field(default_factory=list)
    live_hosts: list[str] = Field(default_factory=list)
    tech_stack: dict[str, list[str]] = Field(default_factory=dict)  # host -> [tech]
    tool_runs: list[ToolRun] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    scope_notes: list[str] = Field(default_factory=list)
    permission_ack: bool = False

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.tool, f.title))

    def counts_by_severity(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def counts_by_tool(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.tool] = out.get(f.tool, 0) + 1
        return out
