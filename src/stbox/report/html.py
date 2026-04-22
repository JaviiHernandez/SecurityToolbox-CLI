"""HTML report via Jinja2 template."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from stbox.models import ScanResult


TEMPLATE_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html"]),
)


def render_html(result: ScanResult) -> str:
    template = _env.get_template("report.html.j2")
    return template.render(
        r=result,
        findings=result.sorted_findings(),
        counts=result.counts_by_severity(),
        counts_by_tool=result.counts_by_tool(),
    )
