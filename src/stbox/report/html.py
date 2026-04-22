"""HTML report via Jinja2 template."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from stbox.models import ScanResult


TEMPLATE_DIR = Path(__file__).parent / "templates"

# Autoescape fix: the old select_autoescape(["html"]) only matched file names
# ending in ".html". Our template is "report.html.j2" (final extension .j2),
# so autoescape was SILENTLY DISABLED. Consequence: any finding description
# containing literal HTML (e.g. "<script> tags run unrestricted") broke the
# DOM — the browser opened a script context mid-page and swallowed every
# subsequent finding, leaving only the FIRST one visible (as happened on
# webpagetest.org where 11 findings appeared in Summary but only 1 rendered).
#
# Enable autoescape for every template name that looks HTML-ish, and also
# default-on for string templates. Any place we genuinely need raw HTML
# should use the explicit {{ x | safe }} filter.
_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(
        enabled_extensions=("html", "html.j2", "htm", "xml"),
        default_for_string=True,
    ),
)


def render_html(result: ScanResult) -> str:
    template = _env.get_template("report.html.j2")
    return template.render(
        r=result,
        findings=result.sorted_findings(),
        counts=result.counts_by_severity(),
        counts_by_tool=result.counts_by_tool(),
    )
