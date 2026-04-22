"""JSON report — machine-readable dump of the full ScanResult."""

from __future__ import annotations

import json

from stbox.models import ScanResult


def render_json(result: ScanResult) -> str:
    return result.model_dump_json(indent=2)
