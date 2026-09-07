"""Report renderers: terminal, JSON, and SARIF 2.1.0.

All three take the same `ReportPayload`, which the CLI assembles once. Nothing in here
computes a fact about the scan that another renderer computes differently - counts,
"did anything error", "what is the worst thing here" are all payload methods, so the
three formats cannot disagree about the same scan.

The three renderers are imported as modules rather than re-exported as bare `render`
functions, because three functions with the same name and different return types
(`None`, `str`, `str`) would be a trap:

    from codereconwork.report import ReportPayload, json_out, sarif, terminal

    payload = ReportPayload(...)
    terminal.render(payload)              # writes to a stream
    Path("report.json").write_text(json_out.render(payload))
    Path("report.sarif").write_text(sarif.render(payload))
"""

from __future__ import annotations

from . import json_out, sarif, terminal
from .payload import (
    CONFIDENCE_ORDER,
    SEVERITY_ORDER,
    TOOL_NAME,
    ReportPayload,
    detection_of,
    finding_dict,
    safe_extra,
)

__all__ = [
    "CONFIDENCE_ORDER",
    "ReportPayload",
    "SEVERITY_ORDER",
    "TOOL_NAME",
    "detection_of",
    "finding_dict",
    "json_out",
    "safe_extra",
    "sarif",
    "terminal",
]
