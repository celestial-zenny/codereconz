"""Machine-consumable JSON report.

This is the format other things pin to, so two properties matter more than prettiness.

**A version they can pin to.** `schema_version` is the first key in the document.
Anything downstream - a dashboard, a policy gate, a script someone wrote in an afternoon -
gets to check one field and know what shape the rest is. Additive changes bump the minor
number; anything that moves or removes a key bumps the major.

**Byte-stable output.** Two renders of the same scan produce identical bytes, so a report
committed in CI diffs to nothing when nothing changed. Every dict is built in a fixed
order, every map that came from arbitrary producer code gets its keys sorted, and no
identifier includes a memory address or an absolute local path. The only values that
cannot be stable are wall-clock ones, and they are quarantined: `scan.started`,
`scan.finished`, `scan.duration_seconds`, and `modules[].duration_seconds` are the whole
set, so a CI diff can drop that one subtree and compare the rest exactly.

Skips and errors are first-class here, not an afterthought at the bottom: `scan.complete`
and `summary.execution_successful` let a consumer tell "found nothing" from "did not
actually look", which is the distinction a JSON report exists to preserve.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from ..core.engine import ModuleResult
from .payload import ReportPayload, _jsonable, detection_of, finding_dict

SCHEMA_VERSION = "1.0"


def render(payload: ReportPayload) -> str:
    """Serialise the payload. Returns a trailing-newline-terminated JSON document."""
    document: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": {
            "name": payload.tool_name,
            "version": payload.tool_version,
            "information_uri": payload.information_uri,
        },
        "scan": _scan_block(payload),
        "config": payload.config_dict(),
        "summary": _summary_block(payload),
        "findings": [_finding_block(f) for f in payload.sorted_findings()],
        "modules": [_module_block(payload, result) for result in payload.module_results],
        "walk_stats": {k: payload.walk_stats[k] for k in sorted(payload.walk_stats)},
        "notes": list(payload.notes),
        "routes": [_jsonable(route) for route in payload.routes],
    }
    if payload.audit_entries:
        document["audit"] = list(payload.audit_entries)
    # sort_keys stays off on purpose: the order above is deliberate and deterministic,
    # and reading a report top-to-bottom should start with what the scan was.
    return json.dumps(document, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def _scan_block(payload: ReportPayload) -> Dict[str, Any]:
    return {
        "command": payload.command,
        "root": _jsonable(payload.scan_root.name or str(payload.scan_root)),
        "targets": list(payload.live_targets),
        "started": payload.started_iso,
        "finished": payload.finished_iso,
        "duration_seconds": round(payload.duration, 3),
        # False whenever a module skipped or errored: a green report from a scan that did
        # not run half its checks is the failure mode this key exists to prevent.
        "complete": not payload.scan_incomplete,
        "modules_ran": [r.name for r in payload.ran_modules],
        "modules_skipped": [r.name for r in payload.skipped_modules],
        "modules_errored": [r.name for r in payload.errored_modules],
    }


def _summary_block(payload: ReportPayload) -> Dict[str, Any]:
    highest = payload.highest_severity
    return {
        "total": payload.total_findings,
        # Two separate maps, never a blended score: severity is how bad it would be,
        # confidence is how sure we are. Collapsing them is what gets scanners muted.
        "by_severity": payload.severity_counts_by_label(),
        "by_confidence": payload.confidence_counts_by_label(),
        "by_module": dict(sorted(payload.module_counts().items())),
        "by_rule": dict(sorted(payload.rule_counts().items())),
        "by_detection": payload.detection_counts(),
        "highest_severity": highest.label if highest is not None else None,
        "suppressed": payload.suppressed_count,
        "modules_skipped": len(payload.skipped_modules),
        "modules_errored": len(payload.errored_modules),
        "execution_successful": not payload.any_module_errored,
    }


def _finding_block(finding: Any) -> Dict[str, Any]:
    """`Finding.to_dict()` with `extra` sanitised, plus `detection` lifted to the top.

    `detection` is a copy of `extra.detection` promoted to a documented top-level key,
    because whether a finding came from a parsed AST or a regex resemblance is not
    rule-specific trivia - it is how a reader decides how much to believe it.
    """
    block = finding_dict(finding)
    method = detection_of(finding)
    if method:
        block["detection"] = method
    return block


def _module_block(payload: ReportPayload, result: ModuleResult) -> Dict[str, Any]:
    """One module's outcome, with its duration honestly scoped.

    `duration_scope` is `shared-file-pass` when the number is the elapsed time of the
    fused pass that several modules ran inside, and `exclusive` when the module owned
    the clock. Without it, a consumer that sums durations gets a total several times the
    real scan time and concludes the tool is slow.
    """
    shared = payload.duration_is_shared(result.name)
    block: Dict[str, Any] = {
        "name": result.name,
        "ran": result.ran,
        "findings": len(result.findings),
        "duration_seconds": round(result.duration, 3),
        "duration_scope": "shared-file-pass" if shared else "exclusive",
    }
    # Present as explicit nulls rather than omitted: a consumer checking `skipped` should
    # never have to distinguish "key absent" from "did not skip".
    block["skipped"] = result.skipped
    block["error"] = result.error
    block["stats"] = _jsonable(result.stats) if result.stats else {}
    return block


def parse(text: str) -> Dict[str, Any]:
    """Read a report back. Exists so baselining does not re-implement the schema."""
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("report must be a JSON object")
    version = data.get("schema_version")
    if not isinstance(version, str):
        raise ValueError("report is missing schema_version")
    major = version.split(".", 1)[0]
    if major != SCHEMA_VERSION.split(".", 1)[0]:
        raise ValueError(
            f"report schema_version {version} is incompatible with {SCHEMA_VERSION}"
        )
    return data


def findings_of(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = data.get("findings")
    return list(findings) if isinstance(findings, list) else []
