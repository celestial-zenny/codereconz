"""SARIF 2.1.0 output.

SARIF is the format that gets consumed by machines nobody in this project controls -
GitHub code scanning, Azure DevOps, VS Code's SARIF viewer - and a SARIF file that is
subtly wrong fails silently: the upload succeeds, the alerts never appear, and everyone
assumes the scanner found nothing. So the details this file is careful about:

* **`security-severity` carries severity, `properties.confidence` carries confidence.**
  GitHub buckets alerts on the numeric `properties["security-severity"]` string, not on
  `level`. Confidence has no native SARIF field, and folding it into `level` would blend
  the two axes the whole tool keeps apart, so it lives in `properties` on each result.
* **`ruleIndex` is only meaningful if it resolves.** The rules array holds exactly one
  entry per rule that actually fired, built once and indexed by id, so every result's
  `ruleIndex` points at a real descriptor.
* **`executionSuccessful` is false when any module errored.** This is the one field that
  lets CI distinguish "clean" from "the scanner crashed and therefore found nothing".
  Skipped and errored modules are also emitted as invocation notifications, because a
  consumer reading only the SARIF must still learn that half the checks did not run.
* **Live findings get no `artifactLocation`.** A DNS or TLS finding is not in a file, and
  pointing it at one would make every downstream tool display a lie. It becomes a
  `logicalLocations` entry naming the network resource instead. The trade-off is real and
  accepted: GitHub's UI centres on file locations, so live results may not surface there.
  Wrong-but-visible is worse than absent.
* **A `region` with `startLine: 0` is invalid.** `startLine` is 1-based and required
  inside a region, so a finding without a line omits the region entirely rather than
  emitting a zero that some validators reject and others silently round.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from ..core.finding import Finding, Severity
from ..core.rules import Rule
from .payload import ReportPayload, _jsonable, detection_of, safe_extra

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
FINGERPRINT_KEY = "codeReconFingerprint/v1"


def render(payload: ReportPayload) -> str:
    """Serialise the payload as a SARIF 2.1.0 log. Newline-terminated."""
    findings = payload.sorted_findings()
    rules, index_of = _build_rules(payload, findings)

    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": payload.tool_name,
                "version": payload.tool_version,
                "semanticVersion": payload.tool_version,
                "informationUri": payload.information_uri,
                "rules": rules,
            }
        },
        # Python string offsets are code points, not UTF-16 code units, and the SARIF
        # default is the latter - so declaring this is the difference between a correct
        # and a subtly shifted column on any line containing an emoji or a CJK character.
        "columnKind": "unicodeCodePoints",
        "automationDetails": {"id": f"{payload.tool_name}/{payload.command}"},
        "invocations": [_invocation(payload)],
        "results": [_result(payload, f, index_of) for f in findings],
        "properties": _run_properties(payload),
    }
    document = {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}
    return json.dumps(document, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


# --------------------------------------------------------------------------------------
# tool.driver.rules
# --------------------------------------------------------------------------------------


def _build_rules(
    payload: ReportPayload, findings: List[Finding]
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """One descriptor per rule that fired, in a stable order.

    Rules are keyed by id and ordered alphabetically so the same scan always produces the
    same indices. Findings from code-implemented checks (the AST analyzer) have no `Rule`
    object at all; their descriptor is synthesised from the strongest finding that fired,
    which is why `_representative` picks by severity then confidence rather than by
    whichever one happened to be first.
    """
    rule_objects = payload.rule_map()
    representative: Dict[str, Finding] = {}
    for finding in findings:
        prior = representative.get(finding.rule_id)
        if prior is None or (finding.severity, finding.confidence) > (
            prior.severity,
            prior.confidence,
        ):
            representative[finding.rule_id] = finding

    descriptors: List[Dict[str, Any]] = []
    index_of: Dict[str, int] = {}
    for rule_id in sorted(representative):
        index_of[rule_id] = len(descriptors)
        descriptors.append(
            _descriptor(
                rule_id,
                rule_objects.get(rule_id),
                representative[rule_id],
                _max_severity(rule_id, findings),
            )
        )
    return descriptors, index_of


def _max_severity(rule_id: str, findings: List[Finding]) -> Severity:
    """Worst severity this rule produced.

    A rule descriptor is per-rule but severity is per-finding, and a module may raise a
    finding above its rule's declared severity. Bucketing on the worst is the safe
    direction: each result still carries its own exact `security-severity`.
    """
    return max(f.severity for f in findings if f.rule_id == rule_id)


def _descriptor(
    rule_id: str, rule: Optional[Rule], sample: Finding, severity: Severity
) -> Dict[str, Any]:
    title = rule.title if rule is not None else sample.title
    description = (rule.message if rule is not None else None) or sample.title
    remediation = (rule.remediation if rule is not None else None) or sample.remediation
    references = list(rule.references) if rule is not None else list(sample.references)
    cwe = (rule.cwe if rule is not None else None) or sample.cwe
    tags = set(rule.tags) if rule is not None else set()
    tags.update(sample.tags)

    descriptor: Dict[str, Any] = {
        "id": rule_id,
        "name": _sarif_name(rule_id),
        "shortDescription": {"text": _one_line(title)},
        "fullDescription": {"text": _one_line(description)},
        "defaultConfiguration": {"level": severity.sarif_level},
        "help": {
            "text": _help_text(remediation, references),
            "markdown": _help_markdown(title, remediation, references),
        },
        "properties": {
            "tags": _tags(tags, cwe, sample),
            # The value GitHub actually buckets on. Not a blend: it is severity alone.
            "security-severity": severity.security_severity,
            "severity": severity.label,
        },
    }
    help_uri = _first_url(references)
    if help_uri:
        descriptor["helpUri"] = help_uri
    if rule is not None:
        # The rule's *declared* confidence, kept separate from severity and from the
        # per-result confidence below.
        descriptor["properties"]["confidence"] = rule.confidence.label
    if cwe:
        descriptor["properties"]["cwe"] = cwe
    return descriptor


def _sarif_name(rule_id: str) -> str:
    """`secret.aws.access-key-id` -> `SecretAwsAccessKeyId`.

    The spec wants `name` to be an identifier-shaped, human-readable token, distinct from
    the opaque stable `id`. Punctuation is the only thing that changes, so the mapping
    stays reversible enough to recognise at a glance.
    """
    parts = [p for p in rule_id.replace("-", " ").replace("_", " ").replace(".", " ").split(" ") if p]
    return "".join(p[:1].upper() + p[1:] for p in parts) or "Rule"


def _tags(tags: Any, cwe: Optional[str], sample: Finding) -> List[str]:
    """Rule tags plus the conventions consumers key off.

    `security` marks the descriptor as a security result, and `external/cwe/cwe-N` is the
    form GitHub renders as a CWE link. The module and detection method are tagged too, so
    a viewer with no access to `properties` can still tell a parsed fact from a regex
    resemblance.
    """
    out = {str(t) for t in tags}
    out.add("security")
    if cwe:
        digits = "".join(ch for ch in cwe if ch.isdigit())
        if digits:
            out.add(f"external/cwe/cwe-{digits}")
    if sample.module:
        out.add(f"module/{sample.module}")
    method = detection_of(sample)
    if method:
        out.add(f"detection/{method}")
    return sorted(out)


def _first_url(references: List[str]) -> Optional[str]:
    """`helpUri` must be a real URL or absent.

    Falling back to the tool's own homepage would make every rule's "learn more" link go
    to the same unhelpful place, which trains people not to click it.
    """
    for ref in references:
        text = str(ref).strip()
        if text.startswith("http://") or text.startswith("https://"):
            return text
    return None


def _help_text(remediation: Optional[str], references: List[str]) -> str:
    parts = [remediation.strip()] if remediation else ["No automated remediation guidance."]
    parts.extend(references)
    return "\n".join(parts)


def _help_markdown(title: str, remediation: Optional[str], references: List[str]) -> str:
    lines = [f"### {_one_line(title)}", ""]
    lines.append(remediation.strip() if remediation else "_No automated remediation guidance._")
    if references:
        lines.extend(["", "**References**", ""])
        lines.extend(f"* {ref}" for ref in references)
    return "\n".join(lines)


# --------------------------------------------------------------------------------------
# results
# --------------------------------------------------------------------------------------


def _result(
    payload: ReportPayload, finding: Finding, index_of: Dict[str, int]
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": index_of[finding.rule_id],
        "level": finding.severity.sarif_level,
        "message": {"text": _one_line(finding.message) or _one_line(finding.title)},
    }
    locations = _locations(finding)
    if locations:
        result["locations"] = locations
    # Excludes line numbers by construction (see `Finding.fingerprint`), which is what
    # keeps GitHub's alert dedup alive across a refactor that only moves code.
    result["partialFingerprints"] = {FINGERPRINT_KEY: finding.fingerprint}
    result["properties"] = _result_properties(finding)
    return result


def _locations(finding: Finding) -> List[Dict[str, Any]]:
    if finding.path:
        # Relative URI with no `uriBaseId`: the only base we could declare is an absolute
        # local path, and publishing `/home/someone/clients/...` in a file that gets
        # attached to a ticket is not worth the resolution hint. Consumers resolve
        # relative URIs against the repository root, which is exactly what these are.
        physical: Dict[str, Any] = {"artifactLocation": {"uri": finding.path}}
        region = _region(finding)
        if region:
            physical["region"] = region
        return [{"physicalLocation": physical}]
    if finding.target:
        return [
            {
                "logicalLocations": [
                    {
                        "name": finding.target,
                        "fullyQualifiedName": finding.target,
                        "kind": "resource",
                    }
                ],
                "message": {"text": f"network target {finding.target}"},
            }
        ]
    # Neither a file nor a target: omit `locations` rather than inventing one. The spec
    # allows a result with no location; it does not allow a location that is not true.
    return []


def _region(finding: Finding) -> Dict[str, Any]:
    """A region, or nothing at all.

    `startLine` is required and 1-based inside a region, so a finding with no line gets no
    region - never `startLine: 0`, which is invalid and which some consumers quietly
    coerce to line 1, moving the alert.
    """
    if finding.line is None or finding.line < 1:
        return {}
    region: Dict[str, Any] = {"startLine": finding.line}
    if finding.column is not None and finding.column >= 1:
        region["startColumn"] = finding.column
    if finding.end_line is not None and finding.end_line > finding.line:
        region["endLine"] = finding.end_line
    if finding.snippet:
        # Already redacted by the producer; passed through untouched, never rebuilt from
        # `extra`, which is the only way a full credential could re-enter the output.
        region["snippet"] = {"text": finding.snippet}
    return region


def _result_properties(finding: Finding) -> Dict[str, Any]:
    props: Dict[str, Any] = {
        # Confidence has no native SARIF home and must not touch `level`.
        "confidence": finding.confidence.label,
        "confidenceRank": int(finding.confidence),
        "severity": finding.severity.label,
        "security-severity": finding.severity.security_severity,
        "module": finding.module or "unknown",
        # Never guessed: absent means the module did not declare one.
        "detection": detection_of(finding) or "unspecified",
    }
    if finding.tags:
        props["tags"] = sorted(finding.tags)
    if finding.cwe:
        props["cwe"] = finding.cwe
    if finding.target:
        props["target"] = finding.target
    if finding.remediation:
        props["remediation"] = _one_line(finding.remediation)
    extra = safe_extra(finding.extra)
    if extra:
        props["extra"] = extra
    return props


# --------------------------------------------------------------------------------------
# invocation and run properties
# --------------------------------------------------------------------------------------


def _invocation(payload: ReportPayload) -> Dict[str, Any]:
    invocation: Dict[str, Any] = {
        # The single field that separates "found nothing" from "crashed and found
        # nothing". CI gates on it.
        "executionSuccessful": not payload.any_module_errored,
    }
    if payload.started_iso:
        invocation["startTimeUtc"] = payload.started_iso
    if payload.finished_iso:
        invocation["endTimeUtc"] = payload.finished_iso

    execution: List[Dict[str, Any]] = []
    configuration: List[Dict[str, Any]] = []
    for result in payload.module_results:
        if result.error:
            execution.append(
                _notification(
                    "error",
                    f"module {result.name} failed and produced no results: {result.error}",
                    f"module/{result.name}/error",
                    result.name,
                )
            )
        elif result.skipped:
            # A skip is a configuration outcome, not a crash - but it is still the reason
            # a whole class of finding is missing from this file.
            configuration.append(
                _notification(
                    "warning",
                    f"module {result.name} did not run: {result.skipped}",
                    f"module/{result.name}/skipped",
                    result.name,
                )
            )
    for note in payload.notes:
        execution.append(_notification("note", note, "scan/note", None))

    if execution:
        invocation["toolExecutionNotifications"] = execution
    if configuration:
        invocation["toolConfigurationNotifications"] = configuration
    return invocation


def _notification(
    level: str, text: str, descriptor_id: str, module: Optional[str]
) -> Dict[str, Any]:
    notification: Dict[str, Any] = {
        "level": level,
        "message": {"text": _one_line(text)},
        "descriptor": {"id": descriptor_id},
    }
    if module:
        notification["properties"] = {"module": module}
    return notification


def _run_properties(payload: ReportPayload) -> Dict[str, Any]:
    """Everything a SARIF-only consumer would otherwise have to guess at.

    The module table lands here in full - name, whether it ran, why it did not, what it
    found - because a reader who has the SARIF and nothing else still needs to know that
    the dependency scanner was skipped.
    """
    props: Dict[str, Any] = {
        "command": payload.command,
        "scanComplete": not payload.scan_incomplete,
        "severityCounts": payload.severity_counts_by_label(),
        "confidenceCounts": payload.confidence_counts_by_label(),
        "detectionCounts": payload.detection_counts(),
        "suppressed": payload.suppressed_count,
        "modules": [
            {
                "name": result.name,
                "ran": result.ran,
                "findings": len(result.findings),
                "skipped": result.skipped,
                "error": result.error,
            }
            for result in payload.module_results
        ],
    }
    if payload.walk_stats:
        props["walkStats"] = {k: payload.walk_stats[k] for k in sorted(payload.walk_stats)}
    if payload.notes:
        props["notes"] = list(payload.notes)
    if payload.live_targets:
        props["targets"] = list(payload.live_targets)
    props["config"] = _jsonable(payload.config_dict())
    return props


def _one_line(text: Optional[str]) -> str:
    """SARIF message text is a single string; collapse whitespace so viewers behave."""
    if not text:
        return ""
    return " ".join(str(text).split())


__all__ = ["render", "SARIF_VERSION", "SARIF_SCHEMA", "FINGERPRINT_KEY"]
