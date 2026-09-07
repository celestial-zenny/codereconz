#!/usr/bin/env python3
"""End-to-end check for the three report renderers.

This project has already lost a session to code that was written but never run, so the
reporting layer gets the same treatment as the scanner: one command that proves it works.

Real findings come from the actual pipeline (walk a generated fixture, run the registered
code modules), because renderers that only ever see hand-built objects break the first
time they meet a real one. Hand-built findings are then added for the shapes that
genuinely break renderers and that the fixture cannot produce yet: a live finding with a
`target` and no file at all, a finding with no line number, one with no CWE, a
pathologically long snippet, a module that was skipped, and a module that crashed.

What it asserts:
  * all three renderers run without raising, on a full payload and on an empty one
  * no credential appears in full in any format, checked against the fixture's literals
  * a non-allowlisted `extra` key carrying a raw value does not reach JSON or SARIF
  * skipped and errored modules, with their reasons, are visible in all three
  * JSON parses, carries `schema_version`, and is byte-identical across two renders
  * SARIF parses; every `ruleIndex` resolves; every result has `partialFingerprints`;
    `executionSuccessful` is false; the live finding has no `artifactLocation`; and no
    region anywhere carries `startLine: 0`
  * the terminal renderer works with `rich` and with `rich` forced unavailable, and emits
    no ANSI escapes when `no_color` is set

Run:  python3 dev/smoke_report.py
Exit: 0 if every assertion holds, 1 otherwise.
"""

from __future__ import annotations

import io
import importlib.util
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import smoke  # noqa: E402  - reuse its fixture, so credential literals live in one place

from codereconwork.core.context import Config, ScanContext  # noqa: E402
from codereconwork.core.engine import ModuleResult, run_code_modules, select_modules  # noqa: E402
from codereconwork.core.finding import Confidence, Finding, Severity  # noqa: E402
from codereconwork.core.rules import load_all_builtin  # noqa: E402
from codereconwork.core.walker import collect  # noqa: E402
import codereconwork.modules  # noqa: E402,F401  - populates the module registry
from codereconwork.report import ReportPayload, json_out, sarif, terminal  # noqa: E402

# Whether the optional `rich` extra is present. Both backends must work; only one of them
# can be tested in any given environment, and CI deliberately runs a bare one.
RICH_AVAILABLE = importlib.util.find_spec("rich") is not None

# Values that must never appear in full in any output. Same list smoke.py checks, plus
# one planted inside a non-allowlisted `extra` key. The Slack token is split for the same
# reason as in smoke.py: the joined value is the one under test, but no contiguous
# `xoxb-...` literal sits in this source for GitHub's push protection to reject.
SLACK_TOKEN = "xoxb-123456789012-1234567890" + "123-AbCdEfGhIjKlMnOpQrStUvWx"

FORBIDDEN = [
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    SLACK_TOKEN,
    "s3cr3tP4ssw0rd99",
]
# Planted in `extra["raw_certificate"]`, a key no allowlist knows, to prove `safe_extra`
# fails closed rather than publishing whatever a module happens to attach.
PLANTED_IN_EXTRA = "PRIVATE-KEY-BODY-4c1f9d2b7a3e"

LIVE_RULE = "live.tls.certificate-expiring"

failures: List[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


# --------------------------------------------------------------------------------------
# payload construction
# --------------------------------------------------------------------------------------


def synthetic_findings() -> List[Finding]:
    """The shapes that break renderers."""
    long_snippet = "payload = '" + "A1b2C3d4" * 700 + "'"
    return [
        # No file at all: live recon. Must not acquire an artifactLocation.
        Finding(
            rule_id=LIVE_RULE,
            title="TLS certificate expires in 9 days",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            message="Certificate for api.example.com:443 expires in 9 days.",
            target="api.example.com:443",
            module="live.tls",
            remediation="Renew before expiry; automate it so this is not a calendar entry.",
            cwe="CWE-298",
            tags=["tls", "expiry"],
            extra={
                "detection": "parsed",
                "port": 443,
                "days_remaining": 9,
                # Not allowlisted, and deliberately holding something secret-shaped.
                "raw_certificate": f"-----BEGIN PRIVATE KEY-----{PLANTED_IN_EXTRA}",
            },
        ),
        # A file finding with no line: whole-file property, so no region is possible.
        Finding(
            rule_id="artifact.env-committed",
            title="Environment file committed to the repository",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            message="`.env` is tracked; it is not covered by .gitignore.",
            path="app/.env",
            module="artifacts",
            remediation="Remove from the index, add to .gitignore, rotate anything inside.",
            extra={"detection": "parsed"},
        ),
        # No CWE, and an AST detection, so the detection column has more than one value.
        Finding(
            rule_id="pattern.python.yaml-unsafe-load",
            title="yaml.load without SafeLoader",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            message="yaml.load on untrusted input can construct arbitrary Python objects.",
            path="app/loader.py",
            line=42,
            column=13,
            snippet="config = yaml.load(fh)",
            module="patterns",
            remediation="Use yaml.safe_load.",
            extra={"detection": "ast"},
        ),
        # Pathological snippet length, and a low-severity/low-confidence corner.
        Finding(
            rule_id="secret.generic.high-entropy-string",
            title="High-entropy string",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            message="A long high-entropy literal that may be a credential.",
            path="app/blob.py",
            line=1,
            snippet=long_snippet,
            module="secrets",
            extra={"detection": "regex", "masked": "A1b2...4'"},
        ),
    ]


def run_pipeline(root: Path) -> Tuple[List[ModuleResult], ScanContext, Dict[str, int]]:
    smoke.build_fixture(root)
    files, walk_stats = collect(root, use_gitignore=True)
    ctx = ScanContext(config=Config(root=root), root=root, files=files, walk_stats=walk_stats)
    results = run_code_modules(ctx, select_modules("code", None))
    return results, ctx, walk_stats


def build_payload(root: Path) -> ReportPayload:
    results, ctx, walk_stats = run_pipeline(root)
    real = [f for result in results for f in result.findings]
    check(bool(real), "the real pipeline produced no findings to report on")

    # A module that never ran, and one that crashed. Both must be impossible to miss.
    results = list(results) + [
        ModuleResult(
            name="deps",
            skipped="OSV.dev lookup needs network access, and --offline was requested",
        ),
        ModuleResult(
            name="githist",
            error="CalledProcessError: 'git rev-list' exited 128 (not a git repository)",
            duration=0.02,
        ),
    ]
    ctx.note("module deps skipped: OSV.dev lookup needs network access, and --offline was requested")
    ctx.note("module githist failed: CalledProcessError: 'git rev-list' exited 128")

    finished = time.time()
    return ReportPayload.from_scan(
        module_results=results,
        config=ctx.config,
        command="code",
        findings=real + synthetic_findings(),
        root=root,
        walk_stats=walk_stats,
        notes=ctx.notes,
        routes=[{"method": "POST", "path": "/admin/users", "authenticated": False}],
        live_targets=["api.example.com"],
        rules=load_all_builtin(""),
        started_at=finished - 0.42,
        finished_at=finished,
        suppressed_count=3,
        baseline_path=Path("/home/someone/clients/acme/baseline.json"),
    )


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def render_terminal(payload: ReportPayload) -> str:
    buffer = io.StringIO()
    terminal.render(payload, stream=buffer)
    return buffer.getvalue()


class no_rich:
    """Force the `rich` import to fail, so the fallback painter is genuinely exercised."""

    def __enter__(self) -> "no_rich":
        self.saved = {name: mod for name, mod in sys.modules.items() if name.split(".")[0] == "rich"}
        for name in self.saved:
            del sys.modules[name]
        sys.modules["rich"] = None  # type: ignore[assignment]
        return self

    def __exit__(self, *exc: object) -> None:
        del sys.modules["rich"]
        sys.modules.update(self.saved)


def walk_json(node: Any, path: str = "$") -> Iterator[Tuple[str, Any]]:
    yield path, node
    if isinstance(node, dict):
        for key, value in node.items():
            yield from walk_json(value, f"{path}.{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from walk_json(value, f"{path}[{i}]")


def check_no_leak(label: str, text: str) -> None:
    for value in FORBIDDEN:
        if value in text:
            failures.append(f"{label}: leaked credential {value[:8]}... in full")
    if PLANTED_IN_EXTRA in text:
        failures.append(f"{label}: published a non-allowlisted extra field containing a secret")


# --------------------------------------------------------------------------------------
# checks
# --------------------------------------------------------------------------------------


def check_terminal(payload: ReportPayload) -> None:
    plain_painter_used = False
    with no_rich():
        painter = terminal._make_painter(io.StringIO(), color=False, width=100)
        plain_painter_used = isinstance(painter, terminal._PlainPainter)
        fallback = render_terminal(payload)
    check(plain_painter_used, "forcing rich unavailable did not select the plain painter")
    check("-- findings" in fallback, "fallback renderer did not print the findings section")

    # rich is an optional extra, so a bare environment is a legitimate one to test in --
    # asserting it is installed would make this suite fail on exactly the zero-dependency
    # setup the project promises to support. Exercise the rich path when it is importable
    # and say so plainly when it is not.
    if RICH_AVAILABLE:
        rich_painter = terminal._make_painter(io.StringIO(), color=False, width=100)
        check(type(rich_painter).__name__ == "_RichPainter",
              "rich is installed here but the rich painter was not selected")
        rich_out = render_terminal(payload)
        check(rich_out != fallback, "rich and fallback output are identical; one path is not running")
        variants = (("terminal[rich]", rich_out), ("terminal[plain]", fallback))
    else:
        rich_out = None
        variants = (("terminal[plain]", fallback),)

    for label, text in variants:
        check_no_leak(label, text)
        # Invariant 4: a skipped module and a crashed module, with reasons, in the output.
        check("deps" in text, f"{label}: skipped module 'deps' is not in the output")
        check("--offline" in text, f"{label}: the skip reason is not in the output")
        check("githist" in text, f"{label}: errored module 'githist' is not in the output")
        check("exited 128" in text, f"{label}: the error detail is not in the output")
        check("SCAN INCOMPLETE" in text, f"{label}: no prominent incomplete-scan banner")
        # Invariant 2: both axes, visibly separate.
        check("severity" in text and "confidence" in text, f"{label}: missing an axis heading")
        # Invariant 5: detection method is shown, and differentiated.
        check("via ast" in text, f"{label}: AST findings are not labelled as parsed")
        check("via regex" in text, f"{label}: regex findings are not labelled heuristic")
        check(LIVE_RULE in text and "api.example.com:443" in text,
              f"{label}: the live finding or its target is missing")
        check("app/loader.py:42:13" in text, f"{label}: no clickable path:line:col location")
        longest = max(len(line) for line in text.splitlines())
        check(longest <= 200, f"{label}: a line ran to {longest} chars; long snippets are not clipped")

    # --no-color must emit no escapes at all, in either backend.
    payload.config.no_color = True
    try:
        mono_rich = render_terminal(payload) if RICH_AVAILABLE else ""
        with no_rich():
            mono_plain = render_terminal(payload)
    finally:
        payload.config.no_color = False
    check("\x1b" not in mono_rich, "rich backend emitted ANSI escapes with no_color=True")
    check("\x1b" not in mono_plain, "plain backend emitted ANSI escapes with no_color=True")

    # A StringIO is not a TTY, so colour must already be off without asking.
    check("\x1b" not in (rich_out or "") and "\x1b" not in fallback,
          "escapes were written to a non-TTY stream")

    # Readability at scale: a big scan must not print one line per finding by default.
    big = ReportPayload(
        findings=[
            Finding(
                rule_id="secret.generic.high-entropy-string",
                title="High-entropy string",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                message="candidate",
                path=f"app/file{i}.py",
                line=i + 1,
                snippet="TOKEN = 'ab12...cd (32 chars)'",
                module="secrets",
                extra={"detection": "regex"},
            )
            for i in range(400)
        ]
    )
    capped = render_terminal(big).splitlines()
    big.config.verbose = True
    full = render_terminal(big).splitlines()
    check(len(capped) < 80, f"400 findings printed {len(capped)} lines by default")
    check(len(full) > len(capped), "--verbose did not lift the per-group cap")

    # Empty payload: no findings, no modules, nothing to divide by.
    render_terminal(ReportPayload())


def check_json(payload: ReportPayload) -> Dict[str, Any]:
    first = json_out.render(payload)
    second = json_out.render(payload)
    check(first == second, "two JSON renders of one payload differ; output is not byte-stable")
    check_no_leak("json", first)

    data = json.loads(first)
    check(data.get("schema_version") == json_out.SCHEMA_VERSION, "schema_version missing or wrong")
    check(data["scan"]["complete"] is False, "scan.complete should be false when a module failed")
    check(data["summary"]["execution_successful"] is False,
          "summary.execution_successful should be false when a module failed")
    check(data["scan"]["modules_skipped"] == ["deps"], "scan.modules_skipped is wrong")
    check(data["scan"]["modules_errored"] == ["githist"], "scan.modules_errored is wrong")

    modules = {m["name"]: m for m in data["modules"]}
    check(bool(modules["deps"]["skipped"]), "the skipped module carries no reason in JSON")
    check(bool(modules["githist"]["error"]), "the errored module carries no error text in JSON")
    check(modules["githist"]["duration_scope"] == "exclusive",
          "a module that owned its clock should not be labelled as sharing one")
    # `secrets` and `patterns` are both FileScanModules, so the real pipeline runs them
    # inside one fused pass and they genuinely share its wall clock.
    check(modules["secrets"]["duration_scope"] == "shared-file-pass"
          and modules["patterns"]["duration_scope"] == "shared-file-pass",
          "the fused file pass was not labelled as shared in JSON")

    check(data["summary"]["total"] == len(data["findings"]), "summary.total disagrees with findings")
    check(set(data["summary"]["by_severity"]) == {s.label for s in Severity},
          "by_severity is not zero-filled across every severity")
    check("by_confidence" in data["summary"], "confidence counts are missing from the summary")
    check(bool(data["notes"]), "notes did not reach the JSON report")
    check(data["config"]["root"] == payload.scan_root.name,
          "config.root should be the final path component only")
    check("/home/" not in first, "an absolute local path leaked into the JSON report")
    check(data["config"]["baseline"] == "baseline.json", "the baseline path was not reduced")

    live = [f for f in data["findings"] if f["rule_id"] == LIVE_RULE]
    check(len(live) == 1, "the live finding is missing from JSON")
    if live:
        check("path" not in live[0] and live[0].get("target") == "api.example.com:443",
              "the live finding has a path or lost its target in JSON")
        check(live[0].get("detection") == "parsed", "detection was not lifted to the top level")
        check("raw_certificate" not in live[0].get("extra", {}),
              "a non-allowlisted extra key survived into JSON as a value")
        check("raw_certificate" in live[0].get("extra", {}).get("extra_omitted", []),
              "the dropped extra key was not named in extra_omitted")

    no_line = [f for f in data["findings"] if f["rule_id"] == "artifact.env-committed"]
    check(bool(no_line) and "line" not in no_line[0], "a line number was invented for a file finding")

    # Round-trip through the reader the baseline code will use.
    json_out.parse(first)
    json.loads(json_out.render(ReportPayload()))
    return data


def check_sarif(payload: ReportPayload) -> None:
    first = sarif.render(payload)
    check(first == sarif.render(payload), "two SARIF renders of one payload differ")
    check_no_leak("sarif", first)

    log = json.loads(first)
    check(log.get("version") == "2.1.0", "SARIF version is not 2.1.0")
    check("$schema" in log, "SARIF log has no $schema")
    check(isinstance(log.get("runs"), list) and len(log["runs"]) == 1, "expected exactly one run")
    run = log["runs"][0]

    driver = run["tool"]["driver"]
    for key in ("name", "version", "informationUri", "rules"):
        check(key in driver, f"tool.driver is missing {key}")
    rules = driver["rules"]
    ids = [r["id"] for r in rules]
    check(len(ids) == len(set(ids)), "tool.driver.rules contains duplicate ids")
    check(set(ids) == set(payload.fired_rule_ids()),
          "tool.driver.rules is not exactly the set of rules that fired")
    for descriptor in rules:
        for key in ("name", "shortDescription", "fullDescription", "help", "properties"):
            check(key in descriptor, f"rule {descriptor['id']} is missing {key}")
        props = descriptor["properties"]
        check("tags" in props and "security" in props["tags"],
              f"rule {descriptor['id']} has no security tag")
        sev = props.get("security-severity")
        check(isinstance(sev, str) and float(sev) > 0,
              f"rule {descriptor['id']} has no numeric security-severity string")
        check("level" in descriptor.get("defaultConfiguration", {}),
              f"rule {descriptor['id']} has no defaultConfiguration.level")

    invocation = run["invocations"][0]
    check(invocation["executionSuccessful"] is False,
          "executionSuccessful must be false when a module errored")
    notifications = json.dumps(
        invocation.get("toolExecutionNotifications", [])
        + invocation.get("toolConfigurationNotifications", [])
    )
    check("githist" in notifications, "the errored module is not in the invocation notifications")
    check("deps" in notifications, "the skipped module is not in the invocation notifications")
    check("--offline" in notifications, "the skip reason is not in the SARIF output")

    results = run["results"]
    check(len(results) == payload.total_findings, "SARIF dropped or duplicated results")
    for result in results:
        rid = result["ruleId"]
        index = result.get("ruleIndex")
        check(isinstance(index, int) and 0 <= index < len(rules),
              f"result for {rid} has an out-of-range ruleIndex {index}")
        if isinstance(index, int) and 0 <= index < len(rules):
            check(rules[index]["id"] == rid,
                  f"ruleIndex {index} resolves to {rules[index]['id']}, not {rid}")
        check(bool(result.get("partialFingerprints")), f"result for {rid} has no partialFingerprints")
        check(result.get("level") in ("none", "note", "warning", "error"),
              f"result for {rid} has an invalid level {result.get('level')}")
        check(bool(result.get("message", {}).get("text")), f"result for {rid} has an empty message")
        props = result.get("properties", {})
        check("confidence" in props, f"result for {rid} does not carry confidence in properties")
        check("detection" in props, f"result for {rid} does not carry a detection method")

    # Fingerprints must be the payload's own, and must not encode a line number - that is
    # what lets GitHub's dedup survive a refactor that only moves code.
    expected = {f.fingerprint for f in payload.findings}
    for result in results:
        for key, value in result["partialFingerprints"].items():
            check(isinstance(value, str) and value in expected,
                  f"result for {result['ruleId']} has fingerprint {value!r} that no finding produced")
            check("/" in key or key.endswith("/v1"),
                  f"partialFingerprint key {key!r} should be versioned, e.g. name/v1")

    # The live finding must not have acquired a file location.
    live = [r for r in results if r["ruleId"] == LIVE_RULE]
    check(len(live) == 1, "the live finding is missing from SARIF")
    if live:
        blob = json.dumps(live[0])
        check("artifactLocation" not in blob, "the live finding invented an artifactLocation")
        check("physicalLocation" not in blob, "the live finding invented a physicalLocation")
        logical = live[0]["locations"][0]["logicalLocations"][0]
        check(logical["name"] == "api.example.com:443", "the live target is not in logicalLocations")

    # startLine is 1-based and required inside a region: never 0, never absent.
    for path, node in walk_json(log):
        if isinstance(node, dict) and path.endswith(".region"):
            check("startLine" in node, f"{path} is a region with no startLine")
            check(isinstance(node.get("startLine"), int) and node["startLine"] >= 1,
                  f"{path} has startLine {node.get('startLine')}")
        if isinstance(node, dict) and "startColumn" in node:
            check(node["startColumn"] >= 1, f"{path} has startColumn {node['startColumn']}")
    no_line = [r for r in results if r["ruleId"] == "artifact.env-committed"]
    if no_line:
        physical = no_line[0]["locations"][0]["physicalLocation"]
        check("region" not in physical, "a finding with no line was given a region anyway")
        check(physical["artifactLocation"]["uri"] == "app/.env", "the artifact URI is wrong")

    check("/home/" not in first, "an absolute local path leaked into the SARIF report")

    # Empty payload: a valid, honest, successful log with no results.
    empty = json.loads(sarif.render(ReportPayload()))
    empty_run = empty["runs"][0]
    check(empty_run["results"] == [], "an empty payload produced results")
    check(empty_run["invocations"][0]["executionSuccessful"] is True,
          "an empty scan with no errors should report executionSuccessful true")


def check_shared_duration() -> None:
    """The fused file pass gives several modules one shared clock; nothing may claim it.

    Only one `FileScanModule` is registered today, so the real pipeline cannot produce
    this shape yet - it is constructed here so the renderers are already correct when
    `patterns.py` lands and makes it the normal case.
    """
    elapsed = 0.41
    shared = ReportPayload(
        module_results=[
            ModuleResult(name="secrets", duration=elapsed),
            ModuleResult(name="patterns", duration=elapsed),
            ModuleResult(name="cicd", duration=0.07),
        ]
    )
    groups = shared.shared_duration_groups()
    check(groups == [(elapsed, ["secrets", "patterns"])],
          f"the shared file pass was not detected: {groups}")
    check(shared.duration_is_shared("secrets") and not shared.duration_is_shared("cicd"),
          "duration_is_shared misattributed the shared pass")

    modules = {m["name"]: m for m in json.loads(json_out.render(shared))["modules"]}
    check(modules["secrets"]["duration_scope"] == "shared-file-pass",
          "JSON did not label the shared file pass")
    check(modules["cicd"]["duration_scope"] == "exclusive",
          "JSON labelled an exclusive module as sharing a pass")

    text = render_terminal(shared)
    check("shared pass" in text, "the terminal claimed a per-module wall clock for a fused pass")
    check("0.07s" in text, "the terminal dropped the exclusive module's own timing")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "app"
        root.mkdir()
        payload = build_payload(root)

    print(f"payload:     {payload.total_findings} findings, "
          f"{len(payload.module_results)} module results, "
          f"{len(payload.rules)} rules loaded")
    print(f"             severity {payload.severity_counts_by_label()}")
    print(f"             confidence {payload.confidence_counts_by_label()}")
    print(f"             detection {payload.detection_counts()}")
    print(f"             highest={payload.highest_severity and payload.highest_severity.label} "
          f"errored={payload.any_module_errored} skipped={payload.any_module_skipped} "
          f"at_or_above_high={payload.count_at_or_above(Severity.HIGH)}")
    print(f"             shared duration groups: {payload.shared_duration_groups()}")

    check_terminal(payload)
    check_shared_duration()
    data = check_json(payload)
    check_sarif(payload)

    print("terminal:    "
          + ("rendered via rich and via the forced fallback" if RICH_AVAILABLE
             else "rendered via the fallback only; SKIPPED the rich path (rich not installed)")
          + ", colour-free on a non-TTY stream")
    print(f"json:        schema_version={data['schema_version']}, "
          f"{len(data['findings'])} findings, byte-identical across two renders")
    log = json.loads(sarif.render(payload))
    run = log["runs"][0]
    print(f"sarif:       {len(run['tool']['driver']['rules'])} rule descriptors, "
          f"{len(run['results'])} results, executionSuccessful="
          f"{run['invocations'][0]['executionSuccessful']}")

    print()
    if failures:
        for problem in failures:
            print(f"FAIL: {problem}")
        return 1
    print("PASS: three renderers, no leaks, skips and errors visible, SARIF structurally valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
