"""Command line entry point.

The CLI's job is to turn flags into a `Config`, run the right modules, and hand one
`ReportPayload` to the renderers. It deliberately contains no detection logic: anything
that decides whether something is a finding lives in a module, so the same scan can be
driven from Python without going through `argparse`.

Three decisions here are load-bearing.

**Exit codes are a contract with CI**, not decoration. `0` clean, `1` the severity
threshold was breached, `2` the tool itself had a problem. The third one exists because
"found nothing" and "the scanner crashed and therefore found nothing" look identical to
a pipeline that only checks for a non-zero status, and conflating them is how a broken
scanner sits green in CI for months. A module that errors forces `2` even when findings
were also reported, because the run was incomplete and its silence cannot be trusted.

**Live recon refuses to start rather than asking forgiveness.** `--authorized` and a
non-empty `--scope` are checked before a single packet moves, and the check lives here
rather than in the live modules so there is exactly one place to audit it.

**Reports are written even when the scan is going to fail the build.** Writing the SARIF
file only on success would mean the one run you most want to inspect is the one that
left no artifact behind.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import __version__
from .core.context import AuditLog, Config, LiveContext, ScanContext, ScopeGuard
from .core.engine import ModuleResult, REGISTRY, run_code_modules, run_live_modules, select_modules
from .core.finding import Confidence, Finding, Severity, dedupe
from .core.rules import RuleError, load_all_builtin, load_pack
from .core.walker import DEFAULT_MAX_BYTES, collect
from .report import ReportPayload, json_out, sarif, terminal

# Importing the modules package is what populates the registry, via @register side
# effects. Without this the CLI would run a scan with zero modules and cheerfully
# report success.
from . import modules as _modules  # noqa: F401

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

PROG = "recon"


# --------------------------------------------------------------------------------------
# Optional pieces
# --------------------------------------------------------------------------------------
#
# `core.suppress` is imported lazily and tolerated as missing. Baselining is a feature of
# the CLI, not a prerequisite for scanning: if the module is absent the scan still runs
# correctly and the user is told plainly that suppression was unavailable, rather than
# the whole tool failing to start over a feature they did not ask for.


def _suppress_module() -> Optional[Any]:
    try:
        from .core import suppress  # type: ignore[attr-defined]
    except ImportError:
        return None
    return suppress


# --------------------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------------------


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _confidence(value: str) -> Confidence:
    try:
        return Confidence.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def _size(value: str) -> int:
    """Accept `4194304`, `4m`, `512k`. File-size flags in bytes are unusable otherwise."""
    text = value.strip().lower()
    multiplier = 1
    if text.endswith(("k", "kb")):
        multiplier, text = 1024, text.rstrip("b").rstrip("k")
    elif text.endswith(("m", "mb")):
        multiplier, text = 1024 * 1024, text.rstrip("b").rstrip("m")
    elif text.endswith(("g", "gb")):
        multiplier, text = 1024 * 1024 * 1024, text.rstrip("b").rstrip("g")
    try:
        number = float(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not a size (try 4m, 512k)") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("size must be positive")
    return int(number * multiplier)


def _add_output_flags(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("output")
    group.add_argument("--json", metavar="PATH", help="write a JSON report to PATH ('-' for stdout)")
    group.add_argument("--sarif", metavar="PATH", help="write a SARIF 2.1.0 report to PATH")
    group.add_argument("--quiet", action="store_true", help="suppress the terminal report")
    group.add_argument("--no-color", action="store_true", help="never emit ANSI colour")
    group.add_argument("-v", "--verbose", action="store_true", help="show every finding and detail")
    group.add_argument(
        "--fail-on",
        type=_severity,
        default=Severity.HIGH,
        metavar="SEVERITY",
        help="exit 1 when a finding at or above this severity survives (default: high)",
    )
    group.add_argument(
        "--no-fail",
        action="store_true",
        help="always exit 0 unless the tool itself errored; for exploratory runs",
    )


def _add_rule_flags(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("rule selection")
    group.add_argument(
        "--rules",
        action="append",
        default=[],
        metavar="PATH",
        help="load an additional rule pack (repeatable)",
    )
    group.add_argument(
        "--enable-rule",
        action="append",
        default=[],
        metavar="ID",
        help="run only these rule ids or family prefixes (repeatable)",
    )
    group.add_argument(
        "--disable-rule",
        action="append",
        default=[],
        metavar="ID",
        help="skip these rule ids or family prefixes (repeatable)",
    )
    group.add_argument("--min-severity", type=_severity, metavar="SEVERITY")
    group.add_argument("--min-confidence", type=_confidence, metavar="CONFIDENCE")


def _add_scan_flags(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("traversal")
    group.add_argument("-j", "--jobs", type=_positive_int, default=0, help="0 = auto")
    group.add_argument("--max-bytes", type=_size, default=DEFAULT_MAX_BYTES, metavar="SIZE")
    group.add_argument(
        "--no-gitignore",
        action="store_true",
        help="scan files git would ignore (build output, vendored code)",
    )
    group.add_argument("--include-minified", action="store_true")
    group.add_argument("--follow-symlinks", action="store_true")
    group.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    group.add_argument("--exclude-dir", action="append", default=[], metavar="NAME")

    group = parser.add_argument_group("modules")
    group.add_argument(
        "--module",
        action="append",
        default=[],
        metavar="NAME",
        help="run only these modules (repeatable; prefixes work, e.g. 'live')",
    )
    group.add_argument("--fast", action="store_true", help="skip rules marked expensive")
    group.add_argument("--offline", action="store_true", help="never touch the network")
    group.add_argument(
        "--history-depth", type=_positive_int, default=300, metavar="N",
        help="commits of git history to search (default: 300)",
    )
    group.add_argument(
        "--max-per-rule", type=_positive_int, default=20, metavar="N",
        help="cap findings per rule per file (default: 20)",
    )
    group.add_argument(
        "--verify-secrets",
        action="store_true",
        help="validate found credentials against their provider. This TRANSMITS the "
             "credential to a third party; off by default for that reason.",
    )

    group = parser.add_argument_group("suppression")
    group.add_argument("--baseline", metavar="PATH", help="suppress findings recorded in PATH")
    group.add_argument(
        "--no-inline-suppression",
        action="store_true",
        help="ignore '# coderecon:ignore' comments",
    )


def _add_live_flags(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("live recon (gated)")
    group.add_argument(
        "--authorized",
        action="store_true",
        help="confirm you have written authorization to probe these targets. Required.",
    )
    group.add_argument(
        "--scope",
        action="append",
        default=[],
        metavar="HOST|CIDR",
        help="allowlist of what may be touched. Required, and enforced on every "
             "connection including hosts discovered mid-scan.",
    )
    group.add_argument("--ports", default="top100", metavar="SPEC")
    group.add_argument("--timeout", type=float, default=5.0, metavar="SECONDS")
    group.add_argument("--max-concurrency", type=_positive_int, default=16, metavar="N")
    group.add_argument(
        "--rate-limit", type=float, default=0.0, metavar="SECONDS",
        help="minimum delay between requests to one host (default: 0)",
    )
    group.add_argument("--audit-log", metavar="PATH", help="append every host/port touched to PATH")
    group.add_argument("--no-subdomain-discovery", action="store_true")
    group.add_argument("--no-http-paths", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Security reconnaissance for codebases and the surface they expose.",
        epilog="Exit codes: 0 clean, 1 findings at or above --fail-on, 2 tool error.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subs = parser.add_subparsers(dest="command", metavar="COMMAND")

    code = subs.add_parser("code", help="scan a codebase on disk")
    code.add_argument("path", nargs="?", default=".", help="directory or file (default: .)")
    _add_scan_flags(code)
    _add_rule_flags(code)
    _add_output_flags(code)

    live = subs.add_parser("live", help="probe live targets (requires --authorized and --scope)")
    live.add_argument("targets", nargs="+", metavar="TARGET")
    _add_live_flags(live)
    _add_rule_flags(live)
    _add_output_flags(live)

    full = subs.add_parser("full", help="scan a codebase, then probe the given targets")
    full.add_argument("path", nargs="?", default=".", help="directory or file (default: .)")
    full.add_argument("--target", action="append", default=[], metavar="TARGET", required=True)
    _add_scan_flags(full)
    _add_live_flags(full)
    _add_rule_flags(full)
    _add_output_flags(full)

    rules = subs.add_parser("rules", help="list the detection rules and checks")
    rules.add_argument("--json", action="store_true", help="machine-readable listing")
    rules.add_argument("--search", metavar="TEXT", help="filter by id, title, or tag")
    rules.add_argument("--rules", action="append", default=[], metavar="PATH")

    baseline = subs.add_parser("baseline", help="record current findings so CI reports only new ones")
    baseline.add_argument("path", nargs="?", default=".", help="directory or file (default: .)")
    baseline.add_argument(
        "-o", "--out", default=".coderecon-baseline.json", metavar="PATH",
        help="where to write the baseline (default: .coderecon-baseline.json)",
    )
    _add_scan_flags(baseline)
    _add_rule_flags(baseline)
    baseline.add_argument("--no-color", action="store_true")
    baseline.add_argument("-v", "--verbose", action="store_true")

    return parser


# --------------------------------------------------------------------------------------
# Flags -> Config
# --------------------------------------------------------------------------------------


def config_from_args(args: argparse.Namespace, root: Path) -> Config:
    """Translate parsed flags into a `Config`.

    `getattr` with defaults throughout, because each subcommand exposes a different slice
    of the flags and `Config` has to be constructible from any of them.
    """
    fail_on: Optional[Severity] = getattr(args, "fail_on", Severity.HIGH)
    if getattr(args, "no_fail", False):
        fail_on = None

    return Config(
        root=root,
        jobs=getattr(args, "jobs", 0),
        max_bytes=getattr(args, "max_bytes", DEFAULT_MAX_BYTES),
        use_gitignore=not getattr(args, "no_gitignore", False),
        include_minified=getattr(args, "include_minified", False),
        excludes=list(getattr(args, "exclude", []) or []),
        exclude_dirs=list(getattr(args, "exclude_dir", []) or []),
        follow_symlinks=getattr(args, "follow_symlinks", False),
        fast=getattr(args, "fast", False),
        offline=getattr(args, "offline", False),
        modules=list(getattr(args, "module", []) or []) or None,
        enable_rules=list(getattr(args, "enable_rule", []) or []),
        disable_rules=list(getattr(args, "disable_rule", []) or []),
        min_severity=getattr(args, "min_severity", None),
        min_confidence=getattr(args, "min_confidence", None),
        rule_packs=[Path(p) for p in (getattr(args, "rules", []) or [])],
        history_depth=getattr(args, "history_depth", 300),
        max_findings_per_rule_per_file=getattr(args, "max_per_rule", 20),
        verify_secrets=getattr(args, "verify_secrets", False),
        authorized=getattr(args, "authorized", False),
        scope=list(getattr(args, "scope", []) or []),
        ports=getattr(args, "ports", "top100"),
        timeout=getattr(args, "timeout", 5.0),
        max_concurrency=getattr(args, "max_concurrency", 16),
        rate_limit=getattr(args, "rate_limit", 0.0),
        audit_log=Path(args.audit_log) if getattr(args, "audit_log", None) else None,
        live_http_paths=not getattr(args, "no_http_paths", False),
        subdomain_discovery=not getattr(args, "no_subdomain_discovery", False),
        baseline=Path(args.baseline) if getattr(args, "baseline", None) else None,
        fail_on=fail_on,
        no_color=getattr(args, "no_color", False),
        verbose=getattr(args, "verbose", False),
    )


class CliError(Exception):
    """A problem with how the tool was invoked. Always exits 2, never a traceback."""


def _resolve_root(raw: str) -> Path:
    root = Path(raw).expanduser()
    if not root.exists():
        raise CliError(f"{raw}: no such file or directory")
    return root.resolve()


def _progress(config: Config, stream: Any) -> Optional[Callable[[str], None]]:
    """Progress goes to stderr, so `--json -` stays a clean pipe on stdout."""
    if config.verbose:
        return lambda name: print(f"  running {name}...", file=stream, flush=True)
    return None


# --------------------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------------------


def _walk(config: Config, root: Path) -> Tuple[List[Any], Dict[str, int]]:
    return collect(
        root,
        excludes=config.excludes,
        exclude_dirs=config.exclude_dirs,
        max_bytes=config.max_bytes,
        use_gitignore=config.use_gitignore,
        include_minified=config.include_minified,
        follow_symlinks=config.follow_symlinks,
    )


def _active_rules(config: Config) -> List[Any]:
    """Every rule this run could fire, for SARIF's `tool.driver.rules[]`.

    Loaded unfiltered on purpose: the payload uses this as a metadata lookup keyed by the
    ids that actually fired, and a rule that fired is by definition one that survived
    filtering. Reproducing the per-module filtering here would only risk disagreeing
    with it.
    """
    rules = load_all_builtin("")
    for extra in config.rule_packs:
        rules.extend(load_pack(extra))
    return rules


def run_code_scan(
    config: Config,
    root: Path,
    *,
    stderr: Any,
) -> Tuple[List[ModuleResult], ScanContext, Dict[str, int]]:
    files, walk_stats = _walk(config, root)
    ctx = ScanContext(config=config, root=root, files=files, walk_stats=walk_stats)
    if not files:
        # An empty scan that prints "no issues" is the most dangerous output this tool
        # can produce, so it is called out rather than left to be inferred from a zero.
        ctx.note(
            f"no scannable files were found under {root} - everything was excluded, "
            f"ignored, binary, or empty"
        )
    try:
        selected = select_modules("code", config.modules)
    except ValueError as exc:
        raise CliError(str(exc)) from exc
    if not selected:
        raise CliError(
            f"--module selected nothing runnable in the code phase. "
            f"Available: {', '.join(sorted(REGISTRY))}"
        )
    results = run_code_modules(ctx, selected, progress=_progress(config, stderr))
    return results, ctx, walk_stats


def run_live_scan(
    config: Config,
    targets: Sequence[str],
    *,
    stderr: Any,
    routes: Optional[Sequence[Dict[str, Any]]] = None,
) -> Tuple[List[ModuleResult], LiveContext]:
    """Run the live phase. Refuses to start unless the gate is fully satisfied."""
    _require_live_authorization(config, targets)

    scope = ScopeGuard(config.scope)
    audit = AuditLog(config.audit_log)
    ctx = LiveContext(
        config=config,
        targets=list(targets),
        scope=scope,
        audit=audit,
        routes=[dict(r) for r in (routes or [])],
    )
    try:
        selected = select_modules("live", config.modules)
    except ValueError as exc:
        audit.close()
        raise CliError(str(exc)) from exc
    if not selected:
        # Not an error: the live modules are simply not built yet. Saying so is the
        # difference between "nothing to report" and "nothing was checked".
        ctx.note(
            "no live modules are available in this build, so no target was probed. "
            "Nothing in this report describes the live attack surface."
        )
        audit.close()
        return [], ctx
    try:
        results = run_live_modules(ctx, selected, progress=_progress(config, stderr))
    finally:
        audit.close()
    return results, ctx


def _require_live_authorization(config: Config, targets: Sequence[str]) -> None:
    """The gate. Every refusal here is deliberate and none of them are warnings.

    Checked before any socket is opened, and kept in one function so that "what stops
    this tool touching something it should not" has a single answer during review.
    """
    if not config.authorized:
        raise CliError(
            "live recon requires --authorized. Pass it only if you have written "
            "permission to probe these targets; scanning hosts you do not own is "
            "unlawful in most jurisdictions."
        )
    if not config.scope:
        raise CliError(
            "live recon requires at least one --scope entry (host or CIDR). The scope "
            "is enforced on every connection, including hosts discovered during the "
            "scan, which is what stops a CNAME to a third party turning into an "
            "unauthorized scan of their infrastructure."
        )
    guard = ScopeGuard(config.scope)
    refused = [(t, guard.check_host(_host_only(t))) for t in targets]
    problems = [f"  {t}: {why}" for t, why in refused if why]
    if problems:
        raise CliError(
            "these targets are outside the declared scope:\n"
            + "\n".join(problems)
            + "\nAdd them to --scope, or remove them from the target list."
        )


def _host_only(target: str) -> str:
    """Strip scheme and port so a target can be scope-checked as a host."""
    text = target.strip()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0].split("@")[-1]
    if text.startswith("["):  # bracketed IPv6 literal
        return text[1 : text.index("]")] if "]" in text else text
    if text.count(":") == 1:  # host:port; a bare IPv6 address has more colons
        text = text.split(":", 1)[0]
    return text


# --------------------------------------------------------------------------------------
# Suppression
# --------------------------------------------------------------------------------------


def _apply_suppressions(
    findings: List[Finding],
    config: Config,
    root: Path,
    notes: List[str],
    *,
    inline: bool,
) -> Tuple[List[Finding], int]:
    """Filter findings through the baseline and inline comments.

    Returns the survivors and how many were suppressed. A failure to *load* a baseline is
    fatal (the user asked for it explicitly and a silently ignored baseline means CI
    passes on findings it should have shown); a failure to check one file is not, because
    `core.suppress` is specified to fail closed and keep the finding.
    """
    suppress = _suppress_module()
    if suppress is None:
        if config.baseline is not None:
            raise CliError(
                "--baseline was given but core/suppress.py is not present in this build"
            )
        return findings, 0

    baseline = None
    if config.baseline is not None:
        try:
            baseline = suppress.load_baseline(config.baseline)
        except suppress.SuppressError as exc:
            raise CliError(str(exc)) from exc

    result = suppress.apply_suppressions(
        findings, root=root, baseline=baseline, inline=inline
    )
    for note in result.notes:
        if note not in notes:
            notes.append(note)
    return list(result.kept), int(result.total)


# --------------------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------------------


def _write(path: str, text: str, *, label: str, stdout: Any, stderr: Any) -> None:
    if path == "-":
        stdout.write(text if text.endswith("\n") else text + "\n")
        return
    target = Path(path).expanduser()
    try:
        if target.parent and not target.parent.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    except OSError as exc:
        raise CliError(f"cannot write the {label} report to {path}: {exc}") from exc
    print(f"{label} report written to {target}", file=stderr)


def emit(
    payload: ReportPayload,
    args: argparse.Namespace,
    *,
    stdout: Any,
    stderr: Any,
) -> None:
    """Render every requested format.

    Files are written before the terminal report so that a broken pipe on stdout (`|
    head`) cannot cost you the artifacts.
    """
    json_path = getattr(args, "json", None)
    if json_path:
        _write(json_path, json_out.render(payload), label="JSON", stdout=stdout, stderr=stderr)
    sarif_path = getattr(args, "sarif", None)
    if sarif_path:
        _write(sarif_path, sarif.render(payload), label="SARIF", stdout=stdout, stderr=stderr)

    if getattr(args, "quiet", False):
        return
    # A JSON report on stdout owns the stream; the human report moves to stderr rather
    # than corrupting it.
    stream = stderr if json_path == "-" else stdout
    terminal.render(payload, stream=stream)


def _exit_code(payload: ReportPayload, config: Config) -> int:
    """0 clean / 1 threshold breached / 2 tool error, with `2` winning.

    An errored module means part of the codebase went unexamined. Reporting `1` in that
    case would tell CI "we looked and found things", when the truth is "we did not
    finish looking" - so the error outranks the findings.
    """
    if payload.any_module_errored:
        return EXIT_ERROR
    if config.fail_on is not None and payload.count_at_or_above(config.fail_on) > 0:
        return EXIT_FINDINGS
    return EXIT_CLEAN


# --------------------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------------------


def cmd_code(args: argparse.Namespace, stdout: Any, stderr: Any) -> int:
    root = _resolve_root(args.path)
    config = config_from_args(args, root)
    started = time.time()

    results, ctx, walk_stats = run_code_scan(config, root, stderr=stderr)
    findings = dedupe([f for result in results for f in result.findings])
    kept, suppressed = _apply_suppressions(
        findings,
        config,
        root,
        ctx.notes,
        inline=not getattr(args, "no_inline_suppression", False),
    )

    payload = ReportPayload.from_scan(
        module_results=results,
        config=config,
        command="code",
        findings=kept,
        root=root,
        walk_stats=walk_stats,
        notes=ctx.notes,
        routes=ctx.routes,
        rules=_active_rules(config),
        started_at=started,
        finished_at=time.time(),
        suppressed_count=suppressed,
        baseline_path=config.baseline,
        terminal_limit_per_rule=0 if config.verbose else 10,
    )
    emit(payload, args, stdout=stdout, stderr=stderr)
    return _exit_code(payload, config)


def cmd_live(args: argparse.Namespace, stdout: Any, stderr: Any) -> int:
    config = config_from_args(args, Path.cwd())
    started = time.time()

    results, ctx = run_live_scan(config, args.targets, stderr=stderr)
    findings = dedupe([f for result in results for f in result.findings])
    payload = ReportPayload.from_scan(
        module_results=results,
        config=config,
        command="live",
        findings=findings,
        root=Path.cwd(),
        notes=ctx.notes,
        live_targets=list(args.targets),
        audit_entries=list(ctx.audit.entries),
        rules=_active_rules(config),
        started_at=started,
        finished_at=time.time(),
        terminal_limit_per_rule=0 if config.verbose else 10,
    )
    emit(payload, args, stdout=stdout, stderr=stderr)
    return _exit_code(payload, config)


def cmd_full(args: argparse.Namespace, stdout: Any, stderr: Any) -> int:
    root = _resolve_root(args.path)
    config = config_from_args(args, root)
    started = time.time()

    # Authorization is checked before the code scan, not after. Failing at the end of a
    # long scan because of a missing flag wastes the user's time and teaches them to
    # pass --authorized reflexively, which is the opposite of what the gate is for.
    _require_live_authorization(config, args.target)

    code_results, ctx, walk_stats = run_code_scan(config, root, stderr=stderr)
    live_results, live_ctx = run_live_scan(
        config, args.target, stderr=stderr, routes=ctx.routes
    )

    results = list(code_results) + list(live_results)
    findings = dedupe([f for result in results for f in result.findings])
    notes = list(ctx.notes)
    for note in live_ctx.notes:
        if note not in notes:
            notes.append(note)

    kept, suppressed = _apply_suppressions(
        findings,
        config,
        root,
        notes,
        inline=not getattr(args, "no_inline_suppression", False),
    )
    payload = ReportPayload.from_scan(
        module_results=results,
        config=config,
        command="full",
        findings=kept,
        root=root,
        walk_stats=walk_stats,
        notes=notes,
        routes=ctx.routes,
        live_targets=list(args.target),
        audit_entries=list(live_ctx.audit.entries),
        rules=_active_rules(config),
        started_at=started,
        finished_at=time.time(),
        suppressed_count=suppressed,
        baseline_path=config.baseline,
        terminal_limit_per_rule=0 if config.verbose else 10,
    )
    emit(payload, args, stdout=stdout, stderr=stderr)
    return _exit_code(payload, config)


def cmd_rules(args: argparse.Namespace, stdout: Any, stderr: Any) -> int:
    """List detection rules AND the code-implemented AST checks.

    Both are listed because both are selectable with `--enable-rule`/`--disable-rule`. A
    listing that showed only the JSON packs would imply the AST checks cannot be
    controlled, and would hide a third of what the tool actually does.
    """
    import json as _json

    rules = load_all_builtin("")
    for extra in (args.rules or []):
        rules.extend(load_pack(Path(extra)))

    entries: List[Dict[str, Any]] = [
        {
            "id": r.id,
            "title": r.title,
            "severity": r.severity.label,
            "confidence": r.confidence.label,
            "detection": "regex",
            "cwe": r.cwe,
            "tags": list(r.tags),
            "languages": list(r.languages),
        }
        for r in rules
    ]
    from .modules.patterns import PY_CHECKS

    entries.extend(
        {
            "id": c.id,
            "title": c.title,
            "severity": c.severity.label,
            "confidence": c.confidence.label,
            "detection": "ast",
            "cwe": c.cwe,
            "tags": list(c.tags),
            "languages": ["python"],
        }
        for c in PY_CHECKS.values()
    )

    needle = (args.search or "").lower()
    if needle:
        entries = [
            e for e in entries
            if needle in e["id"].lower()
            or needle in e["title"].lower()
            or any(needle in t.lower() for t in e["tags"])
        ]
    entries.sort(key=lambda e: e["id"])

    if args.json:
        stdout.write(_json.dumps({"count": len(entries), "rules": entries}, indent=2) + "\n")
        return EXIT_CLEAN

    if not entries:
        print(f"no rules match {args.search!r}", file=stderr)
        return EXIT_CLEAN

    width = max(len(e["id"]) for e in entries)
    for entry in entries:
        marker = "ast " if entry["detection"] == "ast" else "rgx "
        stdout.write(f"{marker}{entry['id']:<{width}}  {entry['severity']:<8}  {entry['title']}\n")
    by_detection: Dict[str, int] = {}
    for entry in entries:
        by_detection[entry["detection"]] = by_detection.get(entry["detection"], 0) + 1
    summary = ", ".join(f"{n} {kind}" for kind, n in sorted(by_detection.items()))
    stdout.write(f"\n{len(entries)} checks ({summary})\n")
    return EXIT_CLEAN


def cmd_baseline(args: argparse.Namespace, stdout: Any, stderr: Any) -> int:
    """Record today's findings so CI reports only what appears after this point.

    Inline suppressions are applied before recording, but the baseline is written from
    the *unsuppressed-by-baseline* set: a baseline that was itself filtered by a previous
    baseline would shrink every time it was regenerated.
    """
    suppress = _suppress_module()
    if suppress is None:
        raise CliError("baseline support needs core/suppress.py, which is not in this build")

    root = _resolve_root(args.path)
    config = config_from_args(args, root)
    config.baseline = None  # never filter the recording against an existing baseline

    results, ctx, _walk_stats = run_code_scan(config, root, stderr=stderr)
    findings = dedupe([f for result in results for f in result.findings])
    kept, _suppressed = _apply_suppressions(findings, config, root, ctx.notes, inline=True)

    errored = [r.name for r in results if r.error]
    if errored:
        # Recording a baseline from an incomplete scan bakes the gap in permanently:
        # whatever that module would have found becomes invisible from now on.
        raise CliError(
            f"refusing to write a baseline from an incomplete scan - these modules "
            f"failed: {', '.join(errored)}. Fix them, or the findings they would have "
            f"reported will be silently accepted forever."
        )

    out = Path(args.out).expanduser()
    try:
        count = suppress.write_baseline(out, kept, root=root, tool_version=__version__)
    except OSError as exc:
        raise CliError(f"cannot write the baseline to {out}: {exc}") from exc

    print(f"baseline written to {out}: {count} findings recorded", file=stderr)
    if not count:
        print(
            "nothing was recorded, so this baseline suppresses nothing - which is the "
            "correct result for a clean scan.",
            file=stderr,
        )
    return EXIT_CLEAN


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------

_COMMANDS: Dict[str, Callable[[argparse.Namespace, Any, Any], int]] = {
    "code": cmd_code,
    "live": cmd_live,
    "full": cmd_full,
    "rules": cmd_rules,
    "baseline": cmd_baseline,
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Return an exit code; never raise. `console_scripts` calls this."""
    stdout, stderr = sys.stdout, sys.stderr
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if not args.command:
        parser.print_help(stderr)
        return EXIT_ERROR

    handler = _COMMANDS[args.command]
    try:
        return handler(args, stdout, stderr)
    except CliError as exc:
        print(f"{PROG}: {exc}", file=stderr)
        return EXIT_ERROR
    except RuleError as exc:
        # Rule packs fail loudly by design; surface the message, not a traceback.
        print(f"{PROG}: rule pack error: {exc}", file=stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print(f"\n{PROG}: interrupted; the scan was not completed", file=stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        # `recon code . | head` closes the pipe early. Exiting quietly is correct, but
        # Python will otherwise print "Exception ignored" at shutdown when it flushes.
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except OSError:
            pass
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - a crash must still be exit 2, not a traceback
        print(f"{PROG}: unexpected error: {type(exc).__name__}: {exc}", file=stderr)
        if getattr(args, "verbose", False):
            import traceback

            traceback.print_exc()
        else:
            print(f"{PROG}: re-run with --verbose for the traceback", file=stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
