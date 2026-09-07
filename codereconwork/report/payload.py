"""The single object every renderer consumes.

Three renderers (terminal, JSON, SARIF) need almost the same facts about a scan, and
each of them computing those facts itself is how the three drift apart: the terminal
says "4 high", the JSON says 5, and nobody trusts either. So the CLI assembles one
`ReportPayload` and hands the same object to all three. Everything a renderer might be
tempted to derive - counts per severity, whether anything errored, the worst thing seen -
is a method here instead.

Two decisions in this file are about not lying:

**A shared file pass has no per-module wall clock.** `core.engine` fuses every
`FileScanModule` into one pass over the file list and gives each `ModuleResult` the
*same* elapsed time, because attributing it per module would be invented. Renderers must
not print it as though each module took that long, so `shared_duration_groups()` finds
the modules that share a duration and lets the renderer label the number honestly.

**`extra` is not automatically safe to publish.** `Finding.snippet` is redacted by its
producer, but `extra` is a free-form bag any future module can put anything in - and
reports get attached to tickets. `safe_extra()` therefore fails closed: known-safe keys
pass, everything else is dropped and *named* in `extra_omitted`, so a reader can tell
that something was withheld rather than that nothing existed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .. import __version__
from ..core.context import Config
from ..core.engine import ModuleResult
from ..core.finding import Confidence, Finding, Severity, sort_findings
from ..core.rules import Rule

TOOL_NAME = "code-recon"
TOOL_INFORMATION_URI = "https://github.com/celestial-zenny/codereconz"

SEVERITY_ORDER: Tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)
CONFIDENCE_ORDER: Tuple[Confidence, ...] = (
    Confidence.CONFIRMED,
    Confidence.HIGH,
    Confidence.MEDIUM,
    Confidence.LOW,
)

# --------------------------------------------------------------------------------------
# extra sanitisation
# --------------------------------------------------------------------------------------

# Allowlisted `Finding.extra` keys. Fail closed: a module that invents a new key gets it
# dropped (and reported as omitted) rather than risking a raw credential in a report.
SAFE_EXTRA_KEYS = frozenset(
    {
        "masked",  # core.redact.mask() output - the only sanctioned form of a value
        "occurrences",  # how many times the same credential appeared in the file
        "detection",  # "ast" | "regex" | "parsed"
        "jwt",  # claim metadata, filtered again below; never the token itself
        "in_test",
        "capped",  # rule confidence was capped by the regex driver
        "validator",  # which format validator accepted the candidate
        "entropy",
        "language",
        "package",  # dependency findings: public advisory metadata, never a credential
        "installed_version",
        "vulnerability_id",
        "fixed_versions",
        "aliases",
        "cvss_score",
        "severity_source",
        "also_declared_in",
        "withdrawn",
        "ecosystem",
        "port",  # live findings
        "protocol",
        "service",
        "status",
        "scheme",
        "record",
        "expires",
        "days_remaining",
        "route",  # surface findings
        "methods",
        "handler",
        "commit",  # git-history findings
        "author_date",
        "deleted_before_head",
    }
)

# JWT claim metadata worth carrying for triage. The token is a credential; its claims are
# how you work out which account to rotate, so they stay - but only these keys, so a
# future change to `jwt_details` cannot widen what a report publishes.
SAFE_JWT_KEYS = frozenset(
    {"alg", "unsigned", "exp", "no_expiry", "privileged_role", "role", "iss", "aud", "sub", "email"}
)

# Belt and braces: even an allowlisted key gets clamped, so a long value cannot smuggle
# a credential through a field that is normally short.
_MAX_EXTRA_STR = 200


def _clamp(value: str) -> str:
    return value if len(value) <= _MAX_EXTRA_STR else value[:_MAX_EXTRA_STR] + "…"


def _jsonable(value: Any) -> Any:
    """Coerce a module-supplied value into something `json.dumps` accepts.

    Dict keys are sorted so two runs serialise identically even when the producing dict
    was built in a thread-order-dependent way.
    """
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _clamp(value)
    if isinstance(value, Path):
        return value.name
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(value, key=str) if isinstance(value, (set, frozenset)) else list(value)
        return [_jsonable(v) for v in items]
    return _clamp(str(value))


def safe_extra(extra: Dict[str, Any]) -> Dict[str, Any]:
    """Filter a `Finding.extra` bag down to what is safe to publish.

    Returns the allowlisted keys, plus `extra_omitted` naming anything dropped. Naming
    the drops matters: silent omission would make a report look complete when it is not.
    """
    if not extra:
        return {}
    out: Dict[str, Any] = {}
    omitted: List[str] = []
    for key in sorted(extra):
        if key not in SAFE_EXTRA_KEYS:
            omitted.append(key)
            continue
        value = extra[key]
        if key == "jwt" and isinstance(value, dict):
            claims = {k: _jsonable(v) for k, v in sorted(value.items()) if k in SAFE_JWT_KEYS}
            dropped = [k for k in sorted(value) if k not in SAFE_JWT_KEYS]
            if dropped:
                claims["claims_omitted"] = dropped
            out[key] = claims
            continue
        out[key] = _jsonable(value)
    if omitted:
        out["extra_omitted"] = omitted
    return out


def detection_of(finding: Finding) -> Optional[str]:
    """The finding's detection method, if the producing module declared one.

    Never guessed. A regex heuristic and a parsed fact must not look alike in a report,
    and inventing the label for a module that did not set it would defeat the point.
    """
    value = finding.extra.get("detection") if finding.extra else None
    return str(value) if isinstance(value, str) and value else None


def finding_dict(finding: Finding) -> Dict[str, Any]:
    """`Finding.to_dict()` with `extra` passed through `safe_extra()`."""
    out = finding.to_dict()
    if "extra" in out:
        cleaned = safe_extra(finding.extra)
        if cleaned:
            out["extra"] = cleaned
        else:
            del out["extra"]
    return out


# --------------------------------------------------------------------------------------
# payload
# --------------------------------------------------------------------------------------


@dataclass
class ReportPayload:
    """Everything the renderers need, assembled once by the CLI."""

    findings: List[Finding] = field(default_factory=list)
    module_results: List[ModuleResult] = field(default_factory=list)
    config: Config = field(default_factory=Config)

    # What ran, and over what.
    command: str = "code"  # subcommand: "code" | "live" | "full"
    root: Optional[Path] = None  # defaults to config.root
    live_targets: List[str] = field(default_factory=list)

    # Scan completeness evidence.
    walk_stats: Dict[str, int] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    routes: List[Dict[str, Any]] = field(default_factory=list)
    audit_entries: List[str] = field(default_factory=list)

    # Rule objects active this run, for SARIF `tool.driver.rules[]` metadata. Findings
    # from code-implemented checks (the AST analyzer) have no `Rule`, which is expected.
    rules: List[Rule] = field(default_factory=list)

    # Timing. Epoch seconds, so the report carries an absolute time; `duration` is wall
    # clock for the whole scan, which is the only duration that is not an attribution.
    started_at: float = 0.0
    finished_at: float = 0.0
    duration: float = 0.0

    # Suppression accounting, so a quiet report is distinguishable from a muted one.
    suppressed_count: int = 0
    baseline_path: Optional[Path] = None

    # Tool identity.
    tool_name: str = TOOL_NAME
    tool_version: str = __version__
    information_uri: str = TOOL_INFORMATION_URI

    # Terminal-only display knobs. These would be `Config` fields if `Config` were mine;
    # defaults are chosen so a caller that ignores them gets sensible output.
    show_remediation: bool = True
    terminal_limit_per_rule: int = 10  # 0 = no cap; Config.verbose also lifts it

    # ---- identity -------------------------------------------------------------------

    @property
    def scan_root(self) -> Path:
        return self.root if self.root is not None else self.config.root

    @property
    def started_iso(self) -> str:
        return _iso(self.started_at)

    @property
    def finished_iso(self) -> str:
        return _iso(self.finished_at)

    # ---- findings -------------------------------------------------------------------

    def sorted_findings(self) -> List[Finding]:
        """Worst and most certain first - the order every renderer should present."""
        return sort_findings(list(self.findings))

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    def severity_counts(self) -> Dict[Severity, int]:
        """Zero-filled, so a report always shows every bucket including the empty ones."""
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def severity_counts_by_label(self) -> Dict[str, int]:
        return {sev.label: count for sev, count in self.severity_counts().items()}

    def confidence_counts(self) -> Dict[Confidence, int]:
        counts = {conf: 0 for conf in CONFIDENCE_ORDER}
        for finding in self.findings:
            counts[finding.confidence] = counts.get(finding.confidence, 0) + 1
        return counts

    def confidence_counts_by_label(self) -> Dict[str, int]:
        return {conf.label: count for conf, count in self.confidence_counts().items()}

    def module_counts(self) -> Dict[str, int]:
        """Findings per module, including a zero for every module that ran and found none.

        The zero is the point: it distinguishes "this module ran and was happy" from
        "this module never ran", which the severity table cannot show.
        """
        counts: Dict[str, int] = {result.name: 0 for result in self.module_results}
        for finding in self.findings:
            name = finding.module or "unknown"
            counts[name] = counts.get(name, 0) + 1
        return counts

    def rule_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for finding in self.findings:
            counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
        return counts

    def detection_counts(self) -> Dict[str, int]:
        """How findings were detected. `unspecified` is honest about modules that did not say."""
        counts: Dict[str, int] = {}
        for finding in self.findings:
            key = detection_of(finding) or "unspecified"
            counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items()))

    @property
    def highest_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(finding.severity for finding in self.findings)

    def count_at_or_above(self, threshold: Severity) -> int:
        """What the CLI's `--fail-on` threshold needs, without an exit-code policy here."""
        return sum(1 for finding in self.findings if finding.severity >= threshold)

    def fired_rule_ids(self) -> List[str]:
        """Rule ids that actually produced a finding, alphabetically for stable indices."""
        return sorted({finding.rule_id for finding in self.findings})

    def rule_map(self) -> Dict[str, Rule]:
        return {rule.id: rule for rule in self.rules}

    # ---- modules --------------------------------------------------------------------

    @property
    def ran_modules(self) -> List[ModuleResult]:
        return [result for result in self.module_results if result.ran]

    @property
    def skipped_modules(self) -> List[ModuleResult]:
        return [result for result in self.module_results if result.skipped]

    @property
    def errored_modules(self) -> List[ModuleResult]:
        return [result for result in self.module_results if result.error]

    @property
    def any_module_errored(self) -> bool:
        """SARIF `executionSuccessful` and the CLI's exit code 2 both hang off this."""
        return any(result.error for result in self.module_results)

    @property
    def any_module_skipped(self) -> bool:
        return any(result.skipped for result in self.module_results)

    @property
    def scan_incomplete(self) -> bool:
        """True when something did not run. A clean report from a partial scan is a lie."""
        return self.any_module_errored or self.any_module_skipped

    def shared_duration_groups(self) -> List[Tuple[float, List[str]]]:
        """Module names that share one wall clock, i.e. the fused file pass.

        Grouped on exact float equality, which only happens when `core.engine` copied one
        measurement into several `ModuleResult`s - two independent `time.monotonic()`
        deltas do not collide.
        """
        by_duration: Dict[float, List[str]] = {}
        for result in self.module_results:
            if result.duration <= 0.0:
                continue
            by_duration.setdefault(result.duration, []).append(result.name)
        return [
            (duration, names)
            for duration, names in sorted(by_duration.items(), reverse=True)
            if len(names) > 1
        ]

    def duration_is_shared(self, name: str) -> bool:
        return any(name in names for _, names in self.shared_duration_groups())

    # ---- config echo ----------------------------------------------------------------

    def config_dict(self) -> Dict[str, Any]:
        """The knobs that changed what this scan looked for, safe to attach to a ticket.

        Deliberately narrowed in two ways. Local filesystem paths are reduced to their
        final component, because `/home/someone/clients/acme-audit/...` is both a
        username leak and often the name of a client under NDA. Purely cosmetic flags
        (`no_color`, `verbose`) are omitted, since they cannot explain a difference in
        findings and would only add diff noise.
        """
        config = self.config
        out: Dict[str, Any] = {
            "root": _safe_path(self.scan_root),
            "jobs": config.jobs,  # as configured; 0 = auto, so no machine detail lands here
            "max_bytes": config.max_bytes,
            "use_gitignore": config.use_gitignore,
            "include_minified": config.include_minified,
            "follow_symlinks": config.follow_symlinks,
            "excludes": list(config.excludes),
            "exclude_dirs": list(config.exclude_dirs),
            "fast": config.fast,
            "offline": config.offline,
            "modules": list(config.modules) if config.modules else None,
            "enable_rules": list(config.enable_rules),
            "disable_rules": list(config.disable_rules),
            "min_severity": config.min_severity.label if config.min_severity else None,
            "min_confidence": config.min_confidence.label if config.min_confidence else None,
            "rule_packs": [_safe_path(p) for p in config.rule_packs],
            "history_depth": config.history_depth,
            "max_findings_per_rule_per_file": config.max_findings_per_rule_per_file,
            "verify_secrets": config.verify_secrets,
            "fail_on": config.fail_on.label if config.fail_on else None,
            "baseline": _safe_path(self.baseline_path) if self.baseline_path else None,
        }
        if self.command != "code":
            out["live"] = {
                "authorized": config.authorized,
                "scope": list(config.scope),
                "ports": config.ports,
                "timeout": config.timeout,
                "max_concurrency": config.max_concurrency,
                "rate_limit": config.rate_limit,
                "user_agent": config.user_agent,
                "http_paths": config.live_http_paths,
                "subdomain_discovery": config.subdomain_discovery,
                "audit_log": _safe_path(config.audit_log) if config.audit_log else None,
            }
        return out

    # ---- assembly helper ------------------------------------------------------------

    @classmethod
    def from_scan(
        cls,
        *,
        module_results: Sequence[ModuleResult],
        config: Config,
        command: str = "code",
        findings: Optional[Sequence[Finding]] = None,
        root: Optional[Path] = None,
        walk_stats: Optional[Dict[str, int]] = None,
        notes: Optional[Sequence[str]] = None,
        routes: Optional[Sequence[Dict[str, Any]]] = None,
        live_targets: Optional[Sequence[str]] = None,
        audit_entries: Optional[Sequence[str]] = None,
        rules: Optional[Sequence[Rule]] = None,
        started_at: Optional[float] = None,
        finished_at: Optional[float] = None,
        suppressed_count: int = 0,
        baseline_path: Optional[Path] = None,
        **kwargs: Any,
    ) -> "ReportPayload":
        """Convenience constructor: collect findings from the results and close the clock.

        Pass `findings` explicitly when suppression or baselining has already filtered
        them; otherwise every module result's findings are used as-is.
        """
        collected = (
            list(findings)
            if findings is not None
            else [f for result in module_results for f in result.findings]
        )
        finished = time.time() if finished_at is None else finished_at
        started = finished if started_at is None else started_at
        return cls(
            findings=collected,
            module_results=list(module_results),
            config=config,
            command=command,
            root=root if root is not None else config.root,
            live_targets=list(live_targets or []),
            walk_stats=dict(walk_stats or {}),
            notes=list(notes or []),
            routes=[dict(r) for r in (routes or [])],
            audit_entries=list(audit_entries or []),
            rules=list(rules or []),
            started_at=started,
            finished_at=finished,
            duration=max(0.0, finished - started),
            suppressed_count=suppressed_count,
            baseline_path=baseline_path,
            **kwargs,
        )


def _iso(epoch: float) -> str:
    """UTC ISO 8601 with a `Z`, which is what SARIF consumers expect."""
    if not epoch:
        return ""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _safe_path(path: Optional[Path]) -> Optional[str]:
    """Final path component only - see `config_dict` for why."""
    if path is None:
        return None
    path = Path(path)
    return path.name or str(path)
