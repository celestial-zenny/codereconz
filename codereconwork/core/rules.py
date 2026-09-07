"""Rule pack loading.

Detection logic lives in JSON data files rather than in Python so that adding a new
provider token or a new dangerous-call pattern does not require touching code, and so
teams can ship their own packs with `--rules ./our-rules.json`. YAML is accepted too,
but only if PyYAML happens to be installed - the tool has no required dependencies.

Bad rules must fail loudly with the offending rule id. A silently-dropped rule is the
worst failure mode a scanner has: everything looks green because nothing ran.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .finding import Confidence, Severity

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


class RuleError(ValueError):
    """A rule pack is malformed. Always names the rule and the problem."""


@dataclass
class Rule:
    """One compiled detection rule."""

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    regex: "re.Pattern[str]"
    # Capture group holding the thing we report. 0 = whole match.
    group: int = 0
    # Capture group holding the credential to mask, when it differs from `group`
    # (a connection string is reported whole, but only the password is masked).
    secret_group: Optional[int] = None

    # Cheap case-insensitive pre-filter. Empty means "always run this rule".
    keywords: List[str] = field(default_factory=list)

    min_entropy: Optional[float] = None
    reject_placeholders: bool = False
    reject_known_formats: bool = False
    validate: Optional[str] = None
    # Rules flagged expensive are skipped under --fast.
    expensive: bool = False
    # Regex findings are capped at MEDIUM confidence, because a pattern match is
    # evidence about text and not about program behaviour. A rule sets this when its
    # pattern matches a literal, unmistakable API call (`.csrf().disable()`) rather than
    # a resemblance, which earns it the confidence it declares.
    unambiguous: bool = False
    # The pattern driver drops matches that land inside a comment, which is one of the
    # largest false-positive sources there is. A rule whose whole point is to read
    # comments (`# TODO: fix this auth bypass`) sets this to opt out of that filter.
    match_in_comments: bool = False

    message: Optional[str] = None
    remediation: Optional[str] = None
    cwe: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    # Scoping: languages this applies to, and path globs to include/exclude.
    languages: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)
    not_paths: List[str] = field(default_factory=list)

    def applies_to(self, relpath: str, language: Optional[str]) -> bool:
        if self.languages and (language or "") not in self.languages:
            return False
        if self.paths and not any(_glob_match(p, relpath) for p in self.paths):
            return False
        if self.not_paths and any(_glob_match(p, relpath) for p in self.not_paths):
            return False
        return True

    def prefilter(self, lowered_text: str) -> bool:
        """True if this rule could possibly match, based on keywords alone.

        This is the main performance lever: most rules are eliminated per-file with a
        handful of substring checks instead of running 45 regexes over every file.
        """
        if not self.keywords:
            return True
        return any(k in lowered_text for k in self.keywords)


def _glob_match(pattern: str, path: str) -> bool:
    import fnmatch

    return fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(Path(path).name, pattern)


_REQUIRED = ("id", "title", "severity", "confidence", "regex")


def _rule_from_dict(raw: Dict[str, Any], source: str) -> Rule:
    rid = raw.get("id") or "<missing id>"
    for key in _REQUIRED:
        if key not in raw:
            raise RuleError(f"{source}: rule {rid!r} is missing required field {key!r}")

    try:
        regex = re.compile(raw["regex"])
    except re.error as exc:
        raise RuleError(f"{source}: rule {rid!r} has an invalid regex: {exc}") from exc

    group = int(raw.get("group", 0))
    if group > regex.groups:
        raise RuleError(
            f"{source}: rule {rid!r} references capture group {group} "
            f"but the pattern only has {regex.groups}"
        )
    secret_group = raw.get("secret_group")
    if secret_group is not None:
        secret_group = int(secret_group)
        if secret_group > regex.groups:
            raise RuleError(
                f"{source}: rule {rid!r} references secret_group {secret_group} "
                f"but the pattern only has {regex.groups}"
            )

    try:
        severity = Severity.parse(raw["severity"])
        confidence = Confidence.parse(raw["confidence"])
    except ValueError as exc:
        raise RuleError(f"{source}: rule {rid!r}: {exc}") from exc

    min_entropy = raw.get("min_entropy")
    return Rule(
        id=rid,
        title=raw["title"],
        severity=severity,
        confidence=confidence,
        regex=regex,
        group=group,
        secret_group=secret_group,
        keywords=[k.lower() for k in raw.get("keywords", [])],
        min_entropy=float(min_entropy) if min_entropy is not None else None,
        reject_placeholders=bool(raw.get("reject_placeholders", False)),
        reject_known_formats=bool(raw.get("reject_known_formats", False)),
        validate=raw.get("validate"),
        expensive=bool(raw.get("expensive", False)),
        unambiguous=bool(raw.get("unambiguous", False)),
        match_in_comments=bool(raw.get("match_in_comments", False)),
        message=raw.get("message"),
        remediation=raw.get("remediation"),
        cwe=raw.get("cwe"),
        tags=list(raw.get("tags", [])),
        references=list(raw.get("references", [])),
        languages=[lang.lower() for lang in raw.get("languages", [])],
        paths=list(raw.get("paths", [])),
        not_paths=list(raw.get("not_paths", [])),
    )


def _parse_pack_text(text: str, source: str) -> Dict[str, Any]:
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuleError(f"{source}: invalid JSON at line {exc.lineno}: {exc.msg}") from exc
    # Not JSON - try YAML, which is optional.
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise RuleError(
            f"{source}: does not look like JSON, and YAML rule packs need PyYAML "
            f"installed (`pip install pyyaml`). Convert the pack to JSON to avoid the "
            f"dependency."
        ) from exc
    try:
        data = yaml.safe_load(text)
    except Exception as exc:  # noqa: BLE001 - yaml raises a wide variety
        raise RuleError(f"{source}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise RuleError(f"{source}: top level must be a mapping with a 'rules' key")
    return data


def load_pack(path: Path) -> List[Rule]:
    """Load and compile one rule pack from disk."""
    source = str(path)
    try:
        text = path.read_text("utf-8")
    except OSError as exc:
        raise RuleError(f"cannot read rule pack {source}: {exc}") from exc

    data = _parse_pack_text(text, source)
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise RuleError(f"{source}: expected a top-level 'rules' array")

    rules = [_rule_from_dict(r, source) for r in raw_rules]
    seen: Dict[str, int] = {}
    for rule in rules:
        if rule.id in seen:
            raise RuleError(f"{source}: duplicate rule id {rule.id!r}")
        seen[rule.id] = 1
    return rules


def load_builtin(*names: str) -> List[Rule]:
    """Load bundled packs by stem, e.g. `load_builtin('secrets', 'patterns_python')`."""
    rules: List[Rule] = []
    for name in names:
        path = RULES_DIR / f"{name}.json"
        if not path.exists():
            raise RuleError(f"bundled rule pack {name!r} not found at {path}")
        rules.extend(load_pack(path))
    return rules


def load_all_builtin(prefix: str) -> List[Rule]:
    """Load every bundled pack whose filename starts with `prefix`."""
    rules: List[Rule] = []
    for path in sorted(RULES_DIR.glob(f"{prefix}*.json")):
        rules.extend(load_pack(path))
    return rules


def selector_matches(rule_id: str, selectors: Sequence[str]) -> bool:
    """Whether `rule_id` is picked out by any of `selectors`.

    A selector is either an exact id or a family prefix, so
    `--disable-rule secret.generic` turns off every rule beneath it without listing them.
    Shared with the pattern module's AST checks, which are selected by the same flags
    even though they are code rather than data - two implementations of rule selection
    would inevitably drift apart.
    """
    return any(
        rule_id == s or rule_id.startswith(s.rstrip("*").rstrip(".") + ".") for s in selectors
    )


def filter_rules(
    rules: Iterable[Rule],
    *,
    enable: Sequence[str] = (),
    disable: Sequence[str] = (),
    min_severity: Optional[Severity] = None,
    min_confidence: Optional[Confidence] = None,
    fast: bool = False,
) -> List[Rule]:
    """Apply CLI-level rule selection.

    `enable`/`disable` accept exact ids or prefixes, so `--disable-rule secret.generic`
    turns off the whole generic family without listing each one.
    """
    out: List[Rule] = []
    for rule in rules:
        if enable and not selector_matches(rule.id, enable):
            continue
        if disable and selector_matches(rule.id, disable):
            continue
        if min_severity is not None and rule.severity < min_severity:
            continue
        if min_confidence is not None and rule.confidence < min_confidence:
            continue
        if fast and rule.expensive:
            continue
        out.append(rule)
    return out
