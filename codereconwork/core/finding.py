"""Core finding model.

Every check in Code Recon, whether it reads a file or talks to a host, produces
`Finding` objects. Two things here are load-bearing for the rest of the tool:

* Severity and confidence are *separate* axes. A 64-character high-entropy blob is
  high-severity but low-confidence; a hardcoded `AKIA...` key is both high. Scanners
  that collapse these into one number train people to ignore them.
* Fingerprints deliberately exclude line numbers, so a finding survives a refactor
  that shifts code around. That is what makes baselining usable in CI.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional

_WS = re.compile(r"\s+")


class Severity(IntEnum):
    """How bad it is if real. Ordered so thresholds are plain comparisons."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError:
            valid = ", ".join(s.label for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {valid})")

    @property
    def sarif_level(self) -> str:
        if self >= Severity.HIGH:
            return "error"
        if self == Severity.MEDIUM:
            return "warning"
        return "note"

    @property
    def security_severity(self) -> str:
        """GitHub code scanning buckets findings on this numeric string, not on level."""
        return {
            Severity.CRITICAL: "9.5",
            Severity.HIGH: "8.0",
            Severity.MEDIUM: "5.5",
            Severity.LOW: "3.0",
            Severity.INFO: "1.0",
        }[self]


class Confidence(IntEnum):
    """How sure we are it is real. Drives triage order, never severity."""

    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CONFIRMED = 3

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> "Confidence":
        try:
            return cls[value.strip().upper()]
        except KeyError:
            valid = ", ".join(c.label for c in cls)
            raise ValueError(f"unknown confidence {value!r} (expected one of: {valid})")


@dataclass
class Finding:
    """A single issue. Either file-located (`path`) or network-located (`target`)."""

    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    message: str

    # Where it is: source location...
    path: Optional[str] = None  # relative to scan root, posix separators
    line: Optional[int] = None  # 1-indexed
    column: Optional[int] = None  # 1-indexed
    end_line: Optional[int] = None
    snippet: Optional[str] = None  # MUST already be redacted by the producer

    # ...or a network location, for live-recon findings that have no file at all.
    target: Optional[str] = None  # "example.com", "example.com:443", or a URL

    module: str = ""
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    cwe: Optional[str] = None

    # Producers set this when the snippet is a poor identity (e.g. secrets, where we
    # want the fingerprint keyed on a hash of the credential, not the whole line).
    fingerprint_seed: Optional[str] = None

    # Anything rule-specific worth carrying into JSON output.
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def location(self) -> str:
        """Human-readable location, clickable in most terminals when it is a file."""
        if self.path:
            return f"{self.path}:{self.line}" if self.line else self.path
        return self.target or "<unknown>"

    @property
    def fingerprint(self) -> str:
        """Stable identity across runs.

        Excludes line/column so shifting code does not invalidate a baseline. Includes
        the rule and location so the same rule firing twice in one file on genuinely
        different content stays two findings.
        """
        seed = self.fingerprint_seed
        if seed is None:
            seed = _WS.sub(" ", (self.snippet or "").strip())
        parts = [self.rule_id, self.path or self.target or "", seed]
        return hashlib.sha256("\x00".join(parts).encode("utf-8", "replace")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "confidence": self.confidence.label,
            "message": self.message,
            "module": self.module,
            "fingerprint": self.fingerprint,
        }
        if self.path:
            out["path"] = self.path
            if self.line is not None:
                out["line"] = self.line
            if self.column is not None:
                out["column"] = self.column
            if self.end_line is not None and self.end_line != self.line:
                out["end_line"] = self.end_line
        if self.target:
            out["target"] = self.target
        if self.snippet:
            out["snippet"] = self.snippet
        if self.remediation:
            out["remediation"] = self.remediation
        if self.cwe:
            out["cwe"] = self.cwe
        if self.references:
            out["references"] = list(self.references)
        if self.tags:
            out["tags"] = sorted(self.tags)
        if self.extra:
            out["extra"] = self.extra
        return out


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Worst and most certain first, then stable by location for readable diffs."""
    return sorted(
        findings,
        key=lambda f: (
            -int(f.severity),
            -int(f.confidence),
            f.path or f.target or "",
            f.line or 0,
            f.rule_id,
        ),
    )


def dedupe(findings: List[Finding]) -> List[Finding]:
    """Drop exact fingerprint collisions, keeping the highest-confidence instance.

    Overlapping rule packs (a provider pattern and the generic entropy sweep both
    catching one key) otherwise report the same line twice.
    """
    best: Dict[str, Finding] = {}
    for f in findings:
        prior = best.get(f.fingerprint)
        if prior is None or f.confidence > prior.confidence or f.severity > prior.severity:
            best[f.fingerprint] = f
    return sort_findings(list(best.values()))
