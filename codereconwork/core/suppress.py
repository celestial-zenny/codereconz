"""Baseline diffing and inline suppression.

Two ways to say "yes, we know about that one":

* a **baseline** file, which is an ordinary Code Recon JSON report recording what was
  already there when the tool was adopted, so CI can fail on new findings without
  demanding the backlog be cleared first;
* an inline `# coderecon:ignore` comment, for the single line where a human has looked
  at the finding and decided it is fine.

Three decisions here are load-bearing.

**Suppression is applied centrally, after every module has run** — not inside modules.
That way one implementation governs every finding regardless of which module produced it,
and the cost is bounded: only files that actually produced a finding are re-read, which
on a real repo is a handful out of thousands.

**It fails closed.** If a file cannot be re-read, or a finding has no line number, the
finding is *kept* and a note explains why the check could not run. The alternative -
dropping a finding because we failed to confirm it should be dropped - turns an I/O error
into a silent hole in the report, which is the exact failure this tool exists to prevent.

**A baseline that cannot be loaded is fatal, not a warning.** The user asked for it
explicitly; ignoring it silently means CI passes on findings the baseline was never
actually consulted about. `core.rules` treats a malformed rule pack the same way and for
the same reason.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .finding import Finding
from .rules import selector_matches

# The token predates the package rename from `coderecon` to `codereconwork` and is
# deliberately NOT updated: it is already baked into the remediation text of shipped
# rules in `rules/secrets.json`, and it is a string users have typed into their source
# files. Renaming it would silently stop honouring every existing suppression comment,
# which is a security regression, not a tidy-up.
INLINE_TOKEN = "coderecon:ignore"

# `coderecon:ignore` or `coderecon:ignore[rule.id, other.family]`. Matched anywhere in the
# line rather than after a comment marker, so `#`, `//`, `--`, `/* */` and `<!-- -->` all
# work without this module having to know one comment syntax per language.
_INLINE_RE = re.compile(re.escape(INLINE_TOKEN) + r"\s*(?:\[([^\]]*)\])?", re.IGNORECASE)

SCHEMA_HINT = (
    "a baseline is a Code Recon JSON report - generate one with `recon baseline .`"
)


class SuppressError(Exception):
    """A baseline file is missing or malformed. Always says what to do about it."""


# --------------------------------------------------------------------------------------
# Baseline
# --------------------------------------------------------------------------------------


@dataclass
class Baseline:
    """Fingerprints that were already known, plus enough context to audit the file.

    Keyed on `Finding.fingerprint`, which excludes line and column - so a baseline
    survives the reformatting and code movement that would otherwise invalidate it on
    the first refactor after it was written.
    """

    path: Path
    fingerprints: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    generated_at: Optional[str] = None
    tool_version: Optional[str] = None

    @property
    def size(self) -> int:
        return len(self.fingerprints)

    def __contains__(self, fingerprint: object) -> bool:
        return fingerprint in self.fingerprints

    def __bool__(self) -> bool:
        return bool(self.fingerprints)


def load_baseline(path: Path) -> Baseline:
    """Read a baseline, failing loudly on anything it cannot trust."""
    path = Path(path)
    try:
        text = path.read_text("utf-8")
    except FileNotFoundError as exc:
        raise SuppressError(f"baseline {path} does not exist. {SCHEMA_HINT}") from exc
    except OSError as exc:
        raise SuppressError(f"cannot read baseline {path}: {exc}") from exc

    # Imported here rather than at module scope: `report` sits above `core` in the
    # dependency order, and this is the one place that inversion is worth it. The
    # alternative is a second implementation of the report schema, which would drift
    # from the real one and start rejecting valid baselines.
    from ..report import json_out

    try:
        data = json_out.parse(text)
    except (ValueError, json.JSONDecodeError) as exc:
        raise SuppressError(f"baseline {path} is not usable: {exc}. {SCHEMA_HINT}") from exc

    entries: Dict[str, Dict[str, Any]] = {}
    for raw in json_out.findings_of(data):
        fingerprint = raw.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            # A finding without a fingerprint cannot be matched against anything, and
            # skipping it silently would mean the baseline quietly covers less than its
            # size suggests.
            raise SuppressError(
                f"baseline {path} contains a finding with no fingerprint "
                f"(rule {raw.get('rule_id', '?')}); it cannot be matched. {SCHEMA_HINT}"
            )
        entries[fingerprint] = {
            "rule_id": raw.get("rule_id"),
            "path": raw.get("path") or raw.get("target"),
            "severity": raw.get("severity"),
            "title": raw.get("title"),
        }

    scan = data.get("scan") if isinstance(data.get("scan"), dict) else {}
    return Baseline(
        path=path,
        fingerprints=entries,
        generated_at=(scan or {}).get("finished") or (scan or {}).get("started"),
        tool_version=(data.get("tool") or {}).get("version")
        if isinstance(data.get("tool"), dict)
        else None,
    )


def write_baseline(
    path: Path,
    findings: Sequence[Finding],
    *,
    root: Path,
    tool_version: str,
) -> int:
    """Record `findings` as accepted. Returns how many fingerprints were written.

    Written by hand rather than through `report.json_out` so that the file contains only
    what matching needs plus what a reviewer needs to audit it. In particular **snippets
    are deliberately omitted**: a baseline is committed to the repository, and a secrets
    scanner whose baseline file quotes the lines the secrets are on would put those
    credentials into version control permanently.
    """
    path = Path(path)
    records: List[Dict[str, Any]] = []
    for finding in findings:
        record: Dict[str, Any] = {
            "fingerprint": finding.fingerprint,
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity.label,
            "confidence": finding.confidence.label,
            "module": finding.module,
        }
        if finding.path:
            record["path"] = finding.path
        if finding.target:
            record["target"] = finding.target
        records.append(record)
    records.sort(key=lambda r: (r["fingerprint"], r["rule_id"]))

    from ..report.json_out import SCHEMA_VERSION

    now = time.time()
    document = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "code-recon", "version": tool_version},
        "scan": {
            "root": Path(root).name,
            "started": _iso(now),
            "finished": _iso(now),
            "complete": True,
        },
        "summary": {"total": len(records)},
        "findings": records,
        "baseline": {
            "note": (
                "Findings recorded as already-known. Delete an entry to make Code Recon "
                "report it again. Line numbers are absent on purpose: fingerprints "
                "ignore them so this file survives refactoring."
            )
        },
    }
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return len(records)


def _iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


# --------------------------------------------------------------------------------------
# Inline comments
# --------------------------------------------------------------------------------------


def parse_inline_directives(line: str) -> Optional[List[str]]:
    """Selectors from a suppression comment on `line`.

    Returns `None` when the line carries no directive, an empty list for a bare
    `coderecon:ignore` (meaning every rule on this line), or the listed selectors.
    Distinguishing "no directive" from "directive with no selectors" is why this returns
    `Optional[List[str]]` rather than just a list.
    """
    match = _INLINE_RE.search(line)
    if match is None:
        return None
    inside = match.group(1)
    if not inside:
        return []
    return [part.strip() for part in inside.split(",") if part.strip()]


def _suppressed_by(selectors: List[str], rule_id: str) -> bool:
    """A bare directive covers everything; otherwise honour prefix semantics."""
    if not selectors:
        return True
    return selector_matches(rule_id, selectors)


# --------------------------------------------------------------------------------------
# Applying
# --------------------------------------------------------------------------------------


@dataclass
class SuppressionResult:
    kept: List[Finding] = field(default_factory=list)
    suppressed: List[Finding] = field(default_factory=list)
    by_baseline: int = 0
    by_inline: int = 0
    stale_baseline: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.suppressed)


def apply_suppressions(
    findings: Sequence[Finding],
    *,
    root: Path,
    baseline: Optional[Baseline] = None,
    inline: bool = True,
) -> SuppressionResult:
    """Filter `findings` through the baseline and inline comments.

    The baseline is checked first because it needs no file access at all, so a baselined
    finding never costs a read. Inline checking then re-reads only the files that still
    have findings left.
    """
    result = SuppressionResult()
    remaining: List[Finding] = []

    for finding in findings:
        if baseline is not None and finding.fingerprint in baseline:
            result.suppressed.append(finding)
            result.by_baseline += 1
            continue
        remaining.append(finding)

    if baseline is not None:
        matched = {f.fingerprint for f in result.suppressed}
        result.stale_baseline = sorted(set(baseline.fingerprints) - matched)
        if result.stale_baseline:
            # Worth saying out loud: entries that match nothing are usually fixed code,
            # and a baseline that keeps them forever grows into a list of suppressions
            # nobody can justify.
            result.notes.append(
                f"baseline {baseline.path.name}: {len(result.stale_baseline)} of "
                f"{baseline.size} recorded finding(s) no longer occur and can be removed"
            )

    if not inline or not remaining:
        result.kept = remaining
        return result

    for finding, lines, problem in _grouped_by_file(remaining, root):
        if problem is not None:
            result.kept.append(finding)
            if problem not in result.notes:
                result.notes.append(problem)
            continue

        selectors = _directive_for(finding, lines)
        if selectors is not None and _suppressed_by(selectors, finding.rule_id):
            result.suppressed.append(finding)
            result.by_inline += 1
        else:
            result.kept.append(finding)

    return result


def _directive_for(finding: Finding, lines: List[str]) -> Optional[List[str]]:
    """The directive governing `finding`, from its own line or the line above.

    Both are honoured because appending a comment is not always possible - the finding
    may be inside a multi-line string, a JSON file, or a line that is already at the
    column limit - and a suppression mechanism that only works on short lines of Python
    would push people to disable the rule globally instead.
    """
    line_no = finding.line or 0
    for candidate in (line_no, line_no - 1):
        if 1 <= candidate <= len(lines):
            selectors = parse_inline_directives(lines[candidate - 1])
            if selectors is not None:
                return selectors
    return None


def _grouped_by_file(
    findings: Sequence[Finding],
    root: Path,
) -> List[Tuple[Finding, List[str], Optional[str]]]:
    """Pair each finding with its file's lines, reading each file at most once.

    The third element is a reason the check could not be performed; when it is set the
    caller must keep the finding. Reading is done here rather than through `walker.
    ScanFile` because these files were already walked and released, and re-walking to get
    a handful of them back would cost more than a direct read.
    """
    out: List[Tuple[Finding, List[str], Optional[str]]] = []
    cache: Dict[str, Optional[List[str]]] = {}
    root = Path(root)

    for finding in findings:
        if not finding.path:
            # Live-recon findings have a target, not a file. There is nothing to read and
            # nothing to suppress inline, which is not a failure worth noting.
            out.append((finding, [], None))
            continue
        if finding.line is None:
            out.append((
                finding,
                [],
                f"suppress: {finding.rule_id} in {finding.path} has no line number, so an "
                f"inline '{INLINE_TOKEN}' comment cannot be matched against it; the "
                f"finding was kept",
            ))
            continue

        relpath = finding.path
        if relpath not in cache:
            cache[relpath] = _read_lines(root / relpath)
        lines = cache[relpath]
        if lines is None:
            out.append((
                finding,
                [],
                f"suppress: could not re-read {relpath} to check for inline "
                f"'{INLINE_TOKEN}' comments; its finding(s) were kept",
            ))
            continue
        out.append((finding, lines, None))

    return out


def _read_lines(path: Path) -> Optional[List[str]]:
    """Decode exactly as `walker.ScanFile.text` does, so line numbers line up.

    `errors="replace"` matters: a file the scanner read with replacement characters must
    be re-read the same way, or a single undecodable byte would shift every line after it
    and the wrong line would be inspected for a directive.
    """
    try:
        return path.read_text("utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return None
