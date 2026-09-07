"""Human triage output.

The audience is somebody with twenty minutes and a list of 400 findings, so the layout is
built around what makes a list of that size survivable:

**Grouped by (severity, confidence, rule), worst first.** A flat list of 400 lines is not
readable no matter how it is coloured. Identical findings collapse into one block with its
occurrences beneath it, capped unless `--verbose`, so the *shape* of the problem is
visible on one screen: eleven places leak the same key, and that is one decision, not
eleven. Grouping on severity *and* confidence together keeps both columns truthful for
every line in a block, instead of a header claiming a confidence one occurrence does not
have.

**Two columns, never one score.** Severity says how bad it is if real, confidence says
how sure we are. They are printed side by side and coloured on different scales, because
the moment a tool merges them into a single number, everything it says becomes noise to
be muted.

**Skips and errors go at the top *and* the bottom.** A banner before the findings and a
detailed section after them. A scan that quietly did not run half its checks and printed
"no findings" is the worst thing this tool could do, so it is impossible to miss here.

**One layout, two backends.** `rich` is an optional upgrade, so all layout decisions live
in `render()` and only the painting is swapped: `_RichPainter` when the import works,
`_PlainPainter` when it does not. The fallback is not a degraded afterthought - it prints
the same tables and the same blocks, which is the only way to keep both paths honest.
Colour is suppressed for `--no-color`, for `NO_COLOR`, and for anything that is not a TTY,
because escape codes in a piped log are worse than no colour at all.
"""

from __future__ import annotations

import os
import shutil
import sys
import textwrap
from typing import Any, Dict, List, Optional, Sequence, TextIO, Tuple

from ..core.finding import Confidence, Finding, Severity
from .payload import CONFIDENCE_ORDER, SEVERITY_ORDER, ReportPayload, detection_of

SEVERITY_STYLE: Dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}
# A deliberately different scale from severity, so the eye does not read the two columns
# as one gradient.
CONFIDENCE_STYLE: Dict[Confidence, str] = {
    Confidence.CONFIRMED: "bold magenta",
    Confidence.HIGH: "magenta",
    Confidence.MEDIUM: "dim",
    Confidence.LOW: "dim",
}

_SEV_WIDTH = max(len(s.label) for s in Severity)
_CONF_WIDTH = max(len(c.label) for c in Confidence)
_MIN_WIDTH = 60
_MAX_WIDTH = 110
_PIPE_WIDTH = 100  # fixed when not a TTY, so redirected output is reproducible


def render(payload: ReportPayload, *, stream: TextIO = sys.stdout) -> None:
    """Write the human-readable report to `stream`."""
    color = _color_enabled(payload, stream)
    width = _width(stream)
    painter = _make_painter(stream, color=color, width=width)

    _header(painter, payload)
    _incomplete_banner(painter, payload)
    _findings(painter, payload)
    _severity_summary(painter, payload)
    _module_summary(painter, payload)
    _walk_summary(painter, payload)
    _problems(painter, payload)
    _verdict(painter, payload)
    painter.flush()


# --------------------------------------------------------------------------------------
# sections
# --------------------------------------------------------------------------------------


def _header(painter: "_Painter", payload: ReportPayload) -> None:
    root = payload.scan_root
    # A live-only scan has no meaningful root; a code scan with targets attached has both,
    # and showing the targets as though they were the thing scanned would misdescribe it.
    if payload.command == "live":
        where = ", ".join(payload.live_targets) or "no targets"
    else:
        where = root.name or str(root)
        if payload.live_targets:
            where += " + " + ", ".join(payload.live_targets)
    painter.line(
        painter.paint(f"{payload.tool_name} {payload.tool_version}", "bold")
        + painter.paint(f"  {payload.command} scan  ", "")
        + painter.paint(where, "bold")
    )
    stamp = payload.finished_iso or payload.started_iso
    detail = f"{payload.total_findings} finding(s)"
    if payload.duration:
        detail += f" in {payload.duration:.2f}s"
    if stamp:
        detail += f"  ({stamp})"
    if payload.suppressed_count:
        detail += f"  [{payload.suppressed_count} suppressed]"
    painter.line(painter.paint(detail, "dim"))
    painter.line()


def _incomplete_banner(painter: "_Painter", payload: ReportPayload) -> None:
    """Loud, and before the findings. Buried skip notices do not get read."""
    if not payload.scan_incomplete:
        return
    bits: List[str] = []
    if payload.errored_modules:
        bits.append(f"{len(payload.errored_modules)} module(s) FAILED")
    if payload.skipped_modules:
        bits.append(f"{len(payload.skipped_modules)} module(s) skipped")
    style = "bold red" if payload.errored_modules else "bold yellow"
    painter.line(painter.paint(f"!! SCAN INCOMPLETE: {', '.join(bits)}", style))
    painter.line(
        painter.paint(
            "   findings below are only what the modules that ran could see", "dim"
        )
    )
    painter.line()


def _findings(painter: "_Painter", payload: ReportPayload) -> None:
    findings = payload.sorted_findings()
    if not findings:
        painter.rule("findings")
        painter.line(painter.paint("  none", "dim"))
        painter.line()
        return

    painter.rule(f"findings ({len(findings)})")
    verbose = bool(payload.config.verbose)
    limit = 0 if verbose else max(0, payload.terminal_limit_per_rule)

    for (severity, confidence, rule_id), group in _grouped(findings):
        sample = group[0]
        painter.line()
        painter.line(_group_header(painter, severity, confidence, rule_id, group, sample))
        painter.line(painter.paint(f"    {_clip(sample.title, painter.width - 4)}", ""))

        shown = group if limit == 0 else group[:limit]
        for finding in shown:
            painter.line(painter.paint(f"    {_where(finding)}", "cyan"))
            if finding.snippet:
                painter.line(painter.paint(f"      {_clip(finding.snippet, painter.width - 6)}", "dim"))
            if verbose:
                _verbose_detail(painter, finding)
        hidden = len(group) - len(shown)
        if hidden > 0:
            painter.line(
                painter.paint(
                    f"      ... {hidden} more occurrence(s); rerun with --verbose to list them",
                    "dim",
                )
            )
        if payload.show_remediation and sample.remediation:
            for line in _wrap(f"fix: {sample.remediation}", painter.width - 4, "    "):
                painter.line(painter.paint(line, "green"))
    painter.line()


def _group_header(
    painter: "_Painter",
    severity: Severity,
    confidence: Confidence,
    rule_id: str,
    group: Sequence[Finding],
    sample: Finding,
) -> str:
    """`critical  confirmed  rule.id x3    secrets - via regex`.

    Padding happens before painting: styled strings carry escape codes that would
    otherwise be counted as visible characters and wreck the column alignment.
    """
    sev = painter.paint(severity.label.ljust(_SEV_WIDTH), SEVERITY_STYLE[severity])
    conf = painter.paint(confidence.label.ljust(_CONF_WIDTH), CONFIDENCE_STYLE[confidence])
    count = f" x{len(group)}" if len(group) > 1 else ""
    origin = f"{sample.module or 'unknown'} - {_method_label(sample)}"
    return f"  {sev}  {conf}  " + painter.paint(rule_id + count, "bold") + painter.paint(f"   {origin}", "dim")


def _method_label(finding: Finding) -> str:
    """A parsed fact and a regex resemblance must not read the same."""
    method = detection_of(finding)
    if method == "ast":
        return "via ast (parsed code)"
    if method == "parsed":
        return "via parsed data"
    if method == "regex":
        return "via regex (heuristic)"
    if method:
        return f"via {method}"
    return "detection method not declared"


def _verbose_detail(painter: "_Painter", finding: Finding) -> None:
    bits: List[str] = [f"fingerprint {finding.fingerprint}"]
    if finding.cwe:
        bits.append(finding.cwe)
    if finding.tags:
        bits.append("tags: " + ",".join(sorted(finding.tags)))
    masked = finding.extra.get("masked") if finding.extra else None
    if isinstance(masked, str):
        bits.append(f"value {masked}")
    painter.line(painter.paint("      " + "  |  ".join(bits), "dim"))
    for ref in finding.references:
        painter.line(painter.paint(f"      see {ref}", "dim"))


def _severity_summary(painter: "_Painter", payload: ReportPayload) -> None:
    painter.rule("counts")
    sev_counts = payload.severity_counts()
    conf_counts = payload.confidence_counts()
    # Side-by-side would imply a correspondence between the rows that does not exist, so
    # they are two separate tables.
    painter.table(
        ["severity", "findings"],
        [
            [painter.paint(sev.label, SEVERITY_STYLE[sev]), str(sev_counts.get(sev, 0))]
            for sev in SEVERITY_ORDER
        ],
    )
    painter.table(
        ["confidence", "findings"],
        [
            [painter.paint(conf.label, CONFIDENCE_STYLE[conf]), str(conf_counts.get(conf, 0))]
            for conf in CONFIDENCE_ORDER
        ],
    )
    detection = payload.detection_counts()
    if detection:
        painter.table(
            ["detection", "findings"],
            [[method, str(count)] for method, count in detection.items()],
        )


def _module_summary(painter: "_Painter", payload: ReportPayload) -> None:
    if not payload.module_results:
        return
    painter.rule("modules")
    counts = payload.module_counts()
    rows: List[List[str]] = []
    for result in payload.module_results:
        if result.error:
            status = painter.paint("ERROR", "bold red")
        elif result.skipped:
            status = painter.paint("skipped", "bold yellow")
        else:
            status = painter.paint("ok", "green")
        # `ModuleResult.duration` is the shared elapsed time of the fused file pass for
        # every module inside it, so printing it per module would invent a measurement.
        if result.duration <= 0:
            timing = "-"
        elif payload.duration_is_shared(result.name):
            timing = "shared pass"
        else:
            timing = f"{result.duration:.2f}s"
        rows.append([result.name, status, str(counts.get(result.name, 0)), timing])
    painter.table(["module", "status", "findings", "time"], rows)
    for elapsed, names in payload.shared_duration_groups():
        painter.line(
            painter.paint(
                f"  shared file pass: {elapsed:.2f}s total for {', '.join(sorted(names))}"
                " (one read per file, not per module)",
                "dim",
            )
        )


def _walk_summary(painter: "_Painter", payload: ReportPayload) -> None:
    if not payload.walk_stats:
        return
    painter.rule("traversal")
    # An unexpectedly tiny `files_scanned` is the tell for a scan that looked at nothing,
    # which is why these are in the default output and not behind --verbose.
    order = [
        "files_seen",
        "files_scanned",
        "bytes_scanned",
        "skipped_ignored",
        "skipped_binary",
        "skipped_large",
        "skipped_minified",
    ]
    stats = payload.walk_stats
    keys = [k for k in order if k in stats] + [k for k in sorted(stats) if k not in order]
    painter.line("  " + painter.paint("  ".join(f"{k}={stats[k]}" for k in keys), "dim"))
    if payload.routes:
        painter.line(painter.paint(f"  routes discovered: {len(payload.routes)}", "dim"))


def _problems(painter: "_Painter", payload: ReportPayload) -> None:
    """Skips, errors, and notes. Full reasons, never truncated."""
    if payload.errored_modules:
        painter.rule("module errors")
        for result in payload.errored_modules:
            painter.line(painter.paint(f"  {result.name}: FAILED", "bold red"))
            for line in _wrap(str(result.error), painter.width - 4, "    "):
                painter.line(line)
    if payload.skipped_modules:
        painter.rule("skipped modules")
        for result in payload.skipped_modules:
            painter.line(painter.paint(f"  {result.name}: did not run", "bold yellow"))
            for line in _wrap(str(result.skipped), painter.width - 4, "    "):
                painter.line(line)
    if payload.notes:
        painter.rule("notes")
        for note in payload.notes:
            for line in _wrap(note, painter.width - 4, "  ", first_prefix="  - "):
                painter.line(line)


def _verdict(painter: "_Painter", payload: ReportPayload) -> None:
    painter.line()
    highest = payload.highest_severity
    parts: List[str] = []
    counts = payload.severity_counts()
    for sev in SEVERITY_ORDER:
        if counts.get(sev):
            parts.append(f"{counts[sev]} {sev.label}")
    summary = ", ".join(parts) if parts else "no findings"
    style = SEVERITY_STYLE[highest] if highest is not None else "green"
    painter.line(painter.paint(f"summary: {summary}", style))
    if payload.any_module_errored:
        painter.line(
            painter.paint(
                "warning: at least one module failed - this scan is not a clean bill of health",
                "bold red",
            )
        )
    elif payload.any_module_skipped:
        painter.line(
            painter.paint(
                "note: some modules were skipped - see the reasons above", "bold yellow"
            )
        )


# --------------------------------------------------------------------------------------
# grouping and text helpers
# --------------------------------------------------------------------------------------


def _grouped(
    findings: Sequence[Finding],
) -> List[Tuple[Tuple[Severity, Confidence, str], List[Finding]]]:
    """Collapse to (severity, confidence, rule) blocks, worst and most certain first."""
    groups: Dict[Tuple[Severity, Confidence, str], List[Finding]] = {}
    for finding in findings:  # already in sort_findings order, so members stay ordered
        groups.setdefault((finding.severity, finding.confidence, finding.rule_id), []).append(
            finding
        )
    return sorted(groups.items(), key=lambda kv: (-int(kv[0][0]), -int(kv[0][1]), kv[0][2]))


def _where(finding: Finding) -> str:
    """`path:line:col`, which most terminals turn into a clickable link."""
    if finding.path:
        if finding.line:
            if finding.column:
                return f"{finding.path}:{finding.line}:{finding.column}"
            return f"{finding.path}:{finding.line}"
        return finding.path
    return finding.target or "<no location>"


def _clip(text: str, width: int) -> str:
    """One line, clipped. Snippets can be pathologically long; the terminal is not."""
    flat = " ".join(str(text).split())
    width = max(20, width)
    return flat if len(flat) <= width else flat[: width - 1] + "…"


def _wrap(text: str, width: int, prefix: str, first_prefix: Optional[str] = None) -> List[str]:
    flat = " ".join(str(text).split())
    return textwrap.wrap(
        flat,
        width=max(30, width),
        initial_indent=first_prefix if first_prefix is not None else prefix,
        subsequent_indent=prefix,
    ) or [prefix.rstrip()]


def _color_enabled(payload: ReportPayload, stream: TextIO) -> bool:
    if payload.config.no_color:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return bool(stream.isatty())
    except Exception:  # noqa: BLE001 - a stream that cannot answer is not a terminal
        return False


def _width(stream: TextIO) -> int:
    try:
        if stream.isatty():
            return max(_MIN_WIDTH, min(_MAX_WIDTH, shutil.get_terminal_size().columns))
    except Exception:  # noqa: BLE001
        pass
    return _PIPE_WIDTH


# --------------------------------------------------------------------------------------
# painters
# --------------------------------------------------------------------------------------


class _Painter:
    """Everything that differs between the rich and plain backends, and nothing else."""

    def __init__(self, stream: TextIO, *, color: bool, width: int) -> None:
        self.stream = stream
        self.color = color
        self.width = width

    def paint(self, text: str, style: str) -> str:
        raise NotImplementedError

    def line(self, text: str = "") -> None:
        raise NotImplementedError

    def rule(self, title: str) -> None:
        raise NotImplementedError

    def table(self, headers: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
        raise NotImplementedError

    def flush(self) -> None:
        try:
            self.stream.flush()
        except Exception:  # noqa: BLE001
            pass


_ANSI = {
    "bold": "1",
    "dim": "2",
    "italic": "3",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "white": "37",
}


class _PlainPainter(_Painter):
    """stdlib-only renderer: SGR codes when colour is on, bare text when it is not."""

    def paint(self, text: str, style: str) -> str:
        if not self.color or not style or not text:
            return text
        codes = [_ANSI[word] for word in style.split() if word in _ANSI]
        if not codes:
            return text
        return f"\x1b[{';'.join(codes)}m{text}\x1b[0m"

    def line(self, text: str = "") -> None:
        self.stream.write(text + "\n")

    def rule(self, title: str) -> None:
        label = f"-- {title} "
        self.line()
        self.line(self.paint(label + "-" * max(0, self.width - len(label)), "bold"))

    def table(self, headers: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
        widths = [_visible_len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], _visible_len(cell))
        head = "  ".join(self.paint(_pad(h, widths[i]), "bold") for i, h in enumerate(headers))
        self.line(("  " + head).rstrip())
        self.line("  " + "  ".join("-" * w for w in widths))
        for row in rows:
            cells = "  ".join(_pad(cell, widths[i]) for i, cell in enumerate(row))
            self.line(("  " + cells).rstrip())
        self.line()


class _RichPainter(_Painter):
    """Same layout, rendered through `rich` when it is importable."""

    def __init__(self, stream: TextIO, *, color: bool, width: int, console: Any, table_cls: Any) -> None:
        super().__init__(stream, color=color, width=width)
        self.console = console
        self.table_cls = table_cls

    def paint(self, text: str, style: str) -> str:
        if not style or not text:
            return _escape_markup(text)
        return f"[{style}]{_escape_markup(text)}[/{style}]"

    def line(self, text: str = "") -> None:
        # highlight off: rich's auto-highlighter recolours anything that looks like a
        # number or a path, which fights the severity colouring.
        self.console.print(text, highlight=False, soft_wrap=True)

    def rule(self, title: str) -> None:
        self.line()
        self.console.rule(f"[bold]{_escape_markup(title)}", align="left")

    def table(self, headers: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
        table = self.table_cls(box=None, pad_edge=False, show_edge=False)
        for i, header in enumerate(headers):
            # Two leading spaces on the first column only, matching the plain backend's
            # indentation so the two paths produce the same shape.
            label = ("  " if i == 0 else "") + _escape_markup(header)
            table.add_column(f"[bold]{label}", overflow="fold")
        for row in rows:
            cells = list(row)
            if cells:
                cells[0] = "  " + cells[0]
            table.add_row(*cells)
        self.console.print(table)
        self.console.print()


def _make_painter(stream: TextIO, *, color: bool, width: int) -> _Painter:
    """Prefer rich, fall back cleanly. Both paths must stay usable, so this never raises."""
    try:
        from rich.console import Console  # noqa: PLC0415 - optional dependency
        from rich.table import Table  # noqa: PLC0415
    except Exception:  # noqa: BLE001 - ImportError, or a broken partial install
        return _PlainPainter(stream, color=color, width=width)
    try:
        console = Console(
            file=stream,
            width=width,
            # force_terminal only when we already decided colour is wanted; otherwise rich
            # sees a non-TTY and emits no escapes, which is what --no-color requires.
            force_terminal=True if color else False,
            no_color=not color,
            highlight=False,
            emoji=False,
            markup=True,
            soft_wrap=True,
        )
    except Exception:  # noqa: BLE001
        return _PlainPainter(stream, color=color, width=width)
    return _RichPainter(stream, color=color, width=width, console=console, table_cls=Table)


def _escape_markup(text: str) -> str:
    """Snippets contain `[` from real code; rich would read that as markup."""
    return text.replace("[", "\\[")


def _visible_len(text: str) -> int:
    """Length ignoring SGR sequences, so padded columns line up once painted."""
    out, i = 0, 0
    while i < len(text):
        if text[i] == "\x1b":
            end = text.find("m", i)
            if end == -1:
                break
            i = end + 1
            continue
        out += 1
        i += 1
    return out


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _visible_len(text))


__all__ = ["render"]
