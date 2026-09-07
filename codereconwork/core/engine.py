"""Module registry and scan orchestration.

Two things here are deliberate:

**Single-pass file scanning.** Modules that work file-by-file subclass `FileScanModule`
and the runner fuses them: each file is read, decoded, handed to every such module, then
its cached text is dropped. Reading a large repo once instead of once per module is the
difference between a few seconds and half a minute, and it bounds peak memory to the
worker count rather than the repo size.

**A failing module never fails the scan.** Modules are isolated; a crash is recorded
against that module, reported, and turns the final exit code into 2 (tool error) so CI
can tell "nothing found" apart from "the dependency scanner blew up and found nothing".
"""

from __future__ import annotations

import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from .context import LiveContext, ScanContext
from .finding import Finding
from .walker import ScanFile

AnyContext = Union[ScanContext, LiveContext]


@dataclass
class ModuleResult:
    name: str
    findings: List[Finding] = field(default_factory=list)
    skipped: Optional[str] = None  # why it did not run
    error: Optional[str] = None  # traceback summary if it crashed
    duration: float = 0.0
    stats: Dict[str, Any] = field(default_factory=dict)

    @property
    def ran(self) -> bool:
        return self.skipped is None and self.error is None


class ScanModule:
    """Base class for all checks."""

    name: str = ""
    description: str = ""
    phase: str = "code"  # "code" or "live"
    requires_network: bool = False
    requires_git: bool = False
    # Modules that are noisy or slow can be opt-in via --module.
    default_enabled: bool = True

    def unavailable(self, ctx: AnyContext) -> Optional[str]:
        """Return a human-readable reason to skip, or None to run.

        Base implementation enforces the global `--offline` switch so no network module
        has to remember to.
        """
        if self.requires_network and getattr(ctx.config, "offline", False):
            return "needs network access, and --offline was requested"
        return None

    def run(self, ctx: AnyContext) -> List[Finding]:
        raise NotImplementedError

    # Set by the runner so modules can report counters in the JSON output.
    def stats(self) -> Dict[str, Any]:
        return {}


class FileScanModule(ScanModule):
    """A module that examines one file at a time, fused into the shared file pass."""

    def scan_file(self, sf: ScanFile, ctx: ScanContext) -> List[Finding]:
        raise NotImplementedError

    def prepare(self, ctx: ScanContext) -> None:
        """Hook for work that must happen once before the file pass (e.g. compile rules)."""

    def finish(self, ctx: ScanContext) -> List[Finding]:
        """Hook for findings that can only be determined after seeing every file."""
        return []

    def run(self, ctx: AnyContext) -> List[Finding]:
        # Standalone path, used when a single file module is run outside the fused pass.
        assert isinstance(ctx, ScanContext)
        self.prepare(ctx)
        out: List[Finding] = []
        for sf in ctx.files:
            out.extend(self.scan_file(sf, ctx))
            sf.release()
        out.extend(self.finish(ctx))
        return out


# --------------------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------------------

REGISTRY: Dict[str, ScanModule] = {}


def register(cls: Callable[[], ScanModule]) -> Callable[[], ScanModule]:
    """Class decorator: instantiate and register a module."""
    instance = cls()
    if not instance.name:
        raise ValueError(f"{cls.__name__} must set a `name`")
    if instance.name in REGISTRY:
        raise ValueError(f"duplicate module name {instance.name!r}")
    REGISTRY[instance.name] = instance
    return cls


def modules_for_phase(phase: str) -> List[ScanModule]:
    return [m for m in REGISTRY.values() if m.phase == phase]


def select_modules(phase: str, selected: Optional[Sequence[str]]) -> List[ScanModule]:
    """Resolve `--module` selectors against the registry.

    Accepts exact names and prefixes, so `--module live` picks up every live submodule.
    """
    available = modules_for_phase(phase)
    if not selected:
        return [m for m in available if m.default_enabled]
    picked: List[ScanModule] = []
    unknown: List[str] = []
    for sel in selected:
        sel = sel.strip()
        hits = [m for m in available if m.name == sel or m.name.startswith(sel + ".")]
        if not hits:
            # Might belong to the other phase; only complain if it is nowhere.
            if not any(m.name == sel or m.name.startswith(sel + ".") for m in REGISTRY.values()):
                unknown.append(sel)
            continue
        for m in hits:
            if m not in picked:
                picked.append(m)
    if unknown:
        known = ", ".join(sorted(REGISTRY))
        raise ValueError(f"unknown module(s): {', '.join(unknown)}. Available: {known}")
    return picked


# --------------------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------------------


def _summarize_error(exc: BaseException) -> str:
    tb = traceback.format_exception_only(type(exc), exc)
    return "".join(tb).strip()


def run_code_modules(
    ctx: ScanContext,
    modules: Sequence[ScanModule],
    *,
    progress: Optional[Callable[[str], None]] = None,
) -> List[ModuleResult]:
    """Run code-phase modules, fusing the file-by-file ones into a single pass."""
    results: List[ModuleResult] = []

    file_modules: List[FileScanModule] = []
    other_modules: List[ScanModule] = []
    for mod in modules:
        reason = mod.unavailable(ctx)
        if reason:
            results.append(ModuleResult(name=mod.name, skipped=reason))
            ctx.note(f"module {mod.name} skipped: {reason}")
            continue
        (file_modules if isinstance(mod, FileScanModule) else other_modules).append(mod)  # type: ignore[arg-type]

    if file_modules:
        results.extend(_run_fused_file_pass(ctx, file_modules, progress))

    for mod in other_modules:
        if progress:
            progress(mod.name)
        started = time.monotonic()
        try:
            findings = list(mod.run(ctx))
            results.append(
                ModuleResult(
                    name=mod.name,
                    findings=findings,
                    duration=time.monotonic() - started,
                    stats=mod.stats(),
                )
            )
        except Exception as exc:  # noqa: BLE001 - isolation is the point
            results.append(
                ModuleResult(
                    name=mod.name,
                    error=_summarize_error(exc),
                    duration=time.monotonic() - started,
                )
            )
            ctx.note(f"module {mod.name} failed: {_summarize_error(exc)}")

    return results


def _run_fused_file_pass(
    ctx: ScanContext,
    modules: List[FileScanModule],
    progress: Optional[Callable[[str], None]],
) -> List[ModuleResult]:
    started = time.monotonic()
    per_module: Dict[str, List[Finding]] = {m.name: [] for m in modules}
    errors: Dict[str, str] = {}

    for mod in modules:
        try:
            mod.prepare(ctx)
        except Exception as exc:  # noqa: BLE001
            errors[mod.name] = _summarize_error(exc)
    active = [m for m in modules if m.name not in errors]

    if progress:
        progress("+".join(m.name for m in active) or "file scan")

    def scan_one(sf: ScanFile) -> Dict[str, List[Finding]]:
        local: Dict[str, List[Finding]] = {}
        for mod in active:
            try:
                found = mod.scan_file(sf, ctx)
            except Exception as exc:  # noqa: BLE001 - one bad file must not stop the scan
                errors.setdefault(mod.name, f"{sf.relpath}: {_summarize_error(exc)}")
                continue
            if found:
                local[mod.name] = found
        sf.release()  # bound memory: worker count, not repo size
        return local

    # Threads, not processes: the win is overlapping file reads. Python's `re` module
    # holds the GIL while matching, so regex work does not parallelize here - the
    # keyword pre-filter in Rule.prefilter is what keeps that cost down instead.
    workers = max(1, min(ctx.config.effective_jobs(), 32))
    if workers == 1 or len(ctx.files) < 32:
        for sf in ctx.files:
            for name, found in scan_one(sf).items():
                per_module[name].extend(found)
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for local in pool.map(scan_one, ctx.files):
                for name, found in local.items():
                    per_module[name].extend(found)

    for mod in active:
        try:
            per_module[mod.name].extend(mod.finish(ctx))
        except Exception as exc:  # noqa: BLE001
            errors.setdefault(mod.name, _summarize_error(exc))

    elapsed = time.monotonic() - started
    results: List[ModuleResult] = []
    for mod in modules:
        results.append(
            ModuleResult(
                name=mod.name,
                findings=per_module.get(mod.name, []),
                error=errors.get(mod.name),
                # The pass is shared, so attributing wall-clock per module would be a
                # lie; report the shared duration and let the report label it.
                duration=elapsed,
                stats=mod.stats(),
            )
        )
        if mod.name in errors:
            ctx.note(f"module {mod.name} failed: {errors[mod.name]}")
    return results


def run_live_modules(
    ctx: LiveContext,
    modules: Sequence[ScanModule],
    *,
    progress: Optional[Callable[[str], None]] = None,
) -> List[ModuleResult]:
    """Run live-phase modules in order.

    Sequential on purpose: ordering matters (DNS resolution feeds the port scan, which
    feeds TLS and HTTP), and serialising keeps the request rate against a single target
    predictable and polite.
    """
    results: List[ModuleResult] = []
    for mod in modules:
        reason = mod.unavailable(ctx)
        if reason:
            results.append(ModuleResult(name=mod.name, skipped=reason))
            ctx.note(f"module {mod.name} skipped: {reason}")
            continue
        if progress:
            progress(mod.name)
        started = time.monotonic()
        try:
            findings = list(mod.run(ctx))
            results.append(
                ModuleResult(
                    name=mod.name,
                    findings=findings,
                    duration=time.monotonic() - started,
                    stats=mod.stats(),
                )
            )
        except Exception as exc:  # noqa: BLE001
            results.append(
                ModuleResult(
                    name=mod.name,
                    error=_summarize_error(exc),
                    duration=time.monotonic() - started,
                )
            )
            ctx.note(f"module {mod.name} failed: {_summarize_error(exc)}")
    return results
