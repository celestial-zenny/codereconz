"""Dependency vulnerability scanning against OSV.dev.

Eleven manifest formats are parsed into one flat list of `(ecosystem, name, version)`
triples, deduplicated, and looked up in OSV's `querybatch` API. The design decisions
worth knowing:

**A standalone module, not a `FileScanModule`.** Fusing into the shared file pass would
be cheaper on I/O, but it would tie dependency discovery to the walker's filters, which
are tuned for *source* scanning: a 6 MB `package-lock.json` exceeds the default 4 MB
source cap, and a `Cargo.lock` that a library author gitignored still describes what gets
built. Missing dependencies silently is the one failure this module cannot afford, so it
does its own filename-driven walk with its own size cap and reports anything it had to
drop.

**Only exactly-pinned versions are queried.** `requests>=2.0` cannot be resolved to a
version without running a real dependency resolver, and guessing would invent findings.
Unpinned requirements are counted by reason and reported, never silently passed over -
"12 requirements were not pinned and could not be checked" is a true statement about scan
completeness; omitting them is not.

**Lockfiles get CONFIRMED confidence, manifests get HIGH.** A lockfile entry is the
version that will be installed. A `pom.xml` or `requirements.txt` pin can still be
overridden at build time, so it is one notch less certain. Severity comes from the
advisory's CVSS vector, computed here (the v3.1 base-score formula is ~40 lines of
well-specified arithmetic), because bucketing a 9.8 RCE and a 3.7 DoS both as "medium" is
how scanners get muted.

**Two cache namespaces, two different TTLs.** Package lookups expire in a day, because
new advisories land daily. Vulnerability records are keyed on `id + modified`, so the key
itself changes whenever upstream edits the record - that makes a 30-day TTL safe rather
than stale.

**A failed OSV batch fails the scan.** `HttpClient` already retries 5xx/429/transport
errors with backoff, so an exhausted batch means OSV is genuinely unreachable. Returning
the findings we did collect would let CI read an incomplete dependency scan as a clean
one, so the module raises and the run exits 2. The vulnerability counts it *did* find are
pushed into `ctx.note()` first, so nothing learned is thrown away. Failing to fetch a
vuln's *details* is different and does not raise: we already know the package is
affected, and only the enrichment is missing.

Package names and versions are sent to `api.osv.dev` - that is the point of the module,
but it is a disclosure, so the scan notes say so explicitly.
"""

from __future__ import annotations

import json
import math
import os
import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..core.cache import DEFAULT_TTL, TtlCache, default_cache_path
from ..core.context import ScanContext
from ..core.engine import ScanModule, register
from ..core.finding import Confidence, Finding, Severity
from ..core.http import HttpClient, HttpError
from ..core.walker import DEFAULT_EXCLUDE_DIRS

# --------------------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------------------

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

# OSV's documented ceiling for one querybatch call.
OSV_BATCH_SIZE = 1000

# Manifests are allowed to be much larger than source files: a lockfile for a big npm
# project routinely passes 4 MB, and skipping it would mean silently missing every
# dependency in the project.
MANIFEST_MAX_BYTES = 16 * 1024 * 1024

# Vulnerability records are content-addressed by `modified`, so a long TTL cannot serve
# an outdated record - the key changes when the record does.
VULN_RECORD_TTL = 30 * 24 * 3600.0

# OSV ecosystem identifiers, spelled exactly as the API expects them.
ECO_PYPI = "PyPI"
ECO_NPM = "npm"
ECO_GO = "Go"
ECO_RUBYGEMS = "RubyGems"
ECO_PACKAGIST = "Packagist"
ECO_CRATES = "crates.io"
ECO_MAVEN = "Maven"

_ECO_SLUG = {
    ECO_PYPI: "pypi",
    ECO_NPM: "npm",
    ECO_GO: "go",
    ECO_RUBYGEMS: "rubygems",
    ECO_PACKAGIST: "packagist",
    ECO_CRATES: "crates-io",
    ECO_MAVEN: "maven",
}

# Default when an advisory carries no machine-readable severity at all. Not a guess about
# impact - a placeholder that the finding is tagged with, so it can be told apart from a
# rating we actually computed.
UNRATED_SEVERITY = Severity.MEDIUM

# "Dependency on Vulnerable Third-Party Component", used when the advisory names no CWE.
DEFAULT_CWE = "CWE-1395"


# --------------------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Package:
    """One resolved dependency, ready to query."""

    ecosystem: str
    name: str  # as written in the manifest, for display
    version: str
    path: str  # manifest, relative to scan root
    line: Optional[int] = None
    dev: bool = False
    from_lockfile: bool = True
    tags: Tuple[str, ...] = ()

    @property
    def query_name(self) -> str:
        """The name OSV indexes, which is not always the name in the manifest."""
        return normalize_name(self.ecosystem, self.name)

    @property
    def key(self) -> str:
        return f"{self.ecosystem}|{self.query_name}|{self.version}"

    @property
    def coordinate(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass
class Manifest:
    """A discovered dependency file and the parser that claims it."""

    path: Path
    relpath: str
    kind: str
    size: int


@dataclass
class ParseResult:
    """What one manifest yielded, including everything it could *not* resolve."""

    packages: List[Package] = field(default_factory=list)
    # reason -> count. Surfaced in the report so an unpinned range is visibly
    # unchecked rather than invisibly absent.
    skipped: Dict[str, int] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def skip(self, reason: str, count: int = 1) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + count


def normalize_name(ecosystem: str, name: str) -> str:
    """Map a manifest name onto the spelling OSV indexes.

    Only PyPI and Packagist genuinely need this (PEP 503 collapses `.`/`_`/`-` runs and
    lowercases; Packagist is case-insensitive), but normalising here also keeps the cache
    from storing `Django` and `django` as two different keys for one package.
    """
    name = name.strip()
    if ecosystem == ECO_PYPI:
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == ECO_PACKAGIST:
        return name.lower()
    return name


# --------------------------------------------------------------------------------------
# Minimal TOML, for hosts without `tomllib`
# --------------------------------------------------------------------------------------


def _tomllib_load(text: str) -> Optional[Dict[str, Any]]:
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        return None
    try:
        return tomllib.loads(text)
    except Exception:  # noqa: BLE001 - a malformed lockfile is the caller's problem
        raise


_TOML_HEADER = re.compile(r"^\s*\[(\[?)([^\]]+)\]\]?\s*$")
_TOML_KV = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*=\s*(.+?)\s*$")


def _mini_toml_packages(text: str) -> List[Dict[str, Any]]:
    """Extract `[[package]]` blocks from a lockfile without a TOML library.

    Deliberately not a TOML parser. It understands array-of-tables headers and
    single-line `key = "value"` pairs, skips over multi-line arrays and triple-quoted
    strings, and ignores everything else - which is the entire shape of a generated
    `poetry.lock` or `Cargo.lock`. The zero-dependency rule is why this exists at all;
    the narrow scope is why it can be trusted.
    """
    blocks: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    in_package = False
    skip_until: Optional[str] = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if skip_until is not None:
            if skip_until in line:
                skip_until = None
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        header = _TOML_HEADER.match(line)
        if header:
            is_array = header.group(1) == "["
            name = header.group(2).strip()
            if is_array and name == "package":
                current = {"_line": None}
                blocks.append(current)
                in_package = True
            else:
                # Any other header ends the block: `[package.metadata]` and friends carry
                # keys we would otherwise mistake for the package's own.
                in_package = False
                current = None
            continue

        if not in_package or current is None:
            continue

        kv = _TOML_KV.match(line)
        if not kv:
            continue
        key, value = kv.group(1), kv.group(2)
        if value.startswith('"""') or value.startswith("'''"):
            marker = value[:3]
            if value.count(marker) < 2:
                skip_until = marker
            continue
        if value.startswith("[") and not value.rstrip().endswith("]"):
            skip_until = "]"
            continue
        current.setdefault(key, _toml_scalar(value))

    return blocks


def _toml_scalar(value: str) -> Any:
    value = value.strip()
    if value.startswith('"') and value.endswith('"') and len(value) >= 2:
        return value[1:-1]
    if value.startswith("'") and value.endswith("'") and len(value) >= 2:
        return value[1:-1]
    if value in ("true", "false"):
        return value == "true"
    if value.startswith("["):
        inner = value.strip("[]")
        return [_toml_scalar(part) for part in inner.split(",") if part.strip()]
    return value


def _toml_package_blocks(text: str) -> List[Dict[str, Any]]:
    """`[[package]]` blocks via `tomllib` when present, else the mini reader."""
    parsed = _tomllib_load(text)
    if parsed is not None:
        packages = parsed.get("package")
        if isinstance(packages, list):
            return [p for p in packages if isinstance(p, dict)]
        return []
    return _mini_toml_packages(text)


# --------------------------------------------------------------------------------------
# Line lookup for structured formats
# --------------------------------------------------------------------------------------


def _line_of_key(text: str, needle: str, *, start_at: int = 0) -> Optional[int]:
    """Best-effort 1-indexed line for a JSON/XML key, for clickable output.

    A real position-tracking parser would be exact, but a missing line number costs the
    user a jump and nothing else, so the cheap scan is the right trade here.
    """
    index = text.find(needle, start_at)
    if index < 0:
        return None
    return text.count("\n", 0, index) + 1


# --------------------------------------------------------------------------------------
# Python
# --------------------------------------------------------------------------------------

_REQ_PIN = re.compile(
    r"""^(?P<name>[A-Za-z0-9][A-Za-z0-9._\-]*)
         (?:\[(?P<extras>[^\]]*)\])?
         \s*(?P<op>===|==)\s*
         (?P<version>[^\s;#\\]+)\s*$""",
    re.VERBOSE,
)
_REQ_ANY_SPEC = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:\[[^\]]*\])?\s*([<>!~=].*)$")
_COMMENT = re.compile(r"(?:^|\s)#.*$")


def _logical_lines(text: str) -> List[Tuple[int, str]]:
    """Join backslash continuations, keeping the first physical line number."""
    out: List[Tuple[int, str]] = []
    buffer = ""
    start = 0
    for lineno, raw in enumerate(text.splitlines(), 1):
        stripped = raw.rstrip()
        if not buffer:
            start = lineno
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        buffer += stripped
        out.append((start, buffer))
        buffer = ""
    if buffer:
        out.append((start, buffer))
    return out


def parse_requirements(text: str, relpath: str) -> ParseResult:
    """pip requirements files. Only `==`/`===` pins are queryable."""
    result = ParseResult()
    includes: List[str] = []

    for lineno, logical in _logical_lines(text):
        line = _COMMENT.sub("", logical).strip()
        if not line:
            continue

        if line.startswith("-"):
            option = line.split("=", 1)[0].split()[0]
            if option in ("-r", "--requirement", "-c", "--constraint"):
                target = line.split(maxsplit=1)[1].strip() if " " in line else ""
                includes.append(target or "?")
            elif option in ("-e", "--editable"):
                result.skip("editable install (no fixed version)")
            # Index URLs, hashes and flags carry no dependency information.
            continue

        # A requirement may carry its own long-form options - `--hash` above all, which
        # pip conventionally puts on continuation lines that were just joined above.
        # Only `--` is stripped; a bare `-` could appear inside an environment marker.
        option_at = re.search(r"\s--[A-Za-z]", line)
        if option_at:
            line = line[: option_at.start()].strip()

        # `pkg @ https://...` direct references and bare paths pin a URL, not a version
        # OSV can match.
        if " @ " in line or line.startswith((".", "/")) or "://" in line:
            result.skip("direct URL or path reference (not a registry version)")
            continue

        marker = None
        if ";" in line:
            line, marker = line.split(";", 1)
            line = line.strip()
            marker = marker.strip()

        match = _REQ_PIN.match(line)
        if not match:
            spec = _REQ_ANY_SPEC.match(line)
            if spec:
                result.skip(f"version range {spec.group(2).strip()!r} is not an exact pin")
            elif line:
                result.skip("no version specified")
            continue

        version = match.group("version")
        if "*" in version:
            result.skip(f"wildcard pin {version!r} does not name one version")
            continue

        tags = ("marker-gated",) if marker else ()
        result.packages.append(
            Package(
                ecosystem=ECO_PYPI,
                name=match.group("name"),
                version=version,
                path=relpath,
                line=lineno,
                # A requirements file is an input to resolution, not its output.
                from_lockfile=False,
                tags=tags,
            )
        )

    if includes:
        result.notes.append(
            f"{relpath} includes {len(includes)} other requirements file(s) "
            f"({', '.join(sorted(set(includes))[:3])}); they are only checked if the walk "
            f"found them on their own"
        )
    return result


def parse_poetry_lock(text: str, relpath: str) -> ParseResult:
    result = ParseResult()
    for block in _toml_package_blocks(text):
        name = block.get("name")
        version = block.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            result.skip("lock entry without a name/version pair")
            continue
        groups = block.get("groups")
        dev = block.get("category") == "dev" or (
            isinstance(groups, list) and bool(groups) and "main" not in groups
        )
        result.packages.append(
            Package(
                ecosystem=ECO_PYPI,
                name=name,
                version=version,
                path=relpath,
                line=_line_of_key(text, f'name = "{name}"'),
                dev=bool(dev),
            )
        )
    return result


def parse_pipfile_lock(text: str, relpath: str) -> ParseResult:
    result = ParseResult()
    data = json.loads(text)
    for section, dev in (("default", False), ("develop", True)):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for name, meta in entries.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if not isinstance(version, str) or not version.startswith("=="):
                # Git/file/editable requirements resolve to a ref, not a release.
                result.skip("Pipfile entry pinned to a VCS ref or path, not a version")
                continue
            result.packages.append(
                Package(
                    ecosystem=ECO_PYPI,
                    name=name,
                    version=version[2:].strip(),
                    path=relpath,
                    line=_line_of_key(text, f'"{name}"'),
                    dev=dev,
                )
            )
    return result


# --------------------------------------------------------------------------------------
# JavaScript
# --------------------------------------------------------------------------------------


def parse_package_lock(text: str, relpath: str) -> ParseResult:
    """npm `package-lock.json` / `npm-shrinkwrap.json`, lockfile versions 1 through 3."""
    result = ParseResult()
    data = json.loads(text)

    packages = data.get("packages")
    if isinstance(packages, dict):
        # v2/v3. Ignored on purpose: the sibling `dependencies` block that v2 keeps for
        # backwards compatibility describes the same tree and would double every entry.
        for location, meta in packages.items():
            if not location or not isinstance(meta, dict):
                continue  # "" is the project itself
            if meta.get("link"):
                continue  # a symlink to a workspace member, not an installed release
            marker = "node_modules/"
            if marker not in location:
                continue  # a workspace package declared by path
            name = location.rsplit(marker, 1)[1]
            version = meta.get("version")
            if not isinstance(version, str) or not version:
                result.skip("lock entry without a resolved version")
                continue
            result.packages.append(
                Package(
                    ecosystem=ECO_NPM,
                    name=name,
                    version=version,
                    path=relpath,
                    line=_line_of_key(text, f'"{location}"'),
                    dev=bool(meta.get("dev") or meta.get("devOptional")),
                )
            )
        return result

    # v1: a recursive `dependencies` tree.
    def walk(node: Dict[str, Any], dev_parent: bool) -> None:
        deps = node.get("dependencies")
        if not isinstance(deps, dict):
            return
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            dev = bool(meta.get("dev")) or dev_parent
            if isinstance(version, str) and version and "://" not in version:
                result.packages.append(
                    Package(
                        ecosystem=ECO_NPM,
                        name=name,
                        version=version,
                        path=relpath,
                        line=_line_of_key(text, f'"{name}"'),
                        dev=dev,
                    )
                )
            elif isinstance(version, str) and "://" in version:
                result.skip("npm dependency resolved to a URL, not a registry version")
            else:
                result.skip("lock entry without a resolved version")
            walk(meta, dev)

    walk(data, False)
    return result


_YARN_DESC = re.compile(r'^(?P<desc>(?:"[^"]+"|[^\s:][^:]*?))\s*:\s*$')
_YARN_VERSION = re.compile(r'^\s+"?version"?\s*[:\s]\s*"?(?P<version>[^"\s]+)"?\s*$')


def _yarn_package_name(descriptor: str) -> Optional[str]:
    """`"@babel/core@npm:^7.0.0"` -> `@babel/core`."""
    descriptor = descriptor.strip().strip('"')
    if not descriptor:
        return None
    # Scoped names start with @, so only an @ past position 0 separates the range.
    at = descriptor.rfind("@")
    if at <= 0:
        return descriptor or None
    return descriptor[:at]


def parse_yarn_lock(text: str, relpath: str) -> ParseResult:
    """yarn v1 (custom format) and Berry v2+ (YAML), which differ only in punctuation."""
    result = ParseResult()
    pending: List[str] = []
    pending_line = 0

    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue

        if not raw[0].isspace():
            match = _YARN_DESC.match(raw.strip())
            pending = []
            pending_line = lineno
            if not match:
                continue
            descriptors = [d.strip() for d in match.group("desc").split(",")]
            for descriptor in descriptors:
                cleaned = descriptor.strip().strip('"')
                if cleaned.startswith("__metadata"):
                    continue
                # A workspace/file/link protocol names local code, not a release.
                if re.search(r"@(?:workspace|file|link|portal|exec):", cleaned):
                    continue
                name = _yarn_package_name(cleaned)
                if name:
                    pending.append(name)
            continue

        if not pending:
            continue
        version_match = _YARN_VERSION.match(raw)
        if not version_match:
            continue
        version = version_match.group("version")
        for name in dict.fromkeys(pending):
            result.packages.append(
                Package(
                    ecosystem=ECO_NPM,
                    name=name,
                    version=version,
                    path=relpath,
                    line=pending_line,
                )
            )
        pending = []

    return result


# --------------------------------------------------------------------------------------
# Go
# --------------------------------------------------------------------------------------

_GO_REQUIRE_LINE = re.compile(r"^(?P<module>[^\s]+)\s+(?P<version>v[^\s]+)")
_GO_REPLACE = re.compile(
    r"^replace\s+(?P<from>[^\s]+)(?:\s+(?P<fromver>v[^\s]+))?\s*=>\s*"
    r"(?P<to>[^\s]+)(?:\s+(?P<tover>v[^\s]+))?\s*$"
)


def _go_version(version: str) -> str:
    """OSV indexes Go versions without the `v` prefix or `+incompatible` suffix."""
    version = version.strip()
    if version.startswith("v"):
        version = version[1:]
    return version.split("+incompatible", 1)[0]


def parse_go_mod(text: str, relpath: str) -> ParseResult:
    """`go.mod`, honouring `replace` directives.

    A replaced module is not the code that gets built, so querying the original would
    report a vulnerability in something the binary does not contain. Replacements onto a
    local path drop out entirely - there is no upstream version to ask about.
    """
    result = ParseResult()
    requires: Dict[str, Tuple[str, int, bool]] = {}
    replaces: Dict[str, Optional[Tuple[str, str]]] = {}
    in_require = False
    in_replace = False

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("//")[0].strip() if not raw.strip().startswith("//") else ""
        indirect = "// indirect" in raw
        if not line:
            continue

        if line.startswith("require (") or (in_require and line == "("):
            in_require = True
            continue
        if line.startswith("replace (") or (in_replace and line == "("):
            in_replace = True
            continue
        if line == ")":
            in_require = in_replace = False
            continue

        if line.startswith("require "):
            single = _GO_REQUIRE_LINE.match(line[len("require ") :].strip())
            if single:
                requires[single.group("module")] = (
                    single.group("version"),
                    lineno,
                    indirect,
                )
            continue

        if line.startswith("replace ") or in_replace:
            candidate = line if line.startswith("replace ") else f"replace {line}"
            replace = _GO_REPLACE.match(candidate)
            if replace:
                target, target_version = replace.group("to"), replace.group("tover")
                if target_version and not target.startswith((".", "/")):
                    replaces[replace.group("from")] = (target, target_version)
                else:
                    replaces[replace.group("from")] = None
            continue

        if in_require:
            entry = _GO_REQUIRE_LINE.match(line)
            if entry:
                requires[entry.group("module")] = (
                    entry.group("version"),
                    lineno,
                    indirect,
                )

    for module, (version, lineno, indirect) in sorted(requires.items()):
        if module in replaces:
            replacement = replaces[module]
            if replacement is None:
                result.skip("module replaced by a local path (no upstream version)")
                continue
            module, version = replacement
        result.packages.append(
            Package(
                ecosystem=ECO_GO,
                name=module,
                version=_go_version(version),
                path=relpath,
                line=lineno,
                tags=("indirect",) if indirect else (),
            )
        )
    return result


def parse_go_sum(text: str, relpath: str) -> ParseResult:
    """`go.sum`, used only when no `go.mod` sits beside it.

    `go.sum` records every module version in the graph, not the subset minimal version
    selection actually builds, so it over-reports. Findings from it are tagged.
    """
    result = ParseResult()
    seen: Dict[str, int] = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        parts = raw.split()
        if len(parts) < 3 or parts[1].endswith("/go.mod"):
            continue
        key = f"{parts[0]}@{parts[1]}"
        if key in seen:
            continue
        seen[key] = lineno
        result.packages.append(
            Package(
                ecosystem=ECO_GO,
                name=parts[0],
                version=_go_version(parts[1]),
                path=relpath,
                line=lineno,
                tags=("from-go-sum",),
            )
        )
    return result


# --------------------------------------------------------------------------------------
# Ruby, PHP, Rust
# --------------------------------------------------------------------------------------

_GEM_SPEC = re.compile(r"^    (?P<name>[A-Za-z0-9._\-]+) \((?P<version>[^)]+)\)\s*$")
_GEM_PLATFORM_TAIL = re.compile(
    r"-(?:x86_64|x86|x64|i386|arm64|aarch64|arm|universal|java|"
    r"[a-z0-9_]*(?:linux|darwin|mingw|mswin|musl|freebsd|solaris)[a-z0-9_\-]*)$",
    re.IGNORECASE,
)


def _ruby_version(version: str) -> str:
    """Strip a platform suffix: `1.2.3-x86_64-linux` is release `1.2.3` to OSV."""
    previous = None
    while previous != version:
        previous = version
        version = _GEM_PLATFORM_TAIL.sub("", version)
    return version


def parse_gemfile_lock(text: str, relpath: str) -> ParseResult:
    """`Gemfile.lock`. Indentation is the grammar: four spaces is a gem, six is its dep."""
    result = ParseResult()
    section: Optional[str] = None
    in_specs = False
    non_gem_sections = 0

    for lineno, raw in enumerate(text.splitlines(), 1):
        if raw and not raw[0].isspace():
            section = raw.strip()
            in_specs = False
            if section in ("GIT", "PATH", "PLUGIN SOURCE"):
                non_gem_sections += 1
            continue
        if raw.strip() == "specs:":
            in_specs = True
            continue
        if not in_specs or section != "GEM":
            continue
        spec = _GEM_SPEC.match(raw)
        if spec:
            result.packages.append(
                Package(
                    ecosystem=ECO_RUBYGEMS,
                    name=spec.group("name"),
                    version=_ruby_version(spec.group("version")),
                    path=relpath,
                    line=lineno,
                )
            )

    if non_gem_sections:
        result.skip(
            "gem sourced from git or a local path (not a RubyGems release)",
            non_gem_sections,
        )
    return result


def parse_composer_lock(text: str, relpath: str) -> ParseResult:
    result = ParseResult()
    data = json.loads(text)
    for section, dev in (("packages", False), ("packages-dev", True)):
        entries = data.get(section)
        if not isinstance(entries, list):
            continue
        for meta in entries:
            if not isinstance(meta, dict):
                continue
            name, version = meta.get("name"), meta.get("version")
            if not isinstance(name, str) or not isinstance(version, str):
                result.skip("composer entry without a name/version pair")
                continue
            if version.startswith("dev-"):
                result.skip("composer package pinned to a dev branch, not a release")
                continue
            result.packages.append(
                Package(
                    ecosystem=ECO_PACKAGIST,
                    name=name,
                    version=version[1:] if version.startswith("v") else version,
                    path=relpath,
                    line=_line_of_key(text, f'"name": "{name}"'),
                    dev=dev,
                )
            )
    return result


def parse_cargo_lock(text: str, relpath: str) -> ParseResult:
    result = ParseResult()
    for block in _toml_package_blocks(text):
        name, version = block.get("name"), block.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            result.skip("lock entry without a name/version pair")
            continue
        if not block.get("source"):
            # No source means a workspace member - the project's own code, which the
            # rest of Code Recon is already scanning directly.
            continue
        result.packages.append(
            Package(
                ecosystem=ECO_CRATES,
                name=name,
                version=version,
                path=relpath,
                line=_line_of_key(text, f'name = "{name}"'),
            )
        )
    return result


# --------------------------------------------------------------------------------------
# Maven
# --------------------------------------------------------------------------------------

_DOCTYPE = re.compile(rb"<!(?:DOCTYPE|ENTITY)", re.IGNORECASE)
_PROPERTY_REF = re.compile(r"\$\{([^}]+)\}")


def _pom_text(element: Optional[ET.Element]) -> Optional[str]:
    if element is None or element.text is None:
        return None
    value = element.text.strip()
    return value or None


def parse_pom_xml(text: str, relpath: str) -> ParseResult:
    """A Maven POM, with `${property}` substitution but no parent-POM resolution.

    Resolving a parent would mean fetching it from a repository, which a code scan has no
    business doing, so a version that only a parent could supply is skipped and counted
    rather than guessed at.

    `xml.etree` expands internal entities, which is the billion-laughs primitive that
    `patterns.py` flags in other people's code. Refusing any POM carrying a DOCTYPE is the
    dependency-free way for this scanner not to be guilty of the bug it reports.
    """
    result = ParseResult()
    if _DOCTYPE.search(text[:8192].encode("utf-8", "replace")):
        result.notes.append(
            f"{relpath} declares a DOCTYPE or entity; Code Recon does not parse XML with "
            f"internal entities (billion-laughs risk), so its dependencies were not checked"
        )
        return result

    root = ET.fromstring(text)

    properties: Dict[str, str] = {}
    for props in root.findall("{*}properties"):
        for child in props:
            tag = child.tag.split("}")[-1]
            if child.text and child.text.strip():
                properties[tag] = child.text.strip()

    project_version = _pom_text(root.find("{*}version"))
    project_group = _pom_text(root.find("{*}groupId"))
    parent = root.find("{*}parent")
    if parent is not None:
        project_version = project_version or _pom_text(parent.find("{*}version"))
        project_group = project_group or _pom_text(parent.find("{*}groupId"))
    for alias, value in (
        ("project.version", project_version),
        ("version", project_version),
        ("project.groupId", project_group),
    ):
        if value:
            properties.setdefault(alias, value)

    def resolve(value: str, depth: int = 0) -> Optional[str]:
        if depth > 8 or not value:
            return None
        match = _PROPERTY_REF.search(value)
        if not match:
            return value
        replacement = properties.get(match.group(1))
        if replacement is None:
            return None
        return resolve(value.replace(match.group(0), replacement, 1), depth + 1)

    # Both plain `<dependencies>` and the `<dependencyManagement>` block are read: a
    # managed version is the version modules actually resolve to, so ignoring it would
    # miss the pin that matters in a multi-module build.
    for dependency in root.iterfind(".//{*}dependency"):
        group = _pom_text(dependency.find("{*}groupId"))
        artifact = _pom_text(dependency.find("{*}artifactId"))
        raw_version = _pom_text(dependency.find("{*}version"))
        scope = _pom_text(dependency.find("{*}scope")) or "compile"

        if not group or not artifact:
            result.skip("dependency without a groupId/artifactId")
            continue
        if not raw_version:
            result.skip("version inherited from a parent POM (not resolved offline)")
            continue
        version = resolve(raw_version)
        if version is None:
            result.skip(f"unresolved property in version {raw_version!r}")
            continue
        if version.startswith(("[", "(")):
            result.skip(f"version range {version!r} is not an exact pin")
            continue

        group = resolve(group) or group
        artifact = resolve(artifact) or artifact
        result.packages.append(
            Package(
                ecosystem=ECO_MAVEN,
                name=f"{group}:{artifact}",
                version=version,
                path=relpath,
                line=_line_of_key(text, f"<artifactId>{artifact}</artifactId>"),
                dev=scope in ("test", "provided"),
                # A POM is a declaration; the build can still override it.
                from_lockfile=False,
                tags=(f"scope-{scope}",) if scope != "compile" else (),
            )
        )
    return result


# --------------------------------------------------------------------------------------
# Manifest discovery
# --------------------------------------------------------------------------------------

# filename -> (kind, parser). Exact names only; `requirements*.txt` is matched separately.
_PARSERS: Dict[str, Tuple[str, Any]] = {
    "poetry.lock": ("poetry.lock", parse_poetry_lock),
    "pipfile.lock": ("Pipfile.lock", parse_pipfile_lock),
    "package-lock.json": ("package-lock.json", parse_package_lock),
    "npm-shrinkwrap.json": ("npm-shrinkwrap.json", parse_package_lock),
    "yarn.lock": ("yarn.lock", parse_yarn_lock),
    "go.mod": ("go.mod", parse_go_mod),
    "go.sum": ("go.sum", parse_go_sum),
    "gemfile.lock": ("Gemfile.lock", parse_gemfile_lock),
    "composer.lock": ("composer.lock", parse_composer_lock),
    "cargo.lock": ("Cargo.lock", parse_cargo_lock),
    "pom.xml": ("pom.xml", parse_pom_xml),
}

_REQUIREMENTS_NAME = re.compile(r"^requirements.*\.txt$", re.IGNORECASE)

# Lockfiles we recognise but cannot parse without a YAML library. Reported, not ignored:
# a pnpm project that got a silent clean bill of health would be actively misleading.
_UNSUPPORTED = {
    "pnpm-lock.yaml": "pnpm (needs a YAML parser; PyYAML is an optional dependency)",
    "pnpm-lock.yml": "pnpm (needs a YAML parser; PyYAML is an optional dependency)",
    "packages.lock.json": "NuGet",
    "gradle.lockfile": "Gradle",
    "mix.lock": "Hex",
    "pubspec.lock": "Pub",
}


def classify(filename: str) -> Optional[Tuple[str, Any]]:
    lowered = filename.lower()
    if lowered in _PARSERS:
        return _PARSERS[lowered]
    if _REQUIREMENTS_NAME.match(lowered):
        return ("requirements.txt", parse_requirements)
    return None


def discover_manifests(ctx: ScanContext) -> Tuple[List[Manifest], List[str], Dict[str, int]]:
    """Walk for dependency files. Returns (manifests, notes, skipped-by-reason).

    `.gitignore` is deliberately *not* consulted here, unlike the source walk. A lockfile
    someone chose not to commit still determines what their build installs, and library
    authors routinely gitignore `Cargo.lock`. Vendored directories are pruned instead,
    which is what actually keeps the walk cheap and the results relevant.
    """
    root = Path(ctx.root)
    notes: List[str] = []
    skipped: Dict[str, int] = {}
    manifests: List[Manifest] = []
    unsupported: Dict[str, int] = {}

    excluded = set(DEFAULT_EXCLUDE_DIRS) | {
        d.strip() for d in ctx.config.exclude_dirs if d.strip()
    }

    def consider(path: Path) -> None:
        kind = classify(path.name)
        lowered = path.name.lower()
        if kind is None:
            if lowered in _UNSUPPORTED:
                unsupported[_UNSUPPORTED[lowered]] = (
                    unsupported.get(_UNSUPPORTED[lowered], 0) + 1
                )
            return
        try:
            size = path.stat().st_size
        except OSError as exc:
            skipped["manifest could not be read"] = skipped.get(
                "manifest could not be read", 0
            ) + 1
            notes.append(f"deps: could not stat {path}: {exc}")
            return
        if size > MANIFEST_MAX_BYTES:
            skipped["manifest larger than the 16 MB cap"] = (
                skipped.get("manifest larger than the 16 MB cap", 0) + 1
            )
            notes.append(
                f"deps: {_relative(path, root)} is {size / 1048576:.1f} MB, above the "
                f"16 MB manifest cap; its dependencies were not checked"
            )
            return
        manifests.append(
            Manifest(path=path, relpath=_relative(path, root), kind=kind[0], size=size)
        )

    if root.is_file():
        consider(root)
    else:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in excluded)
            for filename in sorted(filenames):
                consider(Path(dirpath) / filename)

    # `go.sum` over-reports, so it is only used where no `go.mod` sits beside it.
    go_mod_dirs = {m.path.parent for m in manifests if m.kind == "go.mod"}
    filtered: List[Manifest] = []
    dropped_sums = 0
    for manifest in manifests:
        if manifest.kind == "go.sum" and manifest.path.parent in go_mod_dirs:
            dropped_sums += 1
            continue
        filtered.append(manifest)
    if dropped_sums:
        notes.append(
            f"deps: used go.mod instead of go.sum in {dropped_sums} module(s); go.sum "
            f"lists the whole module graph, not the versions actually selected"
        )

    for label, count in sorted(unsupported.items()):
        skipped[f"{label} lockfile format is not supported"] = count
        notes.append(
            f"deps: found {count} {label} lockfile(s), which Code Recon cannot parse; "
            f"those dependencies were NOT checked"
        )

    return filtered, notes, skipped


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


# --------------------------------------------------------------------------------------
# CVSS
# --------------------------------------------------------------------------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS 3.1's own rounding, which is not `round()`.

    Spec Appendix A: work in integer hundred-thousandths so binary floating point cannot
    push a boundary score to the wrong side.
    """
    integer = int(round(value * 100000))
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def cvss31_base_score(vector: str) -> Optional[float]:
    """Compute a CVSS v3.x base score from its vector string, or None if unusable."""
    parts = [p for p in vector.strip().split("/") if p]
    metrics: Dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        metrics[key.upper()] = value.upper()

    version = metrics.get("CVSS", "")
    if version and not version.startswith("3"):
        return None
    try:
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        ui = _UI[metrics["UI"]]
        scope_changed = metrics["S"] == "C"
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        conf = _CIA[metrics["C"]]
        integ = _CIA[metrics["I"]]
        avail = _CIA[metrics["A"]]
    except KeyError:
        return None

    iss = 1.0 - ((1.0 - conf) * (1.0 - integ) * (1.0 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    combined = impact + exploitability
    if scope_changed:
        combined *= 1.08
    return _roundup(min(combined, 10.0))


def severity_from_score(score: float) -> Severity:
    """CVSS v3 qualitative bands, mapped onto our scale."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


_TEXT_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "NONE": Severity.INFO,
}


def _severity_entries(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    entries = []
    for candidate in record.get("severity") or []:
        if isinstance(candidate, dict):
            entries.append(candidate)
    for affected in record.get("affected") or []:
        if isinstance(affected, dict):
            for candidate in affected.get("severity") or []:
                if isinstance(candidate, dict):
                    entries.append(candidate)
    return entries


def rate_severity(record: Dict[str, Any]) -> Tuple[Severity, Optional[float], str]:
    """Best available severity for an OSV record, plus where it came from.

    Order: a CVSS v3 vector we can compute exactly, then the publisher's own qualitative
    rating, then unrated. The source string travels into the finding so a rating is never
    presented as more precise than its origin.
    """
    best: Optional[float] = None
    for entry in _severity_entries(record):
        if str(entry.get("type", "")).upper() not in ("CVSS_V3", "CVSS_V3_1", "CVSS_V31"):
            continue
        score = cvss31_base_score(str(entry.get("score", "")))
        if score is not None and (best is None or score > best):
            best = score
    if best is not None:
        return severity_from_score(best), best, "cvss_v3"

    specific = record.get("database_specific")
    if isinstance(specific, dict):
        text = str(specific.get("severity", "")).upper()
        if text in _TEXT_SEVERITY:
            return _TEXT_SEVERITY[text], None, "database_specific"

    # A v4 vector needs a different formula than the one implemented here; rather than
    # approximate it, fall through and say the rating is missing.
    for entry in _severity_entries(record):
        if str(entry.get("type", "")).upper().startswith("CVSS_V4"):
            return UNRATED_SEVERITY, None, "unrated_cvss_v4"

    return UNRATED_SEVERITY, None, "unrated"


# --------------------------------------------------------------------------------------
# Fix versions
# --------------------------------------------------------------------------------------

_VERSION_PART = re.compile(r"(\d+|[A-Za-z]+)")


def _loose_key(version: str) -> Tuple[Any, ...]:
    """A comparable key that is good enough to order release numbers for display.

    Not a per-ecosystem version implementation. It never decides whether a package is
    affected - OSV does that server-side against the exact version we send - so being
    approximate here only risks listing fixes in an odd order.
    """
    out: List[Tuple[int, Any]] = []
    for token in _VERSION_PART.findall(version):
        if token.isdigit():
            out.append((0, int(token)))
        else:
            out.append((1, token.lower()))
    return tuple(out)


def fixed_versions(record: Dict[str, Any], package: Package) -> List[str]:
    """Versions the advisory says the problem is fixed in, nearest upgrade first."""
    wanted = package.query_name
    found: List[str] = []
    for affected in record.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        meta = affected.get("package")
        if isinstance(meta, dict):
            name = str(meta.get("name", ""))
            ecosystem = str(meta.get("ecosystem", "")).split(":")[0]
            if name and normalize_name(package.ecosystem, name) != wanted:
                continue
            if ecosystem and ecosystem != package.ecosystem:
                continue
        for range_ in affected.get("ranges") or []:
            if not isinstance(range_, dict):
                continue
            for event in range_.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    found.append(str(event["fixed"]))

    unique = sorted(set(found), key=_loose_key)
    current = _loose_key(package.version)
    ahead = [v for v in unique if _loose_key(v) > current]
    return ahead or unique


# --------------------------------------------------------------------------------------
# OSV client
# --------------------------------------------------------------------------------------


class OsvClient:
    """Batched OSV lookups with a per-package cache.

    Caching per package rather than per batch is what makes the cache useful: batch
    composition changes every time a manifest does, while `django@4.2.1` is the same
    question in every repository on the machine.
    """

    def __init__(
        self,
        http: HttpClient,
        *,
        package_cache: Optional[TtlCache] = None,
        vuln_cache: Optional[TtlCache] = None,
        batch_size: int = OSV_BATCH_SIZE,
        timeout: Optional[float] = None,
        querybatch_url: Optional[str] = None,
        vuln_url: Optional[str] = None,
    ) -> None:
        self.http = http
        self.package_cache = package_cache
        self.vuln_cache = vuln_cache
        self.batch_size = max(1, min(int(batch_size), OSV_BATCH_SIZE))
        self.timeout = timeout
        # Read from the module globals at call time rather than bound as a default
        # argument, so a test can point the client at a loopback server.
        self.querybatch_url = querybatch_url or OSV_QUERYBATCH_URL
        self.vuln_url = vuln_url or OSV_VULN_URL

        self.counters: Dict[str, int] = {
            "cache_hits": 0,
            "cache_misses": 0,
            "batches": 0,
            "batch_failures": 0,
            "stale_answers": 0,
            "detail_fetches": 0,
            "detail_failures": 0,
            "detail_cache_hits": 0,
        }
        self.failures: List[str] = []
        self.truncated: List[str] = []

    def _bump(self, key: str, amount: int = 1) -> None:
        self.counters[key] = self.counters.get(key, 0) + amount

    # --- package -> vulnerability stubs ---------------------------------------------

    def lookup(self, keys: Sequence[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Map each `ecosystem|name|version` key to its list of `{id, modified}` stubs."""
        answers: Dict[str, List[Dict[str, Any]]] = {}
        misses: List[str] = []

        for key in keys:
            entry = None
            if self.package_cache is not None:
                entry = self.package_cache.get_entry(key)
            if entry is None:
                misses.append(key)
                self._bump("cache_misses")
            else:
                # An empty list is a real answer ("no known vulnerabilities"), which is
                # why this reads entries rather than truthiness.
                answers[key] = list(entry.value or [])
                self._bump("cache_hits")

        for start in range(0, len(misses), self.batch_size):
            chunk = misses[start : start + self.batch_size]
            try:
                answers.update(self._query_batch(chunk))
            except HttpError as exc:
                self._bump("batch_failures")
                self.failures.append(str(exc))
                answers.update(self._stale_fallback(chunk))
        return answers

    def _query_batch(self, keys: Sequence[str]) -> Dict[str, List[Dict[str, Any]]]:
        queries = []
        for key in keys:
            ecosystem, name, version = key.split("|", 2)
            queries.append(
                {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
            )

        self._bump("batches")
        response = self.http.post_json(
            self.querybatch_url, {"queries": queries}, timeout=self.timeout
        )
        if not response.ok:
            raise HttpError(
                f"OSV querybatch returned {response.status} {response.reason} for "
                f"{len(queries)} package(s)".rstrip()
            )
        payload = response.json()
        results = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(results, list) or len(results) != len(keys):
            raise HttpError(
                f"OSV querybatch answered {len(results) if isinstance(results, list) else 0} "
                f"result(s) for {len(keys)} query(ies); the positional mapping cannot be "
                f"trusted, so the batch was discarded"
            )

        out: Dict[str, List[Dict[str, Any]]] = {}
        for key, result in zip(keys, results):
            stubs: List[Dict[str, Any]] = []
            if isinstance(result, dict):
                for vuln in result.get("vulns") or []:
                    if isinstance(vuln, dict) and vuln.get("id"):
                        stubs.append(
                            {
                                "id": str(vuln["id"]),
                                "modified": str(vuln.get("modified", "")),
                            }
                        )
                if result.get("next_page_token"):
                    self.truncated.append(key)
            out[key] = stubs
            if self.package_cache is not None:
                self.package_cache.set(key, stubs)
        return out

    def _stale_fallback(self, keys: Sequence[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Expired cache data beats nothing, as long as the report says it is expired."""
        out: Dict[str, List[Dict[str, Any]]] = {}
        if self.package_cache is None:
            return out
        for key in keys:
            entry = self.package_cache.get_stale(key)
            if entry is not None:
                out[key] = list(entry.value or [])
                self._bump("stale_answers")
        return out

    # --- vulnerability details -------------------------------------------------------

    def details(self, stubs: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Fetch full records for the vulnerabilities we actually matched.

        Threaded because a repository with a hundred stale dependencies would otherwise
        make a hundred sequential round trips. `HttpClient` and `TtlCache` are both
        documented thread-safe, and the client's own rate limiter still applies.
        """
        wanted: Dict[str, Dict[str, Any]] = {}
        for stub in stubs:
            wanted.setdefault(stub["id"], stub)
        if not wanted:
            return {}

        records: Dict[str, Dict[str, Any]] = {}
        pending: List[Dict[str, Any]] = []
        for vuln_id, stub in wanted.items():
            cached = None
            if self.vuln_cache is not None:
                cached = self.vuln_cache.get_entry(self._vuln_key(stub))
            if cached is not None and isinstance(cached.value, dict):
                records[vuln_id] = cached.value
                self._bump("detail_cache_hits")
            else:
                pending.append(stub)

        if pending:
            workers = max(1, min(8, len(pending)))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for stub, record in zip(pending, pool.map(self._fetch_one, pending)):
                    if record is not None:
                        records[stub["id"]] = record
        return records

    def _vuln_key(self, stub: Dict[str, Any]) -> str:
        return f"{stub['id']}|{stub.get('modified', '')}"

    def _fetch_one(self, stub: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._bump("detail_fetches")
        try:
            response = self.http.get(self.vuln_url + stub["id"], timeout=self.timeout)
            if not response.ok:
                raise HttpError(
                    f"OSV returned {response.status} for {stub['id']}".rstrip()
                )
            record = response.json()
        except HttpError as exc:
            self._bump("detail_failures")
            self.failures.append(f"details for {stub['id']}: {exc}")
            return None
        if not isinstance(record, dict):
            self._bump("detail_failures")
            return None
        if self.vuln_cache is not None:
            self.vuln_cache.set(self._vuln_key(stub), record, ttl=VULN_RECORD_TTL)
        return record


# --------------------------------------------------------------------------------------
# Finding construction
# --------------------------------------------------------------------------------------


def _summarize(record: Dict[str, Any], vuln_id: str, package: Package) -> str:
    summary = str(record.get("summary") or "").strip().replace("\n", " ")
    if summary:
        return summary if len(summary) <= 120 else summary[:117].rstrip() + "..."
    return f"{package.name} {package.version} is affected by {vuln_id}"


def _references(record: Dict[str, Any], vuln_id: str) -> List[str]:
    urls = [f"https://osv.dev/vulnerability/{vuln_id}"]
    for reference in record.get("references") or []:
        if not isinstance(reference, dict):
            continue
        url = reference.get("url")
        if isinstance(url, str) and url.startswith(("http://", "https://")):
            if str(reference.get("type", "")).upper() in ("ADVISORY", "FIX", "REPORT"):
                urls.append(url)
    # Modest cap: a SARIF result with forty links is unreadable.
    return list(dict.fromkeys(urls))[:6]


def build_finding(
    package: Package,
    vuln_id: str,
    record: Dict[str, Any],
    *,
    locations: Sequence[str] = (),
    module: str = "deps",
) -> Finding:
    """Turn one (package, advisory) pair into a Finding."""
    severity, score, rating_source = rate_severity(record)
    fixes = fixed_versions(record, package)
    aliases = [str(a) for a in (record.get("aliases") or []) if isinstance(a, str)]

    if fixes:
        remediation = (
            f"Upgrade {package.name} from {package.version} to {fixes[0]} or later "
            f"(fixed in: {', '.join(fixes[:4])})."
        )
    else:
        remediation = (
            f"No fixed version is published for {vuln_id}. Check the advisory for a "
            f"workaround, or replace {package.name}."
        )

    tags = ["dependency", f"ecosystem-{_ECO_SLUG.get(package.ecosystem, 'other')}"]
    tags.extend(package.tags)
    if package.dev:
        tags.append("dev-dependency")
    if rating_source.startswith("unrated"):
        tags.append("severity-unrated")
    if not fixes:
        tags.append("no-fix-available")

    cwe = DEFAULT_CWE
    specific = record.get("database_specific")
    if isinstance(specific, dict):
        cwe_ids = specific.get("cwe_ids")
        if isinstance(cwe_ids, list) and cwe_ids and isinstance(cwe_ids[0], str):
            cwe = cwe_ids[0]

    extra: Dict[str, Any] = {
        # The version was read out of a manifest and the range match was done by OSV;
        # that is a lookup against a database, not a textual guess, and the report says
        # so rather than calling it a regex hit.
        "detection": "dependency-lookup",
        "ecosystem": package.ecosystem,
        "package": package.name,
        "installed_version": package.version,
        "vulnerability_id": vuln_id,
        "severity_source": rating_source,
    }
    if score is not None:
        extra["cvss_score"] = score
    if fixes:
        extra["fixed_versions"] = fixes[:8]
    if aliases:
        extra["aliases"] = aliases[:8]
    others = [p for p in locations if p != package.path]
    if others:
        extra["also_declared_in"] = sorted(others)[:8]
    if record.get("withdrawn"):
        extra["withdrawn"] = str(record["withdrawn"])

    identifier = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
    message = (
        f"{package.name} {package.version} ({package.ecosystem}) is affected by "
        f"{vuln_id}"
        + (f" / {identifier}" if identifier != vuln_id else "")
        + f": {_summarize(record, vuln_id, package)}"
    )

    return Finding(
        rule_id=f"dep.{_ECO_SLUG.get(package.ecosystem, 'other')}.{vuln_id}",
        title=_summarize(record, vuln_id, package),
        severity=severity,
        confidence=Confidence.CONFIRMED if package.from_lockfile else Confidence.HIGH,
        message=message,
        path=package.path,
        line=package.line,
        module=module,
        remediation=remediation,
        references=_references(record, vuln_id),
        tags=sorted(set(tags)),
        cwe=cwe,
        # Keyed on the package, not the manifest line, so moving an entry within a
        # lockfile does not invalidate a baseline - but bumping the version does, which
        # is correct: a different version is a different finding to triage.
        fingerprint_seed=f"{package.ecosystem}/{package.query_name}@{package.version}",
        extra=extra,
    )


# --------------------------------------------------------------------------------------
# Module
# --------------------------------------------------------------------------------------


@register
class DepsModule(ScanModule):
    name = "deps"
    description = "Known-vulnerable dependencies, via the OSV.dev advisory database"
    phase = "code"
    requires_network = True

    # Overridable so a test never writes to the user's real `~/.cache`.
    cache_path: Optional[Path] = None

    def __init__(self) -> None:
        self._stats: Dict[str, Any] = {}

    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    # --- helpers ---------------------------------------------------------------------

    def _open_caches(self, ctx: ScanContext) -> Tuple[Optional[TtlCache], Optional[TtlCache]]:
        """Two namespaces over one SQLite file. A cache failure must not fail a scan."""
        try:
            path = self.cache_path or default_cache_path()
            packages = TtlCache(path, namespace="osv", default_ttl=DEFAULT_TTL)
            vulns = TtlCache(path, namespace="osv-vuln", default_ttl=VULN_RECORD_TTL)
        except Exception as exc:  # noqa: BLE001 - a cache is an optimisation
            ctx.note(f"deps: dependency cache unavailable ({exc}); every lookup will be live")
            return None, None
        for cache in (packages, vulns):
            if cache.degraded and cache.degraded_reason:
                ctx.note(f"deps: {cache.degraded_reason}")
            if cache.recreated_reason:
                ctx.note(f"deps: {cache.recreated_reason}")
        return packages, vulns

    def _parse_all(
        self, ctx: ScanContext, manifests: Sequence[Manifest]
    ) -> Tuple[List[Package], Dict[str, int], Dict[str, int]]:
        packages: List[Package] = []
        skipped: Dict[str, int] = {}
        by_kind: Dict[str, int] = {}

        for manifest in manifests:
            by_kind[manifest.kind] = by_kind.get(manifest.kind, 0) + 1
            parser = classify(manifest.path.name)
            if parser is None:  # pragma: no cover - discovery already filtered these
                continue
            try:
                text = manifest.path.read_text("utf-8", errors="replace")
            except OSError as exc:
                ctx.note(f"deps: could not read {manifest.relpath}: {exc}")
                skipped["manifest could not be read"] = (
                    skipped.get("manifest could not be read", 0) + 1
                )
                continue
            try:
                result = parser[1](text, manifest.relpath)
            except Exception as exc:  # noqa: BLE001 - one bad manifest, not the scan
                # Loud on purpose: a lockfile we failed to parse is a set of dependencies
                # nobody checked, and silence would read as "nothing to report".
                ctx.note(
                    f"deps: {manifest.relpath} could not be parsed as "
                    f"{manifest.kind} ({type(exc).__name__}: {exc}); its dependencies "
                    f"were NOT checked"
                )
                skipped[f"{manifest.kind} failed to parse"] = (
                    skipped.get(f"{manifest.kind} failed to parse", 0) + 1
                )
                continue

            packages.extend(result.packages)
            for reason, count in result.skipped.items():
                skipped[reason] = skipped.get(reason, 0) + count
            for note in result.notes:
                ctx.note(note if note.startswith("deps:") else f"deps: {note}")

        return packages, skipped, by_kind

    # --- entry point -----------------------------------------------------------------

    def run(self, ctx: ScanContext) -> List[Finding]:
        # The registry holds one long-lived instance, so per-run state is reset here
        # rather than in __init__.
        self._stats = {}

        manifests, notes, discovery_skips = discover_manifests(ctx)
        for note in notes:
            ctx.note(note)

        if not manifests:
            ctx.note(
                "deps: no dependency manifests found (looked for requirements*.txt, "
                "poetry.lock, Pipfile.lock, package-lock.json, yarn.lock, go.mod/sum, "
                "Gemfile.lock, composer.lock, Cargo.lock, pom.xml)"
            )
            self._stats = {"manifests": 0, "packages_queried": 0}
            return []

        packages, parse_skips, by_kind = self._parse_all(ctx, manifests)
        skipped = {**discovery_skips, **parse_skips}

        # One query per distinct package, but remember every manifest that named it, so
        # the finding can point at all of them without being reported N times.
        grouped: Dict[str, List[Package]] = {}
        for package in packages:
            grouped.setdefault(package.key, []).append(package)

        self._stats = {
            "manifests": len(manifests),
            "manifest_kinds": dict(sorted(by_kind.items())),
            "packages_found": len(packages),
            "packages_queried": len(grouped),
            "ecosystems": sorted({p.ecosystem for p in packages}),
        }
        if skipped:
            self._stats["unresolved"] = sum(skipped.values())
            self._stats["unresolved_reasons"] = dict(
                sorted(skipped.items(), key=lambda kv: -kv[1])[:8]
            )
            total = sum(skipped.values())
            ctx.note(
                f"deps: {total} dependency declaration(s) could not be resolved to an "
                f"exact version and were NOT checked - "
                + "; ".join(
                    f"{reason} (x{count})"
                    for reason, count in sorted(skipped.items(), key=lambda kv: -kv[1])[:4]
                )
            )

        if not grouped:
            ctx.note(
                f"deps: parsed {len(manifests)} manifest(s) but found no exactly-pinned "
                f"dependency versions to check"
            )
            return []

        ctx.note(
            f"deps: sent {len(grouped)} package name/version pair(s) to api.osv.dev "
            f"(use --offline to skip all dependency lookups)"
        )

        package_cache, vuln_cache = self._open_caches(ctx)
        http = HttpClient(
            ctx.config,
            # A 1000-package batch is a much bigger request than a page fetch, and the
            # default 5 s target timeout would fail it on a slow link.
            timeout=max(float(ctx.config.timeout), 30.0),
        )
        client = OsvClient(
            http,
            package_cache=package_cache,
            vuln_cache=vuln_cache,
            timeout=max(float(ctx.config.timeout), 30.0),
        )

        try:
            findings = self._collect(ctx, client, grouped)
        finally:
            for cache in (package_cache, vuln_cache):
                if cache is not None:
                    cache.close()

        return findings

    def _collect(
        self,
        ctx: ScanContext,
        client: OsvClient,
        grouped: Dict[str, List[Package]],
    ) -> List[Finding]:
        keys = sorted(grouped)
        answers = client.lookup(keys)

        stubs: List[Dict[str, Any]] = []
        for key in keys:
            stubs.extend(answers.get(key, []))
        records = client.details(stubs)

        findings: List[Finding] = []
        withdrawn = 0
        undetailed = 0

        for key in keys:
            occurrences = grouped[key]
            # Report against the first manifest in sorted order so the anchor is stable
            # from run to run regardless of walk order.
            anchor = sorted(occurrences, key=lambda p: (p.path, p.line or 0))[0]
            locations = [p.path for p in occurrences]
            for stub in answers.get(key, []):
                vuln_id = stub["id"]
                record = records.get(vuln_id)
                if record is None:
                    # We know the package is affected; only the enrichment is missing.
                    undetailed += 1
                    record = {"id": vuln_id}
                if record.get("withdrawn"):
                    withdrawn += 1
                    continue
                findings.append(
                    build_finding(
                        anchor,
                        vuln_id,
                        record,
                        locations=locations,
                        module=self.name,
                    )
                )

        self._stats.update(
            {
                "vulnerabilities": len(findings),
                "cache_hits": client.counters["cache_hits"],
                "cache_misses": client.counters["cache_misses"],
                "osv_batches": client.counters["batches"],
                "detail_fetches": client.counters["detail_fetches"],
            }
        )
        if withdrawn:
            self._stats["withdrawn_skipped"] = withdrawn
        if client.counters["stale_answers"]:
            self._stats["stale_answers"] = client.counters["stale_answers"]

        if withdrawn:
            ctx.note(f"deps: skipped {withdrawn} withdrawn advisory record(s)")
        if undetailed:
            ctx.note(
                f"deps: {undetailed} advisory record(s) could not be fetched in full; "
                f"those findings carry an unrated severity and no fix version"
            )
        if client.counters["stale_answers"]:
            ctx.note(
                f"deps: answered {client.counters['stale_answers']} package(s) from "
                f"expired cache data because OSV was unreachable"
            )
        if client.truncated:
            ctx.note(
                f"deps: OSV paginated the results for {len(client.truncated)} package(s); "
                f"their advisory lists may be incomplete"
            )

        if client.counters["batch_failures"]:
            # Recorded as notes first: the counts above are real information and the
            # report still shows them next to the error. But a dependency scan that
            # could not reach OSV must not exit 0/1, because CI would read that as
            # "no vulnerable dependencies".
            raise RuntimeError(
                f"OSV was unreachable for {client.counters['batch_failures']} of "
                f"{client.counters['batches']} batch(es); only {len(answers)} of "
                f"{len(keys)} package(s) were checked (found {len(findings)} "
                f"vulnerabilit(ies) in those). First failure: "
                f"{client.failures[0] if client.failures else 'unknown'}"
            )

        return findings
