"""Filesystem traversal for code scanning.

The single biggest determinant of whether a scanner is useful is what it refuses to
read. Scanning `node_modules`, a minified bundle, or a 40 MB fixture produces thousands
of findings nobody will ever triage, and buries the twelve that matter. So this module
is mostly about exclusion:

* vendored/build directories are skipped by default,
* `.gitignore` is honoured (including nested ones), because things people chose not to
  commit are not their code,
* binaries and minified assets are skipped — high-entropy by nature, so they trip every
  secret heuristic there is.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

# Directories that are almost never the user's own source. Skipped before we even stat
# their contents, which is also where most of the walk's speed comes from.
DEFAULT_EXCLUDE_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", ".bzr",
        "node_modules", "bower_components", "jspm_packages",
        "vendor", "third_party", "external",
        "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".nox",
        "venv", ".venv", "env", ".env.d", "virtualenv", "site-packages",
        "dist", "build", "out", "target", ".next", ".nuxt", ".svelte-kit",
        ".gradle", ".idea", ".vscode", ".terraform", ".serverless",
        "coverage", "htmlcov", ".nyc_output",
        "Pods", "DerivedData",
    }
)

# Extensions we never treat as source. Binary sniffing catches most of this anyway;
# the list short-circuits the read.
BINARY_EXTS = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff", ".avif",
        ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac", ".ogg", ".webm", ".mkv",
        ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".jar", ".war", ".whl",
        ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a", ".class",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt",
        ".ttf", ".otf", ".woff", ".woff2", ".eot",
        ".wasm", ".pack", ".idx", ".node",
    }
)

LANGUAGE_BY_EXT: Dict[str, str] = {
    ".py": "python", ".pyi": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".go": "go",
    ".rb": "ruby", ".rake": "ruby", ".gemspec": "ruby",
    ".php": "php", ".phtml": "php",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".groovy": "groovy",
    ".cs": "csharp", ".fs": "fsharp", ".vb": "vbnet",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".rs": "rust", ".swift": "swift", ".m": "objc", ".mm": "objc",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ksh": "shell", ".fish": "shell",
    ".ps1": "powershell", ".psm1": "powershell", ".bat": "batch", ".cmd": "batch",
    ".pl": "perl", ".pm": "perl", ".lua": "lua", ".r": "r", ".jl": "julia",
    ".ex": "elixir", ".exs": "elixir", ".erl": "erlang", ".clj": "clojure", ".dart": "dart",
    ".sql": "sql", ".graphql": "graphql", ".gql": "graphql",
    ".html": "html", ".htm": "html", ".vue": "vue", ".svelte": "svelte",
    ".css": "css", ".scss": "scss", ".sass": "sass", ".less": "less",
    ".json": "json", ".yaml": "yaml", ".yml": "yaml", ".toml": "toml", ".ini": "ini",
    ".xml": "xml", ".properties": "properties", ".cfg": "ini", ".conf": "conf",
    ".tf": "terraform", ".tfvars": "terraform", ".hcl": "hcl",
    ".env": "dotenv", ".md": "markdown", ".rst": "rst", ".txt": "text",
    ".dockerfile": "dockerfile", ".tpl": "template", ".j2": "jinja",
}

# Filenames with no useful extension that we still want to classify.
LANGUAGE_BY_NAME: Dict[str, str] = {
    "dockerfile": "dockerfile",
    "containerfile": "dockerfile",
    "makefile": "makefile",
    "gnumakefile": "makefile",
    "jenkinsfile": "groovy",
    "rakefile": "ruby",
    "gemfile": "ruby",
    "vagrantfile": "ruby",
    "procfile": "text",
    "brewfile": "ruby",
    "justfile": "text",
    "cmakelists.txt": "cmake",
}

DEFAULT_MAX_BYTES = 4 * 1024 * 1024
_SNIFF_BYTES = 8192
# A "line" this long means generated/minified content, not something a human typed.
_MINIFIED_LINE_LEN = 500
_MINIFIED_NAME = re.compile(r"[.-](min|bundle|chunk|vendor)\.(js|css|mjs)$", re.I)


def language_for(name: str) -> Optional[str]:
    lower = name.lower()
    if lower in LANGUAGE_BY_NAME:
        return LANGUAGE_BY_NAME[lower]
    # Dockerfile.prod, Dockerfile.dev, ...
    if lower.startswith("dockerfile"):
        return "dockerfile"
    ext = os.path.splitext(lower)[1]
    return LANGUAGE_BY_EXT.get(ext)


# --------------------------------------------------------------------------------------
# .gitignore
# --------------------------------------------------------------------------------------


class _IgnoreRule:
    """One compiled `.gitignore` line, anchored at the directory of its source file."""

    __slots__ = ("regex", "negated", "dir_only", "base")

    def __init__(self, regex: "re.Pattern[str]", negated: bool, dir_only: bool, base: str):
        self.regex = regex
        self.negated = negated
        self.dir_only = dir_only
        self.base = base  # posix path of the dir containing the .gitignore, "" for root

    def applies_to(self, relpath: str) -> bool:
        return not self.base or relpath == self.base or relpath.startswith(self.base + "/")

    def matches(self, relpath: str, is_dir: bool) -> bool:
        if self.dir_only and not is_dir:
            return False
        if not self.applies_to(relpath):
            return False
        local = relpath[len(self.base) + 1 :] if self.base else relpath
        return bool(self.regex.match(local))


def _glob_to_regex(pattern: str) -> str:
    """Translate a gitignore glob into a regex source string.

    Handles the parts that actually show up in real repos: `*`, `?`, `**`, character
    classes, and the rule that `*` does not cross a directory boundary.
    """
    out: List[str] = []
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            if pattern.startswith("**", i):
                # `**/` may match zero directories; a trailing `**` matches everything.
                if pattern.startswith("**/", i):
                    out.append("(?:[^/]+/)*")
                    i += 3
                    continue
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        elif ch == "[":
            close = pattern.find("]", i + 1)
            if close == -1:
                out.append(re.escape(ch))
            else:
                body = pattern[i + 1 : close]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body + "]")
                i = close + 1
                continue
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out)


def _compile_ignore_line(line: str, base: str) -> Optional[_IgnoreRule]:
    raw = line.rstrip("\n")
    # Trailing whitespace is insignificant unless backslash-escaped.
    if not raw.endswith("\\ "):
        raw = raw.rstrip()
    if not raw or raw.lstrip().startswith("#"):
        return None

    negated = raw.startswith("!")
    if negated:
        raw = raw[1:]
    if raw.startswith("\\"):  # escaped leading '!' or '#'
        raw = raw[1:]

    dir_only = raw.endswith("/")
    if dir_only:
        raw = raw[:-1]
    if not raw:
        return None

    # git: a pattern containing a non-trailing '/' is anchored to the .gitignore's dir;
    # otherwise it matches a basename at any depth.
    anchored = "/" in raw
    if raw.startswith("/"):
        raw = raw[1:]

    body = _glob_to_regex(raw)
    prefix = "" if anchored else "(?:.*/)?"
    # Match the path itself or anything beneath it: ignoring `build` ignores its contents.
    try:
        regex = re.compile(f"^{prefix}{body}(?:/.*)?$")
    except re.error:
        return None
    return _IgnoreRule(regex, negated, dir_only, base)


class GitIgnore:
    """Aggregated ignore rules, including nested `.gitignore` files.

    Rules are evaluated in order with later matches winning, which is how negation
    (`!keep-this.py`) is supposed to work.
    """

    def __init__(self) -> None:
        self._rules: List[_IgnoreRule] = []

    def add_file(self, path: Path, base: str) -> None:
        try:
            text = path.read_text("utf-8", errors="replace")
        except OSError:
            return
        for line in text.splitlines():
            rule = _compile_ignore_line(line, base)
            if rule is not None:
                self._rules.append(rule)

    def add_patterns(self, patterns: Sequence[str], base: str = "") -> None:
        for pattern in patterns:
            rule = _compile_ignore_line(pattern, base)
            if rule is not None:
                self._rules.append(rule)

    def ignored(self, relpath: str, is_dir: bool = False) -> bool:
        result = False
        for rule in self._rules:
            if rule.matches(relpath, is_dir):
                result = not rule.negated
        return result

    def __bool__(self) -> bool:
        return bool(self._rules)


# --------------------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------------------


@dataclass
class ScanFile:
    """A candidate source file. Text is decoded lazily and cached."""

    abspath: Path
    relpath: str
    size: int
    language: Optional[str] = None
    _text: Optional[str] = field(default=None, repr=False, compare=False)
    _lines: Optional[List[str]] = field(default=None, repr=False, compare=False)
    _read_failed: bool = field(default=False, repr=False, compare=False)

    @property
    def text(self) -> str:
        if self._text is None and not self._read_failed:
            try:
                self._text = self.abspath.read_text("utf-8", errors="replace")
            except OSError:
                self._read_failed = True
                self._text = ""
        return self._text or ""

    @property
    def lines(self) -> List[str]:
        """1-indexed access is the caller's job: `lines[line_no - 1]`."""
        if self._lines is None:
            self._lines = self.text.splitlines()
        return self._lines

    def line_at(self, lineno: int) -> str:
        lines = self.lines
        if 1 <= lineno <= len(lines):
            return lines[lineno - 1]
        return ""

    @property
    def name(self) -> str:
        return self.abspath.name

    @property
    def is_minified(self) -> bool:
        if _MINIFIED_NAME.search(self.name):
            return True
        text = self.text
        if not text:
            return False
        newlines = text.count("\n")
        if newlines == 0:
            return len(text) > _MINIFIED_LINE_LEN
        return (len(text) / (newlines + 1)) > _MINIFIED_LINE_LEN

    def release(self) -> None:
        """Drop cached text. Called after a file is scanned to bound memory."""
        self._text = None
        self._lines = None


def looks_binary(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXTS:
        return True
    try:
        with path.open("rb") as fh:
            chunk = fh.read(_SNIFF_BYTES)
    except OSError:
        return True
    if b"\x00" in chunk:
        return True
    # A high proportion of undecodable bytes means binary even without a NUL.
    if not chunk:
        return False
    try:
        chunk.decode("utf-8")
    except UnicodeDecodeError:
        nonprintable = sum(1 for b in chunk if b < 9 or (13 < b < 32))
        return nonprintable / len(chunk) > 0.10
    return False


class Walker:
    """Yields `ScanFile`s under `root`, applying exclusions."""

    def __init__(
        self,
        root: Path,
        *,
        excludes: Sequence[str] = (),
        exclude_dirs: Sequence[str] = (),
        max_bytes: int = DEFAULT_MAX_BYTES,
        use_gitignore: bool = True,
        include_minified: bool = False,
        follow_symlinks: bool = False,
    ) -> None:
        self.root = root.resolve()
        self.max_bytes = max_bytes
        self.use_gitignore = use_gitignore
        self.include_minified = include_minified
        self.follow_symlinks = follow_symlinks
        self.exclude_dirs = set(DEFAULT_EXCLUDE_DIRS) | set(exclude_dirs)
        self.ignore = GitIgnore()
        if excludes:
            self.ignore.add_patterns(list(excludes))
        # Stats, surfaced in the report so a suspiciously empty scan is diagnosable.
        self.stats: Dict[str, int] = {
            "files_seen": 0,
            "files_scanned": 0,
            "skipped_binary": 0,
            "skipped_large": 0,
            "skipped_minified": 0,
            "skipped_ignored": 0,
            "bytes_scanned": 0,
        }

    def _rel(self, path: Path) -> str:
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    def files(self) -> Iterator[ScanFile]:
        if self.root.is_file():
            sf = self._consider(self.root)
            if sf:
                yield sf
            return

        for dirpath, dirnames, filenames in os.walk(
            self.root, topdown=True, followlinks=self.follow_symlinks
        ):
            here = Path(dirpath)
            rel_here = self._rel(here)

            if self.use_gitignore and ".gitignore" in filenames:
                base = "" if rel_here == "." else rel_here
                self.ignore.add_file(here / ".gitignore", base)

            kept: List[str] = []
            for d in dirnames:
                if d in self.exclude_dirs:
                    continue
                rel_dir = d if rel_here == "." else f"{rel_here}/{d}"
                if self.ignore.ignored(rel_dir, is_dir=True):
                    self.stats["skipped_ignored"] += 1
                    continue
                kept.append(d)
            dirnames[:] = kept  # in-place: prunes the walk

            for fname in filenames:
                rel = fname if rel_here == "." else f"{rel_here}/{fname}"
                self.stats["files_seen"] += 1
                if self.ignore.ignored(rel, is_dir=False):
                    self.stats["skipped_ignored"] += 1
                    continue
                sf = self._consider(here / fname, rel)
                if sf is not None:
                    yield sf

    def _consider(self, path: Path, rel: Optional[str] = None) -> Optional[ScanFile]:
        rel = rel if rel is not None else self._rel(path)
        try:
            st = path.stat()
        except OSError:
            return None
        if not stat.S_ISREG(st.st_mode):  # skip fifos, sockets, devices
            return None
        if st.st_size > self.max_bytes:
            self.stats["skipped_large"] += 1
            return None
        if st.st_size == 0:
            return None
        if looks_binary(path):
            self.stats["skipped_binary"] += 1
            return None

        sf = ScanFile(
            abspath=path, relpath=rel, size=st.st_size, language=language_for(path.name)
        )
        if not self.include_minified and sf.is_minified:
            self.stats["skipped_minified"] += 1
            sf.release()
            return None

        self.stats["files_scanned"] += 1
        self.stats["bytes_scanned"] += st.st_size
        return sf


def collect(root: Path, **kwargs: object) -> Tuple[List[ScanFile], Dict[str, int]]:
    """Eagerly walk `root`. Returns the files plus the walker's skip statistics."""
    walker = Walker(root, **kwargs)  # type: ignore[arg-type]
    files = list(walker.files())
    return files, walker.stats
