"""Insecure code-pattern detection.

Two detectors live here, deliberately unequal:

**Python gets a real parser.** `PythonAstAnalyzer` walks the `ast`, resolves import
aliases, and matches on canonical dotted names. It can tell `os.system(cmd)` from a
method called `system` on somebody's own object, and it can tell a parameterised query
from an f-string with a `WHERE` clause in it. Those findings are labelled `detection:
"ast"` and are allowed to claim high confidence.

**Everything else gets regexes**, driven from the five bundled `patterns_*` packs. A
regex match is evidence about *text*, not about program behaviour, so those findings are
labelled `detection: "regex"` and capped at MEDIUM confidence unless the rule sets
`"unambiguous": true` — which is reserved for patterns that match a literal, unmistakable
construct (`NODE_TLS_REJECT_UNAUTHORIZED = '0'`) rather than a resemblance. The report
prints the detection method either way. Claiming parser-grade certainty for a regex is
how scanners earn the reputation that gets them muted.

The two overlap on Python (the language-agnostic `patterns_generic` pack applies
everywhere), so where both fire on the same `(path, line, cwe)` the AST finding wins and
the regex one is dropped.

One more thing this module does is *refuse to look at comments*. `# don't use md5 here`
is not a finding, and commented-out code is the single largest false-positive source in
regex-based scanning. `comment_spans()` is a heuristic, not a lexer, so it is written to
fail toward keeping findings rather than dropping them.
"""

from __future__ import annotations

import ast
import re
from bisect import bisect_right
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ..core.context import ScanContext
from ..core.engine import FileScanModule, register
from ..core.finding import Confidence, Finding, Severity
from ..core.heuristics import is_placeholder, is_test_context
from ..core.redact import MAX_SNIPPET, mask, safe_snippet
from ..core.rules import Rule, filter_rules, load_all_builtin, load_pack, selector_matches
from ..core.textutil import line_of, line_span, line_starts
from ..core.walker import ScanFile

# --------------------------------------------------------------------------------------
# Comment detection
# --------------------------------------------------------------------------------------
#
# This is a heuristic and is documented as one. It tracks per-line quote state so a `#`
# inside a string is not mistaken for a comment, but it does not understand multi-line
# strings, heredocs, or template literals. Every ambiguity is resolved in favour of
# *keeping* the finding, because a dropped finding is invisible and a false positive is
# merely annoying. Languages absent from these tables get no comment filtering at all.

_HASH = ("#",)
_SLASH = ("//",)
_DASH = ("--",)

_LINE_COMMENTS: Dict[str, Tuple[str, ...]] = {
    "python": _HASH, "ruby": _HASH, "shell": _HASH, "perl": _HASH, "r": _HASH,
    "yaml": _HASH, "toml": _HASH, "conf": _HASH, "ini": ("#", ";"),
    "properties": ("#", "!"), "dockerfile": _HASH, "makefile": _HASH, "cmake": _HASH,
    "elixir": _HASH, "julia": _HASH, "powershell": _HASH, "jinja": _HASH,
    "terraform": ("#", "//"), "hcl": ("#", "//"),
    "javascript": _SLASH, "typescript": _SLASH, "go": _SLASH, "java": _SLASH,
    "kotlin": _SLASH, "scala": _SLASH, "groovy": _SLASH, "csharp": _SLASH,
    "fsharp": _SLASH, "c": _SLASH, "cpp": _SLASH, "rust": _SLASH, "swift": _SLASH,
    "dart": _SLASH, "objc": _SLASH, "vue": _SLASH, "svelte": _SLASH,
    "scss": _SLASH, "less": _SLASH, "sass": _SLASH,
    "php": ("//", "#"),
    "sql": _DASH, "lua": _DASH,
}

_C_BLOCK: Tuple[Tuple[str, str], ...] = (("/*", "*/"),)
_XML_BLOCK: Tuple[Tuple[str, str], ...] = (("<!--", "-->"),)

_BLOCK_COMMENTS: Dict[str, Tuple[Tuple[str, str], ...]] = {
    "javascript": _C_BLOCK, "typescript": _C_BLOCK, "go": _C_BLOCK, "java": _C_BLOCK,
    "kotlin": _C_BLOCK, "scala": _C_BLOCK, "groovy": _C_BLOCK, "csharp": _C_BLOCK,
    "fsharp": _C_BLOCK, "c": _C_BLOCK, "cpp": _C_BLOCK, "rust": _C_BLOCK,
    "swift": _C_BLOCK, "dart": _C_BLOCK, "objc": _C_BLOCK, "php": _C_BLOCK,
    "sql": _C_BLOCK, "css": _C_BLOCK, "scss": _C_BLOCK, "less": _C_BLOCK,
    "sass": _C_BLOCK,
    "html": _XML_BLOCK, "xml": _XML_BLOCK, "markdown": _XML_BLOCK,
    "vue": _C_BLOCK + _XML_BLOCK, "svelte": _C_BLOCK + _XML_BLOCK,
}

# A "block comment" longer than this is almost certainly a mis-detection - an unbalanced
# `/*` inside a string literal, say. Swallowing hundreds of lines would silently delete
# real findings, so an implausibly long span is discarded instead of trusted.
_MAX_BLOCK_LINES = 200


def _line_comment_start(line: str, tokens: Sequence[str]) -> int:
    """Offset within `line` where a line comment begins, or -1 if none does.

    Quote-aware, so `url = "http://x/#frag"` is not read as a comment.
    """
    quote = ""
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch == '"' or ch == "'" or ch == "`":
            quote = ch
            i += 1
            continue
        matched = False
        for tok in tokens:
            if line.startswith(tok, i):
                # `https://` is the single most common false comment there is.
                if tok == "//" and i > 0 and line[i - 1] == ":":
                    matched = True
                    break
                return i
        if matched:
            i += 1
            continue
        i += 1
    return -1


def _merge_spans(spans: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    if not spans:
        return []
    spans.sort()
    out: List[List[int]] = [[spans[0][0], spans[0][1]]]
    for start, end in spans[1:]:
        if start <= out[-1][1]:
            out[-1][1] = max(out[-1][1], end)
        else:
            out.append([start, end])
    return [(a, b) for a, b in out]


def comment_spans(text: str, language: Optional[str]) -> List[Tuple[int, int]]:
    """Character ranges of `text` that are comments, merged and sorted."""
    lang = (language or "").lower()
    line_tokens = _LINE_COMMENTS.get(lang, ())
    blocks = _BLOCK_COMMENTS.get(lang, ())
    if not line_tokens and not blocks:
        return []

    starts = line_starts(text)
    spans: List[Tuple[int, int]] = []

    if line_tokens:
        for idx, line_begin in enumerate(starts):
            line_end = starts[idx + 1] if idx + 1 < len(starts) else len(text)
            offset = _line_comment_start(text[line_begin:line_end], line_tokens)
            if offset >= 0:
                spans.append((line_begin + offset, line_end))

    # Line comments are computed first so a `/*` that is itself commented out with `//`
    # cannot open a bogus block.
    line_spans = _merge_spans(list(spans))
    for open_tok, close_tok in blocks:
        cursor = 0
        while True:
            start = text.find(open_tok, cursor)
            if start == -1:
                break
            if _in_spans(line_spans, start):
                cursor = start + len(open_tok)
                continue
            close = text.find(close_tok, start + len(open_tok))
            end = len(text) if close == -1 else close + len(close_tok)
            if text.count("\n", start, end) <= _MAX_BLOCK_LINES:
                spans.append((start, end))
            cursor = end

    return _merge_spans(spans)


def _in_spans(spans: Sequence[Tuple[int, int]], offset: int) -> bool:
    if not spans:
        return False
    idx = bisect_right(spans, (offset, offset + 1)) - 1
    if idx < 0:
        return False
    start, end = spans[idx]
    return start <= offset < end


# --------------------------------------------------------------------------------------
# Python AST checks
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class PyCheck:
    """Metadata for one AST check.

    These are code, not `Rule` data, because "is argument 0 a non-literal" is not
    expressible as a regex. They still carry a rule id and honour `--enable-rule` /
    `--disable-rule` through `selector_matches`, so a user does not have to learn that
    some checks are selectable and others are not.
    """

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    cwe: str
    remediation: str
    tags: Tuple[str, ...] = ()
    references: Tuple[str, ...] = ()


_PY = "pattern.python."

PY_CHECKS: Dict[str, PyCheck] = {
    "eval-exec": PyCheck(
        id=_PY + "eval-exec-non-literal",
        title="eval()/exec() on a value that is not a literal",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe="CWE-95",
        remediation=(
            "Remove the dynamic evaluation. Use `ast.literal_eval` for data, an explicit "
            "dispatch dict for behaviour, or `json.loads` for serialised input."
        ),
        tags=("injection", "code-execution"),
        references=("https://docs.python.org/3/library/ast.html#ast.literal_eval",),
    ),
    "deserialization": PyCheck(
        id=_PY + "unsafe-deserialization",
        title="Deserialising with a format that executes code",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe="CWE-502",
        remediation=(
            "pickle, marshal, dill and shelve reconstruct arbitrary objects and are "
            "equivalent to running the payload. Use JSON, or a schema-validated format, "
            "for anything that crosses a trust boundary."
        ),
        tags=("deserialization", "code-execution"),
        references=("https://docs.python.org/3/library/pickle.html",),
    ),
    "yaml-load": PyCheck(
        id=_PY + "yaml-unsafe-load",
        title="yaml.load() without a safe loader",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe="CWE-502",
        remediation="Use `yaml.safe_load()`, or pass `Loader=yaml.SafeLoader` explicitly.",
        tags=("deserialization", "code-execution"),
        references=("https://pyyaml.org/wiki/PyYAMLDocumentation",),
    ),
    "shell-true": PyCheck(
        id=_PY + "subprocess-shell-true",
        title="subprocess call with shell=True",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe="CWE-78",
        remediation=(
            "Pass the command as a list and drop `shell=True`. If a shell really is "
            "required, build arguments with `shlex.quote`."
        ),
        tags=("injection", "command-execution"),
    ),
    "os-system": PyCheck(
        id=_PY + "os-system",
        title="Command executed through a shell",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe="CWE-78",
        remediation="Use `subprocess.run([...])` with an argument list and no shell.",
        tags=("injection", "command-execution"),
    ),
    "verify-false": PyCheck(
        id=_PY + "tls-verification-disabled",
        title="TLS certificate verification disabled",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        cwe="CWE-295",
        remediation=(
            "Remove `verify=False`. To trust an internal CA, point `verify` at its "
            "certificate bundle path instead of disabling the check."
        ),
        tags=("transport", "tls"),
    ),
    "weak-hash": PyCheck(
        id=_PY + "weak-hash",
        title="Broken hash algorithm",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cwe="CWE-328",
        remediation=(
            "Use SHA-256 or better for integrity, and a password KDF (`argon2`, "
            "`bcrypt`, `hashlib.scrypt`) for passwords. For a non-security checksum, "
            "pass `usedforsecurity=False` to make the intent explicit."
        ),
        tags=("crypto",),
    ),
    "mktemp": PyCheck(
        id=_PY + "insecure-tempfile",
        title="tempfile.mktemp() is race-prone",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cwe="CWE-377",
        remediation="Use `tempfile.mkstemp()` or `NamedTemporaryFile`, which create atomically.",
        tags=("filesystem", "race"),
    ),
    "random": PyCheck(
        id=_PY + "random-for-security",
        title="Predictable randomness for a security value",
        severity=Severity.MEDIUM,
        # Heuristic: this rests on the *name* of the thing being generated, so it does
        # not get the confidence the parser-grade checks do.
        confidence=Confidence.MEDIUM,
        cwe="CWE-330",
        remediation=(
            "`random` is a Mersenne Twister and is predictable from its output. Use the "
            "`secrets` module (`secrets.token_urlsafe()`, `secrets.choice()`)."
        ),
        tags=("crypto", "randomness"),
        references=("https://docs.python.org/3/library/secrets.html",),
    ),
    "debug": PyCheck(
        id=_PY + "debug-enabled",
        title="Debug mode enabled",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cwe="CWE-489",
        remediation=(
            "Never ship debug mode. Flask's debugger exposes an interactive console; "
            "drive it from an environment variable that defaults to off."
        ),
        tags=("hardening", "exposure"),
    ),
    "sql": PyCheck(
        id=_PY + "sql-injection",
        title="SQL built by string interpolation",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe="CWE-89",
        remediation=(
            "Pass parameters to the driver instead of formatting them into the query: "
            "`cur.execute('... WHERE id = %s', (user_id,))`."
        ),
        tags=("injection", "sql"),
    ),
    "assert": PyCheck(
        id=_PY + "assert-for-validation",
        title="Security check written as an assert",
        severity=Severity.MEDIUM,
        # Vocabulary-driven, so honestly medium.
        confidence=Confidence.MEDIUM,
        cwe="CWE-617",
        remediation=(
            "`python -O` removes assert statements, taking the check with them. Raise an "
            "explicit exception instead."
        ),
        tags=("validation",),
    ),
    "except-pass": PyCheck(
        id=_PY + "swallowed-exception",
        title="Exception caught and discarded",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        cwe="CWE-390",
        remediation=(
            "Catching everything and doing nothing hides failed security checks as "
            "readily as it hides bugs. Narrow the exception type and log it."
        ),
        tags=("error-handling",),
    ),
    "unverified-context": PyCheck(
        id=_PY + "ssl-unverified-context",
        title="ssl._create_unverified_context() used",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        cwe="CWE-295",
        remediation="Use `ssl.create_default_context()`, which verifies certificates and hostnames.",
        tags=("transport", "tls"),
    ),
    "cert-none": PyCheck(
        id=_PY + "ssl-cert-none",
        title="Certificate validation set to CERT_NONE",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        cwe="CWE-295",
        remediation="Leave `verify_mode` at `ssl.CERT_REQUIRED`.",
        tags=("transport", "tls"),
    ),
    "check-hostname": PyCheck(
        id=_PY + "ssl-no-hostname-check",
        title="TLS hostname verification disabled",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        cwe="CWE-297",
        remediation=(
            "Keep `check_hostname = True`. Without it a valid certificate for any host "
            "is accepted for every host."
        ),
        tags=("transport", "tls"),
    ),
    "weak-tls": PyCheck(
        id=_PY + "weak-tls-version",
        title="Obsolete TLS/SSL protocol version selected",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cwe="CWE-327",
        remediation=(
            "SSLv2/SSLv3/TLS 1.0/TLS 1.1 are deprecated and broken. Use "
            "`ssl.PROTOCOL_TLS_CLIENT` and set `minimum_version` to TLS 1.2 or later."
        ),
        tags=("transport", "tls", "crypto"),
    ),
    "mark-safe": PyCheck(
        id=_PY + "xss-mark-safe",
        title="Autoescaping bypassed on a non-literal value",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe="CWE-79",
        remediation=(
            "`mark_safe`/`Markup` tell the template engine to stop escaping. Only ever "
            "apply them to a literal you wrote, or sanitise with a library like `nh3` "
            "or `bleach` first."
        ),
        tags=("xss",),
    ),
    "xml": PyCheck(
        id=_PY + "xml-parse-untrusted",
        title="Standard-library XML parser on possibly untrusted input",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        cwe="CWE-611",
        remediation=(
            "Use `defusedxml`. Current CPython blocks external entities in ElementTree, "
            "but the stdlib parsers remain exposed to entity-expansion denial of "
            "service, and `xml.sax`/`minidom` can still resolve external DTDs."
        ),
        tags=("xml", "dos"),
        references=("https://pypi.org/project/defusedxml/",),
    ),
    "extractall": PyCheck(
        id=_PY + "archive-extract-path-traversal",
        title="Archive extracted without path validation",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe="CWE-22",
        remediation=(
            "An archive member may be named `../../etc/cron.d/x` or be a symlink. On "
            "Python 3.12+ pass `filter='data'`; otherwise validate every resolved member "
            "path stays inside the destination before extracting."
        ),
        tags=("path-traversal", "zip-slip"),
        references=("https://docs.python.org/3/library/tarfile.html#extraction-filters",),
    ),
    "paramiko-autoadd": PyCheck(
        id=_PY + "ssh-auto-add-host-key",
        title="SSH host keys accepted automatically",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cwe="CWE-322",
        remediation=(
            "`AutoAddPolicy` trusts whatever key answers, which is exactly what host-key "
            "checking exists to prevent. Load known hosts and use `RejectPolicy`."
        ),
        tags=("transport", "ssh"),
    ),
    "allowed-hosts": PyCheck(
        id=_PY + "django-allowed-hosts-wildcard",
        title="ALLOWED_HOSTS accepts any Host header",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        cwe="CWE-346",
        remediation=(
            "List the hostnames the site actually serves. A wildcard enables Host-header "
            "poisoning of password-reset links and cache entries."
        ),
        tags=("hardening", "django"),
    ),
    "jwt-unverified": PyCheck(
        id=_PY + "jwt-signature-not-verified",
        title="JWT decoded without verifying its signature",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        cwe="CWE-347",
        remediation=(
            "An unverified JWT is attacker-supplied JSON. Verify with an explicit "
            "`algorithms=[...]` allowlist and the real key."
        ),
        tags=("auth", "jwt"),
    ),
    "timing": PyCheck(
        id=_PY + "timing-unsafe-comparison",
        title="Secret compared with ==",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        cwe="CWE-208",
        remediation="Use `hmac.compare_digest()`, which takes constant time.",
        tags=("crypto", "timing"),
    ),
    "ecb": PyCheck(
        id=_PY + "ecb-mode",
        title="Block cipher in ECB mode",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe="CWE-327",
        remediation=(
            "ECB encrypts identical plaintext blocks to identical ciphertext blocks, so "
            "it leaks structure. Use an authenticated mode such as AES-GCM."
        ),
        tags=("crypto",),
    ),
    "env-default": PyCheck(
        id=_PY + "secret-env-default",
        title="Secret-looking environment variable with a hardcoded fallback",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe="CWE-798",
        remediation=(
            "A fallback secret is a committed secret, and it is the value that gets used "
            "wherever the variable was forgotten. Fail closed instead: read the variable "
            "and raise if it is missing."
        ),
        tags=("secret", "credential"),
    ),
}


# Names that mean "this value protects something". Deliberately tight: adding `id` or
# `uuid` here would light up every seed script in every repo.
_SECURITY_NAME = re.compile(
    r"(?i)(?:^|[_.])(?:secret|password|passwd|pwd|token|apikey|api_key|nonce|salt|"
    r"iv|otp|pin|session|csrf|xsrf|auth|credential|signature|cookie|reset)(?:[_.]|$)"
)
_SECRETISH_ENV = re.compile(
    r"(?i)(secret|password|passwd|token|api_?key|private_?key|credential|access_?key|"
    r"auth|salt|signing)"
)
_VALIDATION_WORDS = re.compile(
    r"(?i)\b(auth|authoriz|authentic|permission|token|valid|verif|allowed|owner|admin|"
    r"role|csrf|xsrf|signature|password|secret|is_staff|is_superuser|can_)"
)
_MAC_NAME = re.compile(
    r"(?i)(?:^|[_.])(?:signature|signed|hmac|mac|token|otp|passcode|password_hash|"
    r"secret|api_?key|csrf|xsrf)(?:[_.]|$)"
)
_SQL_KEYWORD = re.compile(
    r"(?i)\b(select\s|insert\s+into|update\s|delete\s+from|drop\s+table|"
    r"where\s|from\s|values\s*\(|order\s+by|group\s+by|union\s|"
    r"create\s+table|alter\s+table)"
)

_WEAK_HASHES = frozenset({"md5", "sha1", "md4", "md2", "sha", "ripemd", "ripemd160"})
_WEAK_TLS_PROTOCOLS = frozenset(
    {"PROTOCOL_SSLv2", "PROTOCOL_SSLv3", "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1"}
)
_RANDOM_FUNCS = frozenset(
    {
        "random", "randint", "randrange", "choice", "choices", "sample", "shuffle",
        "uniform", "getrandbits", "randbytes", "betavariate", "gauss", "normalvariate",
    }
)
_DESERIALIZERS = frozenset(
    {
        "pickle.load", "pickle.loads", "pickle.Unpickler",
        "cPickle.load", "cPickle.loads", "_pickle.load", "_pickle.loads",
        "marshal.load", "marshal.loads",
        "dill.load", "dill.loads",
        "shelve.open",
        "jsonpickle.decode",
    }
)
_SHELL_EXEC = frozenset({"os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput"})
_XML_PARSERS = frozenset(
    {
        "xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring",
        "xml.etree.ElementTree.iterparse", "xml.etree.ElementTree.XMLParser",
        "xml.etree.cElementTree.parse", "xml.etree.cElementTree.fromstring",
        "xml.dom.minidom.parse", "xml.dom.minidom.parseString",
        "xml.dom.pulldom.parse", "xml.dom.pulldom.parseString",
        "xml.sax.parse", "xml.sax.parseString", "xml.sax.make_parser",
        "xml.sax.expatreader.create_parser",
        "lxml.etree.parse", "lxml.etree.fromstring",
    }
)
_SAFE_YAML_LOADERS = frozenset({"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"})
_MARK_SAFE = frozenset(
    {
        "django.utils.safestring.mark_safe",
        "django.utils.html.mark_safe",
        "markupsafe.Markup",
        "jinja2.Markup",
        "flask.Markup",
    }
)
# tarfile's 3.12 extraction filters. "fully_trusted" is the unsafe one, so it is absent.
_SAFE_EXTRACT_FILTERS = frozenset({"data", "tar"})
_EXECUTE_METHODS = frozenset({"execute", "executemany", "executescript", "raw"})


def _is_str_const(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_literal(node: ast.AST) -> bool:
    """Whether a node is a value written out in the source, not computed at runtime."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        return not any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_literal(e) for e in node.elts)
    if isinstance(node, ast.Dict):
        return all(k is not None and _is_literal(k) for k in node.keys) and all(
            _is_literal(v) for v in node.values
        )
    # Adjacent string literals parse as a single Constant, but an explicit `"a" + "b"`
    # is a BinOp of two literals and is still static.
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_literal(node.left) and _is_literal(node.right)
    return False


def _is_falsey_const(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Constant) and (node.value is False or node.value == 0)


def _is_truthy_const(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Constant) and (node.value is True or node.value == 1)


def _keyword(node: ast.Call, name: str) -> Optional[ast.expr]:
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _dotted(node: ast.AST) -> Optional[str]:
    """`a.b.c` -> "a.b.c" for Name/Attribute chains; None for anything else."""
    parts: List[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if not isinstance(cur, ast.Name):
        return None
    parts.append(cur.id)
    return ".".join(reversed(parts))


def _is_sentinel(node: ast.AST) -> bool:
    """Whether a name is an ALL-CAPS constant, i.e. an enum or sentinel.

    Load-bearing for the timing check. Parser vocabulary collides with credential
    vocabulary constantly - a lexer is full of `token == TOKEN_NAME` - and comparing
    against a named constant is never the secret comparison we are looking for.
    """
    name = _dotted(node)
    if not name:
        return False
    leaf = name.split(".")[-1]
    return len(leaf) > 1 and leaf.isupper()


def _is_interpolation(node: ast.AST) -> bool:
    """Whether an expression builds a string at runtime from parts."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Mod):
            return True
        if isinstance(node.op, ast.Add):
            return not _is_literal(node)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in ("format", "join"):
            return True
    return False


class PythonAstAnalyzer(ast.NodeVisitor):
    """Runs the Python checks over one parsed module.

    Construct one per file: it carries per-file state (import aliases, scope stack).
    That also makes it trivially safe to use from the engine's threaded file pass.
    """

    def __init__(
        self,
        text: str,
        path: str,
        *,
        checks: Dict[str, PyCheck],
        module: str = "patterns",
        in_test: bool = False,
    ) -> None:
        self.text = text
        self.path = path
        self.checks = checks
        self.module = module
        self.in_test = in_test
        self.findings: List[Finding] = []

        self._starts: Optional[List[int]] = None
        self._seen: Set[Tuple[str, int]] = set()
        # local name -> canonical dotted module path, from the import pre-pass
        self.aliases: Dict[str, str] = {}
        # scope stack of name -> assigned expression, for one level of taint
        self._scopes: List[Dict[str, ast.expr]] = []
        self._func_names: List[str] = []
        self._assign_targets: List[Tuple[str, ...]] = []

    # -- infrastructure ---------------------------------------------------------------

    def run(self, tree: ast.Module) -> List[Finding]:
        self._collect_imports(tree)
        self._push_scope(tree.body)
        self.visit(tree)
        self._scopes.pop()
        return self.findings

    def _collect_imports(self, tree: ast.AST) -> None:
        """Map every local name to the canonical dotted path it refers to.

        Done in one pre-pass over the whole tree rather than during the walk, because a
        function-local import still tells us what a name means, and because matching on
        canonical names is what separates `os.system(x)` from `self.os.system(x)`.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self.aliases[alias.asname] = alias.name
                    else:
                        # `import os.path` binds `os`; the dotted form resolves through it.
                        head = alias.name.split(".", 1)[0]
                        self.aliases.setdefault(head, head)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    # Relative import: the canonical path is package-dependent, so
                    # recording a guess would create false matches. Skip it.
                    continue
                base = node.module or ""
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    self.aliases[local] = f"{base}.{alias.name}" if base else alias.name

    def canonical(self, node: ast.AST) -> Optional[str]:
        """Dotted name with its head rewritten through the import table.

        Returns None when the head was never imported. Requiring import evidence is what
        stops a local object with a `.system()` method from being read as `os.system`.
        """
        raw = _dotted(node)
        if raw is None:
            return None
        head, _, rest = raw.partition(".")
        base = self.aliases.get(head)
        if base is None:
            return None
        return f"{base}.{rest}" if rest else base

    def _line_starts(self) -> List[int]:
        if self._starts is None:
            self._starts = line_starts(self.text)
        return self._starts

    def _report(
        self,
        key: str,
        node: ast.AST,
        message: str,
        *,
        severity: Optional[Severity] = None,
        confidence: Optional[Confidence] = None,
        secret: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        check = self.checks.get(key)
        if check is None:  # disabled by --disable-rule or a threshold
            return
        line = int(getattr(node, "lineno", 0) or 0)
        col = int(getattr(node, "col_offset", 0) or 0) + 1
        # One finding per check per line. Several checks legitimately see the same line
        # from different nodes - `set_missing_host_key_policy(paramiko.AutoAddPolicy())`
        # is two calls and one problem - and a report that says it twice looks broken.
        dedupe = (key, line)
        if dedupe in self._seen:
            return
        self._seen.add(dedupe)

        raw = line_span(self.text, self._line_starts(), line) if line else ""
        conf = confidence or check.confidence
        tags = list(check.tags)
        if self.in_test and conf > Confidence.LOW:
            conf = Confidence(int(conf) - 1)
            tags.append("in-test")

        payload: Dict[str, Any] = {"detection": "ast", "language": "python"}
        if extra:
            payload.update(extra)
        if secret is not None:
            payload["masked"] = mask(secret)

        end = getattr(node, "end_lineno", None)
        self.findings.append(
            Finding(
                rule_id=check.id,
                title=check.title,
                severity=severity or check.severity,
                confidence=conf,
                message=message,
                path=self.path,
                line=line or None,
                column=col,
                end_line=int(end) if end else None,
                snippet=safe_snippet(raw, secret),
                module=self.module,
                remediation=check.remediation,
                references=list(check.references),
                tags=sorted(set(tags)),
                cwe=check.cwe,
                extra=payload,
            )
        )

    # -- scope tracking ---------------------------------------------------------------

    def _push_scope(self, body: Sequence[ast.stmt]) -> None:
        scope: Dict[str, ast.expr] = {}
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue  # its own scope
            self._collect_assignments(stmt, scope)
        self._scopes.append(scope)

    def _collect_assignments(self, stmt: ast.stmt, scope: Dict[str, ast.expr]) -> None:
        stack: List[ast.AST] = [stmt]
        while stack:
            cur = stack.pop()
            if isinstance(cur, ast.Assign):
                for target in cur.targets:
                    if isinstance(target, ast.Name):
                        # Keep the most suspicious binding: if a name is ever assigned an
                        # interpolated string, that is the one worth remembering.
                        if target.id not in scope or _is_interpolation(cur.value):
                            scope[target.id] = cur.value
            elif isinstance(cur, ast.AnnAssign) and cur.value is not None:
                if isinstance(cur.target, ast.Name):
                    scope.setdefault(cur.target.id, cur.value)
            for child in ast.iter_child_nodes(cur):
                if isinstance(
                    child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
                ):
                    continue
                stack.append(child)

    def _lookup(self, name: str) -> Optional[ast.expr]:
        for scope in reversed(self._scopes):
            if name in scope:
                return scope[name]
        return None

    def _in_security_context(self) -> Optional[str]:
        """Whether the current assignment target or function name names a secret."""
        for targets in reversed(self._assign_targets):
            for target in targets:
                if _SECURITY_NAME.search(target):
                    return target
        if self._func_names and _SECURITY_NAME.search(self._func_names[-1]):
            return self._func_names[-1]
        return None

    # -- traversal --------------------------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._func_names.append(node.name)
        self._push_scope(node.body)
        self.generic_visit(node)
        self._scopes.pop()
        self._func_names.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._push_scope(node.body)
        self.generic_visit(node)
        self._scopes.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        names: List[str] = []
        for target in node.targets:
            dotted = _dotted(target)
            if dotted:
                names.append(dotted)
            if isinstance(target, ast.Attribute):
                names.append(target.attr)

        self._check_settings_assignment(node, names)
        self._check_attribute_assignment(node, names)

        self._assign_targets.append(tuple(names))
        self.generic_visit(node)
        self._assign_targets.pop()

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in _WEAK_TLS_PROTOCOLS:
            canon = self.canonical(node)
            if canon and canon.startswith("ssl."):
                self._report(
                    "weak-tls",
                    node,
                    f"{node.attr} selects a deprecated protocol version in {self.path}.",
                )
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        self._check_assert(node)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self._check_except(node)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        self._check_timing(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        canon = self.canonical(node.func)
        attr = node.func.attr if isinstance(node.func, ast.Attribute) else None
        bare = node.func.id if isinstance(node.func, ast.Name) else None

        self._check_eval_exec(node, bare, canon)
        self._check_deserialization(node, canon)
        self._check_yaml(node, canon)
        self._check_subprocess(node, canon, attr)
        self._check_verify_false(node, canon)
        self._check_hash(node, canon)
        self._check_mktemp(node, canon)
        self._check_random(node, canon)
        self._check_debug(node, attr)
        self._check_sql(node, attr)
        self._check_ssl_calls(node, canon)
        self._check_mark_safe(node, canon, bare)
        self._check_xml(node, canon)
        self._check_extractall(node, attr)
        self._check_paramiko(node, canon, attr)
        self._check_jwt(node, canon)
        self._check_ecb(node, canon, attr)
        self._check_env_default(node, canon)

        self.generic_visit(node)

    # -- individual checks ------------------------------------------------------------

    def _check_eval_exec(
        self, node: ast.Call, bare: Optional[str], canon: Optional[str]
    ) -> None:
        target = bare if bare in ("eval", "exec") else None
        if target is None and canon in ("builtins.eval", "builtins.exec"):
            target = canon.split(".")[-1]
        if target is None:
            return
        if not node.args:
            return
        arg = node.args[0]
        if _is_literal(arg):
            return  # `eval("1+1")` is pointless, not injectable
        self._report(
            "eval-exec",
            node,
            f"{target}() is called on a computed value in {self.path}; whatever "
            f"produces that value can run arbitrary Python.",
        )

    def _check_deserialization(self, node: ast.Call, canon: Optional[str]) -> None:
        if canon and canon in _DESERIALIZERS:
            self._report(
                "deserialization",
                node,
                f"{canon}() reconstructs arbitrary objects; a crafted payload executes "
                f"code during load.",
            )

    def _check_yaml(self, node: ast.Call, canon: Optional[str]) -> None:
        if canon == "yaml.unsafe_load":
            self._report("yaml-load", node, "yaml.unsafe_load() can instantiate any Python object.")
            return
        if canon != "yaml.load":
            return
        loader = _keyword(node, "Loader")
        if loader is None and len(node.args) >= 2:
            loader = node.args[1]
        if loader is None:
            self._report(
                "yaml-load",
                node,
                "yaml.load() without a Loader argument uses the unsafe full loader.",
            )
            return
        name = _dotted(loader)
        leaf = name.split(".")[-1] if name else None
        if leaf in _SAFE_YAML_LOADERS:
            return
        if leaf in ("FullLoader", "CFullLoader"):
            self._report(
                "yaml-load",
                node,
                "yaml.load() with FullLoader still resolves Python-specific tags; "
                "SafeLoader is the safe choice.",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
            )
            return
        self._report("yaml-load", node, f"yaml.load() with an unsafe loader ({leaf or 'unknown'}).")

    def _check_subprocess(
        self, node: ast.Call, canon: Optional[str], attr: Optional[str]
    ) -> None:
        if canon and canon in _SHELL_EXEC:
            self._report("os-system", node, f"{canon}() passes its argument to a shell.")

        shell = _keyword(node, "shell")
        if not _is_truthy_const(shell):
            return
        # `shell=True` only means anything on a process-spawning call.
        looks_like_subprocess = (canon or "").startswith("subprocess.") or attr in (
            "run", "call", "check_call", "check_output", "Popen", "getoutput",
        )
        if not looks_like_subprocess:
            return
        command = node.args[0] if node.args else _keyword(node, "args")
        dynamic = command is not None and not _is_literal(command)
        self._report(
            "shell-true",
            node,
            (
                "shell=True with a command built at runtime: anything in that string "
                "reaching a shell metacharacter is command injection."
                if dynamic
                else "shell=True runs the command through a shell, which is unnecessary "
                "here and becomes injectable the moment the command stops being literal."
            ),
            severity=Severity.HIGH if dynamic else Severity.MEDIUM,
            confidence=Confidence.HIGH if dynamic else Confidence.MEDIUM,
        )

    def _check_verify_false(self, node: ast.Call, canon: Optional[str]) -> None:
        verify = _keyword(node, "verify")
        if verify is None or not _is_falsey_const(verify):
            return
        # requests/httpx/aiohttp all spell it `verify`; a `verify=False` on somebody's
        # own function is not our business, so require an HTTP-client-shaped callee.
        head = (canon or "").split(".")[0]
        if head not in ("requests", "httpx", "session", "aiohttp") and not (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in ("get", "post", "put", "patch", "delete", "head", "request", "send")
        ):
            return
        self._report(
            "verify-false",
            node,
            "TLS certificate verification is disabled for this request, which makes the "
            "connection interceptable.",
        )

    def _check_hash(self, node: ast.Call, canon: Optional[str]) -> None:
        if not canon:
            return
        used_for_security = _keyword(node, "usedforsecurity")
        if _is_falsey_const(used_for_security):
            return  # explicitly a checksum, not a security primitive

        algo: Optional[str] = None
        if canon.startswith("hashlib."):
            leaf = canon.split(".", 1)[1]
            if leaf in _WEAK_HASHES:
                algo = leaf
            elif leaf == "new" and node.args and _is_str_const(node.args[0]):
                candidate = str(node.args[0].value).lower().replace("-", "")
                if candidate in _WEAK_HASHES:
                    algo = candidate
        if algo is None:
            return
        self._report("weak-hash", node, f"{algo.upper()} is broken for any security purpose.")

    def _check_mktemp(self, node: ast.Call, canon: Optional[str]) -> None:
        if canon == "tempfile.mktemp":
            self._report(
                "mktemp",
                node,
                "tempfile.mktemp() returns a name without creating the file, leaving a "
                "window for another process to win the race.",
            )

    def _check_random(self, node: ast.Call, canon: Optional[str]) -> None:
        if not canon or not canon.startswith("random."):
            return
        leaf = canon.split(".", 1)[1]
        if leaf not in _RANDOM_FUNCS:
            return  # SystemRandom() and friends are fine
        because = self._in_security_context()
        if not because:
            return
        self._report(
            "random",
            node,
            f"random.{leaf}() generates {because!r}, which is a security value; the "
            f"Mersenne Twister is reconstructible from a few hundred outputs.",
        )

    def _check_debug(self, node: ast.Call, attr: Optional[str]) -> None:
        if attr != "run":
            return
        if _is_truthy_const(_keyword(node, "debug")):
            self._report(
                "debug",
                node,
                "Debug mode is enabled on this app; the Werkzeug debugger allows "
                "arbitrary code execution if it is ever reachable.",
            )

    def _check_sql(self, node: ast.Call, attr: Optional[str]) -> None:
        if attr not in _EXECUTE_METHODS or not node.args:
            return
        query = node.args[0]
        how = self._dynamic_sql(query)
        if how is None:
            return
        if not _SQL_KEYWORD.search(self._literal_text(query)):
            # Without SQL-looking text this floods on every `.execute()` in the codebase.
            return
        self._report(
            "sql",
            node,
            f"Query passed to .{attr}() is assembled by {how}; use driver parameters so "
            f"the value can never be read as SQL.",
            extra={"detection": "ast"},
        )

    def _dynamic_sql(self, node: ast.AST, depth: int = 0) -> Optional[str]:
        """How this expression interpolates, or None if it is a static string.

        One level of local-variable resolution, per the module design: `q = f"..."`
        followed by `cur.execute(q)` is the overwhelmingly common shape, and chasing
        further without real dataflow produces confident nonsense.
        """
        if isinstance(node, ast.JoinedStr):
            if any(isinstance(v, ast.FormattedValue) for v in node.values):
                return "f-string interpolation"
            return None
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Mod):
                return "%-formatting"
            if isinstance(node.op, ast.Add):
                left, right = node.left, node.right
                if _is_literal(node):
                    return None
                if _is_str_const(left) or _is_str_const(right):
                    return "string concatenation"
                for side in (left, right):
                    inner = self._dynamic_sql(side, depth)
                    if inner:
                        return inner
            return None
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "format":
                return "str.format()"
            if isinstance(func, ast.Attribute) and func.attr == "join":
                return "str.join()"
            return None
        if isinstance(node, ast.Name) and depth == 0:
            assigned = self._lookup(node.id)
            if assigned is not None:
                inner = self._dynamic_sql(assigned, depth + 1)
                if inner:
                    return f"{inner} in local variable {node.id!r}"
        return None

    def _literal_text(self, node: ast.AST, depth: int = 0) -> str:
        """Every string constant reachable in this expression, concatenated.

        Used only to ask "does this look like SQL", so order and spacing are irrelevant.
        """
        if depth > 3:
            return ""
        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, str) else ""
        if isinstance(node, ast.JoinedStr):
            return " ".join(self._literal_text(v, depth + 1) for v in node.values)
        if isinstance(node, ast.FormattedValue):
            return ""
        if isinstance(node, ast.BinOp):
            return (
                self._literal_text(node.left, depth + 1)
                + " "
                + self._literal_text(node.right, depth + 1)
            )
        if isinstance(node, ast.Call):
            parts = [self._literal_text(a, depth + 1) for a in node.args]
            if isinstance(node.func, ast.Attribute):
                parts.append(self._literal_text(node.func.value, depth + 1))
            return " ".join(parts)
        if isinstance(node, (ast.List, ast.Tuple)):
            return " ".join(self._literal_text(e, depth + 1) for e in node.elts)
        if isinstance(node, ast.Name) and depth == 0:
            assigned = self._lookup(node.id)
            if assigned is not None:
                return self._literal_text(assigned, depth + 1)
        return ""

    def _check_assert(self, node: ast.Assert) -> None:
        if self.in_test:
            return
        if self._func_names and self._func_names[-1].startswith("test"):
            return
        try:
            source = ast.unparse(node.test)
        except Exception:  # noqa: BLE001 - unparse is best-effort context, never fatal
            source = line_span(self.text, self._line_starts(), node.lineno)
        if not _VALIDATION_WORDS.search(source):
            return
        self._report(
            "assert",
            node,
            "This assert looks like an authorisation or validation check. Running under "
            "`python -O` removes it and the check silently stops happening.",
        )

    def _check_except(self, node: ast.ExceptHandler) -> None:
        if node.type is not None:
            name = _dotted(node.type)
            if name not in ("Exception", "BaseException"):
                return
        body = node.body
        if len(body) != 1:
            return
        only = body[0]
        swallowed = isinstance(only, ast.Pass) or (
            isinstance(only, ast.Expr)
            and isinstance(only.value, ast.Constant)
            and only.value.value is Ellipsis
        )
        if not swallowed:
            return
        kind = "bare `except:`" if node.type is None else f"`except {_dotted(node.type)}:`"
        self._report("except-pass", node, f"{kind} with an empty body discards every error here.")

    def _check_ssl_calls(self, node: ast.Call, canon: Optional[str]) -> None:
        if canon == "ssl._create_unverified_context":
            self._report(
                "unverified-context",
                node,
                "ssl._create_unverified_context() returns a context that validates nothing.",
            )
        if _is_falsey_const(_keyword(node, "check_hostname")):
            self._report(
                "check-hostname",
                node,
                "check_hostname=False accepts a certificate issued for any hostname.",
            )
        cert_reqs = _keyword(node, "cert_reqs")
        if cert_reqs is not None and (_dotted(cert_reqs) or "").endswith("CERT_NONE"):
            self._report("cert-none", node, "cert_reqs=CERT_NONE disables certificate validation.")
        # Protocol constants are not checked here: `visit_Attribute` sees every
        # `ssl.PROTOCOL_*` reference whether it arrives positionally or by keyword, and
        # checking both places would report the same line twice.

    def _check_settings_assignment(self, node: ast.Assign, names: Sequence[str]) -> None:
        if "ALLOWED_HOSTS" not in names:
            return
        value = node.value
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            if any(_is_str_const(e) and e.value == "*" for e in value.elts):
                self._report(
                    "allowed-hosts",
                    node,
                    "ALLOWED_HOSTS = ['*'] accepts any Host header, which enables "
                    "Host-header poisoning of generated links.",
                )

    def _check_attribute_assignment(self, node: ast.Assign, names: Sequence[str]) -> None:
        value = node.value
        if "check_hostname" in names and _is_falsey_const(value):
            self._report(
                "check-hostname",
                node,
                "check_hostname is set to False, so a certificate for any hostname is accepted.",
            )
        if "verify_mode" in names and (_dotted(value) or "").endswith("CERT_NONE"):
            self._report(
                "cert-none",
                node,
                "verify_mode is set to CERT_NONE, which turns off certificate validation.",
            )

    def _check_mark_safe(
        self, node: ast.Call, canon: Optional[str], bare: Optional[str]
    ) -> None:
        is_mark_safe = (canon in _MARK_SAFE) or (
            bare in ("mark_safe", "Markup") and bare in self.aliases
        )
        if not is_mark_safe:
            return
        if not node.args or _is_literal(node.args[0]):
            return
        name = canon or bare or "mark_safe"
        self._report(
            "mark-safe",
            node,
            f"{name}() is applied to a computed value, disabling template autoescaping "
            f"for whatever that value contains.",
        )

    def _check_xml(self, node: ast.Call, canon: Optional[str]) -> None:
        if canon and canon in _XML_PARSERS:
            self._report(
                "xml",
                node,
                f"{canon}() parses XML with the standard library; prefer `defusedxml` "
                f"when the document is not fully trusted.",
            )

    def _check_extractall(self, node: ast.Call, attr: Optional[str]) -> None:
        if attr not in ("extractall", "extract"):
            return
        filt = _keyword(node, "filter")
        if filt is not None and _is_str_const(filt) and filt.value in _SAFE_EXTRACT_FILTERS:
            return
        self._report(
            "extractall",
            node,
            f".{attr}() writes archive members wherever their names point, including "
            f"outside the destination directory.",
        )

    def _check_paramiko(
        self, node: ast.Call, canon: Optional[str], attr: Optional[str]
    ) -> None:
        if canon and canon.endswith(("paramiko.AutoAddPolicy", "paramiko.WarningPolicy")):
            self._report(
                "paramiko-autoadd",
                node,
                f"{canon.split('.')[-1]} accepts unknown SSH host keys instead of refusing them.",
            )
            return
        if attr != "set_missing_host_key_policy" or not node.args:
            return
        policy = _dotted(node.args[0]) or (
            _dotted(node.args[0].func) if isinstance(node.args[0], ast.Call) else None
        )
        if policy and policy.split(".")[-1] in ("AutoAddPolicy", "WarningPolicy"):
            self._report(
                "paramiko-autoadd",
                node,
                f"Host-key policy {policy.split('.')[-1]} trusts whatever key the server "
                f"presents on first contact.",
            )

    def _check_jwt(self, node: ast.Call, canon: Optional[str]) -> None:
        # Covers `jwt.decode`, `jose.jwt.decode`, and any aliased import of either.
        if not canon or not canon.endswith("jwt.decode"):
            return
        reason: Optional[str] = None
        if _is_falsey_const(_keyword(node, "verify")):
            reason = "verify=False"
        options = _keyword(node, "options")
        if isinstance(options, ast.Dict):
            for key, value in zip(options.keys, options.values):
                if (
                    _is_str_const(key)
                    and key.value in ("verify_signature", "verify_exp", "verify_aud")
                    and _is_falsey_const(value)
                ):
                    if key.value == "verify_signature":
                        reason = 'options={"verify_signature": False}'
                    elif reason is None:
                        reason = f'options={{"{key.value}": False}}'
        algorithms = _keyword(node, "algorithms")
        if isinstance(algorithms, (ast.List, ast.Tuple)):
            if any(
                _is_str_const(e) and str(e.value).lower() == "none" for e in algorithms.elts
            ):
                reason = 'algorithms=["none"]'
        if reason is None:
            return
        weak_exp = reason.startswith('options={"verify_exp') or reason.startswith(
            'options={"verify_aud'
        )
        self._report(
            "jwt-unverified",
            node,
            f"jwt.decode() called with {reason}; the token's claims are then just "
            f"attacker-supplied JSON.",
            severity=Severity.MEDIUM if weak_exp else None,
            confidence=Confidence.MEDIUM if weak_exp else None,
        )

    def _check_timing(self, node: ast.Compare) -> None:
        if not any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            return
        sides = [node.left] + list(node.comparators)
        # An enum comparison is not a secret comparison, whatever the operands are named.
        if any(_is_sentinel(side) for side in sides):
            return
        macish: Optional[str] = None
        for side in sides:
            if isinstance(side, ast.Call):
                func = side.func
                if isinstance(func, ast.Attribute) and func.attr in ("hexdigest", "digest"):
                    macish = f".{func.attr}()"
                    break
            name = _dotted(side)
            if name and _MAC_NAME.search(name):
                macish = name
                break
        if macish is None:
            return
        # Comparing against a literal is nearly always a test or a sentinel check.
        if any(isinstance(s, ast.Constant) for s in sides):
            return
        self._report(
            "timing",
            node,
            f"{macish} is compared with == , which short-circuits on the first "
            f"differing byte and leaks the correct value through timing.",
        )

    def _check_ecb(self, node: ast.Call, canon: Optional[str], attr: Optional[str]) -> None:
        if attr == "ECB" or (canon or "").endswith(".ECB"):
            self._report("ecb", node, "ECB mode selected for a block cipher.")
            return
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            leaf = (_dotted(arg) or "").split(".")[-1]
            if leaf.startswith("MODE_ECB"):
                self._report("ecb", node, "MODE_ECB selected for a block cipher.")
                return

    def _check_env_default(self, node: ast.Call, canon: Optional[str]) -> None:
        if canon not in ("os.environ.get", "os.getenv", "os.environ.setdefault"):
            return
        if len(node.args) < 2:
            return
        name_node, default = node.args[0], node.args[1]
        if not _is_str_const(name_node) or not _is_str_const(default):
            return
        var, value = str(name_node.value), str(default.value)
        if not _SECRETISH_ENV.search(var):
            return
        if len(value) < 8 or is_placeholder(value):
            return
        self._report(
            "env-default",
            node,
            f"{var} falls back to a hardcoded value ({mask(value)}) when the environment "
            f"variable is unset, so the committed value is what gets used.",
            secret=value,
        )


# --------------------------------------------------------------------------------------
# Regex driver
# --------------------------------------------------------------------------------------

# Rules whose match text contains live credential material. Their snippets are redacted
# positionally, using the match offsets rather than a string search, so a short password
# cannot slip through the length floor in `redact_in_line`.
_CREDENTIAL_TAGS = frozenset(
    {"secret", "credential", "credentials", "credential-exposure", "default-password"}
)


def _splice_mask(raw_line: str, line_start: int, span: Tuple[int, int], secret: str) -> str:
    """Replace `span` (absolute offsets) inside `raw_line` with the masked value."""
    begin = span[0] - line_start
    end = span[1] - line_start
    first_break = raw_line.find("\n")
    if first_break != -1 and begin > first_break:
        # The captured value is on a later line of a multi-line match; showing the first
        # line unredacted is safe, and showing the value's line is what matters.
        raw_line = raw_line[first_break + 1 :]
        begin -= first_break + 1
        end -= first_break + 1
    if begin < 0 or end > len(raw_line) or begin >= end:
        # Offsets did not line up; refuse to guess and drop the snippet entirely rather
        # than risk emitting the raw value.
        return f"<redacted: {mask(secret)}>"
    out = (raw_line[:begin] + mask(secret) + raw_line[end:]).splitlines()[0].strip()
    return out if len(out) <= MAX_SNIPPET else out[:MAX_SNIPPET] + "…"


@dataclass
class PreparedRule:
    """A rule plus the confidence it is actually allowed to report at."""

    rule: Rule
    confidence: Confidence
    capped: bool


class PatternRegexScanner:
    """Applies the `patterns_*` packs to file text. Thread-safe once constructed."""

    def __init__(self, prepared: Sequence[PreparedRule]):
        self.prepared = list(prepared)
        self.capped_rule_ids = sorted(p.rule.id for p in self.prepared if p.capped)
        self.comment_filtered = 0
        self.cap_applied = 0

    def scan(
        self,
        text: str,
        path: str,
        *,
        language: Optional[str] = None,
        module: str = "patterns",
        max_per_rule: int = 20,
    ) -> List[Finding]:
        if not text:
            return []
        lowered = text.lower()
        starts: Optional[List[int]] = None
        spans: Optional[List[Tuple[int, int]]] = None
        in_test = is_test_context(path)
        out: List[Finding] = []

        for item in self.prepared:
            rule = item.rule
            if not rule.applies_to(path, language):
                continue
            if not rule.prefilter(lowered):
                continue

            hits = 0
            for match in rule.regex.finditer(text):
                if hits >= max_per_rule:
                    break
                reported = match.group(rule.group)
                if reported is None or not reported.strip():
                    continue

                offset = match.start(rule.group)
                if not rule.match_in_comments:
                    if spans is None:
                        # Computed lazily: most files never match a rule at all, and
                        # this is the one per-file cost that is not trivially cheap.
                        spans = comment_spans(text, language)
                    if _in_spans(spans, offset):
                        self.comment_filtered += 1
                        continue

                if starts is None:
                    starts = line_starts(text)
                line_no = line_of(starts, offset)
                line_start = starts[line_no - 1]
                raw_line = text[line_start : line_start + 1024]

                credential = bool(_CREDENTIAL_TAGS & set(rule.tags))
                secret: Optional[str] = None
                if credential:
                    secret = (
                        match.group(rule.secret_group)
                        if rule.secret_group is not None
                        else reported
                    )
                    span = (
                        match.span(rule.secret_group)
                        if rule.secret_group is not None
                        else match.span(rule.group)
                    )
                    snippet = _splice_mask(raw_line, line_start, span, secret or "")
                else:
                    snippet = safe_snippet(raw_line)

                confidence = item.confidence
                tags = list(rule.tags)
                if in_test and confidence > Confidence.LOW:
                    confidence = Confidence(int(confidence) - 1)
                    tags.append("in-test")

                extra: Dict[str, Any] = {"detection": "regex"}
                if language:
                    extra["language"] = language
                if item.capped:
                    extra["capped"] = True
                    self.cap_applied += 1
                if secret is not None:
                    extra["masked"] = mask(secret)

                end_line = line_of(starts, max(offset, match.end(rule.group) - 1))
                out.append(
                    Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        confidence=confidence,
                        message=rule.message or f"{rule.title} at {path}:{line_no}.",
                        path=path,
                        line=line_no,
                        column=offset - line_start + 1,
                        end_line=end_line,
                        snippet=snippet,
                        module=module,
                        remediation=rule.remediation,
                        references=list(rule.references),
                        tags=sorted(set(tags)),
                        cwe=rule.cwe,
                        extra=extra,
                    )
                )
                hits += 1
        return out


def prepare_rules(rules: Sequence[Rule], min_confidence: Optional[Confidence]) -> List[PreparedRule]:
    """Apply the regex confidence cap, then the confidence threshold.

    Order matters. Filtering on the *declared* confidence first would admit a rule that
    says `high`, cap it to `medium`, and report it under `--min-confidence high` — so the
    cap is computed first and the threshold is applied to the effective value.
    """
    prepared: List[PreparedRule] = []
    for rule in rules:
        confidence = rule.confidence
        capped = False
        if not rule.unambiguous and confidence > Confidence.MEDIUM:
            confidence = Confidence.MEDIUM
            capped = True
        if min_confidence is not None and confidence < min_confidence:
            continue
        prepared.append(PreparedRule(rule=rule, confidence=confidence, capped=capped))
    return prepared


def build_regex_scanner(ctx: ScanContext) -> PatternRegexScanner:
    rules = load_all_builtin("patterns_")
    for extra in ctx.config.rule_packs:
        rules.extend(load_pack(extra))
    rules = filter_rules(
        rules,
        enable=ctx.config.enable_rules,
        disable=ctx.config.disable_rules,
        min_severity=ctx.config.min_severity,
        # min_confidence is applied in prepare_rules, against the capped value.
        min_confidence=None,
        fast=ctx.config.fast,
    )
    # The secrets module owns the secrets pack; an extra pack passed with --rules may
    # contain both families, so keep only what this module is responsible for.
    rules = [r for r in rules if not r.id.startswith("secret.")]
    return PatternRegexScanner(prepare_rules(rules, ctx.config.min_confidence))


def active_checks(ctx: ScanContext) -> Dict[str, PyCheck]:
    """The AST checks left standing after rule selection and the severity thresholds."""
    enable = ctx.config.enable_rules
    disable = ctx.config.disable_rules
    out: Dict[str, PyCheck] = {}
    for key, check in PY_CHECKS.items():
        if enable and not selector_matches(check.id, enable):
            continue
        if disable and selector_matches(check.id, disable):
            continue
        if ctx.config.min_severity is not None and check.severity < ctx.config.min_severity:
            continue
        if ctx.config.min_confidence is not None and check.confidence < ctx.config.min_confidence:
            continue
        out[key] = check
    return out


# --------------------------------------------------------------------------------------
# Module
# --------------------------------------------------------------------------------------


@register
class PatternsModule(FileScanModule):
    name = "patterns"
    description = "Insecure code patterns: Python via AST, other languages via regex"
    phase = "code"

    def __init__(self) -> None:
        self.scanner: Optional[PatternRegexScanner] = None
        self.checks: Dict[str, PyCheck] = {}
        self.counters: Dict[str, int] = {
            "python_files": 0,
            "parse_failures": 0,
            "ast_findings": 0,
            "regex_findings": 0,
            "regex_superseded_by_ast": 0,
        }

    def prepare(self, ctx: ScanContext) -> None:
        self.scanner = build_regex_scanner(ctx)
        self.checks = active_checks(ctx)
        if not self.scanner.prepared and not self.checks:
            ctx.note("patterns: every rule and AST check was filtered out by the current flags")
        elif not self.checks:
            ctx.note("patterns: all Python AST checks are disabled; Python gets no coverage")
        elif not self.scanner.prepared:
            ctx.note("patterns: all regex rule packs are disabled; only Python is covered")

    def scan_file(self, sf: ScanFile, ctx: ScanContext) -> List[Finding]:
        if self.scanner is None:
            return []
        regex_findings = self.scanner.scan(
            sf.text,
            sf.relpath,
            language=sf.language,
            module=self.name,
            max_per_rule=ctx.config.max_findings_per_rule_per_file,
        )
        ast_findings: List[Finding] = []
        if sf.language == "python" and self.checks:
            ast_findings = self._scan_python(sf, ctx)

        self.counters["ast_findings"] += len(ast_findings)
        if not ast_findings:
            self.counters["regex_findings"] += len(regex_findings)
            return regex_findings

        # A parsed fact beats a text resemblance about the same thing. Keyed on CWE
        # rather than rule id because the two detectors name their rules differently.
        claimed = {(f.path, f.line, f.cwe) for f in ast_findings if f.cwe}
        kept = [f for f in regex_findings if (f.path, f.line, f.cwe) not in claimed]
        self.counters["regex_superseded_by_ast"] += len(regex_findings) - len(kept)
        self.counters["regex_findings"] += len(kept)
        return ast_findings + kept

    def _scan_python(self, sf: ScanFile, ctx: ScanContext) -> List[Finding]:
        self.counters["python_files"] += 1
        text = sf.text
        try:
            tree = ast.parse(text, filename=sf.relpath)
        except SyntaxError as exc:
            self.counters["parse_failures"] += 1
            where = f" at line {exc.lineno}" if exc.lineno else ""
            # Never silent: a Python file that does not parse gets *no* pattern coverage,
            # because the regex packs deliberately do not cover Python.
            ctx.note(
                f"patterns: {sf.relpath} could not be parsed as Python{where} "
                f"({exc.msg}); it received no pattern checks at all"
            )
            return []
        except (ValueError, RecursionError) as exc:
            self.counters["parse_failures"] += 1
            ctx.note(
                f"patterns: {sf.relpath} could not be analysed ({type(exc).__name__}: "
                f"{exc}); it received no pattern checks at all"
            )
            return []

        analyzer = PythonAstAnalyzer(
            text,
            sf.relpath,
            checks=self.checks,
            module=self.name,
            in_test=is_test_context(sf.relpath),
        )
        return analyzer.run(tree)

    def stats(self) -> Dict[str, Any]:
        out: Dict[str, Any] = dict(self.counters)
        if self.scanner is not None:
            out["rules_active"] = len(self.scanner.prepared)
            out["rules_capped_to_medium"] = len(self.scanner.capped_rule_ids)
            out["findings_capped"] = self.scanner.cap_applied
            out["comment_matches_dropped"] = self.scanner.comment_filtered
        out["ast_checks_active"] = len(self.checks)
        return out
