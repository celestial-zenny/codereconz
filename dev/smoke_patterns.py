#!/usr/bin/env python3
"""End-to-end check for the `patterns` module: AST analyzer + regex driver.

Companion to `dev/smoke.py`, which covers the secrets module. This one exists because
`patterns.py` makes claims that are easy to get subtly wrong and hard to notice:

  1. the Python AST checks fire on real vulnerable code, and are labelled `ast`
  2. the regex packs fire on the other languages, and are labelled `regex`
  3. declared-high regex rules are capped to MEDIUM; `unambiguous` rules are not
  4. matches inside comments are dropped, EXCEPT for the rule that reads comments
  5. safe idiomatic code produces ZERO findings (the false-positive guard)
  6. an AST finding supersedes a regex finding about the same line and CWE
  7. a Python file that cannot be parsed produces a recorded note, never silence
  8. no credential appears in full in any finding

Run:  python3 dev/smoke_patterns.py
Exit: 0 if every assertion holds, 1 otherwise.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from codereconwork.core.context import Config, ScanContext  # noqa: E402
from codereconwork.core.engine import run_code_modules, select_modules  # noqa: E402
from codereconwork.core.finding import Confidence  # noqa: E402
from codereconwork.core.walker import collect  # noqa: E402
from codereconwork.modules.patterns import PY_CHECKS, comment_spans  # noqa: E402
import codereconwork.modules  # noqa: E402,F401  - populates the module registry

# --------------------------------------------------------------------------------------
# Fixture
# --------------------------------------------------------------------------------------

VULNERABLE_PY = '''
import ast
import hashlib
import os
import pickle
import random
import ssl
import subprocess
import tarfile
import tempfile
import yaml
import jwt
import paramiko
import requests
from django.utils.safestring import mark_safe
from xml.etree import ElementTree
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ALLOWED_HOSTS = ["*"]


def run_user_code(payload, expr):
    eval(expr)                                    # eval-exec
    exec(compile(payload, "<s>", "exec"))         # eval-exec
    ast.literal_eval(payload)                     # SAFE: not eval


def load(blob, stream):
    pickle.loads(blob)                            # deserialization
    yaml.load(stream)                             # yaml-load
    yaml.load(stream, Loader=yaml.SafeLoader)      # SAFE


def shell(target):
    os.system("ping " + target)                    # os-system
    subprocess.run(f"grep {target} log", shell=True)   # shell-true
    subprocess.run(["grep", target, "log"])        # SAFE


def net(url):
    requests.get(url, verify=False)               # verify-false
    ctx = ssl._create_unverified_context()         # unverified-context
    ctx.check_hostname = False                     # check-hostname
    ctx.verify_mode = ssl.CERT_NONE                # cert-none
    ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1)    # weak-tls


def crypto(password, provided_sig, computed):
    hashlib.md5(password.encode()).hexdigest()     # weak-hash
    hashlib.new("sha1", b"x")                      # weak-hash
    hashlib.sha256(b"x").hexdigest()               # SAFE
    hashlib.md5(b"x", usedforsecurity=False)       # SAFE: declared non-security
    session_token = random.randint(0, 999999)      # random (security name)
    dice_roll = random.randint(1, 6)               # SAFE: not a security value
    if provided_sig == computed.hexdigest():        # timing
        return session_token, dice_roll


def files(archive):
    tempfile.mktemp()                              # mktemp
    with tarfile.open(archive) as tf:
        tf.extractall("/tmp/out")                  # extractall
    with tarfile.open(archive) as tf2:
        tf2.extractall("/tmp/out", filter="data")  # SAFE


def query(cur, user_id, name):
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")   # sql
    sql = "DELETE FROM sessions WHERE user = '%s'" % name
    cur.execute(sql)                               # sql, via local taint
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))   # SAFE
    cur.execute(f"log line {name}")                # SAFE: not SQL-shaped


def auth(user, token):
    assert user.is_admin, "not permitted"          # assert
    assert len(token) == 32                        # SAFE: not security vocabulary
    jwt.decode(token, options={"verify_signature": False})   # jwt-unverified
    try:
        check(token)
    except Exception:
        pass                                       # except-pass


def render(user_input):
    return mark_safe(user_input)                   # mark-safe


def serve(app):
    app.run(host="127.0.0.1", debug=True)          # debug


def encrypt(key, data):
    Cipher(algorithms.AES(key), modes.ECB())       # ecb (cryptography)
    AES.new(key, AES.MODE_ECB)                     # ecb (pycryptodome)
    return data


def parse(doc):
    return ElementTree.fromstring(doc)             # xml


def connect(host):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())   # paramiko-autoadd
    return client


API_SECRET = os.environ.get("APP_SIGNING_SECRET", "s3cr3t-fallback-value")   # env-default
DEBUG_OK = os.environ.get("PORT", "8080")          # SAFE: not secret-ish


def check(token):
    return True
'''

# Every line here is idiomatic and safe. Any finding in this file is a false positive.
CLEAN_PY = '''
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path

import requests
import yaml


def load_config(path):
    """# TODO: this hash-like comment must not be read as code."""
    with open(path) as fh:
        return yaml.safe_load(fh)


def parse_payload(raw):
    return json.loads(raw)


def token():
    return secrets.token_urlsafe(32)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify(expected, provided):
    return hmac.compare_digest(expected, provided)


def fetch(url):
    # NOTE: verify defaults to True; do not pass verify=False here
    return requests.get(url, timeout=10)


def run(args):
    return subprocess.run(list(args), check=True, capture_output=True)


def workdir():
    return tempfile.mkdtemp()


def query(cur, user_id):
    cur.execute("SELECT email FROM users WHERE id = %s", (user_id,))
    return cur.fetchone()


def home():
    return Path(os.environ["HOME"])


DOCS_URL = "http://localhost:8000/docs"
'''

VULNERABLE_JS = '''
const crypto = require("crypto");
const { exec } = require("child_process");

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

function render(el, userInput) {
  el.innerHTML = userInput;
  document.write(userInput);
}

function run(target) {
  exec("ping " + target, (e, out) => console.log(out));
}

function query(db, id) {
  return db.query(`SELECT * FROM users WHERE id = ${id}`);
}

function token() {
  const sessionToken = Math.random().toString(36);
  return sessionToken;
}

function send(win, msg) {
  win.postMessage(msg, "*");
}

// eval(userInput) is commented out and must NOT be reported
/* el.innerHTML = other; also commented out */
// TODO: fix the auth bypass before release
const url = "https://example.com//not-a-comment";
'''

VULNERABLE_TF = '''
resource "aws_security_group" "open" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "public" {
  acl = "public-read"
}

# acl = "public-read" in a comment must not be reported
'''

BROKEN_PY = '''
def truncated(
    this file does not parse at all
'''

FIXTURE = {
    "app/vulnerable.py": VULNERABLE_PY,
    "app/clean.py": CLEAN_PY,
    "web/vulnerable.js": VULNERABLE_JS,
    "infra/main.tf": VULNERABLE_TF,
    "app/broken.py": BROKEN_PY,
}

# Every AST check must be exercised by the fixture above. Derived from the check table on
# purpose: adding a check without planting a case for it should fail this test, not slip
# through as an untested claim.
EXPECTED_AST = {check.id for check in PY_CHECKS.values()}

# Regex rules that must fire on the non-Python fixtures.
EXPECTED_REGEX = {
    "pattern.js.innerhtml-assignment",
    "pattern.js.document-write",
    "pattern.js.tls-reject-unauthorized",
    "pattern.js.math-random-for-secret",
    "pattern.js.insecure-random-uuid",
    "pattern.js.postmessage-wildcard",
    "pattern.generic.security-todo",
    "pattern.iac.tf-open-ingress",
    "pattern.iac.tf-public-bucket",
}

SECRET_LITERAL = "s3cr3t-fallback-value"


def build_fixture(root: Path) -> None:
    for rel, body in FIXTURE.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body.lstrip("\n"), encoding="utf-8")


def check_comment_spans(failures: list) -> None:
    """Unit-level checks on the comment heuristic, which the rest of it depends on."""
    cases = [
        ("py-hash", 'x = 1  # secret = "abc"\n', "python", '# secret = "abc"'),
        ("py-hash-in-string", 'url = "http://x/#frag"\n', "python", None),
        ("js-slash", "let a = 1; // eval(x)\n", "javascript", "// eval(x)"),
        ("js-url", 'const u = "https://example.com//x";\n', "javascript", None),
        ("js-block", "/* eval(x) */ let b = 2;\n", "javascript", "/* eval(x) */"),
        ("tf-hash", '# acl = "public-read"\n', "terraform", '# acl = "public-read"'),
        ("unknown-lang", "# not filtered here\n", "cobol", None),
    ]
    for name, text, lang, expected in cases:
        spans = comment_spans(text, lang)
        got = text[spans[0][0] : spans[0][1]].strip() if spans else None
        if expected is None:
            if spans:
                failures.append(f"comment_spans[{name}]: expected none, got {got!r}")
        elif got != expected:
            failures.append(f"comment_spans[{name}]: expected {expected!r}, got {got!r}")


def main() -> int:
    failures: list = []
    check_comment_spans(failures)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "repo"
        root.mkdir()
        build_fixture(root)

        files, walk_stats = collect(root, use_gitignore=True)
        print(f"walk:        {len(files)} files, {walk_stats['bytes_scanned']} bytes")

        ctx = ScanContext(config=Config(root=root), root=root, files=files, walk_stats=walk_stats)
        modules = select_modules("code", ["patterns"])
        results = run_code_modules(ctx, modules)

        result = next(r for r in results if r.name == "patterns")
        if result.error:
            print(f"FAIL: patterns module errored: {result.error}")
            return 1
        findings = result.findings

        print(f"patterns:    {len(findings)} findings")
        print(f"             stats: {result.stats}")

        by_detection: dict = {}
        for f in findings:
            by_detection.setdefault(f.extra.get("detection", "none"), []).append(f)
        print(
            "             by detection: "
            + ", ".join(f"{k}={len(v)}" for k, v in sorted(by_detection.items()))
        )

        ast_ids = {f.rule_id for f in by_detection.get("ast", [])}
        regex_ids = {f.rule_id for f in by_detection.get("regex", [])}

        print(f"\n--- AST findings ({len(by_detection.get('ast', []))})")
        for f in sorted(by_detection.get("ast", []), key=lambda f: (f.path or "", f.line or 0)):
            print(f"    [{f.severity.label:8} {f.confidence.label:9}] {f.location:24} {f.rule_id}")

        print(f"\n--- regex findings ({len(by_detection.get('regex', []))})")
        for f in sorted(by_detection.get("regex", []), key=lambda f: (f.path or "", f.line or 0)):
            cap = " capped" if f.extra.get("capped") else ""
            print(
                f"    [{f.severity.label:8} {f.confidence.label:9}]"
                f" {f.location:24} {f.rule_id}{cap}"
            )

        # 1 + 2. both detectors fired, and labelled themselves
        missing_ast = EXPECTED_AST - ast_ids
        if missing_ast:
            failures.append(f"AST checks did not fire: {sorted(missing_ast)}")
        missing_regex = EXPECTED_REGEX - regex_ids
        if missing_regex:
            failures.append(f"regex rules did not fire: {sorted(missing_regex)}")
        if any(f.extra.get("detection") not in ("ast", "regex") for f in findings):
            failures.append("a finding did not declare its detection method")
        if any(f.rule_id.startswith("pattern.python.") for f in by_detection.get("regex", [])):
            failures.append("a python.* rule id was reported as a regex finding")

        # 3. the regex confidence cap
        for f in by_detection.get("regex", []):
            if f.confidence > Confidence.MEDIUM and not f.extra.get("capped"):
                # Only legitimate if the rule opted out via `unambiguous`.
                from codereconwork.core.rules import load_all_builtin

                rule = next(
                    (r for r in load_all_builtin("patterns_") if r.id == f.rule_id), None
                )
                if rule is None or not rule.unambiguous:
                    failures.append(
                        f"{f.rule_id} reported {f.confidence.label} confidence from a regex "
                        f"without declaring `unambiguous`"
                    )
        if not any(f.extra.get("capped") for f in by_detection.get("regex", [])):
            failures.append("no regex finding was capped; the cap is not being applied")

        # 4. comments were filtered, except where a rule opts out
        js_lines = FIXTURE["web/vulnerable.js"].lstrip("\n").splitlines()
        commented_eval_line = next(
            i + 1 for i, line in enumerate(js_lines) if line.startswith("// eval(")
        )
        commented_html_line = next(
            i + 1 for i, line in enumerate(js_lines) if line.startswith("/* el.innerHTML")
        )
        todo_line = next(i + 1 for i, line in enumerate(js_lines) if "auth bypass" in line)
        for line_no, label in ((commented_eval_line, "// eval"), (commented_html_line, "/* */")):
            hit = [f for f in findings if f.path == "web/vulnerable.js" and f.line == line_no]
            if hit:
                failures.append(
                    f"reported a match inside a {label} comment: {[f.rule_id for f in hit]}"
                )
        todo_hits = [
            f
            for f in findings
            if f.path == "web/vulnerable.js"
            and f.line == todo_line
            and f.rule_id == "pattern.generic.security-todo"
        ]
        if not todo_hits:
            failures.append(
                "pattern.generic.security-todo did not fire; match_in_comments opt-out is broken"
            )
        tf_lines = FIXTURE["infra/main.tf"].lstrip("\n").splitlines()
        tf_comment_line = next(
            i + 1 for i, line in enumerate(tf_lines) if line.startswith("# acl")
        )
        if [f for f in findings if f.path == "infra/main.tf" and f.line == tf_comment_line]:
            failures.append("reported a match inside a Terraform # comment")

        # 5. the false-positive guard
        clean_hits = [f for f in findings if f.path == "app/clean.py"]
        if clean_hits:
            failures.append(
                "false positives in clean.py: "
                + ", ".join(f"{f.rule_id}@{f.line}" for f in clean_hits)
            )

        # 6. AST supersedes regex on the same line + CWE. The generic TLS regex rule and
        #    the AST verify=False check both cover the `requests.get(url, verify=False)`
        #    line, so exactly one finding must survive there.
        py_lines = FIXTURE["app/vulnerable.py"].lstrip("\n").splitlines()
        verify_line = next(
            i + 1 for i, line in enumerate(py_lines) if "verify=False" in line
        )
        at_verify = [f for f in findings if f.path == "app/vulnerable.py" and f.line == verify_line]
        if len(at_verify) != 1:
            failures.append(
                f"expected 1 finding at the verify=False line, got "
                f"{[f.rule_id for f in at_verify]}"
            )
        elif at_verify[0].extra.get("detection") != "ast":
            failures.append("the regex finding won over the AST finding at the verify=False line")
        if not result.stats.get("regex_superseded_by_ast"):
            failures.append("regex_superseded_by_ast is 0; the supersede path never ran")

        # 7. the unparseable file was reported, not skipped in silence
        if not any("broken.py" in note for note in ctx.notes):
            failures.append("app/broken.py failed to parse without a recorded note")
        if result.stats.get("parse_failures") != 1:
            failures.append(f"expected 1 parse failure, got {result.stats.get('parse_failures')}")

        # 8. no credential in full, anywhere
        for f in findings:
            blob = f"{f.snippet or ''} {f.message} {f.extra}"
            if SECRET_LITERAL in blob:
                failures.append(f"{f.rule_id} leaked the fallback secret in full")

        print("\nnotes:")
        for note in ctx.notes:
            print(f"    - {note}")

    print()
    if failures:
        for problem in failures:
            print(f"FAIL: {problem}")
        return 1
    print(
        "PASS: AST + regex both fire, cap applied, comments filtered, clean.py silent, "
        "AST supersedes regex, parse failure reported, no leaks"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
