"""Heuristics that separate real credentials from things that merely look like them.

This module is the difference between a scanner people run and a scanner people mute.
Provider-prefixed tokens (`AKIA...`, `ghp_...`) are self-identifying and need almost no
help. Everything else - a 40-character string assigned to something called `api_key` -
needs judgement, and getting that judgement wrong in the noisy direction is fatal:
a scanner with a 60% false-positive rate is worse than no scanner, because the team
learns to skip its output entirely.

Three filters, applied in increasing cost order:
  `is_placeholder`      - is it obviously fake or a template?
  `looks_like_known_format` - is it a hash, UUID, path, or encoded asset?
  `shannon_entropy`     - is its character distribution consistent with randomness?
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from collections import Counter
from typing import Optional, Tuple

# --------------------------------------------------------------------------------------
# Entropy
# --------------------------------------------------------------------------------------


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character of the observed distribution.

    Note the ceiling is log2(len(value)), so short strings cannot score highly no matter
    how random they are. A random 32-char base64 string lands around 4.6-4.8; a 32-char
    hex hash caps near 4.0. That gap is why a ~4.5 threshold excludes hashes for free.
    """
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def char_classes(value: str) -> int:
    """How many of lower/upper/digit/symbol appear. Real keys usually mix 3+."""
    return sum(
        (
            any(c.islower() for c in value),
            any(c.isupper() for c in value),
            any(c.isdigit() for c in value),
            any(not c.isalnum() for c in value),
        )
    )


# --------------------------------------------------------------------------------------
# Placeholders
# --------------------------------------------------------------------------------------

# Substrings that mean "a human wrote this to be replaced later".
_PLACEHOLDER_SUBSTRINGS = (
    "example", "sample", "dummy", "placeholder", "changeme", "change_me", "change-me",
    "yourkey", "your_key", "your-key", "yourtoken", "your_token", "your-token",
    "yoursecret", "your_secret", "your-secret", "yourapi", "your_api", "your-api",
    "yourpassword", "your_password", "mykey", "my_key", "my-key", "mysecret",
    "insert", "replace", "putyour", "put_your", "addyour", "add_your", "enter_your",
    "enteryour", "provide", "supply_your", "setme", "set_me", "fillme", "fill_me",
    "redacted", "removed", "sanitized", "scrubbed", "hidden", "obfuscated", "masked",
    "notreal", "not_real", "not-real", "notarealkey", "fakekey", "fake_key", "fake-key",
    "faketoken", "invalid", "unset", "undefined", "todo", "tbd", "fixme", "xxxxx",
    "abcdef", "abc123", "123456", "qwerty", "asdf", "hunter2", "letmein", "passw0rd",
    "deadbeef", "cafebabe", "0123456789", "lorem", "ipsum", "foobar", "foo_bar",
    "test_key", "testkey", "test-key", "testsecret", "test_secret", "testtoken",
    "dev_key", "devkey", "local_only", "localhost", "somekey", "some_key",
    "keyhere", "key_here", "tokenhere", "token_here", "secrethere", "secret_here",
    "canary", "donotuse", "do_not_use", "unused", "disabled", "n/a", "none", "null",
)

# Template/interpolation syntax: the value is computed at runtime, not baked in.
_TEMPLATE_MARKERS = (
    "${", "{{", "%(", "<%", "$(", "#{", "%s", "%d", "{0}", "{1}", "<<", "@@",
    "os.environ", "os.getenv", "process.env", "getenv", "env[", "env.get", "deno.env",
    "system.getenv", "configmapkeyref", "secretkeyref", "vault:", "aws:secretsmanager",
    "credential_process", "keyring.get", "config.get", "settings.",
)

_ALL_SAME = re.compile(r"^(.)\1{7,}$")
_REPEATED_UNIT = re.compile(r"^(.{1,4}?)\1{3,}$")
_ANGLE_WRAPPED = re.compile(r"^\s*[<\[({].*[>\])}]\s*$")


def is_placeholder(value: str) -> bool:
    """True when the value is plainly not a live credential."""
    v = value.strip()
    if not v:
        return True
    lowered = v.lower()

    if any(marker in lowered for marker in _TEMPLATE_MARKERS):
        return True
    if _ANGLE_WRAPPED.match(v):  # <your-api-key>, [REDACTED], {{token}}
        return True
    if any(s in lowered for s in _PLACEHOLDER_SUBSTRINGS):
        return True
    if _ALL_SAME.match(v) or _REPEATED_UNIT.match(v):
        return True
    # Sequential runs: "abcdefgh", "12345678"
    if len(v) >= 8 and all(ord(v[i + 1]) - ord(v[i]) == 1 for i in range(len(v) - 1)):
        return True
    # A value that is all one case with no digits is usually prose or an identifier.
    if len(v) >= 16 and v.isalpha() and (v.islower() or v.isupper()):
        return True
    return False


# --------------------------------------------------------------------------------------
# Known non-secret formats
# --------------------------------------------------------------------------------------

_HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")
_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_SEMVER = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?")
_PATHISH = re.compile(
    r"(^\.{0,2}/)|(^[A-Za-z]:\\)|(/[A-Za-z0-9_.\-]+){2,}"
    r"|\.(py|js|ts|go|rb|php|java|json|ya?ml|toml|html|css|md|txt|png|jpe?g|svg|lock)$"
)
_URLISH = re.compile(r"^(https?|ftp|ws|wss|file|data|mailto|git\+ssh)://|^www\.")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_MIME = re.compile(r"^[a-z]+/[a-z0-9.+\-]+$")
_SRI = re.compile(r"^sha(256|384|512)-")
_IDENTIFIER_RUN = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:[_\-.][A-Za-z0-9]+){2,}$")
_CSS_CLASSES = re.compile(r"^[a-z0-9\-]+(?: [a-z0-9\-]+){2,}$")

# Base64 prefixes of common binary assets. If a "secret" decodes to a PNG, it is a PNG.
_ASSET_B64_PREFIXES = (
    "iVBORw0KGgo",  # PNG
    "/9j/",         # JPEG
    "R0lGODlh", "R0lGODdh",  # GIF
    "JVBERi0",      # PDF
    "PHN2Zy",       # <svg
    "PD94bWw",      # <?xml
    "UEsDB",        # ZIP / docx / jar
    "H4sI",         # gzip
    "AAABAA",       # ICO
    "RIFF", "T2dnUw",  # WAV / OGG
    "data:image",
    "AAAAIGZ0eX",   # MP4
)


def looks_like_known_format(value: str) -> Tuple[bool, str]:
    """Identify strings that are structurally *not* credentials.

    Returns `(matched, reason)`. Only consulted for the generic entropy sweep - a
    provider rule that already matched `AKIA[A-Z0-9]{16}` should not be talked out of
    it just because the tail happens to be hex.
    """
    v = value.strip()
    if not v:
        return True, "empty"
    if _UUID.match(v):
        return True, "uuid"
    if _HEX_ONLY.match(v) and len(v) in (32, 40, 56, 64, 96, 128):
        return True, f"hex digest ({len(v)} chars)"
    if _SEMVER.match(v):
        return True, "version string"
    if _ISO_DATE.match(v):
        return True, "timestamp"
    if _SRI.match(v):
        return True, "subresource integrity hash"
    if _URLISH.match(v):
        return True, "url"
    if _EMAIL.match(v):
        return True, "email address"
    if _MIME.match(v):
        return True, "mime type"
    if _PATHISH.search(v):
        return True, "file path"
    if _CSS_CLASSES.match(v):
        return True, "class list"
    if _IDENTIFIER_RUN.match(v) and char_classes(v) <= 2:
        return True, "dotted identifier"
    if any(v.startswith(p) for p in _ASSET_B64_PREFIXES):
        return True, "base64-encoded asset"
    # Long, single-class strings are usually generated identifiers, not keys.
    if len(v) >= 40 and char_classes(v) == 1:
        return True, "single character class"
    return False, ""


# --------------------------------------------------------------------------------------
# Format validators, referenced by name from the rule packs
# --------------------------------------------------------------------------------------


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def validate_aws_access_key(value: str) -> Tuple[bool, str]:
    """AWS key IDs are exactly 20 chars of uppercase base32-ish text."""
    if len(value) != 20:
        return False, "wrong length for an AWS key ID"
    if not re.match(r"^[A-Z0-9]{20}$", value):
        return False, "AWS key IDs are uppercase alphanumeric"
    return True, ""


def validate_jwt(value: str) -> Tuple[bool, str]:
    """Decode the JWT header and require a plausible `alg`.

    Purely local - no signature verification, no network. Also surfaces whether the
    token is expired, which is the first thing you want to know during triage.
    """
    parts = value.split(".")
    if len(parts) != 3:
        return False, "not three dot-separated segments"
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return False, "header is not base64url-encoded JSON"
    if not isinstance(header, dict) or "alg" not in header:
        return False, "header has no alg claim"
    return True, ""


def jwt_details(value: str) -> dict:
    """Extra triage context for a JWT: algorithm, subject, expiry, notable claims."""
    out: dict = {}
    parts = value.split(".")
    if len(parts) != 3:
        return out
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return out
    if isinstance(header, dict):
        out["alg"] = header.get("alg")
        if header.get("alg") == "none":
            out["unsigned"] = True
    if not isinstance(payload, dict):
        return out
    for claim in ("iss", "sub", "aud", "role", "email"):
        if claim in payload:
            out[claim] = payload[claim]
    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        out["exp"] = int(exp)
    if "exp" not in payload:
        # No expiry means it is valid until the signing key rotates.
        out["no_expiry"] = True
    # Supabase/PostgREST service keys bypass row-level security entirely.
    if payload.get("role") in ("service_role", "supabase_admin"):
        out["privileged_role"] = payload["role"]
    return out


VALIDATORS = {
    "aws_access_key": validate_aws_access_key,
    "jwt": validate_jwt,
}


def run_validator(name: Optional[str], value: str) -> Tuple[bool, str]:
    if not name:
        return True, ""
    fn = VALIDATORS.get(name)
    if fn is None:
        return True, ""
    return fn(value)


# --------------------------------------------------------------------------------------
# Path context
# --------------------------------------------------------------------------------------

_TEST_PATH = re.compile(
    r"(^|/)(tests?|testing|spec|specs|__tests__|__mocks__|fixtures?|mocks?|examples?|"
    r"samples?|demos?|docs?|documentation|e2e|integration[_-]?tests?|testdata|"
    r"benchmarks?|playground|sandbox|scratch)(/|$)"
    r"|(^|/)(conftest|test_[^/]*|[^/]*_test|[^/]*\.test|[^/]*\.spec)\.[A-Za-z0-9]+$"
    r"|\.(example|sample|template|dist|tmpl)$",
    re.I,
)


def is_test_context(relpath: str) -> bool:
    """Whether a path is test/fixture/example material.

    Findings here are kept - real credentials leak through test files constantly - but
    reported one confidence notch lower and tagged, so triage can sort accordingly.
    """
    return bool(_TEST_PATH.search(relpath))
