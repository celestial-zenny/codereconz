"""Secret masking.

Rule for the whole codebase: a credential that Code Recon found must never appear in
full in terminal output, a JSON report, a SARIF file, or a log. Reports get shared in
Slack and attached to tickets; a scanner that echoes the key it found has just widened
the exposure it was hired to detect.

Producers are responsible for calling `redact_in_line` before putting a snippet on a
Finding. `Finding.snippet` is documented as already-redacted.
"""

from __future__ import annotations

import hashlib
from typing import Iterable, Optional

# Show at most this many leading characters, so a human can still recognise *which*
# key it is (matching against a secrets manager) without the value being usable.
_KEEP_HEAD = 4
_KEEP_TAIL = 2
# Below this length, keeping head+tail would reveal most of the value.
_MIN_FOR_PARTIAL = 12
MAX_SNIPPET = 240


def mask(secret: str) -> str:
    """`AKIAIOSFODNN7EXAMPLE` -> `AKIA...LE (20 chars)`."""
    secret = secret.strip()
    if not secret:
        return "<empty>"
    n = len(secret)
    if n < _MIN_FOR_PARTIAL:
        return f"{'*' * n} ({n} chars)"
    return f"{secret[:_KEEP_HEAD]}...{secret[-_KEEP_TAIL:]} ({n} chars)"


def fingerprint_secret(secret: str) -> str:
    """Stable identity for a credential without retaining it.

    Used as `Finding.fingerprint_seed` so rotating a key produces a genuinely new
    finding, while reformatting the line around it does not.
    """
    return hashlib.sha256(secret.strip().encode("utf-8", "replace")).hexdigest()[:16]


def redact_in_line(line: str, secrets: Iterable[str]) -> str:
    """Replace each secret inside `line` with its masked form, and clamp the length."""
    out = line.rstrip("\n\r")
    for secret in secrets:
        secret = secret.strip()
        if len(secret) >= 6 and secret in out:
            out = out.replace(secret, mask(secret))
    out = out.strip()
    if len(out) > MAX_SNIPPET:
        out = out[:MAX_SNIPPET] + "…"
    return out


def safe_snippet(line: str, secret: Optional[str] = None) -> str:
    """Trim a source line for display, redacting `secret` if given.

    Multi-line matches (PEM blocks) collapse to their first line — the rest is the key
    material itself and has no diagnostic value.
    """
    first = line.splitlines()[0] if line else ""
    return redact_in_line(first, [secret] if secret else [])
