#!/usr/bin/env python3
"""End-to-end check for baseline diffing and inline suppression.

Proves the two suppression paths and, more importantly, the ways they are *not* allowed
to fail: a finding is never dropped because a check could not be run, and a baseline file
never silently records a credential.

Run:  python3 dev/smoke_suppress.py
Exit: 0 if every assertion holds, 1 otherwise.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from codereconwork.core.finding import Confidence, Finding, Severity  # noqa: E402
from codereconwork.core.suppress import (  # noqa: E402
    SuppressError,
    apply_suppressions,
    load_baseline,
    parse_inline_directives,
    write_baseline,
)

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def finding(rule_id: str, path: str, line: int, *, snippet: str = "x = 1") -> Finding:
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        message="test finding",
        path=path,
        line=line,
        snippet=snippet,
        module="test",
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        # --- inline: bare token, targeted token, prefix, line-above --------------------
        (root / "app.py").write_text(
            "\n".join(
                [
                    "a = eval(x)                       # coderecon:ignore",              # 1 bare
                    "b = md5(y)                         # coderecon:ignore[artifact.x]",  # 2 wrong rule
                    "c = md5(z)                         # coderecon:ignore[pattern.python]",  # 3 prefix
                    "# coderecon:ignore[pattern.python.ecb-mode]",                        # 4 above ->
                    "d = ecb()",                                                          # 5 target
                    "e = risky()",                                                        # 6 no directive
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        f_bare = finding("pattern.python.eval-exec-non-literal", "app.py", 1)
        f_wrongrule = finding("pattern.python.weak-hash-md5", "app.py", 2)
        f_prefix = finding("pattern.python.weak-hash-md5", "app.py", 3)
        f_above = finding("pattern.python.ecb-mode", "app.py", 5)
        f_plain = finding("pattern.python.command-injection", "app.py", 6)

        res = apply_suppressions(
            [f_bare, f_wrongrule, f_prefix, f_above, f_plain], root=root
        )
        kept = {f.rule_id + "@" + str(f.line) for f in res.kept}
        supp = {f.rule_id + "@" + str(f.line) for f in res.suppressed}

        check("pattern.python.eval-exec-non-literal@1" in supp, "bare inline token did not suppress")
        check(
            "pattern.python.weak-hash-md5@2" in kept,
            "a targeted token for a different rule wrongly suppressed this finding",
        )
        check("pattern.python.weak-hash-md5@3" in supp, "prefix selector in token did not suppress")
        check("pattern.python.ecb-mode@5" in supp, "a directive on the line above did not suppress")
        check("pattern.python.command-injection@6" in kept, "an undirected finding was suppressed")
        check(res.by_inline == 3, f"expected 3 inline suppressions, got {res.by_inline}")

        # --- directive parsing edge cases ---------------------------------------------
        check(parse_inline_directives("nothing here") is None, "found a directive where there is none")
        check(parse_inline_directives("x # coderecon:ignore") == [], "bare token should parse to []")
        check(
            parse_inline_directives("// coderecon:ignore[a.b, c.d]") == ["a.b", "c.d"],
            "comma-separated selectors did not parse",
        )
        check(
            parse_inline_directives("<!-- CODERECON:IGNORE -->") == [],
            "token match should be case-insensitive and marker-agnostic",
        )

        # --- baseline round-trip ------------------------------------------------------
        SECRET = "AKIAIOSFODNN7EXAMPLE"
        b1 = finding("secret.aws.access-key-id", "conf.py", 10, snippet=f'KEY = "{SECRET}"')
        b2 = finding("pattern.python.debug-enabled", "conf.py", 20)
        new = finding("pattern.python.eval-exec-non-literal", "conf.py", 30)

        bpath = root / "baseline.json"
        count = write_baseline(bpath, [b1, b2], root=root, tool_version="0.1.0")
        check(count == 2, f"write_baseline recorded {count}, expected 2")

        # the snippet held a credential; the baseline file must not contain it
        raw = bpath.read_bytes()
        check(SECRET.encode() not in raw, "a full credential leaked into the baseline file")
        check(b'"snippet"' not in raw, "the baseline recorded snippets, which can carry secrets")

        loaded = load_baseline(bpath)
        check(loaded.size == 2, f"loaded baseline has {loaded.size} entries, expected 2")

        res2 = apply_suppressions([b1, b2, new], root=root, baseline=loaded, inline=False)
        supp_rules = {f.rule_id for f in res2.suppressed}
        kept_rules = {f.rule_id for f in res2.kept}
        check(res2.by_baseline == 2, f"expected 2 baseline suppressions, got {res2.by_baseline}")
        check("secret.aws.access-key-id" in supp_rules, "baselined secret was not suppressed")
        check(
            "pattern.python.eval-exec-non-literal" in kept_rules,
            "a finding absent from the baseline was suppressed anyway",
        )
        check(not res2.stale_baseline, f"unexpected stale entries: {res2.stale_baseline}")

        # --- stale baseline reporting -------------------------------------------------
        res3 = apply_suppressions([new], root=root, baseline=loaded, inline=False)
        check(len(res3.stale_baseline) == 2, "both now-absent baseline entries should be stale")
        check(any("no longer occur" in n for n in res3.notes), "stale baseline was not reported")

        # --- fail-closed: a finding whose file cannot be read is KEPT -----------------
        ghost = finding("pattern.python.eval-exec-non-literal", "deleted.py", 1)
        res4 = apply_suppressions([ghost], root=root)
        check(len(res4.kept) == 1 and not res4.suppressed, "a finding was dropped when its file was unreadable")
        check(any("could not re-read" in n for n in res4.notes), "the unreadable file was not noted")

        # a finding with no line number is also kept, with a note
        noline = Finding(
            rule_id="pattern.generic.security-todo",
            title="t",
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            message="m",
            path="app.py",
            line=None,
            module="test",
        )
        res5 = apply_suppressions([noline], root=root)
        check(len(res5.kept) == 1, "a finding with no line number was dropped")
        check(any("no line number" in n for n in res5.notes), "the missing line number was not noted")

        # --- malformed baselines raise SuppressError ----------------------------------
        bad = root / "bad.json"
        bad.write_text("{ not json", encoding="utf-8")
        _raises(lambda: load_baseline(bad), "malformed JSON baseline did not raise")

        notreport = root / "notreport.json"
        notreport.write_text('{"hello": "world"}', encoding="utf-8")
        _raises(lambda: load_baseline(notreport), "a non-report JSON did not raise")

        _raises(lambda: load_baseline(root / "missing.json"), "a missing baseline did not raise")

    print()
    if failures:
        for problem in failures:
            print(f"FAIL: {problem}")
        return 1
    print(
        "PASS: inline (bare/targeted/prefix/above) and baseline suppression work, "
        "stale entries reported, fail-closed on unreadable files and missing lines, "
        "no credential in the baseline, malformed baselines rejected"
    )
    return 0


def _raises(thunk, message: str) -> None:
    try:
        thunk()
    except SuppressError:
        return
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{message} (raised {type(exc).__name__} instead of SuppressError)")
        return
    failures.append(message)


if __name__ == "__main__":
    raise SystemExit(main())
