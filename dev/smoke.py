#!/usr/bin/env python3
"""End-to-end check: walk a generated fixture and run the registered code modules.

This exists because the whole tool went a full session without executing, and the fastest
way to lose confidence again is to have no single command that proves the pipeline works.
It generates its own fixture in a temp dir, so it is safe to run anywhere and needs no
checked-in secrets.

What it asserts:
  * planted credentials are found
  * `.gitignore`d directories are pruned
  * no credential is ever printed in full
  * deliberate near-misses produce ZERO findings

Run:  python3 dev/smoke.py
Exit: 0 if every assertion holds, 1 otherwise.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from codereconwork.core.context import Config, ScanContext  # noqa: E402
from codereconwork.core.engine import run_code_modules, select_modules  # noqa: E402
from codereconwork.core.rules import load_all_builtin  # noqa: E402
from codereconwork.core.walker import collect  # noqa: E402
import codereconwork.modules  # noqa: E402,F401  - populates the module registry

# Credentials below are the vendors' own published example values, chosen deliberately so
# this file contains nothing live. The Slack one is assembled from two fragments: the
# joined value is what gets written to the fixture file and what the scanner therefore
# has to catch, but no contiguous `xoxb-...` literal exists in this source. Without that,
# GitHub's push protection blocks the repository over a token that was never real.
SLACK_TOKEN = "xoxb-123456789012-1234567890" + "123-AbCdEfGhIjKlMnOpQrStUvWx"

FIXTURE = {
    "config.py": f'''
import os

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
SLACK_BOT = "{SLACK_TOKEN}"
DATABASE_URL = "postgres://admin:s3cr3tP4ssw0rd99@db.internal:5432/prod"
''',
    # Every value here must be rejected by the heuristics. This is the half of the test
    # that decides whether anyone keeps the tool switched on.
    "near_misses.py": '''
import os

example_key = "not-a-real-secret"
api_key = os.environ.get("API_KEY")
placeholder = "your-api-key-here"
content_hash = "d41d8cd98f00b204e9800998ecf8427e"
request_id = "550e8400-e29b-41d4-a716-446655440000"
version = "v2.14.3"
avatar = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8"
''',
    ".gitignore": "ignored_dir/\n",
    "ignored_dir/leaked.py": 'TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"\n',
}

EXPECTED_RULES = {
    "secret.aws.access-key-id",
    "secret.github.personal-access-token",
    "secret.slack.token",
    "secret.db.connection-string",
}


def build_fixture(root: Path) -> None:
    for rel, body in FIXTURE.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body.lstrip("\n"), encoding="utf-8")


def main() -> int:
    failures: list[str] = []

    rules = load_all_builtin("")
    print(f"rule packs:  {len(rules)} rules loaded, all regexes compiled")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "app"
        root.mkdir()
        build_fixture(root)

        files, stats = collect(root, use_gitignore=True)
        scanned = sorted(f.relpath for f in files)
        print(f"walk:        {len(files)} files {scanned}")
        print(f"             {stats}")

        ctx = ScanContext(config=Config(root=root), root=root, files=files, walk_stats=stats)
        modules = select_modules("code", None)
        print(f"modules:     {[m.name for m in modules]}")
        results = run_code_modules(ctx, modules)

        found_rules: set[str] = set()
        by_path: dict[str, int] = {}
        for result in results:
            label = "ok" if result.ran else (result.skipped or result.error)
            print(f"\n--- {result.name} [{label}]")
            print(f"    stats: {result.stats}")
            if result.error:
                failures.append(f"module {result.name} errored: {result.error}")
            for f in result.findings:
                found_rules.add(f.rule_id)
                by_path[f.path or "?"] = by_path.get(f.path or "?", 0) + 1
                print(f"    [{f.severity.label:8} {f.confidence.label:9}] {f.rule_id}")
                print(f"        {f.location}  {f.snippet}")

        # 1. every planted credential was found
        missing = EXPECTED_RULES - found_rules
        if missing:
            failures.append(f"planted credentials not detected: {sorted(missing)}")

        # 2. the ignored directory was never scanned
        if any("ignored_dir" in p for p in by_path):
            failures.append("scanned a .gitignore'd path")

        # 3. no near-miss produced a finding
        if by_path.get("near_misses.py"):
            failures.append(f"{by_path['near_misses.py']} false positive(s) in near_misses.py")

        # 4. nothing was printed in full. Checked against the fixture's own literals.
        live_values = [
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
            "s3cr3tP4ssw0rd99",
        ]
        for result in results:
            for f in result.findings:
                blob = f"{f.snippet or ''} {f.message} {f.extra}"
                for value in live_values:
                    if value in blob:
                        failures.append(f"{f.rule_id} leaked a credential in full")

    print()
    if failures:
        for problem in failures:
            print(f"FAIL: {problem}")
        return 1
    print("PASS: credentials found, gitignore honoured, no leaks, no false positives")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
