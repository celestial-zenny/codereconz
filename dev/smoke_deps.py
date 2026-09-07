#!/usr/bin/env python3
"""Smoke test for `modules/deps.py`: manifest parsing, CVSS, OSV batching, the module.

Same approach as `smoke_httpcache.py`: a real `ThreadingHTTPServer` on 127.0.0.1 stands
in for api.osv.dev, so the actual `HttpClient` code path runs - JSON encode, POST, decode,
retry - rather than a mock that would prove only that the mock works. **No real network is
touched and the user's real `~/.cache` is never written**: the module's `cache_path` is
pointed at a temporary directory.

The fixture tree plants one known-vulnerable version per ecosystem plus a set of
deliberate near-misses (unpinned ranges, VCS pins, workspace members, local `replace`
directives) that must be *counted as unresolved*, not silently dropped. That distinction
is the invariant this module lives or dies by: a dependency nobody checked must never look
like a dependency that came back clean.

    python3 dev/smoke_deps.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from codereconwork.core.context import Config, ScanContext  # noqa: E402
from codereconwork.core.engine import run_code_modules  # noqa: E402
from codereconwork.core.finding import Confidence, Severity  # noqa: E402
from codereconwork.core.http import HttpClient  # noqa: E402
from codereconwork.modules import deps  # noqa: E402
from codereconwork.modules.deps import (  # noqa: E402
    ECO_CRATES,
    ECO_GO,
    ECO_MAVEN,
    ECO_NPM,
    ECO_PACKAGIST,
    ECO_PYPI,
    ECO_RUBYGEMS,
    DepsModule,
    OsvClient,
    Package,
    classify,
    cvss31_base_score,
    discover_manifests,
    fixed_versions,
    parse_cargo_lock,
    parse_composer_lock,
    parse_gemfile_lock,
    parse_go_mod,
    parse_go_sum,
    parse_package_lock,
    parse_pipfile_lock,
    parse_pom_xml,
    parse_poetry_lock,
    parse_requirements,
    parse_yarn_lock,
    rate_severity,
    severity_from_score,
)

failures: List[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def raises(thunk: Callable[[], Any], expected: type, message: str) -> Optional[BaseException]:
    try:
        thunk()
    except expected as exc:  # type: ignore[misc]
        return exc
    except BaseException as exc:  # noqa: BLE001
        failures.append(f"{message} (raised {type(exc).__name__}: {exc})")
        return None
    failures.append(f"{message} (nothing raised)")
    return None


def coords(result: Any) -> Set[Tuple[str, str]]:
    return {(p.name, p.version) for p in result.packages}


# --------------------------------------------------------------------------------------
# The fake advisory database
# --------------------------------------------------------------------------------------

# ecosystem|name|version -> [vuln ids]. Only these are "vulnerable"; everything else in
# the fixture must come back clean, which is what proves the parsers are not inventing
# packages.
VULNERABLE: Dict[str, List[str]] = {
    f"{ECO_PYPI}|django|3.2.4": ["GHSA-pypi-django"],
    f"{ECO_PYPI}|urllib3|1.26.4": ["GHSA-pypi-urllib3", "GHSA-pypi-withdrawn"],
    f"{ECO_NPM}|lodash|4.17.15": ["GHSA-npm-lodash"],
    f"{ECO_NPM}|minimist|1.2.0": ["GHSA-npm-minimist"],
    f"{ECO_GO}|github.com/gogo/protobuf|1.3.1": ["GHSA-go-gogo"],
    f"{ECO_RUBYGEMS}|nokogiri|1.11.1": ["GHSA-gem-nokogiri"],
    f"{ECO_PACKAGIST}|monolog/monolog|1.25.2": ["GHSA-php-monolog"],
    f"{ECO_CRATES}|smallvec|1.6.0": ["GHSA-rust-smallvec"],
    f"{ECO_MAVEN}|org.apache.logging.log4j:log4j-core|2.14.1": ["GHSA-java-log4j"],
    f"{ECO_NPM}|no-detail-package|1.0.0": ["GHSA-detail-explodes"],
}

RECORDS: Dict[str, Dict[str, Any]] = {
    "GHSA-pypi-django": {
        "id": "GHSA-pypi-django",
        "summary": "Directory traversal in Django admin",
        "aliases": ["CVE-2021-99991"],
        # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8, CRITICAL
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ],
        "affected": [
            {
                "package": {"name": "django", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "3.2.0"}, {"fixed": "3.2.5"}],
                    }
                ],
            }
        ],
        "references": [
            {"type": "ADVISORY", "url": "https://example.invalid/django"},
            {"type": "WEB", "url": "https://example.invalid/ignored"},
        ],
        "database_specific": {"cwe_ids": ["CWE-22"], "severity": "LOW"},
    },
    "GHSA-pypi-urllib3": {
        "id": "GHSA-pypi-urllib3",
        "summary": "urllib3 leaks credentials on redirect",
        # No CVSS vector at all, so the publisher's own wording is the fallback.
        "database_specific": {"severity": "MODERATE"},
        "affected": [
            {
                "package": {"name": "urllib3", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.26.5"}]}],
            }
        ],
    },
    "GHSA-pypi-withdrawn": {
        "id": "GHSA-pypi-withdrawn",
        "summary": "Retracted, and must never be reported",
        "withdrawn": "2024-01-01T00:00:00Z",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ],
    },
    "GHSA-npm-lodash": {
        "id": "GHSA-npm-lodash",
        "summary": "Prototype pollution in lodash",
        # AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N -> 5.3, MEDIUM
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"}
        ],
        "affected": [
            {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"fixed": "4.17.19"}, {"fixed": "4.17.21"}],
                    }
                ],
            }
        ],
    },
    "GHSA-npm-minimist": {
        "id": "GHSA-npm-minimist",
        "summary": "Prototype pollution in minimist",
        # A v4-only vector: not approximated, reported as unrated.
        "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"}],
        "affected": [{"package": {"name": "minimist", "ecosystem": "npm"}}],
    },
    "GHSA-go-gogo": {
        "id": "GHSA-go-gogo",
        "summary": "Panic in gogo/protobuf unmarshal",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
        ],
        "affected": [
            {
                "package": {"name": "github.com/gogo/protobuf", "ecosystem": "Go"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.3.2"}]}],
            }
        ],
    },
    "GHSA-gem-nokogiri": {
        "id": "GHSA-gem-nokogiri",
        "summary": "XXE in nokogiri",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"}
        ],
        "affected": [
            {
                "package": {"name": "nokogiri", "ecosystem": "RubyGems"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.11.4"}]}],
            }
        ],
    },
    "GHSA-php-monolog": {
        "id": "GHSA-php-monolog",
        "summary": "Deserialisation issue in monolog",
        "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": "monolog/monolog", "ecosystem": "Packagist"}}],
    },
    "GHSA-rust-smallvec": {
        "id": "GHSA-rust-smallvec",
        "summary": "Buffer overflow in smallvec insert_many",
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}
        ],
        "affected": [
            {
                "package": {"name": "smallvec", "ecosystem": "crates.io"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.6.1"}]}],
            }
        ],
    },
    "GHSA-java-log4j": {
        "id": "GHSA-java-log4j",
        "summary": "Remote code execution via JNDI lookup",
        "aliases": ["CVE-2021-44228"],
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}
        ],
        "affected": [
            {
                "package": {
                    "name": "org.apache.logging.log4j:log4j-core",
                    "ecosystem": "Maven",
                },
                "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.15.0"}]}],
            }
        ],
    },
    # Deliberately absent from the detail endpoint: the enrichment fetch 500s, and the
    # finding must survive as an unrated one rather than vanishing.
}

STATE: Dict[str, Any] = {
    "batches": 0,
    "queries": 0,
    "detail_requests": 0,
    "batch_sizes": [],
    "fail_batches": 0,
    "seen_queries": [],
    "detail_ids": [],
}
STATE_LOCK = threading.Lock()


def reset_state() -> None:
    with STATE_LOCK:
        STATE.update(
            batches=0,
            queries=0,
            detail_requests=0,
            batch_sizes=[],
            fail_batches=0,
            seen_queries=[],
            detail_ids=[],
        )


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args: Any) -> None:  # keep the smoke output readable
        return

    def _send(self, status: int, payload: Any) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's naming
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        if self.path != "/v1/querybatch":
            self._send(404, {"error": "no such endpoint"})
            return

        with STATE_LOCK:
            if STATE["fail_batches"] > 0:
                STATE["fail_batches"] -= 1
                # 503 is retried by HttpClient, so answering it four times in a row is
                # what an unreachable OSV actually looks like to the module.
                self._send(503, {"error": "unavailable"})
                return

        payload = json.loads(raw.decode("utf-8"))
        queries = payload.get("queries") or []
        with STATE_LOCK:
            STATE["batches"] += 1
            STATE["queries"] += len(queries)
            STATE["batch_sizes"].append(len(queries))

        results = []
        for query in queries:
            package = query.get("package") or {}
            key = f"{package.get('ecosystem')}|{package.get('name')}|{query.get('version')}"
            with STATE_LOCK:
                STATE["seen_queries"].append(key)
            ids = VULNERABLE.get(key, [])
            results.append(
                {"vulns": [{"id": i, "modified": "2024-06-01T00:00:00Z"} for i in ids]}
                if ids
                else {}
            )
        self._send(200, {"results": results})

    def do_GET(self) -> None:  # noqa: N802
        prefix = "/v1/vulns/"
        if not self.path.startswith(prefix):
            self._send(404, {"error": "no such endpoint"})
            return
        vuln_id = self.path[len(prefix) :]
        with STATE_LOCK:
            STATE["detail_requests"] += 1
            STATE["detail_ids"].append(vuln_id)
        record = RECORDS.get(vuln_id)
        if record is None:
            self._send(500, {"error": "record exploded"})
            return
        self._send(200, record)


class Server:
    def __init__(self) -> None:
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.host, self.port = self.httpd.server_address[0], self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def url(self, path: str) -> str:
        return f"http://{self.host}:{self.port}{path}"

    def __enter__(self) -> "Server":
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


# --------------------------------------------------------------------------------------
# Fixture tree
# --------------------------------------------------------------------------------------

FIXTURE: Dict[str, str] = {
    # --- Python ---------------------------------------------------------------------
    "requirements.txt": """\
# planted vulnerable pin
Django==3.2.4
urllib3==1.26.4
requests>=2.25.0
flask
PyYAML==6.0 ; python_version >= "3.8"
some-pkg[extra]==1.4.2
-r other-requirements.txt
--index-url https://example.invalid/simple
-e ./local-package
pinned-by-url @ https://example.invalid/pkg.whl
wildcard==1.2.*
cryptography==41.0.1 \\
    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000000
""",
    "poetry.lock": """\
# This file is automatically @generated by Poetry.
[[package]]
name = "smoke-only"
version = "0.1.0"
description = "not vulnerable"
category = "main"
optional = false

[package.dependencies]
name = "should-not-be-read-as-a-package"

[[package]]
name = "pytest"
version = "7.4.0"
category = "dev"

[metadata]
lock-version = "2.0"
""",
    "svc/Pipfile.lock": """\
{
    "default": {
        "django": {"version": "==3.2.4"},
        "from-git": {"git": "https://example.invalid/x.git", "ref": "abc123"}
    },
    "develop": {
        "pytest": {"version": "==7.4.0"}
    }
}
""",
    # --- JavaScript -------------------------------------------------------------------
    "web/package-lock.json": """\
{
  "name": "web",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "web", "version": "1.0.0"},
    "node_modules/lodash": {"version": "4.17.15", "resolved": "https://x/lodash"},
    "node_modules/left-pad": {"version": "1.3.0"},
    "node_modules/@scope/pkg": {"version": "2.0.0"},
    "node_modules/jest": {"version": "29.0.0", "dev": true},
    "node_modules/no-detail-package": {"version": "1.0.0"},
    "node_modules/nested/node_modules/minimist": {"version": "1.2.0"},
    "node_modules/workspace-link": {"resolved": "packages/thing", "link": true},
    "packages/thing": {"name": "thing", "version": "0.0.1"}
  }
}
""",
    "legacy/package-lock.json": """\
{
  "name": "legacy",
  "lockfileVersion": 1,
  "dependencies": {
    "lodash": {"version": "4.17.15"},
    "tape": {
      "version": "5.0.0",
      "dev": true,
      "dependencies": {"minimist": {"version": "1.2.0"}}
    },
    "tarball-dep": {"version": "https://example.invalid/pkg.tgz"}
  }
}
""",
    "ui/yarn.lock": """\
# yarn lockfile v1


"@scope/thing@^2.0.0", "@scope/thing@^2.1.0":
  version "2.3.4"
  resolved "https://example.invalid/thing"

lodash@^4.17.4:
  version "4.17.15"
  resolved "https://example.invalid/lodash"

left-pad@~1.3.0:
  version "1.3.0"
""",
    "berry/yarn.lock": """\
__metadata:
  version: 6
  cacheKey: 8

"lodash@npm:^4.17.4":
  version: 4.17.15
  resolution: "lodash@npm:4.17.15"

"myapp@workspace:.":
  version: 0.0.0-use.local
  resolution: "myapp@workspace:."
""",
    # --- Go ---------------------------------------------------------------------------
    "gosvc/go.mod": """\
module example.invalid/gosvc

go 1.21

require (
	github.com/gogo/protobuf v1.3.1
	github.com/spf13/cobra v1.7.0 // indirect
)

require github.com/single/dep v1.0.0

replace github.com/spf13/cobra => github.com/forked/cobra v1.7.1

replace github.com/single/dep => ./vendored/dep
""",
    "gosvc/go.sum": """\
github.com/gogo/protobuf v1.3.1 h1:deadbeef=
github.com/gogo/protobuf v1.3.1/go.mod h1:deadbeef=
""",
    "gotool/go.sum": """\
github.com/gogo/protobuf v1.3.1 h1:deadbeef=
github.com/gogo/protobuf v1.3.1/go.mod h1:deadbeef=
github.com/other/thing v0.4.0 h1:cafe=
""",
    # --- Ruby / PHP / Rust ------------------------------------------------------------
    "rb/Gemfile.lock": """\
GIT
  remote: https://example.invalid/from-git.git
  revision: abc123
  specs:
    from-git (1.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.11.1)
      racc (~> 1.4)
    racc (1.6.0)
    sqlite3 (1.4.2-x86_64-linux)

PLATFORMS
  ruby

DEPENDENCIES
  nokogiri
""",
    "php/composer.lock": """\
{
  "packages": [
    {"name": "monolog/monolog", "version": "1.25.2"},
    {"name": "psr/log", "version": "v1.1.3"},
    {"name": "dev-branch/thing", "version": "dev-master"}
  ],
  "packages-dev": [
    {"name": "phpunit/phpunit", "version": "9.5.0"}
  ]
}
""",
    "rs/Cargo.lock": """\
version = 3

[[package]]
name = "my-app"
version = "0.1.0"
dependencies = [
 "smallvec",
]

[[package]]
name = "smallvec"
version = "1.6.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaa"
""",
    # --- Maven ------------------------------------------------------------------------
    "java/pom.xml": """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <properties>
    <log4j.version>2.14.1</log4j.version>
    <junit.version>4.13.2</junit.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.apache.logging.log4j</groupId>
        <artifactId>log4j-core</artifactId>
        <version>${log4j.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>${junit.version}</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>sibling</artifactId>
      <version>${project.version}</version>
    </dependency>
    <dependency>
      <groupId>org.inherited</groupId>
      <artifactId>from-parent</artifactId>
    </dependency>
    <dependency>
      <groupId>org.unresolved</groupId>
      <artifactId>mystery</artifactId>
      <version>${nowhere.defined}</version>
    </dependency>
    <dependency>
      <groupId>org.ranged</groupId>
      <artifactId>ranged</artifactId>
      <version>[1.0,2.0)</version>
    </dependency>
  </dependencies>
</project>
""",
    "evil/pom.xml": """\
<?xml version="1.0"?>
<!DOCTYPE project [<!ENTITY lol "haha">]>
<project><dependencies><dependency>
  <groupId>a</groupId><artifactId>b</artifactId><version>1.0</version>
</dependency></dependencies></project>
""",
    # --- decoys -----------------------------------------------------------------------
    "node_modules/should-be-pruned/package-lock.json": """\
{"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.15"}}}
""",
    "front/pnpm-lock.yaml": "lockfileVersion: '6.0'\n",
    "app.py": "import os\n",
}


def build_fixture(root: Path) -> None:
    for relpath, content in FIXTURE.items():
        target = root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def context_for(root: Path, **overrides: Any) -> ScanContext:
    config = Config(root=root, **overrides)
    return ScanContext(config=config, root=root)


# --------------------------------------------------------------------------------------
# Parser checks
# --------------------------------------------------------------------------------------


def check_parsers() -> None:
    # --- requirements.txt --------------------------------------------------------------
    result = parse_requirements(FIXTURE["requirements.txt"], "requirements.txt")
    found = coords(result)
    check(
        found
        == {
            ("Django", "3.2.4"),
            ("urllib3", "1.26.4"),
            ("PyYAML", "6.0"),
            ("some-pkg", "1.4.2"),
            ("cryptography", "41.0.1"),
        },
        f"requirements.txt parsed {sorted(found)}",
    )
    reasons = " ".join(result.skipped)
    check("not an exact pin" in reasons, "an unpinned range was not recorded as skipped")
    check("no version specified" in reasons, "a bare requirement was not recorded")
    check("wildcard" in reasons, "a wildcard pin was not recorded as skipped")
    check("editable" in reasons, "an editable install was not recorded")
    check("direct URL" in reasons, "a URL requirement was not recorded")
    check(
        sum(result.skipped.values()) == 5,
        f"requirements.txt recorded {sum(result.skipped.values())} skips, expected 5 "
        f"(range, bare name, editable, URL, wildcard): {result.skipped}",
    )
    check(bool(result.notes), "an -r include was not surfaced as a note")
    yaml_pkg = next(p for p in result.packages if p.name == "PyYAML")
    check("marker-gated" in yaml_pkg.tags, "an environment marker was not tagged")
    check(not yaml_pkg.from_lockfile, "a requirements.txt pin was treated as a lockfile")
    django = next(p for p in result.packages if p.name == "Django")
    check(django.line == 2, f"Django was reported on line {django.line}, expected 2")
    check(django.query_name == "django", "PEP 503 normalisation did not lowercase Django")

    # --- poetry.lock -------------------------------------------------------------------
    result = parse_poetry_lock(FIXTURE["poetry.lock"], "poetry.lock")
    check(
        coords(result) == {("smoke-only", "0.1.0"), ("pytest", "7.4.0")},
        f"poetry.lock parsed {sorted(coords(result))}",
    )
    check(
        next(p for p in result.packages if p.name == "pytest").dev,
        "poetry's dev category was not carried through",
    )
    check(
        all(p.from_lockfile for p in result.packages),
        "poetry.lock entries were not marked as lockfile-derived",
    )

    # --- Pipfile.lock ------------------------------------------------------------------
    result = parse_pipfile_lock(FIXTURE["svc/Pipfile.lock"], "svc/Pipfile.lock")
    check(
        coords(result) == {("django", "3.2.4"), ("pytest", "7.4.0")},
        f"Pipfile.lock parsed {sorted(coords(result))}",
    )
    check(bool(result.skipped), "a git-pinned Pipfile entry was dropped without a reason")

    # --- package-lock v3 ---------------------------------------------------------------
    result = parse_package_lock(FIXTURE["web/package-lock.json"], "web/package-lock.json")
    check(
        coords(result)
        == {
            ("lodash", "4.17.15"),
            ("left-pad", "1.3.0"),
            ("@scope/pkg", "2.0.0"),
            ("jest", "29.0.0"),
            ("no-detail-package", "1.0.0"),
            ("minimist", "1.2.0"),
        },
        f"package-lock v3 parsed {sorted(coords(result))}",
    )
    check(
        next(p for p in result.packages if p.name == "jest").dev,
        "a dev-only npm package was not flagged",
    )

    # --- package-lock v1 ---------------------------------------------------------------
    result = parse_package_lock(
        FIXTURE["legacy/package-lock.json"], "legacy/package-lock.json"
    )
    check(
        coords(result)
        == {("lodash", "4.17.15"), ("tape", "5.0.0"), ("minimist", "1.2.0")},
        f"package-lock v1 parsed {sorted(coords(result))}",
    )
    check(
        next(p for p in result.packages if p.name == "minimist").dev,
        "dev status did not inherit down the v1 dependency tree",
    )
    check(bool(result.skipped), "a tarball-versioned npm dependency was dropped silently")

    # --- yarn v1 and Berry -------------------------------------------------------------
    result = parse_yarn_lock(FIXTURE["ui/yarn.lock"], "ui/yarn.lock")
    check(
        coords(result)
        == {("@scope/thing", "2.3.4"), ("lodash", "4.17.15"), ("left-pad", "1.3.0")},
        f"yarn v1 parsed {sorted(coords(result))}",
    )
    result = parse_yarn_lock(FIXTURE["berry/yarn.lock"], "berry/yarn.lock")
    check(
        coords(result) == {("lodash", "4.17.15")},
        f"yarn berry parsed {sorted(coords(result))} (workspace/metadata must be skipped)",
    )

    # --- go.mod ------------------------------------------------------------------------
    result = parse_go_mod(FIXTURE["gosvc/go.mod"], "gosvc/go.mod")
    check(
        coords(result)
        == {
            ("github.com/gogo/protobuf", "1.3.1"),
            ("github.com/forked/cobra", "1.7.1"),
        },
        f"go.mod parsed {sorted(coords(result))}",
    )
    check(
        any("local path" in r for r in result.skipped),
        "a filesystem `replace` was dropped without a recorded reason",
    )
    cobra = next(p for p in result.packages if "cobra" in p.name)
    check("indirect" in cobra.tags, "an // indirect require lost its tag through replace")

    # --- go.sum ------------------------------------------------------------------------
    result = parse_go_sum(FIXTURE["gotool/go.sum"], "gotool/go.sum")
    check(
        coords(result)
        == {("github.com/gogo/protobuf", "1.3.1"), ("github.com/other/thing", "0.4.0")},
        f"go.sum parsed {sorted(coords(result))}",
    )
    check(
        all("from-go-sum" in p.tags for p in result.packages),
        "go.sum entries were not tagged as over-reporting",
    )

    # --- Gemfile.lock ------------------------------------------------------------------
    result = parse_gemfile_lock(FIXTURE["rb/Gemfile.lock"], "rb/Gemfile.lock")
    check(
        coords(result)
        == {("nokogiri", "1.11.1"), ("racc", "1.6.0"), ("sqlite3", "1.4.2")},
        f"Gemfile.lock parsed {sorted(coords(result))} (platform suffix must be stripped)",
    )
    check(bool(result.skipped), "a git-sourced gem section was skipped without a reason")

    # --- composer.lock ----------------------------------------------------------------
    result = parse_composer_lock(FIXTURE["php/composer.lock"], "php/composer.lock")
    check(
        coords(result)
        == {
            ("monolog/monolog", "1.25.2"),
            ("psr/log", "1.1.3"),
            ("phpunit/phpunit", "9.5.0"),
        },
        f"composer.lock parsed {sorted(coords(result))} (a leading v must be stripped)",
    )
    check(
        next(p for p in result.packages if "phpunit" in p.name).dev,
        "packages-dev was not marked as a dev dependency",
    )
    check(bool(result.skipped), "a dev-master composer pin was dropped without a reason")

    # --- Cargo.lock -------------------------------------------------------------------
    result = parse_cargo_lock(FIXTURE["rs/Cargo.lock"], "rs/Cargo.lock")
    check(
        coords(result) == {("smallvec", "1.6.0")},
        f"Cargo.lock parsed {sorted(coords(result))} (workspace members have no source)",
    )

    # --- pom.xml ----------------------------------------------------------------------
    result = parse_pom_xml(FIXTURE["java/pom.xml"], "java/pom.xml")
    check(
        coords(result)
        == {
            ("org.apache.logging.log4j:log4j-core", "2.14.1"),
            ("junit:junit", "4.13.2"),
            ("com.example:sibling", "1.0.0"),
        },
        f"pom.xml parsed {sorted(coords(result))}",
    )
    check(
        any("parent POM" in r for r in result.skipped),
        "a parent-inherited version was dropped without a reason",
    )
    check(
        any("unresolved property" in r for r in result.skipped),
        "an unresolvable ${property} was dropped without a reason",
    )
    check(
        any("range" in r for r in result.skipped),
        "a Maven version range was dropped without a reason",
    )
    junit = next(p for p in result.packages if p.name == "junit:junit")
    check(junit.dev, "a test-scoped Maven dependency was not marked dev")
    check("scope-test" in junit.tags, "the Maven scope was not tagged")
    check(not junit.from_lockfile, "a pom.xml pin was treated as a lockfile pin")

    # A POM carrying a DOCTYPE must be refused, not parsed.
    result = parse_pom_xml(FIXTURE["evil/pom.xml"], "evil/pom.xml")
    check(not result.packages, "a POM with an internal entity was parsed anyway")
    check(
        any("DOCTYPE" in n or "entities" in n for n in result.notes),
        "refusing a DOCTYPE POM was not explained",
    )

    # --- classification --------------------------------------------------------------
    check(classify("requirements-dev.txt") is not None, "requirements-dev.txt not matched")
    check(classify("REQUIREMENTS.TXT") is not None, "manifest matching is case-sensitive")
    check(classify("Cargo.toml") is None, "Cargo.toml was mistaken for a lockfile")
    check(classify("random.json") is None, "an unrelated JSON file was claimed")


def check_mini_toml() -> None:
    """The hand-rolled TOML reader must agree with `tomllib` on real lockfiles.

    On this interpreter `tomllib` exists, so the fallback would otherwise never execute -
    yet it is the *only* path on Python 3.9 and 3.10, which the project supports. Comparing
    the two on the same input is what keeps the zero-dependency path honest.
    """
    try:
        import tomllib
    except ImportError:  # pragma: no cover - then the fallback is all there is
        print("mini-toml:   tomllib unavailable, fallback is the only path (not compared)")
        return

    for name in ("poetry.lock", "rs/Cargo.lock"):
        text = FIXTURE[name]
        reference = [p for p in (tomllib.loads(text).get("package") or []) if isinstance(p, dict)]
        fallback = deps._mini_toml_packages(text)
        check(
            len(fallback) == len(reference),
            f"{name}: the mini TOML reader found {len(fallback)} package blocks, "
            f"tomllib found {len(reference)}",
        )
        for expected, actual in zip(reference, fallback):
            check(
                actual.get("name") == expected.get("name")
                and actual.get("version") == expected.get("version"),
                f"{name}: mini TOML read {actual.get('name')}@{actual.get('version')}, "
                f"tomllib read {expected.get('name')}@{expected.get('version')}",
            )
            # A `source` key decides whether a Cargo package is a workspace member.
            check(
                bool(actual.get("source")) == bool(expected.get("source")),
                f"{name}: mini TOML disagreed about {actual.get('name')}'s source key",
            )

    # And the parsers must produce identical output with the library forced out of reach.
    real_load = deps._tomllib_load
    deps._tomllib_load = lambda text: None
    try:
        for name, parser in (
            ("poetry.lock", parse_poetry_lock),
            ("rs/Cargo.lock", parse_cargo_lock),
        ):
            deps._tomllib_load = real_load
            with_library = coords(parser(FIXTURE[name], name))
            deps._tomllib_load = lambda text: None
            without = coords(parser(FIXTURE[name], name))
            check(
                with_library == without,
                f"{name} parsed differently without tomllib: "
                f"{sorted(with_library)} vs {sorted(without)}",
            )
    finally:
        deps._tomllib_load = real_load


# --------------------------------------------------------------------------------------
# CVSS checks
# --------------------------------------------------------------------------------------


def check_cvss() -> None:
    # Vectors and scores straight from the CVSS v3.1 specification's examples.
    cases = [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, Severity.CRITICAL),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 5.3, Severity.MEDIUM),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, Severity.CRITICAL),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, Severity.HIGH),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.0, Severity.CRITICAL),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, Severity.HIGH),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, Severity.LOW),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, Severity.CRITICAL),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, Severity.CRITICAL),
    ]
    for vector, expected, severity in cases:
        score = cvss31_base_score(vector)
        check(
            score is not None and abs(score - expected) < 0.001,
            f"{vector} scored {score}, expected {expected}",
        )
        if score is not None:
            check(
                severity_from_score(score) == severity,
                f"{vector} bucketed as {severity_from_score(score).label}, "
                f"expected {severity.label}",
            )

    # No impact at all is 0.0, not a floor of 0.1.
    check(
        cvss31_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0,
        "an all-None impact vector did not score 0.0",
    )
    check(cvss31_base_score("CVSS:4.0/AV:N/AC:L") is None, "a v4 vector was scored as v3")
    check(cvss31_base_score("nonsense") is None, "a malformed vector produced a score")
    check(cvss31_base_score("CVSS:3.1/AV:N/AC:L") is None, "an incomplete vector scored")

    # A computable vector beats the publisher's qualitative wording: the Django record
    # says LOW in database_specific and carries a 9.8 vector.
    severity, score, source = rate_severity(RECORDS["GHSA-pypi-django"])
    check(
        severity == Severity.CRITICAL and score == 9.8 and source == "cvss_v3",
        f"CVSS did not win over database_specific (got {severity.label}/{score}/{source})",
    )
    severity, score, source = rate_severity(RECORDS["GHSA-pypi-urllib3"])
    check(
        severity == Severity.MEDIUM and score is None and source == "database_specific",
        f"a MODERATE rating did not map to medium (got {severity.label}/{source})",
    )
    severity, _, source = rate_severity(RECORDS["GHSA-npm-minimist"])
    check(source == "unrated_cvss_v4", f"a v4-only record reported source {source}")
    severity, _, source = rate_severity({"id": "x"})
    check(source == "unrated", "a record with no severity was not reported as unrated")

    # Fix versions: nearest upgrade first, and versions behind us are not suggested.
    package = Package(ECO_NPM, "lodash", "4.17.15", "web/package-lock.json")
    check(
        fixed_versions(RECORDS["GHSA-npm-lodash"], package) == ["4.17.19", "4.17.21"],
        "fix versions were not ordered nearest-first",
    )
    ahead = Package(ECO_NPM, "lodash", "4.17.20", "web/package-lock.json")
    check(
        fixed_versions(RECORDS["GHSA-npm-lodash"], ahead) == ["4.17.21"],
        "a fix version behind the installed version was still suggested",
    )
    check(
        fixed_versions(RECORDS["GHSA-npm-minimist"], Package(ECO_NPM, "minimist", "1.2.0", "x"))
        == [],
        "a record with no fix event produced fix versions",
    )


# --------------------------------------------------------------------------------------
# Discovery checks
# --------------------------------------------------------------------------------------


def check_discovery(root: Path) -> None:
    ctx = context_for(root)
    manifests, notes, skipped = discover_manifests(ctx)
    kinds = sorted({m.kind for m in manifests})
    paths = sorted(m.relpath for m in manifests)

    check(
        kinds
        == [
            "Cargo.lock",
            "Gemfile.lock",
            "Pipfile.lock",
            "composer.lock",
            "go.mod",
            "go.sum",
            "package-lock.json",
            "poetry.lock",
            "pom.xml",
            "requirements.txt",
            "yarn.lock",
        ],
        f"discovery found kinds {kinds}",
    )
    check(
        not any("node_modules" in p for p in paths),
        f"node_modules was not pruned: {paths}",
    )
    check(
        "gosvc/go.sum" not in paths and "gotool/go.sum" in paths,
        f"go.sum precedence is wrong: {paths}",
    )
    check(
        any("go.sum" in n and "go.mod" in n for n in notes),
        "preferring go.mod over go.sum was not explained",
    )
    check(
        any("pnpm" in n for n in notes),
        "an unsupported pnpm lockfile was not reported",
    )
    check(
        any("pnpm" in r for r in skipped),
        "the unsupported pnpm lockfile was not counted as unresolved",
    )

    # An explicit --exclude-dir must be honoured.
    ctx = context_for(root, exclude_dirs=["web", "java"])
    manifests, _, _ = discover_manifests(ctx)
    paths = [m.relpath for m in manifests]
    check(
        not any(p.startswith(("web/", "java/")) for p in paths),
        f"--exclude-dir was ignored: {paths}",
    )

    # Pointing the scan at one manifest must scan exactly that file.
    single = context_for(root / "rs" / "Cargo.lock")
    manifests, _, _ = discover_manifests(single)
    check(
        len(manifests) == 1 and manifests[0].kind == "Cargo.lock",
        f"a single-file root produced {len(manifests)} manifest(s)",
    )

    # An empty tree must say so rather than look clean.
    empty = context_for(root / "gosvc" / "vendored")
    manifests, _, _ = discover_manifests(empty)
    check(not manifests, "discovery invented manifests in a directory with none")


# --------------------------------------------------------------------------------------
# OSV client checks
# --------------------------------------------------------------------------------------


def check_osv_client(server: Server, tmp: Path) -> None:
    from codereconwork.core.cache import TtlCache

    reset_state()
    client_http = HttpClient(Config(), timeout=10.0)
    cache_file = tmp / "client.sqlite"
    packages = TtlCache(cache_file, namespace="osv")
    vulns = TtlCache(cache_file, namespace="osv-vuln")
    client = OsvClient(
        client_http,
        package_cache=packages,
        vuln_cache=vulns,
        querybatch_url=server.url("/v1/querybatch"),
        vuln_url=server.url("/v1/vulns/"),
        timeout=10.0,
    )

    keys = [
        f"{ECO_PYPI}|django|3.2.4",
        f"{ECO_PYPI}|urllib3|1.26.4",
        f"{ECO_PYPI}|not-vulnerable|1.0.0",
    ]
    answers = client.lookup(keys)
    check(len(answers) == 3, f"lookup answered {len(answers)} of 3 keys")
    check(
        [v["id"] for v in answers[keys[0]]] == ["GHSA-pypi-django"],
        "django's advisory did not come back",
    )
    check(answers[keys[2]] == [], "a clean package did not answer with an empty list")
    check(STATE["batches"] == 1, f"lookup made {STATE['batches']} batch calls, expected 1")
    check(client.counters["cache_misses"] == 3, "the first lookup was not all misses")

    # A clean package caches as an empty list, which must read back as a hit, not a miss.
    reset_state()
    again = client.lookup(keys)
    check(again == answers, "the cached second lookup disagreed with the first")
    check(STATE["batches"] == 0, f"a fully cached lookup still made {STATE['batches']} calls")
    check(client.counters["cache_hits"] == 3, "an empty-list answer was not a cache hit")

    # Positional mapping under a batch split: 5 keys, batch size 2 -> 3 calls, right answers.
    reset_state()
    split_cache = TtlCache(tmp / "split.sqlite", namespace="osv")
    split = OsvClient(
        client_http,
        package_cache=split_cache,
        querybatch_url=server.url("/v1/querybatch"),
        timeout=10.0,
    )
    split.batch_size = 2
    split_keys = [
        f"{ECO_PYPI}|clean-a|1.0.0",
        f"{ECO_NPM}|lodash|4.17.15",
        f"{ECO_PYPI}|clean-b|1.0.0",
        f"{ECO_MAVEN}|org.apache.logging.log4j:log4j-core|2.14.1",
        f"{ECO_PYPI}|clean-c|1.0.0",
    ]
    split_answers = split.lookup(split_keys)
    check(STATE["batch_sizes"] == [2, 2, 1], f"batch sizes were {STATE['batch_sizes']}")
    check(
        [v["id"] for v in split_answers[split_keys[1]]] == ["GHSA-npm-lodash"],
        "a batched result was mapped to the wrong package",
    )
    check(
        [v["id"] for v in split_answers[split_keys[3]]] == ["GHSA-java-log4j"],
        "the last batch's result was mapped to the wrong package",
    )
    check(
        all(split_answers[k] == [] for k in (split_keys[0], split_keys[2], split_keys[4])),
        "a clean package picked up somebody else's advisory",
    )
    split_cache.close()

    # Detail fetch, then the same fetch served from cache.
    reset_state()
    records = client.details(
        [{"id": "GHSA-pypi-django", "modified": "2024-06-01T00:00:00Z"}]
    )
    check(
        records.get("GHSA-pypi-django", {}).get("summary", "").startswith("Directory"),
        "the advisory record did not come back",
    )
    check(STATE["detail_requests"] == 1, "the detail fetch did not happen")
    reset_state()
    client.details([{"id": "GHSA-pypi-django", "modified": "2024-06-01T00:00:00Z"}])
    check(STATE["detail_requests"] == 0, "a cached advisory record was re-fetched")

    # A record whose `modified` changed must not be served from the old cache entry.
    reset_state()
    client.details([{"id": "GHSA-pypi-django", "modified": "2025-01-01T00:00:00Z"}])
    check(
        STATE["detail_requests"] == 1,
        "an advisory edited upstream was still served from the stale cache key",
    )

    # A failing detail endpoint degrades, and is counted, but does not raise.
    reset_state()
    missing = client.details([{"id": "GHSA-detail-explodes", "modified": "x"}])
    check(missing == {}, "a 500 from the detail endpoint produced a record anyway")
    check(client.counters["detail_failures"] == 1, "a detail failure was not counted")

    # Batch failure: stale cache answers what it can, and the failure is recorded.
    reset_state()
    with STATE_LOCK:
        STATE["fail_batches"] = 10
    stale_cache = TtlCache(tmp / "stale.sqlite", namespace="osv", default_ttl=-1.0)
    stale_cache.set(f"{ECO_NPM}|lodash|4.17.15", [{"id": "GHSA-npm-lodash", "modified": "z"}])
    failing = OsvClient(
        HttpClient(Config(), timeout=5.0, retries=0),
        package_cache=stale_cache,
        querybatch_url=server.url("/v1/querybatch"),
        timeout=5.0,
    )
    out = failing.lookup([f"{ECO_NPM}|lodash|4.17.15", f"{ECO_PYPI}|nothing|1.0.0"])
    check(failing.counters["batch_failures"] == 1, "an unreachable OSV was not counted")
    check(
        failing.counters["stale_answers"] == 1,
        "expired cache data was not used as a fallback",
    )
    check(
        [v["id"] for v in out.get(f"{ECO_NPM}|lodash|4.17.15", [])] == ["GHSA-npm-lodash"],
        "the stale fallback did not return the cached advisory",
    )
    check(
        f"{ECO_PYPI}|nothing|1.0.0" not in out,
        "a package with no cache entry was reported as answered",
    )
    stale_cache.close()
    with STATE_LOCK:
        STATE["fail_batches"] = 0

    # A truncated `results` array must be rejected outright: a positional mapping that is
    # off by one would attribute advisories to the wrong packages.
    reset_state()

    class ShortHandler(Handler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            self._send(200, {"results": [{}]})

    short_server = ThreadingHTTPServer(("127.0.0.1", 0), ShortHandler)
    thread = threading.Thread(target=short_server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = short_server.server_address[0], short_server.server_address[1]
        short = OsvClient(
            HttpClient(Config(), timeout=5.0, retries=0),
            querybatch_url=f"http://{host}:{port}/v1/querybatch",
            timeout=5.0,
        )
        result = short.lookup([f"{ECO_PYPI}|a|1.0", f"{ECO_PYPI}|b|1.0"])
        check(result == {}, "a mismatched results array was accepted")
        check(
            short.counters["batch_failures"] == 1,
            "a mismatched results array was not counted as a failure",
        )
    finally:
        short_server.shutdown()
        short_server.server_close()
        thread.join(timeout=5)

    packages.close()
    vulns.close()


# --------------------------------------------------------------------------------------
# End-to-end module checks
# --------------------------------------------------------------------------------------


def check_module(server: Server, root: Path, tmp: Path) -> None:
    reset_state()
    module = DepsModule()
    module.cache_path = tmp / "module.sqlite"

    original = (deps.OSV_QUERYBATCH_URL, deps.OSV_VULN_URL)
    deps.OSV_QUERYBATCH_URL = server.url("/v1/querybatch")
    deps.OSV_VULN_URL = server.url("/v1/vulns/")
    try:
        ctx = context_for(root, timeout=10.0)
        findings = module.run(ctx)
        stats = module.stats()

        ids = sorted(f.extra["vulnerability_id"] for f in findings)
        check(
            ids
            == [
                "GHSA-detail-explodes",
                "GHSA-gem-nokogiri",
                "GHSA-go-gogo",
                "GHSA-java-log4j",
                "GHSA-npm-lodash",
                "GHSA-npm-minimist",
                "GHSA-php-monolog",
                "GHSA-pypi-django",
                "GHSA-pypi-urllib3",
                "GHSA-rust-smallvec",
            ],
            f"the module reported {ids}",
        )
        check(
            "GHSA-pypi-withdrawn" not in ids,
            "a withdrawn advisory was reported as a finding",
        )
        check(stats.get("withdrawn_skipped") == 1, "the withdrawn record was not counted")

        by_vuln = {f.extra["vulnerability_id"]: f for f in findings}

        # Severity comes from the CVSS vector, not from the record's own wording.
        django = by_vuln["GHSA-pypi-django"]
        check(django.severity == Severity.CRITICAL, "the 9.8 advisory was not critical")
        check(django.extra.get("cvss_score") == 9.8, "the CVSS score was not carried")
        check(django.cwe == "CWE-22", "the advisory's CWE was not used")
        check("CVE-2021-99991" in django.message, "the CVE alias was not surfaced")
        check("3.2.5" in (django.remediation or ""), "the fix version is missing")
        check(
            django.extra.get("detection") == "dependency-lookup",
            "a deps finding did not declare its detection method",
        )
        check(
            "https://osv.dev/vulnerability/GHSA-pypi-django" in django.references,
            "the canonical OSV link is missing",
        )
        check(
            "https://example.invalid/ignored" not in django.references,
            "a non-advisory reference was included",
        )

        lodash = by_vuln["GHSA-npm-lodash"]
        check(lodash.severity == Severity.MEDIUM, "the 5.3 advisory was not medium")
        check(
            lodash.confidence == Confidence.CONFIRMED,
            "a lockfile-derived finding was not CONFIRMED",
        )
        # lodash@4.17.15 appears in four separate manifests; one finding, all locations.
        check(
            len(lodash.extra.get("also_declared_in", [])) == 3,
            f"lodash's other manifests were not recorded: {lodash.extra.get('also_declared_in')}",
        )

        log4j = by_vuln["GHSA-java-log4j"]
        check(log4j.severity == Severity.CRITICAL, "log4shell was not critical")
        check(
            log4j.confidence == Confidence.HIGH,
            "a pom.xml finding was CONFIRMED rather than HIGH",
        )
        check(log4j.line is not None, "the pom.xml finding has no line number")

        minimist = by_vuln["GHSA-npm-minimist"]
        check(
            "severity-unrated" in minimist.tags and minimist.severity == Severity.MEDIUM,
            "a v4-only advisory was not tagged as unrated",
        )
        check("no-fix-available" in minimist.tags, "an advisory with no fix was not tagged")

        exploded = by_vuln["GHSA-detail-explodes"]
        check(
            "severity-unrated" in exploded.tags,
            "a finding whose details failed to fetch was not marked unrated",
        )
        check(
            any("could not be fetched in full" in n for n in ctx.notes),
            "the failed detail fetch was not explained in the notes",
        )

        nokogiri = by_vuln["GHSA-gem-nokogiri"]
        check(
            "ecosystem-rubygems" in nokogiri.tags,
            f"the ecosystem tag is wrong: {nokogiri.tags}",
        )
        check(
            nokogiri.rule_id == "dep.rubygems.GHSA-gem-nokogiri",
            f"the rule id is {nokogiri.rule_id}",
        )

        # No credential-shaped content, and no finding without a location.
        for finding in findings:
            check(bool(finding.path), f"{finding.rule_id} has no path")
            check(bool(finding.remediation), f"{finding.rule_id} has no remediation")
            check(
                "detection" in finding.extra,
                f"{finding.rule_id} did not declare a detection method",
            )

        # Fingerprints must be stable across runs and unique per (package, advisory).
        prints = [f.fingerprint for f in findings]
        check(len(set(prints)) == len(prints), "two deps findings share a fingerprint")

        # Completeness reporting.
        check(stats["manifests"] >= 14, f"only {stats['manifests']} manifests were parsed")
        check(stats["packages_queried"] > 20, f"only {stats['packages_queried']} queried")
        check(stats.get("unresolved", 0) >= 10, f"only {stats.get('unresolved')} unresolved")
        check(
            any("could not be resolved to an exact version" in n for n in ctx.notes),
            "unresolvable dependencies were not reported in the notes",
        )
        check(
            any("api.osv.dev" in n for n in ctx.notes),
            "sending package names to OSV was not disclosed in the notes",
        )
        check(
            any("DOCTYPE" in n for n in ctx.notes),
            "the refused DOCTYPE pom was not reported in the notes",
        )
        check(
            any("pnpm" in n and "NOT checked" in n for n in ctx.notes),
            "the unparseable pnpm lockfile was not reported as unchecked",
        )

        # One query per distinct package, never one per occurrence.
        with STATE_LOCK:
            seen = list(STATE["seen_queries"])
        check(
            len(seen) == len(set(seen)),
            f"{len(seen) - len(set(seen))} duplicate OSV queries were sent",
        )

        # A second run must answer entirely from cache.
        reset_state()
        ctx2 = context_for(root, timeout=10.0)
        again = module.run(ctx2)
        stats2 = module.stats()
        check(
            sorted(f.fingerprint for f in again) == sorted(f.fingerprint for f in findings),
            "the cached second run produced different findings",
        )
        check(
            STATE["batches"] == 0,
            f"the cached run still made {STATE['batches']} OSV batch call(s)",
        )
        # One logical detail fetch, not zero: a fetch that failed is deliberately not
        # cached, so GHSA-detail-explodes is retried while the other ten are cache hits.
        # The server sees more than one request for it because HttpClient retries a 500.
        check(
            stats2.get("detail_fetches") == 1,
            f"the cached run made {stats2.get('detail_fetches')} detail fetch(es), "
            f"expected 1 (the uncacheable failure)",
        )
        check(
            STATE["detail_requests"] >= 1
            and all(i == "GHSA-detail-explodes" for i in STATE["detail_ids"]),
            f"the cached run re-fetched {sorted(set(STATE['detail_ids']))}",
        )

        # An unreachable OSV must fail the scan, not report a clean one.
        reset_state()
        with STATE_LOCK:
            STATE["fail_batches"] = 40
        empty_cache_module = DepsModule()
        empty_cache_module.cache_path = tmp / "failing.sqlite"
        ctx3 = context_for(root, timeout=2.0)
        error = raises(
            lambda: empty_cache_module.run(ctx3),
            RuntimeError,
            "an unreachable OSV did not fail the scan",
        )
        if error is not None:
            check(
                "unreachable" in str(error) and "package(s) were checked" in str(error),
                f"the failure message is unhelpful: {error}",
            )
            # The fixture's packages fit in one batch, and nothing was cached in this
            # fresh file, so the honest report is "1 of 1 batch, 0 packages checked".
            check(
                "1 of 1 batch(es)" in str(error),
                f"the batch count double-counts the failure: {error}",
            )
            check(
                "only 0 of" in str(error),
                f"packages were reported as checked despite the failure: {error}",
            )
        with STATE_LOCK:
            STATE["fail_batches"] = 0

        # --offline must skip with a reason, and must not reach the network.
        reset_state()
        offline_ctx = context_for(root, offline=True)
        results = run_code_modules(offline_ctx, [DepsModule()])
        check(len(results) == 1 and results[0].skipped, "--offline did not skip deps")
        if results[0].skipped:
            check("offline" in results[0].skipped, f"skip reason: {results[0].skipped}")
        check(
            any("deps" in n and "offline" in n for n in offline_ctx.notes),
            "the offline skip was not recorded in the notes",
        )
        check(STATE["batches"] == 0, "an --offline scan still called OSV")

        # A tree with no manifests must say so rather than silently report nothing.
        with tempfile.TemporaryDirectory() as bare:
            bare_ctx = context_for(Path(bare), timeout=5.0)
            bare_module = DepsModule()
            bare_module.cache_path = tmp / "bare.sqlite"
            check(bare_module.run(bare_ctx) == [], "an empty tree produced findings")
            check(
                any("no dependency manifests found" in n for n in bare_ctx.notes),
                "an empty tree did not explain that nothing was checked",
            )

        # And the module must be reachable through the registry the CLI uses.
        from codereconwork.core.engine import select_modules

        names = [m.name for m in select_modules("code", ["deps"])]
        check(names == ["deps"], f"--module deps resolved to {names}")

        check_renderers(findings, ctx, root)
    finally:
        deps.OSV_QUERYBATCH_URL, deps.OSV_VULN_URL = original


def check_renderers(findings: List[Any], ctx: ScanContext, root: Path) -> None:
    """Push deps findings through all three renderers.

    Worth doing here rather than trusting `smoke_report.py`: these are the project's first
    findings with no snippet, no column, a data-driven `references` list and a `line` that
    can legitimately be None. Each of those is a shape a renderer can trip over.
    """
    import io

    from codereconwork.core.engine import ModuleResult
    from codereconwork.report import ReportPayload, json_out, sarif, terminal
    from codereconwork.report.payload import safe_extra

    # The extra-key allowlist in payload.py fails closed, so a key this module invents is
    # dropped from every report unless it is declared there. Nothing warns you: the
    # finding still renders, just without the fix version or the advisory id. Asserting
    # the two agree is the only thing that catches the drift.
    for finding in findings:
        omitted = safe_extra(finding.extra).get("extra_omitted")
        check(
            not omitted,
            f"{finding.rule_id}: extra key(s) {omitted} are not in payload.SAFE_EXTRA_KEYS, "
            f"so they are silently dropped from every report",
        )

    payload = ReportPayload.from_scan(
        module_results=[ModuleResult(name="deps", findings=findings, duration=0.5)],
        config=ctx.config,
        command="code",
        findings=findings,
        root=root,
        walk_stats={},
        notes=ctx.notes,
        started_at=1.0,
        finished_at=1.5,
    )

    buffer = io.StringIO()
    terminal.render(payload, stream=buffer)
    text = buffer.getvalue()
    check("GHSA-java-log4j" in text, "the terminal report omitted a dependency finding")
    check(
        "dependency-lookup" in text or "dependency" in text,
        "the terminal report did not mention how deps findings are detected",
    )

    data = json_out.parse(json_out.render(payload))
    rendered = json_out.findings_of(data)
    check(
        len(rendered) == len(findings),
        f"JSON carried {len(rendered)} of {len(findings)} deps findings",
    )
    log4j = next(f for f in rendered if "log4j" in json.dumps(f))
    check(
        log4j.get("extra", {}).get("installed_version") == "2.14.1",
        "the installed version did not survive JSON rendering",
    )
    check(
        log4j.get("extra", {}).get("vulnerability_id") == "GHSA-java-log4j",
        "the advisory id did not survive JSON rendering",
    )
    check(
        log4j.get("extra", {}).get("fixed_versions") == ["2.15.0"],
        f"the fix version did not survive JSON rendering: {log4j.get('extra')}",
    )
    check(
        log4j.get("extra", {}).get("cvss_score") == 10.0,
        "the CVSS score did not survive JSON rendering",
    )
    check(
        json_out.render(payload) == json_out.render(payload),
        "two JSON renders of a deps report differ",
    )

    report = json.loads(sarif.render(payload))
    rules = report["runs"][0]["tool"]["driver"]["rules"]
    results = report["runs"][0]["results"]
    check(
        len(rules) == len({f.rule_id for f in findings}),
        f"SARIF declared {len(rules)} rule descriptors for "
        f"{len({f.rule_id for f in findings})} distinct rules",
    )
    check(len(results) == len(findings), "SARIF dropped a deps finding")
    ids = {r["id"] for r in rules}
    check(
        "dep.maven.GHSA-java-log4j" in ids,
        f"SARIF rule ids are wrong: {sorted(ids)[:3]}",
    )
    critical = next(
        r for r in rules if r["id"] == "dep.maven.GHSA-java-log4j"
    )
    check(
        critical["properties"]["security-severity"] == "9.5",
        "SARIF did not carry the critical security-severity for a deps rule",
    )
    check(
        all(r.get("partialFingerprints") for r in results),
        "a SARIF deps result has no partialFingerprints",
    )


# --------------------------------------------------------------------------------------


def main() -> int:
    started = time.monotonic()
    check_parsers()
    check_mini_toml()
    check_cvss()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        root = tmp / "fixture"
        root.mkdir()
        build_fixture(root)
        (root / "gosvc" / "vendored").mkdir(parents=True, exist_ok=True)

        check_discovery(root)
        with Server() as server:
            print(
                f"server:      http://{server.host}:{server.port} "
                f"(loopback only, no real network)"
            )
            check_osv_client(server, tmp)
            check_module(server, root, tmp)

    print(f"runtime:     {time.monotonic() - started:.2f}s")
    print()
    if failures:
        for problem in failures:
            print(f"FAIL: {problem}")
        return 1
    print(
        "PASS: 11 manifest formats parsed with every unresolvable declaration counted, "
        "the mini TOML reader agrees with tomllib, CVSS v3.1 base scores match the spec, "
        "OSV batching keeps its positional mapping across splits, per-package cache serves "
        "empty answers as hits, withdrawn advisories dropped, detail failures degrade "
        "without vanishing, unreachable OSV fails the scan, --offline skips with a reason, "
        "all three renderers handle snippet-less findings"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
