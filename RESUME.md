# Code Recon — resume notes

**Status: THE VERTICAL SLICE IS RUNNABLE. `recon code .` works end to end over both
file-scan modules and all 157 rules + 26 AST checks, with terminal/JSON/SARIF output,
baselines, and inline suppression. Exit codes wired (0/1/2). Live phase is gated and
refuses correctly, but has no modules yet.**

**Paths changed 2026-08-23: the project is now `~/codereconwork` and the Python package
is `codereconwork` (was `~/code-recon` / `coderecon`). Imports are `from
codereconwork.core...`.**

Plan file: `~/.claude/plans/lovely-cooking-unicorn.md`

## Session 4 (2026-08-24) — the slice closed, and a stale note corrected

Session 3's RESUME.md was two sessions behind the disk. On resume, `patterns.py` (72 KB,
the full AST analyzer + regex driver) and all three report renderers already existed and
their smokes passed — only `patterns.py` and reports had been written by an earlier
session without RESUME being updated. What was genuinely missing was the CLI, suppression,
and the http/cache/module plumbing. This session:

- **Wrote `codereconwork/cli.py`** — subcommands `code`, `live`, `full`, `rules`,
  `baseline`. Exit codes 0 clean / 1 threshold breached / 2 tool error, with `2` winning
  over `1` when any module errored (an incomplete scan must not report "found things").
  Live phase refuses to start without `--authorized` + non-empty `--scope`, and rejects
  out-of-scope and reserved/metadata IPs *before any socket opens*; the gate lives in one
  function, `_require_live_authorization`. Verified: dirty repo → 1, clean → 0, `--no-fail`
  → 0, bad path / unknown module / bad rule pack → 2, all four live refusals → 2, the
  metadata IP is refused even when explicitly placed in `--scope`.
- **Wrote `codereconwork/core/suppress.py` + `dev/smoke_suppress.py`** — baseline diff
  (a baseline IS a Code Recon JSON report, read back through `report.json_out.parse` /
  `findings_of`, never re-parsed) and inline `# coderecon:ignore[rule.prefix]` honoured on
  the finding's line or the line above. Fails CLOSED: an unreadable file or a line-less
  finding is KEPT with a note, never dropped. `write_baseline` omits snippets on purpose so
  the committed baseline can never carry a credential (asserted). Malformed/missing
  baselines raise `SuppressError` → CLI exit 2. Token stays `coderecon:ignore` (see S3).
- **Fixed a stale assertion in `dev/smoke_report.py`** — it predated `patterns.py`, so it
  asserted `secrets` owned the fused-pass clock alone. Two FileScanModules now share it, so
  the correct label is `shared-file-pass`; `githist` is the exclusive-clock case. Corrected.
- **Fixed an invariant violation in `modules/secrets.py`** — secrets findings set no
  `detection`, so the report printed "detection method not declared" for every credential.
  The invariant requires regex findings be labelled heuristic; added `detection="regex"`
  (they are a text match + heuristic filters, not a parsed fact). Now all findings declare
  a method. Confidence still carries certainty; detection carries how we know.

Dogfooded `recon code .` on the project itself: 37 findings, all method-labelled, no
leaks, exit 1. The bulk are the scanner matching its own rule-definition JSON, RESUME.md,
and the deliberately-vulnerable `dev/smoke_patterns.py` fixture — expected, and the place
to tune it is the `fixtures/clean_app/` false-positive test (item 13), not the tool source.

**Verified green this session:** `dev/smoke.py`, `dev/smoke_patterns.py`,
`dev/smoke_report.py`, `dev/smoke_suppress.py` all PASS; `python3 -m compileall -q
codereconwork dev` clean; the full `baseline → clean rescan → new-bug-breaks-build` loop
works through the real CLI.

### Still in flight (delegated, may or may not have landed — CHECK DISK before assuming)
- `core/http.py` + `core/cache.py` + `dev/smoke_httpcache.py` (item 3) — a subagent was
  writing these. Earlier attempts died on API quota, not on code; nothing partial was left
  on disk. **Verify existence and run `dev/smoke_httpcache.py` before building `deps.py`.**
- `modules/artifacts.py` + `dev/smoke_artifacts.py` (item 5) — likewise delegated. If it
  landed, `modules/__init__.py` imports it and `select_modules("code", None)` returns three
  modules; re-run all smokes. If not, it is unstarted (no partial state).

## Session 2 (2026-08-21) — what was verified


Bash worked this session. The validation pass the old notes demanded is **done, and it
passed cleanly** — better than predicted:

- `python3 -VV` → 3.13.5. Code targets 3.9+.
- **157/157 rules load and every regex compiles.** Zero bad rules across all 6 packs.
- `py_compile` clean on every source file; `import codereconwork` works.
- The two bugs the old notes flagged were **already fixed** in the packs: the `\1`
  backreference is gone from `pattern.java.csrf-disabled`, and the undetectable k8s
  resource-limits rule was deleted outright (correct call — regex cannot see an absent
  sibling key).

**First real end-to-end run (walker + secrets) passed.** Against a planted fixture it
found the AWS key ID, GitHub PAT, Slack token, and Postgres connection string; masked
every value; pruned a `.gitignore`d directory; and rejected all four near-misses with
recorded reasons (`placeholder or template value` ×2, `entropy 4.14 below 4.50`,
`hex digest (32 chars)`). The heuristic filters in `core/heuristics.py` work as designed.

Reproduce it with the smoke script: `python3 dev/smoke.py`

### Changes made to disk this session

- **Added `codereconwork/modules/__init__.py`** — was the one missing package file. Imports
  `secrets` for its `@register` side effect, so importing the package populates the
  registry.
- **Added `Rule.unambiguous`** (`core/rules.py`, field + loader) — see the decision below.
  Currently 0 rules set it; it is opt-in per rule.
- **Added `dev/smoke.py`** — the end-to-end check described above.

### Decision made this session: regex confidence cap

The invariant "regex findings cap at MEDIUM" collided with pack rules that declare
`"confidence": "high"` for matches on literal, unmistakable API calls
(`pattern.java.csrf-disabled` matches `.csrf().disable()` — that is not a resemblance).

**Resolved: the driver caps regex findings at MEDIUM by default, and a rule may opt out
with `"unambiguous": true` to keep its declared confidence.** The cap stays the default
so the invariant holds; the opt-out avoids under-reporting literal API-call matches.
The report must still label detection method (`ast` vs `regex`) either way, and the
driver should report how many rules it capped.

## Session 3 (2026-08-23) — rename, plus two enablers for `patterns.py`

Re-verified before touching anything: 157 rules load, `py_compile` clean, `dev/smoke.py`
passes end to end. Nothing had rotted since session 2.

**Renamed** `~/code-recon` → `~/codereconwork` and the package `coderecon` →
`codereconwork`. Updated `pyproject.toml` (both console_scripts, `packages.find`,
`package-data`, pytest `filterwarnings`) and `dev/smoke.py`'s imports; every
intra-package import was already relative so none needed touching. Re-verified after:
imports, rule load, compile, and smoke all pass. Not a git repo, so this was a plain
`mv` with no history to preserve.

Two things deliberately **not** renamed, because they are user-facing naming decisions
rather than consequences of moving the package:
- the inline suppression token `# coderecon:ignore[rule-id]`, which is already baked into
  the remediation text of two shipped rules in `secrets.json`. Change it only if you also
  change those strings and `core/suppress.py` when it is written.
- (the planned OSV cache path *was* updated to `~/.cache/codereconwork/` — nothing exists
  at the old path, so there was nothing to migrate.)

**Added `Rule.match_in_comments`** (`core/rules.py`, field + loader) and set it on
`pattern.generic.security-todo`. The pattern driver is specified to drop regex matches
that land inside comments, which is a large false-positive source — but that one rule's
entire purpose is to read comments (`# TODO: fix this auth bypass`), so it needs an
opt-out or it would silently never fire again.

**Extracted `selector_matches(rule_id, selectors)`** from inside `filter_rules` to module
level in `core/rules.py`. The AST checks in `patterns.py` are code, not `Rule` data, but
must honour the same `--enable-rule` / `--disable-rule` prefix semantics; two separate
implementations of rule selection would drift.

`modules/patterns.py` is **still not written** — no work was lost, it had not been
started on disk.

## Next thing to do on resume

**First: check what the delegated work actually left on disk** (see "Still in flight"
above) — `core/http.py`, `core/cache.py`, `modules/artifacts.py` and their smokes. Run
every `dev/smoke_*.py` plus `python3 -m codereconwork.cli code .` before building on top.

Then the ordered remaining work is items 4–10 and 13–14 below. `modules/deps.py` (item 4)
is the natural next build once `core/http.py` and `core/cache.py` are confirmed present,
since it is the only thing blocked on them.

**`modules/patterns.py` is DONE** (written in an earlier session, verified this session).
Its settled design, kept here as a record of what was implemented:

- Python gets a real `ast` analyzer; the 5 non-secret packs (110 rules) get a regex
  driver. Two classes in one module: `PythonAstAnalyzer(ast.NodeVisitor)` and
  `PatternRegexScanner`, exposed through one `PatternsModule(FileScanModule)`.
- Resolve import aliases in a pre-pass (`import hashlib as h`, `from hashlib import md5`)
  so dotted-name matching works; then match on the canonical dotted name.
- One level of local-variable taint for the SQL check, scoped per function — and require
  the string to actually look like SQL, or it floods.
- Skip regex matches that fall inside comments (`#`, `//`, `--`, block-comment
  continuation lines). This is a large false-positive source.
- Where an AST finding and a `patterns_generic` regex finding hit the same
  `(path, line, cwe)`, keep the AST one.
- `ast.parse` failure must `ctx.note()` the reason, never silently skip.

## What exists

```
codereconwork/core/
  finding.py      Finding model. severity x confidence as SEPARATE axes.
                  fingerprint excludes line numbers so baselines survive refactors.
  walker.py       gitignore-aware walk (incl. nested .gitignore), binary + minified skip
  heuristics.py   shannon_entropy, is_placeholder, looks_like_known_format,
                  validate_aws_access_key, validate_jwt, jwt_details, is_test_context
  rules.py        JSON (+optional YAML) rule-pack loader. Fails LOUDLY on bad rules.
                  Rule.unambiguous opts a rule out of the regex confidence cap.
                  Rule.match_in_comments opts a rule out of the comment filter.
                  selector_matches() is the shared --enable/--disable prefix matcher.
  context.py      Config, ScopeGuard (scope enforcement + hard-deny reserved IPs), AuditLog
  engine.py       Module registry. Fuses FileScanModules into ONE pass per file.
  redact.py       mask(), fingerprint_secret(), safe_snippet()
  textutil.py     line_starts, line_of, line_span  (offset -> line/col)
  suppress.py     Baseline (a Code Recon JSON report) + inline `# coderecon:ignore`.
                  Applied centrally AFTER modules run; re-reads only files that produced
                  findings. FAILS CLOSED. write_baseline() never records a snippet.
                  *** VERIFIED WORKING ***
cli.py            code | live | full | rules | baseline. Exit 0/1/2, 2 beats 1.
                  Live gate (--authorized + --scope) enforced before any socket opens.
                  *** VERIFIED WORKING ***
codereconwork/modules/
  __init__.py     imports submodules for their @register side effect
  secrets.py      SecretScanner + SecretsModule. Reduces per credential-hash, so one
                  key matched by several rules yields ONE finding. Declares
                  detection="regex".  *** VERIFIED WORKING ***
  patterns.py     PythonAstAnalyzer (26 AST checks) + PatternRegexScanner over the 5
                  non-secret packs. AST supersedes regex on the same (path, line, cwe);
                  regex capped to MEDIUM unless rule.unambiguous; comment matches
                  dropped unless rule.match_in_comments.  *** VERIFIED WORKING ***
codereconwork/report/
  payload.py      ReportPayload — every count/verdict computed ONCE so the three
                  renderers cannot disagree. duration_scope distinguishes the fused
                  file pass from an exclusive clock.
  terminal.py     rich when available, plain ANSI fallback (both exercised by smoke)
  json_out.py     schema_version 1.0, byte-stable. parse()/findings_of() are what
                  suppress.py reads a baseline back through.
  sarif.py        SARIF 2.1.0: driver.rules[], security-severity, partialFingerprints,
                  invocations[].executionSuccessful.  *** ALL THREE VERIFIED ***
codereconwork/rules/          *** ALL 157 RULES LOAD, ALL REGEXES COMPILE ***
  secrets.json              47 rules
  patterns_javascript.json  25
  patterns_compiled.json    25   Go, Java/Kotlin, C#, C/C++
  patterns_scripting.json   26   PHP, Ruby, shell
  patterns_generic.json     15   language-agnostic
  patterns_iac.json         19   Terraform, k8s, compose, CloudFormation
dev/
  smoke.py           end-to-end walker+secrets check against a generated fixture
  smoke_patterns.py  AST + regex, cap, comment filter, supersession, parse failure
  smoke_report.py    all three renderers, leak checks, SARIF structure
  smoke_suppress.py  baseline + inline suppression, fail-closed, no-credential-in-baseline
```

`recon rules` reports **183 checks (157 regex + 26 AST)** — both families are listed
because both are selectable with `--enable-rule`/`--disable-rule`.

## Remaining, in build order

1. ~~**`__init__.py` x4 + `pyproject.toml`**~~ — **DONE.** All four `__init__.py` exist
   (root, core, modules, report) and `pyproject.toml` declares
   `console_scripts: recon = codereconwork.cli:main`. Imports work.
2. ~~**`modules/patterns.py`**~~ — **DONE and verified.** Design as implemented:
   Python `ast` analyzer + a regex driver for the 5 packs.
   AST checks: eval/exec on non-literals, pickle/marshal/dill loads,
   `yaml.load` w/o SafeLoader, `shell=True`, `os.system`, `verify=False`,
   md5/sha1, `tempfile.mktemp`, `random` for security values, `debug=True`,
   f-string/%-format SQL into `.execute()` (with one level of local variable taint),

   assert-for-validation, bare `except: pass`, `ssl._create_unverified_context`,
   `CERT_NONE`, `check_hostname=False`, `mark_safe`/`Markup` on non-literals,
   XXE via stdlib xml parsers, `tarfile`/`zipfile.extractall` (zip slip),
   paramiko `AutoAddPolicy`, `ALLOWED_HOSTS=['*']`, `jwt.decode(verify=False)`,
   `==` on hmac/signature (timing), ECB mode, secret-looking `os.environ.get` default.
   AST findings get HIGH/CONFIRMED confidence; regex findings MEDIUM or lower, and the
   report must say which is which.
3. **`core/http.py`** (urllib wrapper: timeout, retry, gzip, UA) and
   **`core/cache.py`** (sqlite TTL cache at `~/.cache/codereconwork/osv.sqlite`).
4. **`modules/deps.py`** — parse requirements*.txt, poetry.lock, Pipfile.lock,
   package-lock.json, yarn.lock, go.mod/sum, Gemfile.lock, composer.lock, Cargo.lock,
   pom.xml -> OSV.dev `POST /v1/querybatch` (<=1000 per call), cached. `--offline`
   must SKIP WITH A RECORDED REASON, never silently pass.
5. **`modules/artifacts.py`** — committed `.env`, `*.pem/.key/.p12`, `id_rsa`,
   `.npmrc`/`.pypirc`/`.netrc` with tokens, DB dumps, `.DS_Store`, editor backups,
   plus a `.gitignore`-coverage cross-check.
6. **`modules/githist.py`** — `git rev-list` + `git show` under `--history-depth`,
   diffs through the SAME SecretScanner. Prioritise secrets DELETED before HEAD:
   they look fixed, are still in the object store, and are rarely rotated.
   Must skip with a reason if `git` is missing or the dir is not a repo.
7. **`modules/cicd.py`** — GH Actions: `pull_request_target` + PR-head checkout,
   `${{ github.event.* }}` into `run:` (script injection), actions pinned to tag not
   SHA, secrets echoed, broad `permissions`, self-hosted runners on public repos.
   Dockerfile: root user, `:latest`, secrets in ARG/ENV, `curl | bash`.
8. **`modules/surface.py`** — routes from Flask/FastAPI/Django/Express/Gin ->
   `--surface-out routes.json`. Flag unauthenticated state-changing routes.
9. **`modules/live/`** — `dns.py` (bundled minimal stdlib resolver: A/AAAA/MX/NS/TXT/CAA
   over UDP + TCP AXFR; SPF/DMARC policy strength), `ct.py` (crt.sh subdomain discovery,
   passive — NOT wordlist brute force), `ports.py` (TCP connect only), `tls.py`
   (versions, weak ciphers, expiry, chain, SAN mismatch), `http.py` (HSTS, CSP quality
   not mere presence, cookie flags, banners, OPTIONS, dir listing, exposed `.git/HEAD`,
   `.env`, `/actuator`, `security.txt`).
   **Gating is not optional**: refuse without `--authorized`; require `--scope`; refuse
   out-of-scope and reserved/metadata IPs; log every host+port touched to the AuditLog.
10. ~~**`report/terminal.py`, `json_out.py`, `sarif.py`**~~ — **DONE and verified.**
    SARIF 2.1.0 carries `tool.driver.rules[]`, `properties.tags`, `security-severity`
    (GitHub buckets on that, not on `level`), `partialFingerprints`, and
    `invocations[].executionSuccessful`. Live findings use `logicalLocations`, not a
    fake artifactLocation.
11. ~~**`core/suppress.py`**~~ — **DONE and verified.** Baseline diff + inline
    `# coderecon:ignore[rule-id]`, applied centrally AFTER modules run, re-reading only
    the files that actually produced findings. Fails closed.
12. ~~**`cli.py`**~~ — **DONE and verified.** Subcommands `code`, `live`, `full`,
    `rules`, `baseline`. Exit codes 0 clean / 1 threshold breached / 2 tool error, and
    `2` outranks `1` when a module errored.
13. **Tests** — **the next big item after `deps`.** `fixtures/vulnerable_app/` one planted
    instance per rule family with a
    recall test; `fixtures/clean_app/` idiomatic safe code incl. deliberate near-misses
    (`example_key = "not-a-real-secret"`) asserting ZERO findings. The false-positive
    guard is the test that decides whether anyone keeps using this.
14. **`README.md`**

## Design invariants — do not quietly drop these

- **Zero required dependencies.** stdlib only. `rich` and `PyYAML` are optional upgrades
  with fallbacks. This is why DNS is a bundled resolver rather than dnspython.
- **Severity and confidence stay separate.** Collapsing them is what makes scanners
  get muted.
- **No credential ever printed in full** — terminal, JSON, SARIF, or log.
- **No network validation of found secrets by default.** Validating a key means sending
  it to a third party. `--verify-secrets` opt-in only, documented as such.
- **Regex rules are labeled heuristic.** Python gets real AST; other languages get
  regex and the output says so. Honesty over apparent capability.
- **Skips are always reported with a reason.** A scanner that silently does nothing is
  worse than one that errors, because it reports success.

## Est. remaining effort

**The vertical slice is done** (`patterns.py` + the 3 renderers + `cli.py` +
`suppress.py`). `recon code .` is genuinely runnable over both modules and all 157 rules
plus 26 AST checks, with terminal/JSON/SARIF output, baselines and inline suppression.
That was called a third of the remaining work.

What remains is roughly twice the slice again. Two parts dominate: `live/` (5 submodules,
and the hand-rolled stdlib DNS resolver is the biggest single file left in the project)
and the test fixtures. Budget extra for two things that cannot be estimated from reading:
`deps` and the `live` modules need real network calls to
validate, and the first run of the `fixtures/clean_app/` false-positive test will
probably surface a dozen small heuristic fixes.
