# Code Recon

Security reconnaissance for codebases. Finds hardcoded credentials, dangerous code
patterns, and known-vulnerable dependencies, then reports them to your terminal, to
JSON, or to SARIF for GitHub code scanning.

Runs on the Python standard library alone. No install of anything else required.

> **Status: alpha, and honest about it.** The codebase scanner works end to end and is
> what you should try. The live-probing phase is gated, refuses to run, and has no
> modules behind it yet. See [What works today](#what-works-today) before you judge it.

```
$ recon code .

  high      high       pattern.python.os-system   patterns · via ast (parsed code)
    Command executed through a shell
    deploy.py:14:5
      os.system("rsync -a " + target)
    fix: Use `subprocess.run([...])` with an argument list and no shell.

  high      high       secret.aws.access-key-id   secrets · via regex (heuristic)
    AWS access key ID
    config/settings.py:8:22
      AWS_KEY = "AKIA...LE (20 chars)"
    fix: Deactivate the key in IAM immediately, then remove it from the file and from
    git history. Use IAM roles or a credential provider chain instead of static keys.
```

## Install

Python 3.9 or newer.

```bash
git clone https://github.com/celestial-zenny/codereconz.git
cd codereconz
pip install .
```

Or run it straight from a clone without installing:

```bash
python3 -m codereconwork.cli code /path/to/project
```

Two optional extras, both with working fallbacks:

```bash
pip install '.[pretty]'   # rich tables instead of the plain ANSI renderer
pip install '.[yaml]'     # load YAML-authored custom rule packs (bundled packs are JSON)
```

## Usage

```bash
recon code .                        # scan the current directory
recon code . --json report.json     # machine-readable report
recon code . --sarif recon.sarif    # upload to GitHub code scanning
recon code . -v                     # show every finding, not just a summary
recon rules --search sql            # what does it actually look for?
```

Exit codes are built for CI:

| Code | Meaning |
|------|---------|
| `0`  | clean, or nothing at or above `--fail-on` |
| `1`  | a finding at or above `--fail-on` survived (default: `high`) |
| `2`  | the tool itself errored, or a module failed |

`2` outranks `1` on purpose. An incomplete scan must never report "found things" as if
the scan were whole.

### Adopting it on a codebase that already has findings

Record what's there today, then fail the build only on what's new:

```bash
recon baseline -o recon-baseline.json .
recon code . --baseline recon-baseline.json
```

Baselines omit code snippets by design, so a committed baseline can never carry a
credential.

To silence one finding in place, on its line or the line above:

```python
password = get_from_vault()  # coderecon:ignore[secret.generic.password]
```

Suppression fails closed. If a file can't be re-read, or a finding has no line, it is
**kept** with a note rather than dropped.

### CI example

```yaml
- run: pip install git+https://github.com/celestial-zenny/codereconz.git
- run: recon code . --sarif recon.sarif --baseline recon-baseline.json
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: recon.sarif
```

## What works today

**Working, and dogfooded on this repo:**

- **`secrets`** — hardcoded credentials, API tokens, private key material.
- **`patterns`** — 183 checks total: **26 real AST checks** for Python and **157 regex
  rules** across generic, JavaScript, IaC, scripting, and compiled-language packs.
- **`deps`** — dependency manifests resolved against [OSV.dev](https://osv.dev)
  advisories, with an on-disk cache. `--offline` skips it *with a recorded reason*
  rather than silently passing.
- **Reporting** — terminal, JSON, and SARIF 2.1.0 (with `security-severity`,
  `partialFingerprints`, and `executionSuccessful`, which is what GitHub actually reads).
- **Baselines and inline suppression.**

**Not built yet:**

- `artifacts` (committed `.env`, `.pem`, `id_rsa`, `.npmrc` tokens, gitignore coverage)
- `githist` (secrets in git history, especially ones *deleted* before HEAD — they look
  fixed, are still in the object store, and are rarely rotated)
- `cicd` (GitHub Actions script injection, unpinned actions, Dockerfile issues)
- `surface` (route extraction, unauthenticated state-changing endpoints)
- `live/` (DNS, certificate transparency, TCP connect, TLS, HTTP headers). The CLI
  surface exists and the authorization gate is implemented and tested, but there are no
  probe modules behind it. `recon live` will refuse to do anything useful.
- Test fixtures. The false-positive suite is the next real milestone, and until it lands
  **expect some noise.** Current smoke coverage: 6 suites, all passing.

## Design invariants

These are the rules the code holds itself to. If you find a violation, that's a bug
worth reporting.

- **Zero required dependencies.** stdlib only, so it can be dropped onto a host where
  you can't install anything. This is why DNS will be a bundled resolver rather than
  dnspython.
- **Severity and confidence stay separate.** Collapsing them into one number is what
  gets scanners muted.
- **No credential is ever printed in full** — not to the terminal, JSON, SARIF, or logs.
  Everything is `AKIA...LE (20 chars)`.
- **No network validation of secrets by default.** Validating a key means transmitting
  it to a third party. `--verify-secrets` is opt-in and says so.
- **Regex rules are labeled heuristic.** Python gets a real AST; other languages get
  regex, and every finding declares which one found it. Honesty over apparent
  capability.
- **Skips are always reported with a reason.** A scanner that silently does nothing is
  worse than one that errors, because it reports success.

## Live probing, and why it's gated

`recon live` requires `--authorized` and a non-empty `--scope`, refuses out-of-scope
hosts, and refuses reserved and cloud-metadata IP ranges *before any socket opens* —
including when a metadata IP is passed in `--scope` explicitly. Every host and port
touched can be appended to an `--audit-log`.

Only scan things you own or have written permission to test.

## Feedback

Alpha software, and the noise floor is the thing I most need data on. Useful reports:

- **False positives.** The rule id, and the line it fired on. This is the most valuable
  thing you can send.
- **False negatives.** Something real it walked straight past.
- **Crashes.** The command, and the traceback.

The scanner on this repo currently reports findings against its own rule-definition
JSON and its deliberately-vulnerable smoke fixtures in `dev/`. That's expected: those
files contain planted, non-live example credentials (`AKIAIOSFODNN7EXAMPLE` and
friends) so the detectors have something to catch.

## License

MIT. See [LICENSE](LICENSE).
