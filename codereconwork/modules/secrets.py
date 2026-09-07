"""Secret detection.

Runs the `secrets` rule pack over file text, then applies the heuristic filters in
`core.heuristics` to each candidate. The pipeline per match:

    regex match -> placeholder filter -> known-format filter -> entropy gate
                -> format validator -> per-file reduction -> Finding

The reduction step matters more than it looks. Without it, `api_key = "AKIA..."` fires
both the AWS rule and the generic-api-key rule and gets reported twice, which teaches
users that the tool double-counts. Candidates are grouped by a hash of the credential
itself, and the highest-severity rule wins - one credential, one finding.

`SecretScanner` is deliberately separable from the module so the git-history module can
reuse the exact same engine on diff text.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Tuple

from ..core.context import ScanContext
from ..core.engine import FileScanModule, register
from ..core.finding import Confidence, Finding, Severity
from ..core.heuristics import (
    is_placeholder,
    is_test_context,
    jwt_details,
    looks_like_known_format,
    run_validator,
    shannon_entropy,
)
from ..core.redact import fingerprint_secret, mask, safe_snippet
from ..core.rules import Rule, filter_rules, load_builtin, load_pack
from ..core.textutil import line_of, line_starts
from ..core.walker import ScanFile


class SecretScanner:
    """Applies secret rules to arbitrary text. Thread-safe once constructed."""

    def __init__(self, rules: Sequence[Rule]):
        self.rules = list(rules)
        self.filtered: Dict[str, int] = {}  # reason -> count, for the report

    def _reject(self, reason: str) -> None:
        self.filtered[reason] = self.filtered.get(reason, 0) + 1

    def scan(
        self,
        text: str,
        path: str,
        *,
        language: Optional[str] = None,
        module: str = "secrets",
        max_per_rule: int = 20,
        extra_tags: Sequence[str] = (),
        extra_fields: Optional[Dict[str, object]] = None,
        line_offset: int = 0,
    ) -> List[Finding]:
        if not text:
            return []
        lowered = text.lower()

        # secret-hash -> (finding, occurrence count). Keyed on the credential so the
        # same key matched by several rules collapses to the strongest one.
        best: Dict[str, Tuple[Finding, int]] = {}
        starts: Optional[List[int]] = None
        in_test = is_test_context(path)

        for rule in self.rules:
            if not rule.applies_to(path, language):
                continue
            if not rule.prefilter(lowered):
                continue

            hits = 0
            for match in rule.regex.finditer(text):
                if hits >= max_per_rule:
                    self._reject(f"{rule.id}: per-file cap of {max_per_rule} reached")
                    break

                reported = match.group(rule.group) or ""
                secret = (
                    match.group(rule.secret_group) if rule.secret_group is not None else reported
                ) or ""
                if not secret.strip():
                    continue

                if rule.reject_placeholders and is_placeholder(secret):
                    self._reject("placeholder or template value")
                    continue
                if rule.reject_known_formats:
                    known, why = looks_like_known_format(secret)
                    if known:
                        self._reject(why or "recognised non-secret format")
                        continue
                if rule.min_entropy is not None:
                    ent = shannon_entropy(secret)
                    if ent < rule.min_entropy:
                        self._reject(f"entropy {ent:.2f} below {rule.min_entropy:.2f}")
                        continue
                ok, why = run_validator(rule.validate, secret)
                if not ok:
                    self._reject(why or f"failed {rule.validate} validation")
                    continue

                if starts is None:
                    starts = line_starts(text)
                line_index = line_of(starts, match.start()) - 1  # 0-based
                line_start = starts[line_index]
                # Take at most 1 KiB from the line start; safe_snippet clips to the
                # first newline and then to the display width.
                raw_line = text[line_start : line_start + 1024]

                seed = fingerprint_secret(secret)
                dedupe_key = seed

                confidence = rule.confidence
                tags = list(rule.tags) + list(extra_tags)
                # Real credentials leak through fixtures constantly, so these are kept -
                # but a notch lower and tagged, so triage can sort them to the bottom.
                if in_test and confidence > Confidence.LOW:
                    confidence = Confidence(int(confidence) - 1)
                    tags.append("in-test")

                extra: Dict[str, object] = dict(extra_fields or {})
                # Secrets are found by regex and then survive the heuristic filters; that
                # is a text match, not a parsed fact, so it is labelled `regex` like any
                # other heuristic. The report must never present it as more certain than
                # it is - the confidence axis carries how sure we are, the detection label
                # carries how we know.
                extra.setdefault("detection", "regex")
                extra["masked"] = mask(secret)
                if rule.validate == "jwt" or "jwt" in rule.tags:
                    details = jwt_details(secret)
                    if details:
                        extra["jwt"] = details
                        # An unsigned or never-expiring token is materially worse.
                        if details.get("privileged_role") or details.get("no_expiry"):
                            confidence = Confidence.HIGH

                message = rule.message or (
                    f"{rule.title} found in {path}. Value: {mask(secret)}"
                )

                finding = Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    confidence=confidence,
                    message=message,
                    path=path,
                    line=line_index + 1 + line_offset,
                    column=match.start() - line_start + 1,
                    snippet=safe_snippet(raw_line, secret),
                    module=module,
                    remediation=rule.remediation,
                    references=list(rule.references),
                    tags=sorted(set(tags)),
                    cwe=rule.cwe,
                    fingerprint_seed=seed,
                    extra=extra,
                )

                hits += 1
                prior = best.get(dedupe_key)
                if prior is None:
                    best[dedupe_key] = (finding, 1)
                else:
                    prior_finding, count = prior
                    stronger = (finding.severity, finding.confidence) > (
                        prior_finding.severity,
                        prior_finding.confidence,
                    )
                    best[dedupe_key] = (finding if stronger else prior_finding, count + 1)

        out: List[Finding] = []
        for finding, count in best.values():
            if count > 1:
                finding.extra["occurrences"] = count
            out.append(finding)
        return out


def build_scanner(ctx: ScanContext, pack: str = "secrets") -> SecretScanner:
    """Load the secret rules honouring rule-selection flags and any extra packs."""
    rules = load_builtin(pack)
    for extra in ctx.config.rule_packs:
        rules.extend(load_pack(extra))
    rules = filter_rules(
        rules,
        enable=ctx.config.enable_rules,
        disable=ctx.config.disable_rules,
        min_severity=ctx.config.min_severity,
        min_confidence=ctx.config.min_confidence,
        fast=ctx.config.fast,
    )
    return SecretScanner(rules)


@register
class SecretsModule(FileScanModule):
    name = "secrets"
    description = "Hardcoded credentials, API tokens, and private key material"
    phase = "code"

    def __init__(self) -> None:
        self.scanner: Optional[SecretScanner] = None

    def prepare(self, ctx: ScanContext) -> None:
        self.scanner = build_scanner(ctx)
        if not self.scanner.rules:
            ctx.note("secrets: every rule was filtered out by the current flags")

    def scan_file(self, sf: ScanFile, ctx: ScanContext) -> List[Finding]:
        if self.scanner is None:
            return []
        return self.scanner.scan(
            sf.text,
            sf.relpath,
            language=sf.language,
            module=self.name,
            max_per_rule=ctx.config.max_findings_per_rule_per_file,
        )

    def stats(self) -> Dict[str, object]:
        if self.scanner is None:
            return {}
        # Surfacing *why* candidates were dropped is what makes the heuristics auditable
        # instead of a black box people have to trust.
        top = sorted(self.scanner.filtered.items(), key=lambda kv: -kv[1])[:8]
        return {
            "rules_active": len(self.scanner.rules),
            "candidates_filtered": sum(self.scanner.filtered.values()),
            "filter_reasons": dict(top),
        }
