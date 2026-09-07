"""Scan configuration and the context objects handed to each module.

`Config` is the single place CLI flags land, so a module never reads `sys.argv` and can
be driven directly from Python. `ScanContext` carries the walked file list plus the
notes/stats channel that makes a scan self-explanatory: every module that skips work
records *why*, and that shows up in the report. A scanner that quietly does nothing is
more dangerous than one that errors, because it reports success.
"""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .finding import Confidence, Severity
from .walker import DEFAULT_MAX_BYTES, ScanFile


@dataclass
class Config:
    """Everything that changes how a scan behaves."""

    root: Path = field(default_factory=Path.cwd)

    # --- traversal -------------------------------------------------------------------
    jobs: int = 0  # 0 = auto (cpu_count)
    max_bytes: int = DEFAULT_MAX_BYTES
    use_gitignore: bool = True
    include_minified: bool = False
    excludes: List[str] = field(default_factory=list)
    exclude_dirs: List[str] = field(default_factory=list)
    follow_symlinks: bool = False

    # --- behaviour -------------------------------------------------------------------
    fast: bool = False  # skip rules marked expensive
    offline: bool = False  # never touch the network
    modules: Optional[List[str]] = None  # None = every registered module

    # --- rule selection --------------------------------------------------------------
    enable_rules: List[str] = field(default_factory=list)
    disable_rules: List[str] = field(default_factory=list)
    min_severity: Optional[Severity] = None
    min_confidence: Optional[Confidence] = None
    rule_packs: List[Path] = field(default_factory=list)

    # --- module tuning ---------------------------------------------------------------
    history_depth: int = 300
    max_findings_per_rule_per_file: int = 20
    # Off by default and loudly documented: validating a found credential means sending
    # it to a third party, which is not a safe default for a tool that finds secrets.
    verify_secrets: bool = False

    # --- live recon ------------------------------------------------------------------
    authorized: bool = False
    scope: List[str] = field(default_factory=list)
    ports: str = "top100"
    timeout: float = 5.0
    max_concurrency: int = 16
    rate_limit: float = 0.0  # seconds between requests to one host; 0 = no delay
    audit_log: Optional[Path] = None
    user_agent: str = "code-recon/0.1 (+security-assessment)"
    live_http_paths: bool = True  # probe for exposed well-known paths
    subdomain_discovery: bool = True

    # --- reporting -------------------------------------------------------------------
    baseline: Optional[Path] = None
    fail_on: Optional[Severity] = Severity.HIGH
    no_color: bool = False
    verbose: bool = False

    def effective_jobs(self) -> int:
        if self.jobs > 0:
            return self.jobs
        import os

        return min(32, (os.cpu_count() or 4) * 2)


class ScopeGuard:
    """Decides whether a host or address is inside the authorized engagement scope.

    This exists because the obvious failure mode of a recon tool is collateral: you
    scan `example.com`, it has a CNAME to a CDN or a third-party SaaS, and now you are
    unauthorized-scanning somebody else's infrastructure. Everything the live modules
    touch is checked through here first.
    """

    # Blocked outright regardless of scope. Cloud metadata endpoints in particular are
    # an SSRF target, not a recon target, and hitting them from a scanner is never right.
    HARD_DENY_IPS = (
        ipaddress.ip_network("169.254.0.0/16"),  # link-local, incl. 169.254.169.254
        ipaddress.ip_network("fe80::/10"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("100.64.0.0/10"),  # CGNAT - someone else's customers
        ipaddress.ip_network("224.0.0.0/4"),  # multicast
        ipaddress.ip_network("255.255.255.255/32"),
    )

    def __init__(self, patterns: Sequence[str], *, allow_loopback: bool = False):
        self.raw = list(patterns)
        self.domains: List[str] = []
        self.networks: List[Any] = []
        self.allow_loopback = allow_loopback
        for item in patterns:
            item = item.strip().lower().rstrip(".")
            if not item:
                continue
            try:
                self.networks.append(ipaddress.ip_network(item, strict=False))
                continue
            except ValueError:
                pass
            self.domains.append(item.lstrip("*."))

    def __bool__(self) -> bool:
        return bool(self.domains or self.networks)

    def check_host(self, host: str) -> Optional[str]:
        """Return None if in scope, else a human-readable refusal reason."""
        host = host.strip().lower().rstrip(".")
        if not host:
            return "empty host"

        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            addr = None

        if addr is not None:
            return self.check_address(addr)

        for domain in self.domains:
            if host == domain or host.endswith("." + domain):
                return None
        return f"{host} is not within the declared scope ({', '.join(self.raw) or 'none'})"

    def check_address(self, addr: Any) -> Optional[str]:
        for net in self.HARD_DENY_IPS:
            if addr.version == net.version and addr in net:
                if self.allow_loopback and (addr.is_loopback):
                    break
                return (
                    f"{addr} is in a reserved/link-local range ({net}) that Code Recon "
                    f"refuses to probe"
                )
        for net in self.networks:
            if addr.version == net.version and addr in net:
                return None
        # An IP that resolved from an in-scope domain is handled by the caller, which
        # passes the originating hostname; a bare out-of-scope IP is refused.
        return f"{addr} is not within the declared scope ({', '.join(self.raw) or 'none'})"


class AuditLog:
    """Append-only record of every network action taken.

    An engagement needs a defensible answer to "what exactly did you touch, and when".
    Written line-by-line and flushed so it survives a killed process.
    """

    def __init__(self, path: Optional[Path]):
        self.path = path
        self._fh = None
        self.entries: List[str] = []
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = path.open("a", encoding="utf-8")

    def record(self, action: str, target: str, detail: str = "") -> None:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        line = f"{stamp}Z\t{action}\t{target}\t{detail}".rstrip()
        self.entries.append(line)
        if self._fh is not None:
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None


@dataclass
class ScanContext:
    """Handed to every code-scanning module."""

    config: Config
    root: Path
    files: List[ScanFile] = field(default_factory=list)
    walk_stats: Dict[str, int] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    started: float = field(default_factory=time.monotonic)

    # Populated by the surface module so live recon can consume it in the same run.
    routes: List[Dict[str, Any]] = field(default_factory=list)

    def note(self, message: str) -> None:
        """Record something the user should know about scan completeness."""
        if message not in self.notes:
            self.notes.append(message)

    def files_for(self, languages: Sequence[str] = ()) -> List[ScanFile]:
        if not languages:
            return self.files
        wanted = {lang.lower() for lang in languages}
        return [f for f in self.files if (f.language or "") in wanted]

    def files_named(self, pattern: str) -> List[ScanFile]:
        rx = re.compile(pattern, re.I)
        return [f for f in self.files if rx.search(f.relpath)]


@dataclass
class LiveContext:
    """Handed to every live-recon module."""

    config: Config
    targets: List[str]
    scope: ScopeGuard
    audit: AuditLog
    notes: List[str] = field(default_factory=list)
    # host -> resolved addresses, shared between the DNS, port, and TLS modules so one
    # target is resolved once per scan.
    resolved: Dict[str, List[str]] = field(default_factory=dict)
    discovered_hosts: List[str] = field(default_factory=list)
    routes: List[Dict[str, Any]] = field(default_factory=list)

    def note(self, message: str) -> None:
        if message not in self.notes:
            self.notes.append(message)
