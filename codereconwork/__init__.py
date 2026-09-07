"""Code Recon - a security reconnaissance tool for codebases and the surface they expose.

Four scan surfaces, one CLI:

* source analysis (hardcoded secrets, dangerous patterns)
* repository and supply chain (git history, dependencies, CI/CD, committed artifacts)
* attack surface derived from the code (routes, handlers, auth coverage)
* live target reconnaissance (DNS, TLS, HTTP, open ports) - gated behind explicit
  authorization and a mandatory scope allowlist

Deliberately dependency-free: the core runs on the standard library alone, because a
security tool needs to work on a locked-down box you do not control. `rich` and `PyYAML`
are used when present and fall back cleanly when not.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
