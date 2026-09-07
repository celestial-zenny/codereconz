"""Scan modules.

Importing this package registers every module with `core.engine.REGISTRY`. The registry
is populated as a side effect of import, so anything that wants a complete module list
must import this package (not just individual submodules) first.
"""

from __future__ import annotations

from . import deps  # noqa: F401  - imported for its @register side effect
from . import patterns  # noqa: F401  - imported for its @register side effect
from . import secrets  # noqa: F401  - imported for its @register side effect

__all__ = ["deps", "patterns", "secrets"]
