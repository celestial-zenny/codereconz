"""Text offset helpers shared by the scanning modules.

Regex matches come back as character offsets; findings need 1-indexed line and column
numbers. Building the line-start table with `str.find` keeps the work in C - iterations
equal the number of lines, not the number of characters.
"""

from __future__ import annotations

from bisect import bisect_right
from typing import List, Sequence


def line_starts(text: str) -> List[int]:
    """Character offset of the first character of each line."""
    starts = [0]
    idx = text.find("\n")
    while idx != -1:
        starts.append(idx + 1)
        idx = text.find("\n", idx + 1)
    return starts


def line_of(starts: Sequence[int], offset: int) -> int:
    """1-indexed line number containing `offset`."""
    return bisect_right(starts, offset)


def line_span(text: str, starts: Sequence[int], line: int, limit: int = 1024) -> str:
    """Text of `line` (1-indexed), truncated to `limit` characters.

    The truncation matters for pathological single-line files: without it, one generated
    file turns every snippet into a megabyte of memory traffic.
    """
    if line < 1 or line > len(starts):
        return ""
    start = starts[line - 1]
    end = starts[line] if line < len(starts) else len(text)
    return text[start : min(end, start + limit)]
