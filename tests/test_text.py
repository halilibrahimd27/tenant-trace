"""Agreement between a count and its noun.

Trivial on its own; it is here because ``1 endpoint(s)`` is the detail that
makes a security report read like a debug log, and every renderer shares this.
"""

from __future__ import annotations

import pytest

from tenanttrace.core.text import count, plural


@pytest.mark.parametrize(
    ("n", "expected"),
    [(0, "0 endpoints"), (1, "1 endpoint"), (2, "2 endpoints"), (11, "11 endpoints")],
)
def test_count_agrees_with_the_noun(n: int, expected: str) -> None:
    assert count(n, "endpoint") == expected


def test_zero_takes_the_plural() -> None:
    """English, not arithmetic: 'no endpoints', never 'no endpoint'."""
    assert plural(0, "finding") == "findings"


def test_an_irregular_plural_can_be_given() -> None:
    assert count(2, "entry", "entries") == "2 entries"
    assert count(1, "entry", "entries") == "1 entry"
