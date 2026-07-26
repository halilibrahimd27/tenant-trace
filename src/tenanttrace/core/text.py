"""Small phrasing helpers shared by every renderer.

``endpoint(s)`` is the kind of detail nobody files a bug about and everybody
notices. A report that a security team forwards to a client should read like a
sentence, so the count and the noun agree.
"""

from __future__ import annotations

__all__ = ["count", "plural"]


def plural(n: int, singular: str, plural_form: str | None = None) -> str:
    """The noun alone, agreeing with ``n``."""
    if n == 1:
        return singular
    return plural_form if plural_form is not None else f"{singular}s"


def count(n: int, singular: str, plural_form: str | None = None) -> str:
    """The count and the noun together: ``1 endpoint`` / ``4 endpoints``."""
    return f"{n} {plural(n, singular, plural_form)}"
