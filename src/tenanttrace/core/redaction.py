"""What must never be written down, wherever it is about to be written.

Both halves of the tool need this: the prober redacts when it builds an
exchange, and the renderers redact again when they emit a report. Keeping the
rule in one place under ``core`` is what stops the two from drifting — and it
respects the dependency arrow, since ``core`` may not import from ``probe``.

The rule itself is deliberately broad. A fixed list of header names is a
denylist, and a denylist loses to the next application that calls its
credential ``X-Session-Token``. Over-redacting costs nothing: the real value
still goes out on the wire, it just never lands in a file.
"""

from __future__ import annotations

from collections.abc import Mapping

__all__ = ["REDACTED", "SENSITIVE_HEADERS", "is_sensitive_header", "redact_headers"]

REDACTED = "<redacted>"

SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "proxy-authorization",
    }
)

_SENSITIVE_HINTS = (
    "auth",
    "token",
    "secret",
    "session",
    "cookie",
    "credential",
    "password",
    "key",
)


def is_sensitive_header(name: str) -> bool:
    """True when a header's value must never be recorded."""
    lowered = name.lower()
    return lowered in SENSITIVE_HEADERS or any(hint in lowered for hint in _SENSITIVE_HINTS)


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Copy headers with every credential-looking value replaced.

    There is no mode in which this is skipped. ``--full-evidence`` widens what
    a report keeps of the *target's* responses; it is not a switch for writing
    our own bearer tokens into an artifact that CI uploads.
    """
    return {
        name: (REDACTED if is_sensitive_header(name) else value) for name, value in headers.items()
    }
