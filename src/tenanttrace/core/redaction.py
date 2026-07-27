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

import re
from collections.abc import Mapping

__all__ = [
    "REDACTED",
    "SENSITIVE_HEADERS",
    "is_sensitive_header",
    "redact_credentials_in_body",
    "redact_headers",
]

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


# `"access_token": "zW3ne…"` and `access_token=zW3ne…`, in JSON, form bodies and
# prose. The key half reuses the same vocabulary as the header rule, because an
# application that calls its credential `X-Session-Token` in a header calls it
# `session_token` in a body.
_HINT_ALTERNATION = "|".join(_SENSITIVE_HINTS)
_CREDENTIAL_IN_BODY = re.compile(
    rf"""
    (?P<key>["']?[A-Za-z0-9_.\-]*(?:{_HINT_ALTERNATION})[A-Za-z0-9_.\-]*["']?)
    (?P<sep>\s*[:=]\s*)
    (?P<value>"[^"]{{6,}}"|'[^']{{6,}}'|[A-Za-z0-9._\-]{{6,}})
    """,
    re.VERBOSE | re.IGNORECASE,
)


def redact_credentials_in_body(text: str | None) -> str | None:
    """Replace credential-looking values inside a request or response body.

    Header redaction was never enough. A `/me` or `/profile` endpoint that
    echoes the caller's own API token is an ordinary shape, and the positive
    control reads exactly those endpoints — so a live, non-expiring token was
    written verbatim into `report.json` and `exchanges.jsonl`, the files the
    shipped GitHub Action uploads as a build artifact. The same file carried
    `"access_token": "<redacted>"` in the request headers three lines above.

    Deliberately blunt. A false positive costs a mangled snippet; a false
    negative costs a published credential. Applied in every mode, including
    `--full-evidence` — that flag widens what is kept of the target's *data*,
    never of a secret.
    """
    if not text:
        return text

    def replace(match: re.Match[str]) -> str:
        # Keep the value's quoting so a redacted JSON body still parses — a
        # snippet nobody can decode is evidence nobody can read.
        quote = match.group("value")[0] if match.group("value")[0] in "\"'" else ""
        return f"{match.group('key')}{match.group('sep')}{quote}{REDACTED}{quote}"

    return _CREDENTIAL_IN_BODY.sub(replace, text)
