"""What must never be written down.

Header redaction was never enough. Found by an agent seeding Chatwoot:
``/api/v1/profile`` echoes the caller's own non-expiring API token, the
positive control reads exactly that endpoint, and ``report.json`` ended up
carrying ``"access_token": "<redacted>"`` in the request headers and the same
live token verbatim four lines below in the response snippet — in a file the
shipped GitHub Action uploads as a build artifact.
"""

from __future__ import annotations

import json

import pytest

from tenanttrace.core.redaction import (
    REDACTED,
    is_sensitive_header,
    redact_credentials_in_body,
    redact_headers,
)

# --------------------------------------------------------------------------- #
# Headers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name",
    [
        "Authorization",
        "Cookie",
        "Set-Cookie",
        "X-Api-Key",
        "X-Auth-Token",
        "Proxy-Authorization",
        "X-Session-Token",
        "X-Client-Secret",
        "my-password-header",
        "X-Credential",
    ],
)
def test_credential_headers_are_recognised_however_they_are_named(name: str) -> None:
    """A fixed denylist loses to the next application's spelling."""
    assert is_sensitive_header(name)


@pytest.mark.parametrize("name", ["Content-Type", "Accept", "User-Agent", "X-Request-Id"])
def test_ordinary_headers_are_left_alone(name: str) -> None:
    assert not is_sensitive_header(name)


def test_redact_headers_keeps_the_names_and_drops_the_values() -> None:
    out = redact_headers({"Authorization": "Bearer abc123", "Accept": "application/json"})
    assert out == {"Authorization": REDACTED, "Accept": "application/json"}


# --------------------------------------------------------------------------- #
# Bodies
# --------------------------------------------------------------------------- #

SECRETS = (
    "zW3ne9Mx2CMtFuauk7KPERxU",
    "abcdefghijklmnop",
    "s3cr3tvalue",
    "aaaaaaaaaaaa",
    "kkkkkkkkkkkk",
)


@pytest.mark.parametrize(
    "body",
    [
        '{"access_token":"zW3ne9Mx2CMtFuauk7KPERxU"}',
        '{"pubsub_token": "abcdefghijklmnop"}',
        "client_secret=s3cr3tvalue&grant_type=password",
        '{"X-Session-Token": "aaaaaaaaaaaa"}',
        "{'api_key': 'kkkkkkkkkkkk'}",
    ],
)
def test_a_credential_in_a_body_is_never_written_down(body: str) -> None:
    out = redact_credentials_in_body(body)
    assert out is not None
    assert REDACTED in out
    for secret in SECRETS:
        assert secret not in out


def test_a_redacted_json_body_still_parses() -> None:
    """A snippet nobody can decode is evidence nobody can read."""
    out = redact_credentials_in_body('{"access_token":"zW3ne9Mx2CMtFuauk7KPER","amount":102}')
    assert out is not None
    assert json.loads(out)["amount"] == 102


def test_the_evidence_the_report_exists_for_survives() -> None:
    """Over-redacting a canary would destroy the finding it proves."""
    body = '{"title":"tt-canary-B-0123456789abcdef invoice","amount":102,"id":"018f4c1e"}'
    assert redact_credentials_in_body(body) == body


def test_an_empty_body_is_returned_unchanged() -> None:
    assert redact_credentials_in_body(None) is None
    assert redact_credentials_in_body("") == ""
