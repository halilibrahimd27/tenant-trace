"""Sessions, redaction, rate limiting, and the in-process ASGI transport.

Credential redaction is tested here rather than at render time on purpose: the
guarantee is that a token never reaches an artifact in the first place, so the
test has to hold at the point the exchange is built.
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import pytest

from tenanttrace.core.config import load_config
from tenanttrace.core.models import HttpMethod, TenantLabel
from tenanttrace.probe.asgi import SyncASGITransport
from tenanttrace.probe.session import (
    REDACTED,
    RateLimiter,
    TenantSession,
    build_client,
    redact_headers,
)

CONFIG_BODY = '[target]\nbase_url = "http://127.0.0.1:8000"\n'


@pytest.fixture
def config(tmp_path):  # type: ignore[no-untyped-def]
    path = tmp_path / "t.toml"
    path.write_text(CONFIG_BODY, encoding="utf-8")
    return load_config(path)


async def echo_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
    """A minimal ASGI app that echoes what it was sent."""
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if not message.get("more_body"):
            break

    import json

    payload = json.dumps(
        {
            "method": scope["method"],
            "path": scope["path"],
            "query": scope["query_string"].decode(),
            "headers": {k.decode(): v.decode() for k, v in scope["headers"]},
            "body": body.decode() or None,
        }
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": payload})


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "header", ["Authorization", "authorization", "Cookie", "X-Api-Key", "X-Auth-Token"]
)
def test_credential_headers_are_redacted(header: str) -> None:
    assert redact_headers({header: "secret-value"})[header] == REDACTED


def test_ordinary_headers_survive_redaction() -> None:
    assert redact_headers({"Accept": "application/json"}) == {"Accept": "application/json"}


def test_redaction_can_be_disabled_explicitly() -> None:
    assert redact_headers({"Authorization": "x"}, redact=False) == {"Authorization": "x"}


def test_exchange_never_carries_a_live_token(config) -> None:  # type: ignore[no-untyped-def]
    transport = SyncASGITransport(echo_app)
    client = build_client(config, transport=transport)
    session = TenantSession(
        label=TenantLabel.A,
        client=client,
        headers={"Authorization": "Bearer eyJhbGciOi.super.secret"},
        limiter=RateLimiter(1000),
    )
    exchange = session.get("/anything")
    client.close()
    transport.close()

    assert exchange.request_headers["Authorization"] == REDACTED
    # The token still reached the application — redaction is about the record,
    # not about crippling the request.
    assert "super.secret" in exchange.response_text


# --------------------------------------------------------------------------- #
# Session behaviour
# --------------------------------------------------------------------------- #


def test_every_request_is_recorded(config) -> None:  # type: ignore[no-untyped-def]
    transport = SyncASGITransport(echo_app)
    client = build_client(config, transport=transport)
    session = TenantSession(
        label=TenantLabel.A, client=client, headers={}, limiter=RateLimiter(1000)
    )
    session.get("/one")
    session.post("/two", json_body={"a": 1})
    session.delete("/three")
    client.close()
    transport.close()

    assert [e.method for e in session.exchanges] == [
        HttpMethod.GET,
        HttpMethod.POST,
        HttpMethod.DELETE,
    ]
    assert session.exchanges[1].request_body == '{"a": 1}'


def test_with_headers_shares_the_transcript(config) -> None:  # type: ignore[no-untyped-def]
    """An attack variant must not be able to send requests off the record."""
    transport = SyncASGITransport(echo_app)
    client = build_client(config, transport=transport)
    session = TenantSession(
        label=TenantLabel.A, client=client, headers={"A": "1"}, limiter=RateLimiter(1000)
    )
    variant = session.with_headers({"X-Tenant-Id": "other"})
    variant.get("/x")
    client.close()
    transport.close()

    assert len(session.exchanges) == 1
    assert session.exchanges[0].url.endswith("/x")


def test_transport_failure_becomes_an_exchange_not_an_exception(config) -> None:  # type: ignore[no-untyped-def]
    """One dead endpoint must not end the audit."""

    class Failing(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("nope", request=request)

    client = build_client(config, transport=Failing())
    session = TenantSession(
        label=TenantLabel.A, client=client, headers={}, limiter=RateLimiter(1000)
    )
    exchange = session.get("/x")
    client.close()

    assert exchange.status is None
    assert exchange.transport_error is not None
    assert exchange.facts().failed is True


def test_unauthenticated_session_is_detectable(config) -> None:  # type: ignore[no-untyped-def]
    client = build_client(config, transport=SyncASGITransport(echo_app))
    session = TenantSession(
        label=TenantLabel.A, client=client, headers={}, limiter=RateLimiter(1000)
    )
    assert session.authenticated is False
    client.close()


def test_redirects_are_not_followed(config) -> None:  # type: ignore[no-untyped-def]
    """A redirect could move a request to a host outside allowed_hosts."""
    client = build_client(config, transport=SyncASGITransport(echo_app))
    assert client.follow_redirects is False
    client.close()


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #


def test_rate_limiter_spaces_requests_out() -> None:
    limiter = RateLimiter(max_rps=50)
    started = time.monotonic()
    for _ in range(5):
        limiter.wait()
    # Four gaps of 20 ms; allow generous slack for a loaded CI machine.
    assert time.monotonic() - started >= 0.06


def test_rate_limiter_can_be_disabled() -> None:
    limiter = RateLimiter(max_rps=0)
    started = time.monotonic()
    for _ in range(50):
        limiter.wait()
    assert time.monotonic() - started < 0.5


# --------------------------------------------------------------------------- #
# The synchronous ASGI transport
# --------------------------------------------------------------------------- #


def test_asgi_transport_round_trips_a_request() -> None:
    with SyncASGITransport(echo_app) as transport:
        client = httpx.Client(transport=transport, base_url="http://testserver")
        response = client.get("/hello", params={"a": "1"})
        client.close()

    assert response.status_code == 200
    payload = response.json()
    assert payload["path"] == "/hello"
    assert payload["query"] == "a=1"
    assert payload["method"] == "GET"


def test_asgi_transport_sends_bodies_and_headers() -> None:
    with SyncASGITransport(echo_app) as transport:
        client = httpx.Client(transport=transport, base_url="http://testserver")
        response = client.post("/x", json={"k": "v"}, headers={"X-Custom": "yes"})
        client.close()

    payload = response.json()
    assert json.loads(payload["body"]) == {"k": "v"}
    assert payload["headers"]["x-custom"] == "yes"


def test_asgi_transport_survives_an_app_that_raises() -> None:
    async def broken(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            return
        msg = "handler blew up"
        raise RuntimeError(msg)

    transport = SyncASGITransport(broken, raise_app_exceptions=False)
    client = httpx.Client(transport=transport, base_url="http://testserver")
    response = client.get("/x")
    client.close()
    transport.close()

    # A 5xx is what the oracle reads as `inconclusive` — the honest verdict for
    # an endpoint that fell over, and never a silent pass.
    assert response.status_code == 500


def test_asgi_transport_tolerates_an_app_without_lifespan() -> None:
    async def no_lifespan(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            msg = "lifespan not supported"
            raise NotImplementedError(msg)
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    with SyncASGITransport(no_lifespan) as transport:
        client = httpx.Client(transport=transport, base_url="http://testserver")
        assert client.get("/x").status_code == 204
        client.close()


def test_asgi_transport_state_persists_across_requests() -> None:
    """Shared state must survive between requests, or cache bugs vanish."""
    calls: list[int] = []

    async def counting(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            return
        calls.append(1)
        body = str(len(calls)).encode()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": body})

    with SyncASGITransport(counting) as transport:
        client = httpx.Client(transport=transport, base_url="http://testserver")
        assert client.get("/x").text == "1"
        assert client.get("/x").text == "2"
        client.close()
