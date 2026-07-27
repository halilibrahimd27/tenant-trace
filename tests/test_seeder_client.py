"""The helper that removes the boilerplate every real seeder wrote by hand.

Six seeders were written against six real applications. All six hand-rolled the
same four lines — call, check the status, decode the JSON, fail somehow — and
three built their own ``_post`` on top of it.

The boilerplate is the smaller half. Seeding is the most common way a first run
dies, and the failures used to be the most expensive thing to diagnose: a bare
``raise_for_status`` or ``KeyError: 'id'`` says nothing about which call, what
came back, or what was expected. Most of these tests are about the message.
"""

from __future__ import annotations

import httpx
import pytest

from tenanttrace.probe.seeder import SeederClient, SeederError, unique


def client_for(handler: object) -> SeederClient:
    transport = httpx.MockTransport(handler)  # type: ignore[arg-type]
    return SeederClient(httpx.Client(transport=transport, base_url="http://app.test"))


def test_a_successful_call_returns_the_decoded_body() -> None:
    api = client_for(lambda r: httpx.Response(201, json={"id": "abc", "name": "x"}))
    assert api.post("/api/tenants", json={"name": "x"}) == {"id": "abc", "name": "x"}


def test_an_empty_body_is_a_success_with_nothing_to_decode() -> None:
    """A 204 from a delete is not a failure."""
    api = client_for(lambda r: httpx.Response(204))
    assert api.delete("/api/tenants/1") is None


def test_the_wrong_status_names_the_call_and_quotes_the_application() -> None:
    api = client_for(lambda r: httpx.Response(422, json={"error": "name is taken"}))
    with pytest.raises(SeederError) as caught:
        api.post("/api/tenants", json={"name": "x"})

    message = str(caught.value)
    assert "POST /api/tenants" in message
    assert "422" in message
    assert "name is taken" in message


def test_an_expected_status_can_be_narrowed() -> None:
    api = client_for(lambda r: httpx.Response(200, json={}))
    with pytest.raises(SeederError, match="expected 201"):
        api.post("/api/tenants", expect=201)


def test_a_body_that_is_not_json_says_so_rather_than_raising_valueerror() -> None:
    api = client_for(lambda r: httpx.Response(200, text="<html>login</html>"))
    with pytest.raises(SeederError, match="not JSON"):
        api.get("/api/me")


def test_a_transport_failure_names_the_call() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with pytest.raises(SeederError, match="GET /api/me could not be sent"):
        client_for(refuse).get("/api/me")


def test_a_missing_field_lists_the_keys_that_were_there() -> None:
    """`KeyError: 'id'` three frames deep is the other half of the cost."""
    api = client_for(lambda r: httpx.Response(200, json={"uuid": "abc", "slug": "x"}))
    body = api.get("/api/me")
    with pytest.raises(SeederError) as caught:
        api.field(body, "id", "pk")

    message = str(caught.value)
    assert "none of id, pk" in message
    assert "slug" in message and "uuid" in message


def test_a_field_lookup_takes_the_first_name_that_is_present() -> None:
    api = client_for(lambda r: httpx.Response(200, json={"uuid": "abc"}))
    assert api.field(api.get("/api/me"), "id", "uuid") == "abc"


def test_credentials_can_be_attached_without_rebuilding_the_client() -> None:
    seen: dict[str, str] = {}

    def record(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json={})

    client_for(record).with_headers(Authorization="Bearer t").get("/api/me")
    assert seen["authorization"] == "Bearer t"


def test_unique_values_do_not_repeat() -> None:
    assert unique("acme") != unique("acme")
    assert unique("acme").startswith("acme-")
