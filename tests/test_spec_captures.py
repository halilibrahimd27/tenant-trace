"""HAR and Postman imports — how you audit an application with no OpenAPI.

These formats describe concrete requests rather than templates, so identifiers
have to be inferred back out of the URLs. Two properties matter most:

* **Third-party traffic is never probed.** A browser capture is mostly other
  people's servers. Having a HAR is not permission to attack whoever else
  appears in it.
* **Templating never invents coverage.** A path that fails to templatise is
  probed as a literal; it must never silently merge two different endpoints
  into one and report the surface as covered.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tenanttrace.core.config import load_config
from tenanttrace.core.models import HttpMethod
from tenanttrace.probe.spec import (
    SpecError,
    load_inventory,
    parse_har,
    parse_postman,
    templatize,
)


def har(*entries: dict[str, object]) -> dict[str, object]:
    return {"log": {"version": "1.2", "entries": list(entries)}}


def entry(
    method: str,
    url: str,
    *,
    query: list[dict[str, str]] | None = None,
    body: str | None = None,
    mime: str = "application/json",
) -> dict[str, object]:
    request: dict[str, object] = {"method": method, "url": url, "queryString": query or []}
    if body is not None:
        request["postData"] = {"mimeType": mime, "text": body}
    return {"request": request, "response": {"status": 200}}


# --------------------------------------------------------------------------- #
# Templating
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("path", "expected", "params"),
    [
        ("/api/invoices/42", "/api/invoices/{id}", ("id",)),
        (
            "/api/invoices/018f4c1e-3a9b-7c2d-9e5f-1a2b3c4d5e6f",
            "/api/invoices/{id}",
            ("id",),
        ),
        ("/api/invoices/01H2XJKQ8RZ9YV4M6N7P8Q9RST", "/api/invoices/{id}", ("id",)),
        ("/api/t/7/invoices/9", "/api/t/{id}/invoices/{id2}", ("id", "id2")),
        ("/api/invoices", "/api/invoices", ()),
        ("/api/invoices/{invoice_id}", "/api/invoices/{invoice_id}", ("invoice_id",)),
        ("/", "/", ()),
    ],
)
def test_templatize(path: str, expected: str, params: tuple[str, ...]) -> None:
    assert templatize(path) == (expected, params)


def test_short_words_are_not_mistaken_for_identifiers() -> None:
    """Merging two real endpoints into one silently loses coverage."""
    assert templatize("/api/me/settings")[0] == "/api/me/settings"
    assert templatize("/api/v2/health")[0] == "/api/v2/health"


# --------------------------------------------------------------------------- #
# HAR
# --------------------------------------------------------------------------- #


def test_har_requests_become_endpoints() -> None:
    inventory = parse_har(
        har(
            entry("GET", "https://app.example.com/api/invoices"),
            entry("GET", "https://app.example.com/api/invoices/42"),
            entry("POST", "https://app.example.com/api/invoices", body='{"title":"x","amount":1}'),
        ),
        host="app.example.com",
    )
    keys = {e.key for e in inventory.endpoints}
    assert keys == {
        "GET /api/invoices",
        "GET /api/invoices/{id}",
        "POST /api/invoices",
    }


def test_repeated_requests_collapse_into_one_endpoint() -> None:
    """A capture contains the same call many times; the report must not."""
    inventory = parse_har(
        har(*[entry("GET", f"https://a.example/api/invoices/{i}") for i in range(50)]),
        host="a.example",
    )
    assert len(inventory.endpoints) == 1
    assert inventory.endpoints[0].path == "/api/invoices/{id}"


def test_query_parameters_are_merged_across_observations() -> None:
    inventory = parse_har(
        har(
            entry("GET", "https://a.example/api/x?page=1", query=[{"name": "page", "value": "1"}]),
            entry(
                "GET",
                "https://a.example/api/x?sort=asc",
                query=[{"name": "sort", "value": "asc"}],
            ),
        ),
        host="a.example",
    )
    assert set(inventory.endpoints[0].query_params) == {"page", "sort"}


def test_json_body_fields_are_captured() -> None:
    inventory = parse_har(
        har(entry("POST", "https://a.example/api/x", body='{"title":"t","amount":2}')),
        host="a.example",
    )
    assert set(inventory.endpoints[0].body_fields) == {"title", "amount"}


def test_form_body_fields_are_captured() -> None:
    inventory = parse_har(
        har(
            entry(
                "POST",
                "https://a.example/api/x",
                body="name=n&email=e",
                mime="application/x-www-form-urlencoded",
            )
        ),
        host="a.example",
    )
    assert set(inventory.endpoints[0].body_fields) == {"name", "email"}


def test_third_party_traffic_is_never_imported() -> None:
    """Having a capture is not permission to probe whoever is in it."""
    inventory = parse_har(
        har(
            entry("GET", "https://app.example.com/api/invoices"),
            entry("POST", "https://analytics.vendor.com/collect"),
            entry("GET", "https://cdn.other.net/api/data"),
        ),
        host="app.example.com",
    )
    assert {e.path for e in inventory.endpoints} == {"/api/invoices"}
    assert any("other hosts were ignored" in w for w in inventory.warnings)


def test_static_assets_are_skipped() -> None:
    inventory = parse_har(
        har(
            entry("GET", "https://a.example/static/app.js"),
            entry("GET", "https://a.example/img/logo.png"),
            entry("GET", "https://a.example/api/invoices"),
        ),
        host="a.example",
    )
    assert {e.path for e in inventory.endpoints} == {"/api/invoices"}
    assert any("static asset" in w for w in inventory.warnings)


def test_malformed_entries_do_not_stop_the_import() -> None:
    document = har(
        {"request": "not an object"},
        {"no_request": True},
        entry("GET", "https://a.example/api/ok"),
    )
    assert {e.path for e in parse_har(document, host="a.example").endpoints} == {"/api/ok"}


def test_a_capture_with_nothing_usable_says_so() -> None:
    inventory = parse_har(har(entry("GET", "https://a.example/app.css")), host="a.example")
    assert inventory.endpoints == ()
    assert any("no probe-worthy requests" in w for w in inventory.warnings)


def test_not_a_har_is_an_error() -> None:
    with pytest.raises(SpecError, match="log.entries"):
        parse_har({"nope": True})


# --------------------------------------------------------------------------- #
# Postman
# --------------------------------------------------------------------------- #


COLLECTION = {
    "info": {"name": "demo"},
    "item": [
        {
            "name": "Invoices",
            "item": [
                {
                    "request": {
                        "method": "GET",
                        "url": {
                            "raw": "{{baseUrl}}/api/invoices?page=1",
                            "query": [{"key": "page", "value": "1"}],
                        },
                    }
                },
                {
                    "request": {
                        "method": "GET",
                        "url": {"raw": "{{baseUrl}}/api/invoices/:invoiceId"},
                    }
                },
                {
                    "request": {
                        "method": "POST",
                        "url": {"raw": "{{baseUrl}}/api/invoices"},
                        "body": {"mode": "raw", "raw": '{"title": "x", "amount": 1}'},
                    }
                },
            ],
        }
    ],
}


def test_postman_folders_are_walked() -> None:
    inventory = parse_postman(COLLECTION)
    assert {e.key for e in inventory.endpoints} == {
        "GET /api/invoices",
        "GET /api/invoices/{invoiceId}",
        "POST /api/invoices",
    }


def test_postman_keeps_the_authors_parameter_name() -> None:
    """A name a human chose beats one we would have inferred."""
    endpoint = next(e for e in parse_postman(COLLECTION).endpoints if e.path_params)
    assert endpoint.path_params == ("invoiceId",)


def test_postman_variables_are_stripped_not_probed() -> None:
    for endpoint in parse_postman(COLLECTION).endpoints:
        assert "{{" not in endpoint.path
        assert endpoint.path.startswith("/api/")


def test_postman_body_and_query_are_captured() -> None:
    inventory = parse_postman(COLLECTION)
    post = next(e for e in inventory.endpoints if e.method is HttpMethod.POST)
    listing = next(e for e in inventory.endpoints if e.key == "GET /api/invoices")
    assert set(post.body_fields) == {"title", "amount"}
    assert set(listing.query_params) == {"page"}


def test_postman_urlencoded_body() -> None:
    collection = {
        "item": [
            {
                "request": {
                    "method": "POST",
                    "url": {"raw": "/api/x"},
                    "body": {"mode": "urlencoded", "urlencoded": [{"key": "a"}, {"key": "b"}]},
                }
            }
        ]
    }
    assert set(parse_postman(collection).endpoints[0].body_fields) == {"a", "b"}


def test_not_a_collection_is_an_error() -> None:
    with pytest.raises(SpecError, match="'item' array"):
        parse_postman({"log": {}})


# --------------------------------------------------------------------------- #
# Wiring
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("kind", ["har", "postman"])
def test_config_accepts_the_capture_formats(tmp_path: Path, kind: str) -> None:
    document = har(entry("GET", "http://127.0.0.1:8000/api/x")) if kind == "har" else COLLECTION
    spec_file = tmp_path / f"capture.{kind}.json"
    spec_file.write_text(json.dumps(document), encoding="utf-8")

    config_file = tmp_path / "t.toml"
    config_file.write_text(
        f'[target]\nbase_url = "http://127.0.0.1:8000"\n'
        f'spec = "{kind}"\nspec_path = "{spec_file}"\n',
        encoding="utf-8",
    )

    inventory = load_inventory(load_config(config_file), None)
    assert len(inventory) >= 1
    assert all(e.path.startswith("/") for e in inventory.endpoints)
