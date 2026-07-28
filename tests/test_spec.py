"""Endpoint inventory: coverage is bounded by what this module understands."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tenanttrace.core.config import load_config
from tenanttrace.core.models import Endpoint, HttpMethod
from tenanttrace.probe.spec import (
    SpecError,
    load_inventory,
    parse_openapi,
    parse_routes,
    path_param_names,
    substitute_path,
)

OPENAPI: dict[str, Any] = {
    "openapi": "3.1.0",
    "paths": {
        "/api/invoices": {
            "get": {"operationId": "list_invoices", "summary": "List invoices"},
            "post": {
                "operationId": "create_invoice",
                "requestBody": {
                    "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/NewInvoice"}}
                    }
                },
            },
        },
        "/api/invoices/{invoice_id}": {
            "parameters": [{"name": "invoice_id", "in": "path", "required": True}],
            "get": {"operationId": "get_invoice"},
            "delete": {"operationId": "delete_invoice"},
        },
        "/api/customers": {
            "get": {
                "operationId": "list_customers",
                "parameters": [
                    {"name": "tenant_id", "in": "query"},
                    {"name": "page", "in": "query"},
                ],
            }
        },
    },
    "components": {
        "schemas": {
            "NewInvoice": {
                "type": "object",
                "properties": {"title": {"type": "string"}, "amount": {"type": "integer"}},
            }
        }
    },
}


def test_operations_become_endpoints() -> None:
    inventory = parse_openapi(OPENAPI)
    keys = {e.key for e in inventory.endpoints}
    assert "GET /api/invoices" in keys
    assert "POST /api/invoices" in keys
    assert "DELETE /api/invoices/{invoice_id}" in keys


def test_path_parameters_come_from_the_template() -> None:
    endpoint = next(
        e
        for e in parse_openapi(OPENAPI).endpoints
        if e.key.startswith("GET /api/inv") and e.path_params
    )
    assert endpoint.path_params == ("invoice_id",)
    assert endpoint.is_object_endpoint is True


def test_query_parameters_are_captured() -> None:
    endpoint = next(e for e in parse_openapi(OPENAPI).endpoints if e.path == "/api/customers")
    assert set(endpoint.query_params) == {"tenant_id", "page"}


def test_body_fields_resolve_through_a_ref() -> None:
    endpoint = next(e for e in parse_openapi(OPENAPI).endpoints if e.key == "POST /api/invoices")
    assert set(endpoint.body_fields) == {"title", "amount"}


def test_collections_and_objects_are_separated() -> None:
    inventory = parse_openapi(OPENAPI)
    assert {e.path for e in inventory.collections()} == {"/api/invoices", "/api/customers"}
    assert {e.path for e in inventory.objects()} == {"/api/invoices/{invoice_id}"}


def test_creators_are_post_endpoints() -> None:
    assert {e.key for e in parse_openapi(OPENAPI).creators()} == {"POST /api/invoices"}


# --------------------------------------------------------------------------- #
# Hostile and malformed documents
# --------------------------------------------------------------------------- #


def test_document_without_paths_is_an_error() -> None:
    with pytest.raises(SpecError, match="no 'paths'"):
        parse_openapi({"openapi": "3.1.0"})


def test_non_object_document_is_an_error() -> None:
    with pytest.raises(SpecError):
        parse_openapi(["not", "a", "document"])


def test_malformed_entries_are_warned_about_not_fatal() -> None:
    document = {
        "paths": {
            "relative/path": {"get": {}},
            "/ok": {"get": {"operationId": "ok"}},
            "/bad": "not an object",
        }
    }
    inventory = parse_openapi(document)
    assert {e.path for e in inventory.endpoints} == {"/ok"}
    assert len(inventory.warnings) == 2


def test_remote_refs_are_not_followed() -> None:
    """A document the target controls must not be able to trigger outbound fetches."""
    document = {
        "paths": {
            "/x": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "https://evil.example/schema.json"}
                            }
                        }
                    }
                }
            }
        }
    }
    assert parse_openapi(document).endpoints[0].body_fields == ()


def test_circular_refs_terminate() -> None:
    document = {
        "paths": {"/x": {"post": {"requestBody": {"$ref": "#/components/requestBodies/Loop"}}}},
        "components": {"requestBodies": {"Loop": {"$ref": "#/components/requestBodies/Loop"}}},
    }
    assert parse_openapi(document).endpoints[0].body_fields == ()


def test_unknown_methods_are_ignored() -> None:
    document = {"paths": {"/x": {"get": {}, "trace": {}, "x-internal": {}}}}
    assert {e.method for e in parse_openapi(document).endpoints} == {HttpMethod.GET}


# --------------------------------------------------------------------------- #
# routes.yaml
# --------------------------------------------------------------------------- #


def test_routes_file_is_a_supported_alternative() -> None:
    document = {
        "routes": [
            {"method": "GET", "path": "/api/things/{thing_id}"},
            {"method": "POST", "path": "/api/things", "body": ["name"]},
            {"method": "NOPE", "path": "/api/bad"},
        ]
    }
    inventory = parse_routes(document)
    assert {e.key for e in inventory.endpoints} == {
        "GET /api/things/{thing_id}",
        "POST /api/things",
    }
    assert inventory.warnings


# --------------------------------------------------------------------------- #
# Filtering
# --------------------------------------------------------------------------- #


def test_excluded_paths_are_dropped_with_a_warning(tmp_path: Path) -> None:
    config_file = tmp_path / "t.toml"
    config_file.write_text(
        '[target]\nbase_url = "http://127.0.0.1:8000"\n'
        '[probe]\nexclude_paths = ["/api/customers"]\n',
        encoding="utf-8",
    )
    config = load_config(config_file)
    inventory = parse_openapi(OPENAPI).filtered(config)
    assert not any(e.path == "/api/customers" for e in inventory.endpoints)
    assert any("exclude_paths" in w for w in inventory.warnings)


def test_truncation_is_announced_never_silent(tmp_path: Path) -> None:
    """Silently testing less than asked is the failure this tool exists to avoid."""
    config_file = tmp_path / "t.toml"
    config_file.write_text(
        '[target]\nbase_url = "http://127.0.0.1:8000"\n[probe]\nmax_endpoints = 2\n',
        encoding="utf-8",
    )
    config = load_config(config_file)
    inventory = parse_openapi(OPENAPI).filtered(config)
    assert len(inventory.endpoints) == 2
    assert any("truncated" in w for w in inventory.warnings)


def test_spec_path_defaults_to_the_targets_openapi_document(tmp_path: Path) -> None:
    """With no spec_path, the target's own /openapi.json is used — over HTTP."""
    config_file = tmp_path / "t.toml"
    config_file.write_text('[target]\nbase_url = "http://127.0.0.1:8000"\n', encoding="utf-8")
    config = load_config(config_file)
    with pytest.raises(SpecError, match="HTTP client is required"):
        load_inventory(config, None)


def test_spec_from_disk(tmp_path: Path) -> None:
    import json

    spec_file = tmp_path / "openapi.json"
    spec_file.write_text(json.dumps(OPENAPI), encoding="utf-8")
    config_file = tmp_path / "t.toml"
    # as_posix(), because a Windows path in a TOML basic string is a sequence
    # of escapes: `C:\Users\…` fails to parse at `\U`. Forward slashes are a
    # valid path on both platforms and survive the round trip.
    config_file.write_text(
        f'[target]\nbase_url = "http://127.0.0.1:8000"\nspec_path = "{spec_file.as_posix()}"\n',
        encoding="utf-8",
    )
    inventory = load_inventory(load_config(config_file), None)
    assert len(inventory) == 5


# --------------------------------------------------------------------------- #
# Path templating
# --------------------------------------------------------------------------- #


def test_substitute_path_fills_parameters() -> None:
    assert substitute_path("/api/x/{id}", {"id": "7"}) == "/api/x/7"


def test_unfilled_parameters_stay_visible() -> None:
    """A request still carrying {id} should be a visible bug, not a mangled URL."""
    assert substitute_path("/api/x/{id}", {}) == "/api/x/{id}"


def test_fallback_replaces_every_parameter() -> None:
    assert substitute_path("/api/{a}/{b}", {}, fallback="{}") == "/api/{}/{}"


def test_path_param_names() -> None:
    assert path_param_names("/api/{a}/x/{b}") == ("a", "b")


# --------------------------------------------------------------------------- #
# Truncation must not delete an area of the API
# --------------------------------------------------------------------------- #


def test_the_cap_keeps_every_area_of_the_api_represented() -> None:
    """Path order correlates with the API's own grouping, so cutting a sorted
    list drops whole subsystems. One real spec declared 704 operations and the
    cut landed mid-alphabet."""
    import collections

    from tenanttrace.probe.spec import _spread

    endpoints = [
        Endpoint(method=HttpMethod.GET, path=f"/api/{area}/{n}", path_params=())
        for area in ("alpha", "beta", "gamma", "delta", "omega")
        for n in range(20)
    ]
    kept = _spread(endpoints, 10)
    areas = collections.Counter(e.path.split("/")[2] for e in kept)
    assert len(kept) == 10
    assert set(areas) == {"alpha", "beta", "gamma", "delta", "omega"}


def test_the_reachable_surface_excludes_what_this_run_cannot_touch() -> None:
    from tenanttrace.probe.spec import EndpointInventory

    inventory = EndpointInventory(
        endpoints=(
            Endpoint(method=HttpMethod.GET, path="/api/x", path_params=()),
            Endpoint(method=HttpMethod.GET, path="/api/x/{id}", path_params=("id",)),
            Endpoint(method=HttpMethod.POST, path="/api/x", path_params=()),
        )
    )
    assert len(inventory) == 3
    assert len(inventory.reachable()) == 2
    assert len(inventory.reachable(allow_mutation=True)) == 3
