"""Filling an endpoint's path parameters for a cross-tenant request.

Three of the six real applications this tool has been pointed at carry the
tenant in the path — Chatwoot ``/api/v1/accounts/{account_id}/...``, Squidex
``/api/content/{app}/...``, Keycloak ``/admin/realms/{realm}/...``. That is the
canonical BOLA shape, and it was untestable while one object id went into every
slot.
"""

from __future__ import annotations

import pytest

from tenanttrace.core.config import TenancyConfig
from tenanttrace.core.models import Endpoint, HttpMethod, TenantContext, TenantLabel
from tenanttrace.probe.attacks.base import build_path, is_speculative_path, object_params


def endpoint(path: str, *params: str) -> Endpoint:
    return Endpoint(method=HttpMethod.GET, path=path, path_params=params)


VICTIM = TenantContext(label=TenantLabel.B, tenant_id="2", canary="tt-canary-B-abcdef01")
DEFAULTS = TenancyConfig().tenant_path_params()


def test_the_tenant_slot_takes_the_tenant_and_the_object_slot_the_object() -> None:
    path = build_path(
        endpoint("/api/v1/accounts/{account_id}/conversations/{id}", "account_id", "id"),
        "77",
        tenant=VICTIM,
        tenant_params=DEFAULTS,
    )
    assert path == "/api/v1/accounts/2/conversations/77"


@pytest.mark.parametrize("param", ["account_id", "accountId", "account-id", "tenant_id"])
def test_the_tenant_slot_is_recognised_however_it_is_spelled(param: str) -> None:
    path = build_path(
        endpoint(f"/api/{{{param}}}/things/{{id}}", param, "id"),
        "77",
        tenant=VICTIM,
        tenant_params=DEFAULTS,
    )
    assert path == "/api/2/things/77"


def test_an_api_that_names_the_segment_something_else_can_say_so() -> None:
    """Squidex uses {app}; Keycloak uses {realm}. Neither ends in _id."""
    params = TenancyConfig(path_params=("app", "realm")).tenant_path_params()
    assert (
        build_path(
            endpoint("/api/content/{app}/posts/{id}", "app", "id"),
            "abc",
            tenant=VICTIM,
            tenant_params=params,
        )
        == "/api/content/2/posts/abc"
    )


def test_without_a_tenant_every_slot_still_takes_the_identifier() -> None:
    """The old behaviour, kept for endpoints with no tenant segment."""
    assert build_path(endpoint("/api/x/{a}/y/{b}", "a", "b"), "9") == "/api/x/9/y/9"


def test_a_tenant_slot_does_not_make_a_path_speculative() -> None:
    """It is filled with a real value, so nothing about it was guessed."""
    two = endpoint("/api/v1/accounts/{account_id}/conversations/{id}", "account_id", "id")
    assert object_params(two, DEFAULTS) == 1
    assert not is_speculative_path(two, DEFAULTS)


def test_two_object_slots_are_still_speculative() -> None:
    both = endpoint("/api/{doc_id}/versions/{version_id}", "doc_id", "version_id")
    assert object_params(both, DEFAULTS) == 2
    assert is_speculative_path(both, DEFAULTS)


def test_a_single_object_slot_is_exact() -> None:
    assert not is_speculative_path(endpoint("/api/invoices/{id}", "id"), DEFAULTS)


# --------------------------------------------------------------------------- #
# A result may overrule the category its attack would have assigned
# --------------------------------------------------------------------------- #


def test_a_result_defaults_to_its_attack_category() -> None:
    from tenanttrace.core.models import AttackName, Category, ProbeResult, TenantLabel, Verdict

    result = ProbeResult(
        attack=AttackName.IDOR,
        endpoint=endpoint("/api/x/{id}", "id"),
        actor=TenantLabel.A,
        target=TenantLabel.B,
        verdict=Verdict.LEAKED,
    )
    assert result.category_of() is Category.CROSS_TENANT_READ


def test_an_attack_that_establishes_a_differential_can_overrule_itself() -> None:
    from tenanttrace.core.models import AttackName, Category, ProbeResult, TenantLabel, Verdict

    result = ProbeResult(
        attack=AttackName.IDOR,
        endpoint=endpoint("/api/x/{id}", "id"),
        actor=TenantLabel.A,
        target=TenantLabel.B,
        verdict=Verdict.LEAKED,
        category=Category.PUBLIC_ENDPOINT,
    )
    assert result.category_of() is Category.PUBLIC_ENDPOINT


# --------------------------------------------------------------------------- #
# resource_name: the segment before the LAST parameter, not the first
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("path", "params", "expected"),
    [
        ("/api/v1/accounts/{account_id}/contacts/{id}", ("account_id", "id"), "contact"),
        ("/admin/realms/{realm}/users/{user-id}", ("realm", "user-id"), "user"),
        ("/api/content/{app}/{schema}/{id}", ("app", "schema", "id"), "content"),
        ("/api/invoices/{id}", ("id",), "invoice"),
        ("/public/api/v1/inboxes/{inbox_identifier}", ("inbox_identifier",), "inbox"),
        ("/api/entries/{id}", ("id",), "entry"),
        ("/api/classes/{id}", ("id",), "class"),
        ("/api/database/rows/table/{table_id}/", ("table_id",), "table"),
    ],
)
def test_resource_name(path: str, params: tuple[str, ...], expected: str) -> None:
    """Breaking at the first { made all 209 Keycloak endpoints resolve to 'realm'."""
    from tenanttrace.probe.attacks.base import resource_name

    assert resource_name(endpoint(path, *params)) == expected


# --------------------------------------------------------------------------- #
# A request that addressed nothing is not evidence of enforcement
# --------------------------------------------------------------------------- #


def test_an_id_of_the_wrong_kind_makes_the_path_speculative() -> None:
    """A Contact id sent to /Campaign/{id} 404s because no such campaign exists."""
    one_slot = endpoint("/api/v1/Campaign/{id}", "id")
    assert is_speculative_path(one_slot, DEFAULTS, matched_kind=False)
    assert not is_speculative_path(one_slot, DEFAULTS, matched_kind=True)


def test_kind_matching_does_not_rescue_a_multi_slot_path() -> None:
    both = endpoint("/api/{doc_id}/versions/{version_id}", "doc_id", "version_id")
    assert is_speculative_path(both, DEFAULTS, matched_kind=True)


def test_candidate_ids_says_whether_it_knew_what_it_was_doing() -> None:
    from tenanttrace.core.models import SeededRecord
    from tenanttrace.probe.attacks.base import candidate_ids

    tenant = TenantContext(
        label=TenantLabel.B,
        tenant_id="2",
        canary="tt-canary-B-abcdef01",
        records=(
            SeededRecord(kind="contact", id="ct-1", canary="c1", owner=TenantLabel.B),
            SeededRecord(kind="lead", id="ld-1", canary="c2", owner=TenantLabel.B),
        ),
    )
    matched = candidate_ids(endpoint("/api/contacts/{id}", "id"), tenant)
    assert matched.matched_kind and matched.ids == ("ct-1",)

    guessed = candidate_ids(endpoint("/api/campaigns/{id}", "id"), tenant)
    assert not guessed.matched_kind
    assert set(guessed.ids) == {"ct-1", "ld-1"}


# --------------------------------------------------------------------------- #
# Slots that no identifier can fill
# --------------------------------------------------------------------------- #


def test_a_record_can_name_the_parents_that_lead_to_it() -> None:
    """A row cannot be addressed from a row id alone."""
    nested = endpoint("/api/database/rows/table/{table_id}/rows/{row_id}", "table_id", "row_id")
    assert (
        build_path(nested, "1", path_values={"table_id": "38"})
        == "/api/database/rows/table/38/rows/1"
    )


def test_a_slot_naming_a_type_can_be_pinned_to_a_literal() -> None:
    """Squidex routes content as /api/content/{app}/{schema}/{id}; no seeded
    id belongs in {schema}, and without a literal the endpoint is unprobeable."""
    content = endpoint("/api/content/{app}/{schema}/{id}", "app", "schema", "id")
    path = build_path(
        content,
        "abc",
        tenant=VICTIM,
        tenant_params=TenancyConfig(path_params=("app",)).tenant_path_params(),
        literals={"schema": "notes"},
    )
    assert path == "/api/content/2/notes/abc"


def test_a_record_beats_a_literal_because_only_it_knows_its_own_parents() -> None:
    nested = endpoint("/api/t/{table_id}/rows/{row_id}", "table_id", "row_id")
    path = build_path(nested, "1", path_values={"table_id": "38"}, literals={"table_id": "9"})
    assert path == "/api/t/38/rows/1"


def test_a_filled_slot_does_not_make_a_path_speculative() -> None:
    """It holds a real value, so nothing about it was guessed."""
    nested = endpoint("/api/t/{table_id}/rows/{row_id}", "table_id", "row_id")
    assert is_speculative_path(nested, DEFAULTS)
    assert not is_speculative_path(nested, DEFAULTS, known={"table_id": "38"})
