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
