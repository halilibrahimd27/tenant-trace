"""What an application that carries its tenant in the URL was getting.

Found by pointing the prober at a real Keycloak. Every route it serves is
shaped ``/admin/realms/{realm}/…``, so every collection had a path parameter —
and `collections()` required zero. Two of the five enabled attacks iterated an
empty tuple and sent not one request. The report named all five in
`attacks_run`, recorded no error, and read as a completed audit.

Three of the six real applications this tool has been pointed at are that
shape, and the listing attack's own docstring calls it the most common form of
this bug in practice. So the module most likely to find the bug was
structurally dead on the applications most likely to have it.

Two fixes, tested here, because either alone leaves the hole open: the
inventory now knows a tenant slot is not an object slot, and the runner reports
any attack that made no attempt whatever the reason.
"""

from __future__ import annotations

import httpx

from tenanttrace.core.config import TenancyConfig
from tenanttrace.core.models import Endpoint, HttpMethod, Verdict
from tenanttrace.probe.attacks.listing import ListingAttack
from tenanttrace.probe.attacks.param_override import ParamOverrideAttack
from tenanttrace.probe.spec import EndpointInventory
from tests.attack_harness import build_context

REALM = TenancyConfig(column="realm", path_params=("realm",)).tenant_path_params()

GROUPS = Endpoint(
    method=HttpMethod.GET, path="/admin/realms/{realm}/groups", path_params=("realm",)
)
ONE_GROUP = Endpoint(
    method=HttpMethod.GET,
    path="/admin/realms/{realm}/groups/{id}",
    path_params=("realm", "id"),
)
FLAT_LIST = Endpoint(method=HttpMethod.GET, path="/api/invoices")

INVENTORY = EndpointInventory((GROUPS, ONE_GROUP, FLAT_LIST))


# --------------------------------------------------------------------------- #
# The inventory
# --------------------------------------------------------------------------- #


def test_a_tenant_slot_does_not_make_a_collection_an_object() -> None:
    """`/admin/realms/{realm}/groups` addresses a collection that happens to
    live under a tenant. Classifying it as an object endpoint is what removed
    it from the listing surface entirely."""
    assert INVENTORY.collections(REALM) == (GROUPS, FLAT_LIST)
    assert INVENTORY.objects(REALM) == (ONE_GROUP,)


def test_without_tenant_params_the_old_partition_still_holds() -> None:
    """A caller that names no tenant slots gets the previous behaviour, which
    is correct for an API that has none."""
    assert INVENTORY.collections() == (FLAT_LIST,)
    assert set(INVENTORY.objects()) == {GROUPS, ONE_GROUP}


def test_every_endpoint_is_in_exactly_one_of_the_two() -> None:
    """The partition is what the attacks divide up between them; an endpoint in
    neither is an endpoint nothing probes."""
    for params in (REALM, frozenset()):
        both = [*INVENTORY.collections(params), *INVENTORY.objects(params)]
        assert sorted(e.key for e in both) == sorted(e.key for e in INVENTORY)


def test_reachable_counts_the_tenant_in_path_surface() -> None:
    """Coverage is reported against this number, so leaving collections out of
    it made the denominator wrong too."""
    assert len(INVENTORY.reachable(tenant_params=REALM)) == 3


# --------------------------------------------------------------------------- #
# The attacks that were dead
# --------------------------------------------------------------------------- #


def test_the_listing_attack_reaches_a_tenant_scoped_collection() -> None:
    seen: list[str] = []

    def app(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, text="[]", headers={"content-type": "text/plain"})

    ctx = build_context(app, endpoints=(GROUPS, ONE_GROUP))
    results = list(ListingAttack().run(_with_realm(ctx)))

    assert [r.endpoint.key for r in results] == [GROUPS.key]
    assert results[0].verdict is Verdict.ENFORCED
    assert seen and seen[0].endswith(f"/admin/realms/{ctx.victim_ctx.tenant_id}/groups")


def test_the_override_attack_reaches_a_tenant_scoped_collection() -> None:
    """`?realm=<victim>` on an endpoint that already names the realm in its
    path is exactly the confusion this attack exists to find."""
    seen: list[str] = []

    def app(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(403, text="{}", headers={"content-type": "text/plain"})

    ctx = build_context(app, endpoints=(GROUPS,))
    list(ParamOverrideAttack().run(_with_realm(ctx)))
    assert any("realm=" in url.split("?", 1)[-1] for url in seen), seen


def _with_realm(ctx: object) -> object:
    """Point a harness context at an API whose tenant slot is `{realm}`."""
    from tests.attack_harness import replace

    config = ctx.config.model_copy(  # type: ignore[attr-defined]
        update={"tenancy": TenancyConfig(column="realm", path_params=("realm",))}
    )
    return replace(ctx, config=config)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# The positive control's request budget
# --------------------------------------------------------------------------- #


def test_the_control_tries_endpoints_matching_a_seeded_kind_first() -> None:
    """The control stops at the first endpoint that returns the tenant's own
    data, so spec order decided its cost — and spec order is alphabetical.

    On Gitea every one of the four control passes sent exactly 35 requests
    before succeeding: a repository name substituted into
    /api/v1/admin/hooks/{id}, /api/v1/orgs/{org} and /api/v1/licenses/{name},
    three dozen requests at administrative routes with a garbage identifier,
    before the audit proper had begun.
    """
    from tenanttrace.core.models import TenantLabel
    from tenanttrace.probe.runner import _controls_first
    from tests.conftest import make_tenant

    licenses = Endpoint(method=HttpMethod.GET, path="/api/licenses/{name}", path_params=("name",))
    orgs = Endpoint(method=HttpMethod.GET, path="/api/orgs/{org}", path_params=("org",))
    repos = Endpoint(method=HttpMethod.GET, path="/api/repos/{id}", path_params=("id",))

    tenant = make_tenant(TenantLabel.A, record_ids=("r-1", "r-2"), kind="repo")
    ordered = _controls_first((licenses, orgs, repos), tenant)

    assert ordered[0] is repos, "the endpoint whose resource was seeded goes first"
    assert set(ordered) == {licenses, orgs, repos}, "nothing is dropped, only reordered"


def test_ordering_is_stable_when_nothing_matches() -> None:
    """No seeded kind matches, so there is no better guess than spec order —
    and the control still has to try, because an application may expose its
    data under a name the singulariser does not reach."""
    from tenanttrace.core.models import TenantLabel
    from tenanttrace.probe.runner import _controls_first
    from tests.conftest import make_tenant

    a = Endpoint(method=HttpMethod.GET, path="/api/alpha/{id}", path_params=("id",))
    b = Endpoint(method=HttpMethod.GET, path="/api/beta/{id}", path_params=("id",))
    tenant = make_tenant(TenantLabel.A, record_ids=("x",), kind="gamma")
    assert _controls_first((a, b), tenant) == (a, b)
