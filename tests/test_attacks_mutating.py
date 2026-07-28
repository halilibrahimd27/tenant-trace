"""The mass-assignment attack — the only module that writes to the target.

It is tested against a mock transport rather than a fixture app because most of
what needs pinning is not "does it find the bug". The vulnerable fixture already
proves that, in `make metrics`. What is untested there is everything the module
does when the target does *not* cooperate: a write accepted with no id in the
response, a resource with no delete route, a delete that is refused. Each of
those ends with a record this run created sitting inside somebody else's tenant,
and the promise is that the finding says so out loud.

A silent side effect is the worst thing an audit can leave behind, so the
warnings are treated here as behaviour under test, not as log lines.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence

import httpx
import pytest

from tenanttrace.core.models import (
    AttackName,
    Endpoint,
    HttpMethod,
    ProbeResult,
    TenantLabel,
    Verdict,
)
from tenanttrace.probe.attacks.base import AttackContext
from tenanttrace.probe.attacks.mass_assign import MassAssignAttack
from tests.attack_harness import Handler, replace
from tests.attack_harness import build_context as _build_context
from tests.conftest import make_tenant

CREATE = Endpoint(method=HttpMethod.POST, path="/api/invoices", body_fields=("title", "amount"))
DETAIL = Endpoint(
    method=HttpMethod.GET, path="/api/invoices/{invoice_id}", path_params=("invoice_id",)
)
REMOVE = Endpoint(
    method=HttpMethod.DELETE, path="/api/invoices/{invoice_id}", path_params=("invoice_id",)
)


def build_context(
    handler: Handler,
    *,
    endpoints: Sequence[Endpoint] = (CREATE,),
    allow_mutation: bool = True,
    allowlist: tuple[str, ...] = (),
) -> AttackContext:
    """The shared harness, defaulting to permission granted."""
    return _build_context(
        handler,
        endpoints=endpoints,
        allow_mutation=allow_mutation,
        allowlist=allowlist,
    )


def run(ctx: AttackContext) -> list[ProbeResult]:
    return list(MassAssignAttack().run(ctx))


def json_response(status: int, payload: object) -> httpx.Response:
    return httpx.Response(status, text=json.dumps(payload), headers={"content-type": "text/plain"})


# --------------------------------------------------------------------------- #
# It does not run unless it was allowed to
# --------------------------------------------------------------------------- #


def test_it_sends_nothing_without_permission() -> None:
    """Reaching this module unpermitted is a runner bug, not something to
    route around quietly — but it must still not write."""

    def refuse(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not be called
        raise AssertionError(f"a write was attempted without permission: {request.url}")

    assert run(build_context(refuse, allow_mutation=False)) == []


def test_it_sends_nothing_when_the_victim_has_no_tenant_id() -> None:
    """Without a victim selector there is no cross-tenant write to attempt,
    and posting a record with a blank owner would just create litter."""

    def refuse(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not be called
        raise AssertionError("posted with no victim tenant id")

    ctx = build_context(refuse)
    # Copied rather than rebuilt: make_tenant treats an empty id as "not given"
    # and substitutes a default, which is the opposite of what is under test.
    nameless = ctx.victim_ctx.model_copy(update={"tenant_id": ""})
    assert run(replace(ctx, victim_ctx=nameless)) == []


# --------------------------------------------------------------------------- #
# Endpoints it declines to attack still appear in the record
# --------------------------------------------------------------------------- #


def test_an_allowlisted_creator_is_reported_not_silently_skipped() -> None:
    """Silence reads exactly like an endpoint that was checked and held."""

    def refuse(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not be called
        raise AssertionError("attacked an allowlisted endpoint")

    results = run(build_context(refuse, allowlist=("/api/invoices",)))
    assert [r.verdict for r in results] == [Verdict.INCONCLUSIVE]
    assert "cross_tenant_allowlist" in results[0].detail


def test_a_creator_whose_path_cannot_be_built_is_reported() -> None:
    """`creators()` includes POSTs carrying path parameters. The template was
    once sent verbatim, so 190 of 218 exchanges in one run held a literal
    %7Bid%7D and their 404s were reported as the target refusing a write."""
    nested = Endpoint(
        method=HttpMethod.POST, path="/api/projects/{project_id}/invoices", path_params=("wat",)
    )

    def refuse(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not be called
        raise AssertionError(f"sent a request to an unbuildable path: {request.url}")

    ctx = build_context(refuse, endpoints=(nested,))
    # The actor's records are invoices, so strip them to leave the path
    # genuinely unfillable.
    bare = make_tenant(TenantLabel.A, record_ids=())
    results = run(replace(ctx, actor_ctx=bare))
    assert [r.verdict for r in results] == [Verdict.INCONCLUSIVE]
    assert "no real URL could be built" in results[0].detail


# --------------------------------------------------------------------------- #
# The body
# --------------------------------------------------------------------------- #


def test_the_ownership_column_is_added_even_when_undeclared() -> None:
    """Undeclared fields being silently bound is the entire vulnerability, so
    the column goes in whether or not the schema mentions it."""
    seen: list[dict[str, object]] = []

    def capture(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return json_response(422, {"detail": "no"})

    ctx = build_context(capture)
    run(ctx)
    assert seen[0]["tenant_id"] == ctx.victim_ctx.tenant_id
    assert "title" in seen[0] and "amount" in seen[0]


def test_an_endpoint_with_no_declared_fields_still_gets_a_plausible_body() -> None:
    """An empty POST is rejected by validation before it can test anything."""
    seen: list[dict[str, object]] = []

    def capture(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return json_response(422, {"detail": "no"})

    schemaless = Endpoint(method=HttpMethod.POST, path="/api/invoices")
    ctx = build_context(capture, endpoints=(schemaless,))
    run(ctx)
    assert set(seen[0]) == {"title", "name", "tenant_id"}
    assert ctx.actor_ctx.canary in str(seen[0]["title"])
    assert "safe to delete" in str(seen[0]["title"])


# --------------------------------------------------------------------------- #
# Reading the record back as the victim
# --------------------------------------------------------------------------- #


def test_a_record_the_victim_can_read_is_a_confirmed_cross_tenant_write() -> None:
    """The response echoed no owner, so the proof is the follow-up read."""

    def app(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return json_response(201, {"id": "new-1", "title": "x"})
        if request.method == "GET":
            return json_response(200, {"id": "new-1", "title": "x"})
        return httpx.Response(204)

    results = run(build_context(app, endpoints=(CREATE, DETAIL, REMOVE)))
    assert [r.verdict for r in results] == [Verdict.LEAKED]
    assert "readable by tenant B" in results[0].detail
    assert results[0].evidence.matched_ids == ("new-1",)


def test_a_detail_route_that_ignores_the_id_does_not_confirm_anything() -> None:
    """A 2xx is not enough: the route may return a collection or an unrelated
    object, and "the victim can read it" would then be true of a request that
    never reached the record we created."""

    def app(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return json_response(201, {"id": "new-1"})
        return json_response(200, {"items": [{"id": "something-else"}]})

    results = run(build_context(app, endpoints=(CREATE, DETAIL)))
    assert [r.verdict for r in results] == [Verdict.INCONCLUSIVE]


def test_a_refused_read_back_leaves_the_verdict_alone() -> None:
    def app(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return json_response(201, {"id": "new-1"})
        return json_response(403, {"detail": "no"})

    results = run(build_context(app, endpoints=(CREATE, DETAIL)))
    assert [r.verdict for r in results] == [Verdict.INCONCLUSIVE]


def test_no_detail_route_means_no_confirmation_attempt() -> None:
    """Nothing to read the record back with; the verdict stays undecided
    rather than being upgraded on a guess."""

    def app(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST", f"unexpected {request.method} with no detail route"
        return json_response(201, {"id": "new-1"})

    results = run(build_context(app, endpoints=(CREATE,)))
    assert [r.verdict for r in results] == [Verdict.INCONCLUSIVE]


def test_an_application_that_says_the_record_stayed_is_believed() -> None:
    """ENFORCED is a positive statement. Overriding it on a follow-up read
    reported a confirmed critical against an application that behaved."""

    def app(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return json_response(201, {"id": "new-1", "tenant_id": "tenant-a"})
        return json_response(200, {"id": "new-1"})

    results = run(build_context(app, endpoints=(CREATE, DETAIL, REMOVE)))
    assert [r.verdict for r in results] == [Verdict.ENFORCED]


# --------------------------------------------------------------------------- #
# Cleanup — and saying so when there was none
# --------------------------------------------------------------------------- #


def test_a_created_record_is_deleted_and_the_finding_says_so() -> None:
    deleted: list[str] = []

    def app(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return json_response(201, {"id": "new-1"})
        if request.method == "DELETE":
            deleted.append(str(request.url))
            return httpx.Response(204)
        return json_response(200, {"id": "new-1"})

    results = run(build_context(app, endpoints=(CREATE, DETAIL, REMOVE)))
    assert deleted and deleted[0].endswith("/api/invoices/new-1")
    assert "was deleted" in results[0].detail


def test_a_write_with_no_id_in_the_response_is_warned_about_loudly() -> None:
    """There is a record somewhere — possibly inside the other tenant — that
    this run created and cannot locate. Saying nothing leaves the operator to
    discover it later, which is the worst way to learn an audit wrote data."""

    def app(request: httpx.Request) -> httpx.Response:
        return json_response(201, {"status": "created"})

    results = run(build_context(app, endpoints=(CREATE,)))
    assert "WARNING" in results[0].detail
    assert "could not be located or removed" in results[0].detail


def test_a_rejected_write_with_no_id_warns_about_nothing() -> None:
    """Nothing was created, so there is nothing to confess to."""

    def app(request: httpx.Request) -> httpx.Response:
        return json_response(422, {"detail": "tenant_id is not accepted"})

    results = run(build_context(app, endpoints=(CREATE,)))
    assert "WARNING" not in results[0].detail
    assert results[0].verdict is Verdict.ENFORCED


def test_a_resource_with_no_delete_route_is_reported_as_left_behind() -> None:
    def app(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return json_response(201, {"id": "new-1"})
        return json_response(200, {"id": "new-1"})

    results = run(build_context(app, endpoints=(CREATE, DETAIL)))
    assert "was left in place" in results[0].detail
    assert "no delete route" in results[0].detail


def test_a_delete_that_is_refused_by_both_tenants_is_reported() -> None:
    """Tried as the victim first — if the write really crossed tenants, the
    victim is the one authorised to remove it."""
    attempts: list[str] = []

    def app(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return json_response(201, {"id": "new-1"})
        if request.method == "DELETE":
            attempts.append(request.headers.get("authorization", ""))
            return json_response(403, {"detail": "no"})
        return json_response(200, {"id": "new-1"})

    results = run(build_context(app, endpoints=(CREATE, DETAIL, REMOVE)))
    assert len(attempts) == 2, "both tenants should have been tried"
    assert "could not be deleted" in results[0].detail
    assert "remove it manually" in results[0].detail


# --------------------------------------------------------------------------- #
# Field values are inferred from the field name
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("field", "check"),
    [
        ("email", lambda v: v == "tenanttrace@example.invalid"),
        ("contact_mail", lambda v: v == "tenanttrace@example.invalid"),
        ("amount", lambda v: v == 1),
        ("quantity", lambda v: v == 1),
        ("description", lambda v: "safe to delete" in str(v)),
        ("reference", lambda v: str(v).startswith("tt-canary-A-")),
    ],
)
def test_sample_values_are_plausible_for_the_field_name(
    field: str, check: Callable[[object], bool]
) -> None:
    """There is no schema type here, only a name — and a body that fails
    validation tests nothing at all."""
    from tenanttrace.probe.attacks.mass_assign import _sample_value

    assert check(_sample_value(field, "tt-canary-A-deadbeefcafe0001"))


def test_the_attack_is_the_only_mutating_one() -> None:
    """If a second one ever lands, --allow-mutation has to grow to cover it."""
    mutating = [name for name in AttackName if name.is_mutating]
    assert mutating == [AttackName.MASS_ASSIGN]
