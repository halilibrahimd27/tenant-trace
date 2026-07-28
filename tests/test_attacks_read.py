"""The two read attacks, on the paths the fixture apps cannot produce.

`make metrics` already proves that IDOR and listing find the holes in the
deliberately leaky app. What it does not exercise is what they do when a leak
turns out not to be a tenant-scoping failure at all, or when there was nothing
to send in the first place. Both of those decide whether the report blames the
right control — and blaming the wrong one sends the reader to add a WHERE clause
that is either already there or has no caller to scope to.
"""

from __future__ import annotations

import json

import httpx

from tenanttrace.core.models import Category, Endpoint, HttpMethod, ProbeResult, Verdict
from tenanttrace.probe.attacks.base import AttackContext
from tenanttrace.probe.attacks.idor import IdorAttack
from tenanttrace.probe.attacks.listing import ListingAttack
from tests.attack_harness import build_context, replace

DETAIL = Endpoint(
    method=HttpMethod.GET, path="/api/invoices/{invoice_id}", path_params=("invoice_id",)
)
LIST = Endpoint(method=HttpMethod.GET, path="/api/invoices")

VICTIM_CANARY = "tt-canary-B-deadbeefcafe0001"


def idor(ctx: AttackContext) -> list[ProbeResult]:
    return list(IdorAttack().run(ctx))


def listing(ctx: AttackContext) -> list[ProbeResult]:
    return list(ListingAttack().run(ctx))


def text_response(status: int, payload: object) -> httpx.Response:
    """A JSON body served as text/plain, so nothing decodes it for us."""
    return httpx.Response(status, text=json.dumps(payload), headers={"content-type": "text/plain"})


# --------------------------------------------------------------------------- #
# IDOR: endpoints it did not attack must still be visible
# --------------------------------------------------------------------------- #


def test_an_allowlisted_object_endpoint_is_recorded_not_skipped_silently() -> None:
    """An endpoint that appears nowhere reads exactly like one that was checked
    and held."""

    def refuse(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not be called
        raise AssertionError("attacked an allowlisted endpoint")

    results = idor(build_context(refuse, endpoints=(DETAIL,), allowlist=("/api/invoices/*",)))
    assert [r.verdict for r in results] == [Verdict.INCONCLUSIVE]
    assert "cross_tenant_allowlist" in results[0].detail


def test_an_endpoint_with_no_seeded_id_is_recorded_as_untested() -> None:
    """Nothing cross-tenant could be requested, which is not the same as an
    endpoint that refused something."""

    def refuse(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not be called
        raise AssertionError(f"requested {request.url} with no seeded id")

    ctx = build_context(refuse, endpoints=(DETAIL,), victim_records=())
    results = idor(replace(ctx, victim_ctx=ctx.victim_ctx.model_copy(update={"records": ()})))
    assert [r.verdict for r in results] == [Verdict.INCONCLUSIVE]
    assert "no seeded record matches" in results[0].detail


# --------------------------------------------------------------------------- #
# IDOR: a leak anybody can reproduce is a different bug (ADR-0011)
# --------------------------------------------------------------------------- #


def test_a_leak_an_anonymous_request_also_gets_is_a_public_endpoint() -> None:
    """Squidex serves asset content from an unscoped /api/assets/{id}, and the
    report told the reader to add a tenant predicate to a query that has no
    caller to scope to."""

    def serves_everybody(request: httpx.Request) -> httpx.Response:
        return text_response(200, {"id": "b-1", "title": VICTIM_CANARY})

    results = idor(build_context(serves_everybody, endpoints=(DETAIL,), with_anonymous=True))
    assert [r.verdict for r in results] == [Verdict.LEAKED]
    assert results[0].category_of() is Category.PUBLIC_ENDPOINT
    assert "no credential at all" in results[0].detail


def test_a_leak_the_anonymous_request_does_not_get_stays_a_scoping_failure() -> None:
    def needs_a_credential(request: httpx.Request) -> httpx.Response:
        if not request.headers.get("authorization"):
            return text_response(401, {"detail": "unauthenticated"})
        return text_response(200, {"id": "b-1", "title": VICTIM_CANARY})

    results = idor(build_context(needs_a_credential, endpoints=(DETAIL,), with_anonymous=True))
    assert [r.verdict for r in results] == [Verdict.LEAKED]
    assert results[0].category_of() is Category.CROSS_TENANT_READ


def test_without_an_anonymous_session_the_scoping_category_stands() -> None:
    """`serves_anyone` errs towards keeping the original category rather than
    guessing that a route it could not test is public."""

    def leaks(request: httpx.Request) -> httpx.Response:
        return text_response(200, {"id": "b-1", "title": VICTIM_CANARY})

    results = idor(build_context(leaks, endpoints=(DETAIL,), with_anonymous=False))
    assert results[0].category_of() is Category.CROSS_TENANT_READ


def test_one_proven_leak_per_endpoint_is_enough() -> None:
    """Continuing would add an identical finding for every remaining id and
    bury the rest of the report."""
    seen: list[str] = []

    def leaks(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return text_response(200, {"title": VICTIM_CANARY})

    ctx = build_context(leaks, endpoints=(DETAIL,), victim_records=("b-1", "b-2", "b-3"))
    results = idor(ctx)
    assert len(results) == 1
    assert len(seen) == 1, "stopped after the first proven leak"


# --------------------------------------------------------------------------- #
# Listing: shared reference data is not a leak
# --------------------------------------------------------------------------- #


def test_identical_rows_for_both_tenants_are_shared_data_not_a_leak() -> None:
    """A company-wide directory listing `tenant_id: <b>` is a phone book, not
    tenant B's private records — every tenant is meant to see it. Ownership
    evidence is the weakest of the three signals and this is its failure mode.
    """
    directory = {"results": [{"name": "Support", "tenant_id": "tenant-b"}]}

    def same_for_everybody(request: httpx.Request) -> httpx.Response:
        return text_response(200, directory)

    results = listing(build_context(same_for_everybody, endpoints=(LIST,)))
    assert [r.verdict for r in results] == [Verdict.ENFORCED]
    assert "shared reference data" in results[0].detail
    assert "does not own the row" in results[0].detail


def test_different_rows_per_tenant_keep_the_leak() -> None:
    """The differential is what settles it: if the victim sees something else,
    the actor was served data that is not shared."""

    def differs(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization", "").endswith("B"):
            return text_response(200, {"results": [{"name": "B's own", "tenant_id": "tenant-b"}]})
        return text_response(200, {"results": [{"name": "leaked", "tenant_id": "tenant-b"}]})

    results = listing(build_context(differs, endpoints=(LIST,)))
    assert [r.verdict for r in results] == [Verdict.LEAKED]
    assert "naming tenant B as the owner" in results[0].detail


def test_a_canary_is_never_downgraded_to_shared_data() -> None:
    """Only ownership-field evidence is weak enough to need the differential.
    A canary we planted is conclusive however many tenants see it."""

    def leaks_the_canary(request: httpx.Request) -> httpx.Response:
        return text_response(200, {"results": [{"title": VICTIM_CANARY}]})

    results = listing(build_context(leaks_the_canary, endpoints=(LIST,)))
    assert [r.verdict for r in results] == [Verdict.LEAKED]
    assert results[0].evidence.matched_canary == VICTIM_CANARY


def test_a_mirror_request_the_victim_cannot_make_leaves_the_leak_standing() -> None:
    """No differential could be established, so the finding is not softened."""

    def only_the_actor(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization", "").endswith("B"):
            return text_response(403, {"detail": "no"})
        return text_response(200, {"results": [{"tenant_id": "tenant-b"}]})

    results = listing(build_context(only_the_actor, endpoints=(LIST,)))
    assert [r.verdict for r in results] == [Verdict.LEAKED]


def test_non_json_bodies_are_compared_as_text() -> None:
    """A CSV export is a perfectly ordinary collection response."""

    def csv_for_everybody(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text="name,tenant_id\nSupport,tenant-b\n",
            headers={"content-type": "text/csv"},
        )

    results = listing(build_context(csv_for_everybody, endpoints=(LIST,)))
    # No JSON body means the ownership signal cannot fire at all, so the
    # collection reads as enforced — and that is the honest answer, not a
    # silent pass: the run's evidence-basis line reports which signals it used.
    assert [r.verdict for r in results] == [Verdict.ENFORCED]


def test_an_allowlisted_collection_is_recorded_not_skipped_silently() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not be called
        raise AssertionError("attacked an allowlisted collection")

    results = listing(build_context(refuse, endpoints=(LIST,), allowlist=("/api/invoices",)))
    assert [r.verdict for r in results] == [Verdict.INCONCLUSIVE]
    assert "cross_tenant_allowlist" in results[0].detail


def test_a_mirror_that_is_not_json_is_compared_as_text() -> None:
    """The differential still has to work when one side is a CSV export or an
    HTML error page: comparing a decoded body against `None` would silently
    treat every such pair as different."""

    def json_for_a_csv_for_b(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization", "").endswith("B"):
            return httpx.Response(200, text="name,tenant\nSupport,tenant-b\n")
        return text_response(200, {"results": [{"tenant_id": "tenant-b"}]})

    results = listing(build_context(json_for_a_csv_for_b, endpoints=(LIST,)))
    assert [r.verdict for r in results] == [Verdict.LEAKED], "the payloads differ, so it stands"
