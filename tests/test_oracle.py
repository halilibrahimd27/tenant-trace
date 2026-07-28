"""The oracle decides every finding, so it gets the most adversarial tests.

Two properties matter above all others and are stated here as Hypothesis
properties rather than examples:

1. **No false negatives on placement.** A canary must be found wherever an API
   can put it — nested objects, arrays, object *keys*, raw non-JSON text.
2. **No false positives on the actor's own data.** A response containing only
   tenant A's canary must never be judged a leak, whatever else it contains.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tenanttrace.core.models import TenantLabel, Verdict
from tenanttrace.probe.oracle import (
    CANARY_RE,
    AccessMode,
    TenantOracle,
    facts_from_parts,
    iter_json_strings,
    make_canary,
    scan_for_markers,
)
from tests.conftest import make_tenant


@pytest.fixture
def oracle():  # type: ignore[no-untyped-def]
    return TenantOracle(
        actor=make_tenant(TenantLabel.A, record_ids=("a-1", "a-2")),
        victim=make_tenant(TenantLabel.B, record_ids=("b-1", "b-2")),
    )


# --------------------------------------------------------------------------- #
# Canary shape
# --------------------------------------------------------------------------- #


def test_canaries_are_unique_and_well_formed() -> None:
    canaries = {make_canary(TenantLabel.B) for _ in range(200)}
    assert len(canaries) == 200, "canaries must not collide"
    for canary in canaries:
        assert CANARY_RE.fullmatch(canary), canary


def test_canary_carries_its_tenant_label() -> None:
    assert make_canary(TenantLabel.A).startswith("tt-canary-A-")
    assert make_canary(TenantLabel.B).startswith("tt-canary-B-")


# --------------------------------------------------------------------------- #
# Scanning — property tests
# --------------------------------------------------------------------------- #

_JSON_LEAVES = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1000, max_value=1000),
    st.text(max_size=20),
)


@st.composite
def _nested_json(draw: st.DrawFn, marker: str) -> object:
    """A JSON document with ``marker`` buried somewhere inside it."""
    leaf = st.one_of(_JSON_LEAVES, st.just(marker))
    document = draw(
        st.recursive(
            leaf,
            lambda children: st.one_of(
                st.lists(children, max_size=4),
                st.dictionaries(st.text(max_size=8), children, max_size=4),
            ),
            max_leaves=12,
        )
    )
    # Guarantee the marker really is present, wherever the draw put it.
    return {"data": document, "extra": [{"note": marker}]}


@pytest.mark.property
@given(marker=st.just("tt-canary-B-0123456789abcdef"), data=st.data())
def test_scanner_finds_a_canary_anywhere_in_a_json_document(
    marker: str, data: st.DataObject
) -> None:
    document = data.draw(_nested_json(marker))
    facts = facts_from_parts(status=200, text=json.dumps(document))
    assert scan_for_markers(facts, [marker]) == (marker,)


@pytest.mark.property
@given(
    prefix=st.text(alphabet="abcdefghijklmnopqrstuvwxyz <>{}\"',", max_size=200),
    suffix=st.text(alphabet="abcdefghijklmnopqrstuvwxyz <>{}\"',", max_size=200),
)
def test_scanner_finds_a_canary_in_arbitrary_non_json_text(prefix: str, suffix: str) -> None:
    """The oracle is format-agnostic: HTML, CSV, a template render, anything."""
    marker = "tt-canary-B-0123456789abcdef"
    facts = facts_from_parts(status=200, text=f"{prefix}{marker}{suffix}")
    assert scan_for_markers(facts, [marker]) == (marker,)


@pytest.mark.property
@given(payload=st.text(max_size=500))
def test_scanner_never_reports_a_marker_that_is_absent(payload: str) -> None:
    marker = "tt-canary-B-0123456789abcdef"
    facts = facts_from_parts(status=200, text=payload.replace(marker, ""))
    assert scan_for_markers(facts, [marker]) == ()


@pytest.mark.property
@given(noise=st.text(max_size=200))
def test_actors_own_canary_is_never_a_leak(noise: str) -> None:
    """The single most important false-positive guard in the tool."""
    actor = make_tenant(TenantLabel.A, canary="tt-canary-A-aaaaaaaaaaaaaaaa")
    victim = make_tenant(TenantLabel.B, canary="tt-canary-B-bbbbbbbbbbbbbbbb")
    oracle = TenantOracle(actor=actor, victim=victim)

    body = json.dumps({"items": [{"title": f"{actor.canary} {noise}"}]})
    decision = oracle.judge(facts_from_parts(status=200, text=body), mode=AccessMode.COLLECTION)
    assert decision.verdict is Verdict.ENFORCED


def test_empty_marker_never_matches() -> None:
    """An empty needle is in every haystack; it must not report a leak."""
    facts = facts_from_parts(status=200, text="anything at all")
    assert scan_for_markers(facts, ["", None or ""]) == ()


def test_scanner_sees_identifiers_used_as_object_keys() -> None:
    body = json.dumps({"b-1": {"title": "something"}})
    facts = facts_from_parts(status=200, text=body)
    assert scan_for_markers(facts, ["b-1"]) == ("b-1",)


def test_iter_json_strings_is_depth_bounded() -> None:
    """A pathological body must not blow the stack of a CI job."""
    document: object = "tt-canary-B-0123456789abcdef"
    for _ in range(500):
        document = [document]
    assert list(iter_json_strings(document, max_depth=64)) == []


# --------------------------------------------------------------------------- #
# The verdict table
# --------------------------------------------------------------------------- #


def test_canary_in_response_is_a_confirmed_leak(oracle: TenantOracle) -> None:
    body = json.dumps({"title": oracle.victim.canary})
    decision = oracle.judge(facts_from_parts(status=200, text=body), mode=AccessMode.OBJECT)
    assert decision.verdict is Verdict.LEAKED
    assert decision.matched_canary == oracle.victim.canary


def test_echoed_request_id_is_not_evidence(oracle: TenantOracle) -> None:
    """A 404 that names the id you asked for is correct behaviour, not a leak.

    This is why identifiers are secondary evidence: without excluding the ids
    we sent, every well-behaved 'Invoice <id> not found' would be a critical.
    """
    body = json.dumps({"detail": "Invoice b-1 not found"})
    decision = oracle.judge(
        facts_from_parts(status=404, text=body), mode=AccessMode.OBJECT, sent_ids=["b-1"]
    )
    assert decision.verdict is Verdict.ENFORCED


def test_an_echoed_filter_is_not_ownership_evidence(oracle: TenantOracle) -> None:
    """The parameter-override attack asks for `?tenant_id=<victim>`.

    An endpoint that repeats its filters back — `{"filters": {"tenant_id": …},
    "results": []}` — would otherwise confirm a critical cross-tenant read
    whose response contains no rows at all. Same class of defect the echoed-id
    guard exists for, arriving through the ownership signal instead.
    """
    victim_id = oracle.victim.tenant_id
    body = json.dumps({"filters": {"tenant_id": victim_id}, "results": []})
    decision = oracle.judge(
        facts_from_parts(
            status=200,
            text=body,
            request_url=f"http://127.0.0.1:8000/api/invoices?tenant_id={victim_id}",
        ),
        mode=AccessMode.COLLECTION,
    )
    assert decision.verdict is Verdict.ENFORCED
    assert not decision.matched_ids


def test_an_echoed_body_field_is_not_ownership_evidence(oracle: TenantOracle) -> None:
    victim_id = oracle.victim.tenant_id
    facts = facts_from_parts(
        status=422,
        text=json.dumps({"tenant_id": victim_id, "error": "unknown tenant"}),
        request_url="http://127.0.0.1:8000/api/invoices",
        request_body=json.dumps({"tenant_id": victim_id}),
    )
    assert oracle.owner_fields(facts, oracle.victim) == ()


def test_a_tenant_in_the_path_still_names_an_owner(oracle: TenantOracle) -> None:
    """The guard must not reach the path, or it would break the controls.

    Three of six real targets carry the tenant in the URL, so the caller's own
    selector is in every request it makes — including the positive control,
    which leans on this signal when the application has no field a canary can
    live in.
    """
    victim_id = oracle.victim.tenant_id
    facts = facts_from_parts(
        status=200,
        text=json.dumps({"id": "x", "tenant_id": victim_id}),
        request_url=f"http://127.0.0.1:8000/api/accounts/{victim_id}/invoices/7",
    )
    assert oracle.owner_fields(facts, oracle.victim) == (f"tenant_id={victim_id}",)


def test_unsent_victim_id_is_a_leak() -> None:
    sent = "018f4c1e-3a9b-7c2d-9e5f-1a2b3c4d5e60"
    other = "018f4c1e-3a9b-7c2d-9e5f-1a2b3c4d5e6f"
    oracle = TenantOracle(
        actor=make_tenant(TenantLabel.A),
        victim=make_tenant(TenantLabel.B, record_ids=(sent, other)),
    )
    body = json.dumps({"items": [{"id": other}]})
    decision = oracle.judge(
        facts_from_parts(status=200, text=body), mode=AccessMode.COLLECTION, sent_ids=[sent]
    )
    assert decision.verdict is Verdict.LEAKED
    assert decision.matched_ids == (other,)


# --------------------------------------------------------------------------- #
# Identifier evidence has to be worth something
# --------------------------------------------------------------------------- #


def test_short_numeric_ids_are_never_evidence() -> None:
    """The false positive that would fire on every Rails/Django/Laravel app.

    With auto-increment keys the victim owns ids 4, 5, 6 — and those digits
    appear inside the actor's *own* data: in an amount, a timestamp, a tenant
    slug, the hex of the actor's own canary. Substring-matching them reported a
    confirmed critical leak on a perfectly isolated response.
    """
    actor = make_tenant(
        TenantLabel.A,
        canary="tt-canary-A-3b65b29ee79c6dde",
        tenant_id="tenant-5be423aa",
        record_ids=("1", "2", "3"),
    )
    victim = make_tenant(TenantLabel.B, tenant_id="tenant-2", record_ids=("4", "5", "6"))
    oracle = TenantOracle(actor=actor, victim=victim)

    isolated = json.dumps(
        [
            {
                "id": 1,
                "title": f"{actor.canary} thing 0",
                "amount": 100,
                "tenant_id": actor.tenant_id,
            },
            {"id": 2, "amount": 104, "tenant_id": actor.tenant_id},
        ]
    )
    decision = oracle.judge(facts_from_parts(status=200, text=isolated), mode=AccessMode.COLLECTION)
    assert decision.verdict is Verdict.ENFORCED
    assert decision.matched_ids == ()


def test_unjudgeable_ids_are_reported_not_silently_dropped() -> None:
    """An operator with integer keys should know the run leaned on canaries."""
    oracle = TenantOracle(
        actor=make_tenant(TenantLabel.A),
        victim=make_tenant(TenantLabel.B, record_ids=("4", "5", "6")),
    )
    assert oracle.unjudgeable_ids() == ("4", "5", "6")


def test_a_real_leak_in_an_integer_keyed_app_is_still_caught() -> None:
    """Dropping weak id evidence must not cost a genuine finding."""
    victim = make_tenant(TenantLabel.B, record_ids=("4", "5", "6"))
    oracle = TenantOracle(actor=make_tenant(TenantLabel.A, record_ids=("1",)), victim=victim)
    body = json.dumps([{"id": 4, "title": f"{victim.canary} thing 0"}])
    assert oracle.judge(facts_from_parts(status=200, text=body), mode=AccessMode.COLLECTION).leaked


def test_a_uuid_is_evidence_wherever_it_appears() -> None:
    identifier = "018f4c1e-3a9b-7c2d-9e5f-1a2b3c4d5e6f"
    oracle = TenantOracle(
        actor=make_tenant(TenantLabel.A),
        victim=make_tenant(TenantLabel.B, record_ids=(identifier,)),
    )
    for body in (
        json.dumps([{"id": identifier}]),
        json.dumps({"note": f"see {identifier} for details"}),
        f"<html><td>{identifier}</td></html>",
    ):
        decision = oracle.judge(facts_from_parts(status=200, text=body), mode=AccessMode.COLLECTION)
        assert decision.verdict is Verdict.LEAKED, body


def test_an_id_that_only_appears_inside_a_longer_token_is_not_a_match() -> None:
    """`3b65b29e` sits inside the actor's own canary hex; that is not a leak."""
    actor = make_tenant(TenantLabel.A, canary="tt-canary-A-3b65b29ee79c6dde")
    oracle = TenantOracle(actor=actor, victim=make_tenant(TenantLabel.B, record_ids=("3b65b29e",)))
    body = json.dumps([{"title": actor.canary}])
    assert oracle.judge(
        facts_from_parts(status=200, text=body), mode=AccessMode.COLLECTION
    ).verdict is (Verdict.ENFORCED)


def test_matched_ids_are_deterministic() -> None:
    """Sets iterate arbitrarily; a report should not reorder between runs."""
    ids = tuple(f"018f4c1e-3a9b-7c2d-9e5f-1a2b3c4d5e{n:02d}" for n in range(5))
    oracle = TenantOracle(
        actor=make_tenant(TenantLabel.A),
        victim=make_tenant(TenantLabel.B, record_ids=ids),
    )
    facts = facts_from_parts(status=200, text=json.dumps([{"id": i} for i in ids]))
    assert oracle.leaked_ids(facts) == tuple(sorted(ids))


@pytest.mark.parametrize("status", [401, 403, 404])
def test_refusal_is_enforcement(oracle: TenantOracle, status: int) -> None:
    decision = oracle.judge(facts_from_parts(status=status, text="{}"), mode=AccessMode.OBJECT)
    assert decision.verdict is Verdict.ENFORCED


def test_server_error_is_inconclusive_not_enforced(oracle: TenantOracle) -> None:
    decision = oracle.judge(facts_from_parts(status=500, text=""), mode=AccessMode.OBJECT)
    assert decision.verdict is Verdict.INCONCLUSIVE


def test_transport_failure_is_inconclusive(oracle: TenantOracle) -> None:
    facts = facts_from_parts(status=None, text="", transport_error="ConnectTimeout")
    decision = oracle.judge(facts, mode=AccessMode.OBJECT)
    assert decision.verdict is Verdict.INCONCLUSIVE


def test_granted_object_without_content_is_inconclusive(oracle: TenantOracle) -> None:
    """200 on another tenant's id with an empty body is not proof either way."""
    decision = oracle.judge(facts_from_parts(status=200, text="{}"), mode=AccessMode.OBJECT)
    assert decision.verdict is Verdict.INCONCLUSIVE


def test_quiet_collection_is_enforcement(oracle: TenantOracle) -> None:
    decision = oracle.judge(facts_from_parts(status=200, text="[]"), mode=AccessMode.COLLECTION)
    assert decision.verdict is Verdict.ENFORCED


def test_leak_inside_a_server_error_is_still_a_leak(oracle: TenantOracle) -> None:
    """Positive evidence outranks status-code reasoning, always."""
    body = f"Traceback ... {oracle.victim.canary} ..."
    decision = oracle.judge(facts_from_parts(status=500, text=body), mode=AccessMode.OBJECT)
    assert decision.verdict is Verdict.LEAKED


# --------------------------------------------------------------------------- #
# Aggregates
# --------------------------------------------------------------------------- #


def test_count_above_owned_is_a_leak(oracle: TenantOracle) -> None:
    facts = facts_from_parts(status=200, text=json.dumps({"invoice_count": 9}))
    decision = oracle.judge_count(facts, field_name="invoice_count", expected=2)
    assert decision.verdict is Verdict.LEAKED
    assert (decision.expected_count, decision.observed_count) == (2, 9)


def test_count_matching_owned_is_enforcement(oracle: TenantOracle) -> None:
    facts = facts_from_parts(status=200, text=json.dumps({"invoice_count": 2}))
    assert oracle.judge_count(facts, field_name="invoice_count", expected=2).verdict is (
        Verdict.ENFORCED
    )


def test_boolean_is_not_a_count(oracle: TenantOracle) -> None:
    """`True` is an int in Python; a flag must never be read as a row count."""
    facts = facts_from_parts(status=200, text=json.dumps({"invoice_count": True}))
    decision = oracle.judge_count(facts, field_name="invoice_count", expected=0)
    assert decision.verdict is Verdict.INCONCLUSIVE


def test_missing_count_field_is_inconclusive(oracle: TenantOracle) -> None:
    facts = facts_from_parts(status=200, text=json.dumps({"other": 1}))
    decision = oracle.judge_count(facts, field_name="invoice_count", expected=0)
    assert decision.verdict is Verdict.INCONCLUSIVE


# --------------------------------------------------------------------------- #
# Ownership (mass assignment)
# --------------------------------------------------------------------------- #


def test_record_created_into_the_victim_is_a_leak(oracle: TenantOracle) -> None:
    body = json.dumps({"id": "new", "tenant_id": oracle.victim.tenant_id})
    decision = oracle.judge_ownership(
        facts_from_parts(status=201, text=body), tenant_field="tenant_id"
    )
    assert decision.verdict is Verdict.LEAKED


def test_record_that_stayed_with_the_caller_is_enforcement(oracle: TenantOracle) -> None:
    body = json.dumps({"id": "new", "tenant_id": oracle.actor.tenant_id})
    decision = oracle.judge_ownership(
        facts_from_parts(status=201, text=body), tenant_field="tenant_id"
    )
    assert decision.verdict is Verdict.ENFORCED


def test_rejected_write_is_enforcement_not_noise(oracle: TenantOracle) -> None:
    body = json.dumps({"detail": [{"loc": ["body", "tenant_id"], "msg": "extra fields"}]})
    decision = oracle.judge_ownership(
        facts_from_parts(status=422, text=body), tenant_field="tenant_id"
    )
    assert decision.verdict is Verdict.ENFORCED


# --------------------------------------------------------------------------- #
# Truncation
# --------------------------------------------------------------------------- #


def test_oversized_body_is_truncated_and_says_so() -> None:
    facts = facts_from_parts(status=200, text="x" * (5 * 1024 * 1024))
    assert facts.truncated is True
    assert len(facts.text) == 4 * 1024 * 1024


# --------------------------------------------------------------------------- #
# Not every non-2xx is a decision
#
# Found by pointing the tool at a real application behind a rate limiter: it
# answered 429 to 134 of 168 attempts and the run came back VALID and clean.
# --------------------------------------------------------------------------- #


def test_a_throttled_request_is_not_a_refusal(oracle) -> None:  # type: ignore[no-untyped-def]
    """429 means "not now", never "not yours"."""
    for mode in (AccessMode.OBJECT, AccessMode.COLLECTION):
        decision = oracle.judge(facts_from_parts(status=429, text="{}"), mode=mode)
        assert decision.verdict is Verdict.INCONCLUSIVE
        assert "throttled" in decision.reason


def test_a_throttled_response_carrying_the_canary_is_still_a_leak() -> None:
    """Positive evidence outranks every status-code rule, 429 included."""
    victim = make_tenant(TenantLabel.B, canary="tt-canary-B-bbbbbbbbbbbbbbbb")
    oracle = TenantOracle(actor=make_tenant(TenantLabel.A), victim=victim)
    decision = oracle.judge(
        facts_from_parts(status=429, text=json.dumps({"note": victim.canary})),
        mode=AccessMode.OBJECT,
    )
    assert decision.verdict is Verdict.LEAKED


def test_a_404_from_a_url_we_invented_is_not_enforcement(oracle) -> None:  # type: ignore[no-untyped-def]
    """build_path puts one id in every slot; the 404 is our fault, not a refusal."""
    decision = oracle.judge(
        facts_from_parts(status=404, text=""), mode=AccessMode.OBJECT, speculative_path=True
    )
    assert decision.verdict is Verdict.INCONCLUSIVE
    assert "addressed no record" in decision.reason


def test_a_404_on_a_path_we_addressed_exactly_is_still_enforcement(oracle) -> None:  # type: ignore[no-untyped-def]
    decision = oracle.judge(
        facts_from_parts(status=404, text=""), mode=AccessMode.OBJECT, speculative_path=False
    )
    assert decision.verdict is Verdict.ENFORCED


def test_a_speculative_path_does_not_excuse_a_403(oracle) -> None:  # type: ignore[no-untyped-def]
    """401 and 403 are authorisation decisions whatever the URL looked like."""
    for status in (401, 403):
        decision = oracle.judge(
            facts_from_parts(status=status, text=""), mode=AccessMode.OBJECT, speculative_path=True
        )
        assert decision.verdict is Verdict.ENFORCED


# --------------------------------------------------------------------------- #
# The oracle defends itself from its own request
#
# Regression: once the prober began substituting the victim tenant's selector
# into a path parameter (/api/space/{spaceId}/billing), a 404 body echoing that
# selector back was read as the application volunteering another tenant's id.
# Seven criticals were reported against an application that refused every one.
# --------------------------------------------------------------------------- #


def test_an_id_echoed_back_from_our_own_url_is_not_a_leak() -> None:
    victim = make_tenant(TenantLabel.B, record_ids=("spcmREThZd9QRqLb0Nc",))
    oracle = TenantOracle(actor=make_tenant(TenantLabel.A), victim=victim)

    decision = oracle.judge(
        facts_from_parts(
            status=404,
            text='{"message":"Space spcmREThZd9QRqLb0Nc not found"}',
            request_url="http://x/api/space/spcmREThZd9QRqLb0Nc/billing",
        ),
        mode=AccessMode.OBJECT,
    )
    assert decision.verdict is Verdict.ENFORCED


def test_an_id_echoed_back_from_our_own_body_is_not_a_leak() -> None:
    victim = make_tenant(TenantLabel.B, record_ids=("spcmREThZd9QRqLb0Nc",))
    oracle = TenantOracle(actor=make_tenant(TenantLabel.A), victim=victim)

    ids = oracle.leaked_ids(
        facts_from_parts(
            status=200,
            text='{"echo":"spcmREThZd9QRqLb0Nc"}',
            request_body='{"spaceId":"spcmREThZd9QRqLb0Nc"}',
        )
    )
    assert ids == ()


def test_an_id_we_never_sent_is_still_a_leak() -> None:
    """The guard must not swallow the signal it exists to protect."""
    victim = make_tenant(TenantLabel.B, record_ids=("spcmREThZd9QRqLb0Nc",))
    oracle = TenantOracle(actor=make_tenant(TenantLabel.A), victim=victim)

    decision = oracle.judge(
        facts_from_parts(
            status=200,
            text='{"spaces":[{"id":"spcmREThZd9QRqLb0Nc"}]}',
            request_url="http://x/api/space",
        ),
        mode=AccessMode.COLLECTION,
    )
    assert decision.verdict is Verdict.LEAKED


def test_the_canary_still_wins_even_when_the_id_was_sent() -> None:
    victim = make_tenant(TenantLabel.B, canary="tt-canary-B-bbbbbbbbbbbbbbbb", record_ids=("spcX",))
    oracle = TenantOracle(actor=make_tenant(TenantLabel.A), victim=victim)

    decision = oracle.judge(
        facts_from_parts(
            status=200,
            text='{"note":"tt-canary-B-bbbbbbbbbbbbbbbb"}',
            request_url="http://x/api/space/spcX/billing",
        ),
        mode=AccessMode.OBJECT,
    )
    assert decision.verdict is Verdict.LEAKED
