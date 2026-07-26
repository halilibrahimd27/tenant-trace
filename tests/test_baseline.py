"""The baseline and the CI gate.

Two invariants carry the weight: only `confirmed` findings can fail a build,
and the committed file must never contain evidence.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tenanttrace.core.baseline import (
    Baseline,
    apply,
    baseline_from,
    entry_for,
    gate,
    load_baseline,
    save_baseline,
)
from tenanttrace.core.fingerprint import with_fingerprint
from tenanttrace.core.models import (
    Category,
    Confidence,
    Engine,
    Evidence,
    Finding,
    Severity,
)

CANARY = "tt-canary-B-0123456789abcdef"


def _finding(
    *,
    location: str = "GET /api/invoices/{invoice_id}",
    severity: Severity = Severity.CRITICAL,
    confidence: Confidence = Confidence.CONFIRMED,
    category: Category = Category.CROSS_TENANT_READ,
    engine: Engine = Engine.PROBE,
) -> Finding:
    return with_fingerprint(
        Finding(
            id="TT-0001",
            title=f"Cross-tenant read on {location}",
            category=category,
            severity=severity,
            confidence=confidence,
            engine=engine,
            location=location,
            evidence=Evidence(
                matched_canary=CANARY,
                response_snippet=f'{{"title": "{CANARY}"}}',
                request_headers={"Authorization": "Bearer eyJsecret"},
            ),
        )
    )


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #


def test_missing_file_is_an_empty_baseline_not_an_error(tmp_path: Path) -> None:
    """A first run has nothing to suppress; crashing would be a poor welcome."""
    assert load_baseline(tmp_path / "nope.json").entries == ()
    assert load_baseline(None).entries == ()


def test_round_trip(tmp_path: Path) -> None:
    baseline = baseline_from([_finding()], accepted_by="me@example.com", reason="known")
    path = save_baseline(baseline, tmp_path / ".tenanttrace-baseline.json")
    restored = load_baseline(path)
    assert restored.fingerprints == baseline.fingerprints
    assert restored.entries[0].accepted_by == "me@example.com"


def test_the_written_file_contains_no_evidence(tmp_path: Path) -> None:
    """This file is committed to a repository."""
    path = save_baseline(baseline_from([_finding()]), tmp_path / "b.json")
    text = path.read_text(encoding="utf-8")
    assert CANARY not in text
    assert "eyJsecret" not in text
    assert "Bearer" not in text
    assert "response_snippet" not in text


def test_the_written_file_explains_itself(tmp_path: Path) -> None:
    path = save_baseline(baseline_from([_finding()]), tmp_path / "b.json")
    assert "suppresses a real finding" in path.read_text(encoding="utf-8")


def test_comment_key_does_not_break_reading(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    path.write_text(
        json.dumps({"$comment": "hand written", "version": 1, "entries": []}), encoding="utf-8"
    )
    assert load_baseline(path).entries == ()


def test_invalid_json_is_reported_clearly(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_baseline(path)


def test_only_confirmed_findings_are_baselined() -> None:
    """Suspected findings cannot gate a build, so accepting them is noise."""
    baseline = baseline_from(
        [_finding(), _finding(confidence=Confidence.SUSPECTED, location="GET /api/x")]
    )
    assert len(baseline.entries) == 1


# --------------------------------------------------------------------------- #
# Applying
# --------------------------------------------------------------------------- #


def test_baselined_findings_are_suppressed() -> None:
    finding = _finding()
    result = apply(baseline_from([finding]), [finding])
    assert result.suppressed == (finding,)
    assert result.new == ()


def test_new_findings_survive_the_baseline() -> None:
    accepted = _finding()
    fresh = _finding(location="GET /api/documents/{id}")
    result = apply(baseline_from([accepted]), [accepted, fresh])
    assert result.new == (fresh,)


def test_no_baseline_means_everything_is_new() -> None:
    finding = _finding()
    assert apply(None, [finding]).new == (finding,)


def test_stale_entries_are_reported() -> None:
    """A baseline that never shrinks rots into blanket suppression."""
    fixed = _finding(location="GET /api/fixed")
    still_there = _finding(location="GET /api/still")
    result = apply(baseline_from([fixed, still_there]), [still_there])
    assert len(result.stale) == 1
    assert result.stale[0].location == "GET /api/fixed"


def test_suppression_survives_re_seeding() -> None:
    """Concrete ids differ every run; a baseline must not expire because of it."""
    baselined = _finding(location="GET /api/invoices/{invoice_id}")
    rerun = _finding(location="GET /api/invoices/018f4c1e-3a9b-7c2d-9e5f-1a2b3c4d5e6f")
    assert apply(baseline_from([baselined]), [rerun]).new == ()


def test_a_finding_without_a_carried_fingerprint_still_matches() -> None:
    stored = baseline_from([_finding()])
    bare = _finding().model_copy(update={"fingerprint": ""})
    assert apply(stored, [bare]).new == ()


# --------------------------------------------------------------------------- #
# Gating
# --------------------------------------------------------------------------- #


def test_confirmed_finding_at_threshold_fails_the_build() -> None:
    decision = gate([_finding()], fail_on=Severity.HIGH)
    assert decision.failed is True
    assert decision.exit_code == 1
    assert "critical" in decision.message


def test_finding_below_the_threshold_does_not_fail() -> None:
    decision = gate([_finding(severity=Severity.LOW)], fail_on=Severity.HIGH)
    assert decision.failed is False
    assert decision.exit_code == 0


def test_suspected_findings_never_gate_a_build() -> None:
    """Rule 3: a hypothesis the prober has not confirmed must not break a merge."""
    hypothesis = _finding(
        confidence=Confidence.SUSPECTED,
        engine=Engine.STATIC,
        category=Category.MISSING_TENANT_FILTER,
        location="app/routes.py::get_invoice",
    )
    decision = gate([hypothesis], fail_on=Severity.LOW)
    assert decision.failed is False
    assert "hypothes" in decision.message


def test_baselined_findings_do_not_gate() -> None:
    finding = _finding()
    decision = gate([finding], fail_on=Severity.HIGH, baseline=baseline_from([finding]))
    assert decision.failed is False
    assert "accepted by the baseline" in decision.message


def test_fail_on_none_disables_the_gate_entirely() -> None:
    decision = gate([_finding()], fail_on=None)
    assert decision.failed is False
    assert "gate disabled" in decision.message


def test_stale_entries_are_surfaced_in_the_gate_message() -> None:
    decision = gate(
        [], fail_on=Severity.HIGH, baseline=baseline_from([_finding(location="GET /gone")])
    )
    assert "no longer reported" in decision.message


def test_clean_run_says_what_it_checked() -> None:
    decision = gate([], fail_on=Severity.CRITICAL)
    assert decision.failed is False
    assert "no new confirmed findings" in decision.message


@pytest.mark.parametrize(
    ("severity", "threshold", "should_fail"),
    [
        (Severity.CRITICAL, Severity.CRITICAL, True),
        (Severity.HIGH, Severity.CRITICAL, False),
        (Severity.HIGH, Severity.HIGH, True),
        (Severity.MEDIUM, Severity.HIGH, False),
        (Severity.INFO, Severity.INFO, True),
    ],
)
def test_threshold_boundaries(severity: Severity, threshold: Severity, should_fail: bool) -> None:
    assert gate([_finding(severity=severity)], fail_on=threshold).failed is should_fail


def test_entry_records_who_accepted_and_why() -> None:
    entry = entry_for(_finding(), accepted_by="sec@example.com", reason="legacy admin route")
    assert entry.accepted_by == "sec@example.com"
    assert entry.reason == "legacy admin route"
    assert entry.accepted_on


def test_empty_baseline_accepts_nothing() -> None:
    assert Baseline().accepts(_finding()) is False
