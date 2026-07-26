"""Fingerprints decide whether a baseline still recognises a finding.

The properties tested here are the ones a baseline's usefulness rests on: a
fingerprint must be stable across everything that changes between runs, and it
must still separate findings that are genuinely different.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tenanttrace.core.fingerprint import (
    compute_fingerprint,
    normalize_path,
    normalize_source_location,
    with_fingerprint,
)
from tenanttrace.core.models import (
    Category,
    Confidence,
    Engine,
    Evidence,
    Finding,
    Severity,
)


def _finding(**overrides: object) -> Finding:
    base = {
        "id": "TT-0001",
        "title": "Cross-tenant read",
        "category": Category.CROSS_TENANT_READ,
        "severity": Severity.CRITICAL,
        "confidence": Confidence.CONFIRMED,
        "engine": Engine.PROBE,
        "location": "GET /api/invoices/{invoice_id}",
    }
    base.update(overrides)
    return Finding(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Path normalisation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/api/invoices/{invoice_id}", "/api/invoices/{}"),
        ("/api/invoices/{id}", "/api/invoices/{}"),
        ("/api/invoices/7", "/api/invoices/{}"),
        ("/api/invoices/018f4c1e-3a9b-7c2d-9e5f-1a2b3c4d5e6f", "/api/invoices/{}"),
        ("/api/invoices/01H2XJKQ8RZ9YV4M6N7P8Q9RST", "/api/invoices/{}"),
        ("/api/invoices/deadbeefdeadbeef01", "/api/invoices/{}"),
        ("http://localhost:8000/api/invoices/7/", "/api/invoices/{}"),
        ("https://staging.example.com/api/invoices/7?page=2", "/api/invoices/{}"),
        ("/API/Invoices", "/api/invoices"),
        ("api/invoices", "/api/invoices"),
        ("/", "/"),
        ("", "/"),
    ],
)
def test_path_normalisation_examples(raw: str, expected: str) -> None:
    assert normalize_path(raw) == expected


@pytest.mark.property
@given(
    identifier=st.integers(min_value=0, max_value=10**9),
    other=st.integers(min_value=0, max_value=10**9),
)
def test_two_ids_at_the_same_route_normalise_together(identifier: int, other: int) -> None:
    """Re-seeding changes every id; it must not change any fingerprint."""
    assert normalize_path(f"/api/invoices/{identifier}") == normalize_path(f"/api/invoices/{other}")


@pytest.mark.property
@given(name=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=20))
def test_parameter_renames_do_not_change_the_path(name: str) -> None:
    assert normalize_path(f"/api/invoices/{{{name}}}") == "/api/invoices/{}"


@pytest.mark.property
@given(
    path=st.lists(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=8),
        min_size=0,
        max_size=5,
    )
)
def test_normalisation_is_idempotent(path: list[str]) -> None:
    """Normalising twice must equal normalising once, or nothing is stable."""
    raw = "/" + "/".join(path)
    once = normalize_path(raw)
    assert normalize_path(once) == once


@pytest.mark.property
@given(
    path=st.text(alphabet="abcdefghijklmnopqrstuvwxyz/{}0123456789-", max_size=60),
)
def test_normalisation_always_returns_an_absolute_path(path: str) -> None:
    assert normalize_path(path).startswith("/")


def test_trailing_and_duplicate_slashes_collapse() -> None:
    assert normalize_path("/api//invoices///") == normalize_path("/api/invoices")


# --------------------------------------------------------------------------- #
# Source-location normalisation
# --------------------------------------------------------------------------- #


def test_line_numbers_are_dropped_from_source_locations() -> None:
    """The single most important property: baselines must survive edits."""
    assert normalize_source_location("app/routes.py:120:get_invoice") == normalize_source_location(
        "app/routes.py:481:get_invoice"
    )


def test_symbol_is_kept() -> None:
    assert normalize_source_location("app/routes.py::get_invoice") == "app/routes.py::get_invoice"
    assert normalize_source_location("app/routes.py::get_invoice") != normalize_source_location(
        "app/routes.py::list_invoices"
    )


def test_checkout_directory_is_stripped() -> None:
    """CI and a laptop must agree, so the path is anchored to the source root."""
    assert normalize_source_location(
        "/home/runner/work/proj/src/app/routes.py::fn"
    ) == normalize_source_location("/Users/me/dev/proj/src/app/routes.py::fn")


def test_windows_separators_normalise() -> None:
    assert normalize_source_location("src\\app\\routes.py::fn") == "src/app/routes.py::fn"


# --------------------------------------------------------------------------- #
# Fingerprint identity
# --------------------------------------------------------------------------- #


def test_fingerprint_is_stable_across_reseeding() -> None:
    first = _finding(location="GET /api/invoices/018f4c1e-3a9b-7c2d-9e5f-1a2b3c4d5e6f")
    second = _finding(location="GET /api/invoices/{invoice_id}")
    assert compute_fingerprint(first) == compute_fingerprint(second)


def test_fingerprint_ignores_evidence_and_severity() -> None:
    """Evidence differs every run; re-rating a category must not un-accept it."""
    plain = _finding()
    noisy = _finding(
        severity=Severity.MEDIUM,
        evidence=Evidence(matched_canary="tt-canary-B-1234567890abcdef", response_status=200),
        title="a completely different title",
    )
    assert compute_fingerprint(plain) == compute_fingerprint(noisy)


def test_fingerprint_separates_different_endpoints() -> None:
    assert compute_fingerprint(_finding()) != compute_fingerprint(
        _finding(location="GET /api/documents/{id}")
    )


def test_fingerprint_separates_different_categories() -> None:
    assert compute_fingerprint(_finding()) != compute_fingerprint(
        _finding(category=Category.LISTING_LEAK)
    )


def test_fingerprint_separates_methods() -> None:
    assert compute_fingerprint(_finding()) != compute_fingerprint(
        _finding(location="POST /api/invoices/{invoice_id}")
    )


def test_correlated_findings_keep_the_probe_fingerprint() -> None:
    """A baselined probe finding must not re-alert once static agrees with it."""
    probe_only = _finding()
    correlated = _finding(engine=Engine.CORRELATED)
    assert compute_fingerprint(probe_only) == compute_fingerprint(correlated)


def test_static_fingerprint_survives_line_churn() -> None:
    before = _finding(
        engine=Engine.STATIC,
        confidence=Confidence.SUSPECTED,
        category=Category.RAW_SQL_ESCAPE,
        location="src/app/reports.py:12:monthly_report",
    )
    after = before.model_copy(update={"location": "src/app/reports.py:988:monthly_report"})
    assert compute_fingerprint(before) == compute_fingerprint(after)


def test_with_fingerprint_attaches_and_is_deterministic() -> None:
    stamped = with_fingerprint(_finding())
    assert stamped.fingerprint.startswith("sha256:")
    assert with_fingerprint(_finding()).fingerprint == stamped.fingerprint


def test_fingerprint_contains_no_canary_or_identifier() -> None:
    """A baseline is committed to a repository; it must carry no leaked data."""
    canary = "tt-canary-B-1234567890abcdef"
    stamped = with_fingerprint(
        _finding(
            location="GET /api/invoices/018f4c1e-3a9b-7c2d-9e5f-1a2b3c4d5e6f",
            evidence=Evidence(matched_canary=canary, response_snippet=canary),
        )
    )
    assert canary not in stamped.fingerprint
    assert "018f4c1e" not in stamped.fingerprint
