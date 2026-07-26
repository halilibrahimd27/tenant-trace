"""Correlation: static proposes, dynamic proves.

The property that matters most is negative. A wrong link would attach
`confirmed` confidence to a hypothesis about unrelated code, which is exactly
the failure this project refuses to ship — so most of these tests check that
correlation declines to link rather than that it links.
"""

from __future__ import annotations

from tenanttrace.core.fingerprint import with_fingerprint
from tenanttrace.core.models import (
    Category,
    Confidence,
    Engine,
    Evidence,
    Finding,
    Severity,
)
from tenanttrace.correlate.linker import correlate, resource_tokens


def _probe(
    location: str = "GET /api/invoices/{invoice_id}",
    category: Category = Category.CROSS_TENANT_READ,
) -> Finding:
    return with_fingerprint(
        Finding(
            id="TT-0001",
            title=f"Cross-tenant read on {location}",
            category=category,
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            engine=Engine.PROBE,
            location=location,
            evidence=Evidence(response_status=200, note="canary found"),
        )
    )


def _static(
    location: str = "app/routes.py::get_invoice",
    category: Category = Category.MISSING_TENANT_FILTER,
) -> Finding:
    return Finding(
        id="TT-0002",
        title="Query with no tenant predicate",
        category=category,
        severity=Severity.HIGH,
        confidence=Confidence.SUSPECTED,
        engine=Engine.STATIC,
        location=location,
        evidence=Evidence(file="app/routes.py", line=42, snippet="session.get(Invoice, id)"),
    )


# --------------------------------------------------------------------------- #
# Token extraction
# --------------------------------------------------------------------------- #


def test_endpoint_and_handler_reduce_to_the_same_resource() -> None:
    assert "invoice" in resource_tokens("GET /api/invoices/{invoice_id}")
    assert "invoice" in resource_tokens("app/routes.py::get_invoice")


def test_verbs_and_boilerplate_are_not_resources() -> None:
    tokens = resource_tokens("app/routes.py::get_invoice")
    assert "get" not in tokens
    assert "routes" not in tokens
    assert "api" not in resource_tokens("GET /api/v1/invoices")


def test_irregular_plurals_normalise() -> None:
    assert "company" in resource_tokens("GET /api/companies")
    assert "company" in resource_tokens("billing.py::get_company")


# --------------------------------------------------------------------------- #
# Linking
# --------------------------------------------------------------------------- #


def test_matching_resource_and_category_produce_one_correlated_finding() -> None:
    result = correlate([_probe()], [_static()])
    assert len(result.findings) == 1
    merged = result.findings[0]
    assert merged.engine is Engine.CORRELATED
    assert merged.confidence is Confidence.CONFIRMED
    assert merged.related == ("app/routes.py::get_invoice",)
    assert merged.evidence.file == "app/routes.py"
    assert merged.evidence.line == 42


def test_a_different_resource_is_not_linked() -> None:
    """A wrong link would put confirmed confidence on unrelated code."""
    result = correlate([_probe()], [_static(location="app/routes.py::get_document")])
    assert len(result.findings) == 2
    assert {f.engine for f in result.findings} == {Engine.PROBE, Engine.STATIC}
    assert result.unlinked_static == 1


def test_an_incompatible_category_is_not_linked() -> None:
    """A cache-key hypothesis does not explain a mass-assignment write."""
    result = correlate(
        [_probe(location="POST /api/invoices", category=Category.CROSS_TENANT_WRITE)],
        [_static(category=Category.TENANTLESS_CACHE_KEY)],
    )
    assert len(result.findings) == 2


def test_cache_hypothesis_links_to_a_cache_leak() -> None:
    result = correlate(
        [_probe(location="GET /api/documents/{id}", category=Category.CACHE_KEY_LEAK)],
        [_static(location="app/routes.py::get_document", category=Category.TENANTLESS_CACHE_KEY)],
    )
    assert result.findings[0].engine is Engine.CORRELATED


def test_probe_only_findings_pass_through_unchanged() -> None:
    result = correlate([_probe()], [])
    assert result.findings[0].engine is Engine.PROBE
    assert result.findings[0].confidence is Confidence.CONFIRMED


def test_static_only_findings_stay_suspected() -> None:
    """Rule 3: the static engine never emits a standalone verdict."""
    result = correlate([], [_static()])
    assert result.findings[0].confidence is Confidence.SUSPECTED
    assert result.findings[0].engine is Engine.STATIC


def test_a_confirmed_static_finding_is_never_linked() -> None:
    """Only hypotheses get correlated; anything else is a bug upstream."""
    confirmed_static = _static().model_copy(update={"confidence": Confidence.CONFIRMED})
    result = correlate([_probe()], [confirmed_static])
    assert len(result.findings) == 2


def test_multiple_hypotheses_can_back_one_confirmed_finding() -> None:
    result = correlate(
        [_probe()],
        [
            _static(location="app/routes.py::get_invoice"),
            _static(location="app/repo.py::fetch_invoice", category=Category.RAW_SQL_ESCAPE),
        ],
    )
    assert len(result.findings) == 1
    assert len(result.findings[0].related) == 2


def test_correlated_finding_keeps_the_probe_fingerprint() -> None:
    """A baselined probe finding must not re-alert once static agrees."""
    from tenanttrace.core.fingerprint import compute_fingerprint

    probe = _probe()
    merged = correlate([probe], [_static()]).findings[0]
    assert merged.fingerprint == compute_fingerprint(probe)


def test_findings_are_renumbered_and_ranked() -> None:
    findings = correlate(
        [
            _probe(location="GET /api/stats", category=Category.AGGREGATE_LEAK),
            _probe(),
        ],
        [],
    ).findings
    assert [f.id for f in findings] == ["TT-0001", "TT-0002"]
    # critical outranks high
    assert findings[0].severity is Severity.CRITICAL


def test_empty_inputs_produce_nothing() -> None:
    result = correlate([], [])
    assert result.findings == ()
    assert result.links == ()


def test_links_are_reported_for_transparency() -> None:
    result = correlate([_probe()], [_static()])
    assert result.links == (("GET /api/invoices/{invoice_id}", "app/routes.py::get_invoice"),)


def test_tags_from_both_engines_are_merged() -> None:
    probe = _probe().model_copy(update={"tags": ("CWE-639",)})
    static = _static().model_copy(update={"tags": ("CWE-639", "ASVS-V4.2.1")})
    merged = correlate([probe], [static]).findings[0]
    assert set(merged.tags) == {"CWE-639", "ASVS-V4.2.1"}
    assert len(merged.tags) == len(set(merged.tags)), "tags must not duplicate"
