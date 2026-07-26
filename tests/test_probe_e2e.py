"""End-to-end: the assertions the whole project exists to satisfy.

Against the deliberately leaky application every seeded hole must be found,
with the *right* category — an accurate finding with the wrong remediation
attached still sends an engineer to the wrong line. Against the correctly
isolated application nothing may be reported at all, including its
platform-admin endpoint, which crosses tenants on purpose.

The third assertion is the one that is easy to forget and matters most: a run
whose positive controls fail must be INVALID, never a clean report.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tenanttrace.core.config import Config, load_config
from tenanttrace.core.models import (
    AttackName,
    Category,
    Confidence,
    Engine,
    RunStatus,
    Verdict,
)
from tenanttrace.probe.asgi import SyncASGITransport
from tenanttrace.probe.runner import ProbeOptions, run_probe

pytestmark = pytest.mark.filterwarnings("ignore::UserWarning")


def _audit(config: Config, transport: SyncASGITransport, **kwargs: Any):  # type: ignore[no-untyped-def]
    options = ProbeOptions(
        allow_mutation=True,
        transport=transport,
        write_artifacts=False,
        **kwargs,
    )
    return run_probe(config, options).report


@pytest.fixture
def vulnerable_report(vulnerable_config: Config, vulnerable_transport: SyncASGITransport):  # type: ignore[no-untyped-def]
    return _audit(vulnerable_config, vulnerable_transport)


@pytest.fixture
def safe_report(safe_config: Config, safe_transport: SyncASGITransport):  # type: ignore[no-untyped-def]
    return _audit(safe_config, safe_transport)


# --------------------------------------------------------------------------- #
# The vulnerable application: every hole, correctly categorised
# --------------------------------------------------------------------------- #


def test_run_is_valid_and_controls_pass(vulnerable_report) -> None:  # type: ignore[no-untyped-def]
    assert vulnerable_report.status is RunStatus.VALID
    assert vulnerable_report.controls_passed
    assert len(vulnerable_report.controls) == 2


@pytest.mark.parametrize(
    ("location", "category"),
    [
        ("GET /api/invoices/{invoice_id}", Category.CROSS_TENANT_READ),
        ("GET /api/documents", Category.LISTING_LEAK),
        ("GET /api/stats", Category.AGGREGATE_LEAK),
        ("GET /api/customers", Category.PARAM_OVERRIDE),
        ("GET /api/documents/{document_id}", Category.CACHE_KEY_LEAK),
        ("POST /api/invoices", Category.CROSS_TENANT_WRITE),
    ],
)
def test_every_seeded_hole_is_found(vulnerable_report, location: str, category: Category) -> None:  # type: ignore[no-untyped-def]
    match = [
        f for f in vulnerable_report.findings if f.location == location and f.category is category
    ]
    assert match, f"expected a {category.value} finding at {location}; got " + ", ".join(
        f"{f.category.value}@{f.location}" for f in vulnerable_report.findings
    )
    assert match[0].confidence is Confidence.CONFIRMED
    assert match[0].engine is Engine.PROBE


def test_cache_leak_is_not_misreported_as_a_plain_read(vulnerable_report) -> None:  # type: ignore[no-untyped-def]
    """The document detail route queries correctly; only its cache key is wrong.

    Reporting it as a cross-tenant read would hand the reader a remediation
    telling them to add a WHERE clause that is already there.
    """
    at_endpoint = {
        f.category
        for f in vulnerable_report.findings
        if f.location == "GET /api/documents/{document_id}"
    }
    assert at_endpoint == {Category.CACHE_KEY_LEAK}


def test_correctly_scoped_endpoints_in_the_leaky_app_are_not_reported(vulnerable_report) -> None:  # type: ignore[no-untyped-def]
    """Negative controls living inside the vulnerable app itself."""
    reported = {f.location for f in vulnerable_report.findings}
    assert "GET /api/invoices" not in reported
    assert "POST /api/documents" not in reported


def test_findings_carry_evidence_and_remediation(vulnerable_report) -> None:  # type: ignore[no-untyped-def]
    for finding in vulnerable_report.findings:
        assert finding.remediation, f"{finding.location} has no remediation"
        assert finding.tags, f"{finding.location} has no standards tags"
        assert finding.fingerprint.startswith("sha256:")


def test_read_leaks_are_proven_by_a_canary(vulnerable_report) -> None:  # type: ignore[no-untyped-def]
    """Read findings must be backed by seeded ground truth, never inference."""
    read_categories = {
        Category.CROSS_TENANT_READ,
        Category.LISTING_LEAK,
        Category.PARAM_OVERRIDE,
        Category.CACHE_KEY_LEAK,
    }
    proven = [f for f in vulnerable_report.findings if f.category in read_categories]
    assert proven
    for finding in proven:
        assert finding.evidence.matched_canary or finding.evidence.matched_ids


def test_aggregate_finding_shows_the_arithmetic(vulnerable_report) -> None:  # type: ignore[no-untyped-def]
    aggregate = next(f for f in vulnerable_report.findings if f.category is Category.AGGREGATE_LEAK)
    assert aggregate.evidence.observed_count is not None
    assert aggregate.evidence.expected_count is not None
    assert aggregate.evidence.observed_count > aggregate.evidence.expected_count


def test_enforced_attempts_are_recorded_as_coverage(vulnerable_report) -> None:  # type: ignore[no-untyped-def]
    """Zero findings over zero attempts is not the same document as zero over many."""
    assert any(r.verdict is Verdict.ENFORCED for r in vulnerable_report.results)
    assert vulnerable_report.endpoints_tested > 0


def test_both_directions_are_probed(vulnerable_report) -> None:  # type: ignore[no-untyped-def]
    actors = {r.actor for r in vulnerable_report.results}
    assert len(actors) == 2, "isolation must be checked in both directions"


# --------------------------------------------------------------------------- #
# The safe application: silence, including on the intentional admin endpoint
# --------------------------------------------------------------------------- #


def test_safe_app_reports_nothing(safe_report) -> None:  # type: ignore[no-untyped-def]
    assert safe_report.status is RunStatus.VALID
    assert safe_report.controls_passed
    assert list(safe_report.findings) == [], [
        f"{f.category.value} @ {f.location}: {f.evidence.note}" for f in safe_report.findings
    ]


def test_safe_app_was_actually_exercised(safe_report) -> None:  # type: ignore[no-untyped-def]
    """A clean report only means something if the run had real coverage."""
    enforced = [r for r in safe_report.results if r.verdict is Verdict.ENFORCED]
    assert len(enforced) >= 10
    assert safe_report.endpoints_tested >= 5


def test_admin_endpoint_is_allowlisted_not_reported(safe_report) -> None:  # type: ignore[no-untyped-def]
    """The tool must not cry wolf about an endpoint that crosses tenants by design."""
    assert not any("admin" in f.location for f in safe_report.findings)


# --------------------------------------------------------------------------- #
# Safety rails and harness integrity
# --------------------------------------------------------------------------- #


def test_mutating_attacks_are_skipped_by_default(
    vulnerable_config: Config, vulnerable_transport: SyncASGITransport
) -> None:
    report = run_probe(
        vulnerable_config,
        ProbeOptions(allow_mutation=False, transport=vulnerable_transport, write_artifacts=False),
    ).report
    assert AttackName.MASS_ASSIGN not in report.attacks_run
    assert not any(f.category is Category.CROSS_TENANT_WRITE for f in report.findings)


def test_broken_credentials_make_the_run_invalid(
    vulnerable_config: Config, vulnerable_transport: SyncASGITransport
) -> None:
    """The most dangerous possible output is 'no leaks found' from a broken harness."""

    class BrokenSeeder:
        """Seeds normally but hands back credentials that do not work."""

        def __init__(self, client: Any, **_: Any) -> None:
            from fixtures.seeder import FixtureSeeder

            self._real = FixtureSeeder(client)

        def create_tenant(self, label: str) -> dict[str, Any]:
            return self._real.create_tenant(label)

        def auth_headers(self, tenant: dict[str, Any]) -> dict[str, str]:
            return {"Authorization": "Bearer not-a-real-token"}

        def seed_records(self, tenant: dict[str, Any], canary: str) -> list[dict[str, Any]]:
            return self._real.seed_records(tenant, canary)

        def cleanup(self, tenant: dict[str, Any]) -> None:
            return None

    import httpx

    from tenanttrace.probe.session import build_client

    client = build_client(vulnerable_config, transport=vulnerable_transport)
    try:
        report = run_probe(
            vulnerable_config,
            ProbeOptions(
                transport=vulnerable_transport,
                write_artifacts=False,
                seeder=BrokenSeeder(client),  # type: ignore[arg-type]
            ),
        ).report
    finally:
        client.close()
        assert isinstance(client, httpx.Client)

    assert report.status is RunStatus.INVALID
    assert not report.controls_passed
    # An invalid run reports the harness failure and nothing else. It must never
    # look like a clean bill of health.
    assert all(f.category is Category.HARNESS_ERROR for f in report.findings)
    assert all(f.confidence is not Confidence.CONFIRMED for f in report.findings)


def test_dry_run_sends_no_attack_requests(
    vulnerable_config: Config, vulnerable_transport: SyncASGITransport
) -> None:
    outcome = run_probe(
        vulnerable_config,
        ProbeOptions(dry_run=True, transport=vulnerable_transport, write_artifacts=False),
    )
    assert outcome.plan
    assert outcome.report.findings == ()
    assert outcome.report.results == ()
    assert any("dry run" in e for e in outcome.report.errors)


def test_allowlisted_paths_are_marked_as_skipped_in_the_plan(
    vulnerable_config: Config, vulnerable_transport: SyncASGITransport
) -> None:
    outcome = run_probe(
        vulnerable_config,
        ProbeOptions(dry_run=True, transport=vulnerable_transport, write_artifacts=False),
    )
    assert any("cross_tenant_allowlist" in line for line in outcome.plan) or not any(
        "/api/admin" in line for line in outcome.plan
    )


def test_artifacts_are_written_and_contain_no_tokens(
    vulnerable_config: Config, vulnerable_transport: SyncASGITransport, tmp_path: Path
) -> None:
    config = load_config(
        vulnerable_config.source_path or Path("fixtures/tenanttrace.vulnerable.toml"),
        overrides={"report": {"out_dir": str(tmp_path)}},
    )
    outcome = run_probe(config, ProbeOptions(allow_mutation=True, transport=vulnerable_transport))
    assert outcome.artifact_dir is not None
    transcript = (outcome.artifact_dir / "exchanges.jsonl").read_text(encoding="utf-8")
    assert transcript
    assert "<redacted>" in transcript
    assert "Bearer ey" not in transcript, "a JWT reached the run artifact"


def test_run_report_round_trips_through_json(vulnerable_report) -> None:  # type: ignore[no-untyped-def]
    from tenanttrace.core.models import RunReport

    restored = RunReport.model_validate_json(vulnerable_report.model_dump_json())
    assert len(restored.findings) == len(vulnerable_report.findings)
    assert restored.status is vulnerable_report.status
