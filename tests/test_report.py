"""Report rendering: the surface a human actually reads.

Two things are load-bearing and get the most attention here: the INVALID banner
(because a clean-looking report from a broken run is the worst output this tool
could produce) and HTML escaping (because response snippets are strings the
target chose).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tenanttrace.core.models import (
    AttackName,
    Category,
    Confidence,
    ControlResult,
    Endpoint,
    Engine,
    Evidence,
    Finding,
    HttpMethod,
    ProbeResult,
    RunReport,
    RunStatus,
    Severity,
    TenantLabel,
    Verdict,
    utcnow,
)
from tenanttrace.core.report import (
    read_report,
    redact_evidence,
    render,
    render_html,
    render_json,
    render_markdown,
    write_reports,
)

CANARY = "tt-canary-B-0123456789abcdef"


def _finding(**overrides: object) -> Finding:
    base: dict[str, object] = {
        "id": "TT-0001",
        "title": "Cross-tenant read on GET /api/invoices/{invoice_id}",
        "category": Category.CROSS_TENANT_READ,
        "severity": Severity.CRITICAL,
        "confidence": Confidence.CONFIRMED,
        "engine": Engine.PROBE,
        "location": "GET /api/invoices/{invoice_id}",
        "tags": ("CWE-639", "OWASP-API1:2023"),
        "fingerprint": "sha256:abc",
        "remediation": "Scope the query.\n\n```python\nselect(Invoice)\n```\n\nDone.",
        "evidence": Evidence(
            request_method=HttpMethod.GET,
            request_url="http://127.0.0.1:8000/api/invoices/018f",
            request_headers={"Authorization": "Bearer eyJhbGciOi.secret", "Accept": "*/*"},
            response_status=200,
            response_snippet=f'{{"title": "{CANARY} invoice 0"}}',
            matched_canary=CANARY,
            matched_ids=("b-1",),
        ),
    }
    base.update(overrides)
    return Finding(**base)  # type: ignore[arg-type]


def _report(**overrides: object) -> RunReport:
    endpoint = Endpoint(method=HttpMethod.GET, path="/api/invoices", path_params=())
    base: dict[str, object] = {
        "tool_version": "0.1.0",
        "status": RunStatus.VALID,
        "started_at": utcnow(),
        "finished_at": utcnow(),
        "target": "http://127.0.0.1:8000",
        "controls": (
            ControlResult(name="self-access:A", passed=True, detail="A read its own invoice"),
            ControlResult(name="self-access:B", passed=True, detail="B read its own invoice"),
        ),
        "findings": (_finding(),),
        "results": (
            ProbeResult(
                attack=AttackName.LISTING,
                endpoint=endpoint,
                actor=TenantLabel.A,
                target=TenantLabel.B,
                verdict=Verdict.ENFORCED,
                detail="collection returned 200 with no rows from the other tenant",
            ),
            ProbeResult(
                attack=AttackName.IDOR,
                endpoint=endpoint,
                actor=TenantLabel.A,
                target=TenantLabel.B,
                verdict=Verdict.INCONCLUSIVE,
                detail="target returned 500",
            ),
        ),
        "endpoints_tested": 8,
        "endpoints_discovered": 11,
    }
    base.update(overrides)
    return RunReport(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #


def test_credentials_never_render() -> None:
    for fmt in ("json", "md", "html"):
        assert "eyJhbGciOi.secret" not in render(_report(), fmt)
    # JSON is the format that carries request headers at all, so it is where
    # the replacement has to be visible.
    assert "<redacted>" in render_json(_report())


def test_credentials_are_redacted_even_with_full_evidence() -> None:
    """--full-evidence widens what we show of the target, never of our tokens.

    One accidental --full-evidence in CI would otherwise put a live credential
    in a build log.
    """
    for fmt in ("json", "md", "html"):
        assert "eyJhbGciOi.secret" not in render(_report(), fmt, redact=False)
    assert "<redacted>" in render_json(_report(), redact=False)


def test_canary_is_shortened_everywhere_it_appears() -> None:
    """Masking the field but not the body would make the claim false."""
    rendered = render_markdown(_report())
    assert CANARY not in rendered
    assert "tt-canary-…" in rendered


def test_full_evidence_keeps_the_body_verbatim() -> None:
    assert CANARY in render_markdown(_report(), redact=False)


def test_long_bodies_are_truncated_with_a_count() -> None:
    long_body = "x" * 2000
    finding = _finding(evidence=Evidence(response_snippet=long_body))
    rendered = render_markdown(_report(findings=(finding,)))
    assert "more characters" in rendered
    assert "x" * 2000 not in rendered


def test_disabling_redaction_still_strips_credentials() -> None:
    evidence = Evidence(request_headers={"Authorization": "x", "Accept": "*/*"})
    relaxed = redact_evidence(evidence, redact=False)
    assert relaxed.request_headers["Authorization"] == "<redacted>"
    assert relaxed.request_headers["Accept"] == "*/*"


# --------------------------------------------------------------------------- #
# INVALID banner
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("fmt", ["md", "html"])
def test_invalid_run_says_so_before_anything_else(fmt: str) -> None:
    report = _report(
        status=RunStatus.INVALID,
        findings=(),
        errors=("positive controls failed: tenant A could not read its own data",),
    )
    rendered = render(report, fmt)
    assert "RUN INVALID" in rendered
    assert "does NOT mean the application is" in rendered
    # ...and it comes before the findings section, not buried under it.
    assert rendered.index("RUN INVALID") < rendered.index("Findings")


def test_valid_run_has_no_banner() -> None:
    assert "RUN INVALID" not in render_markdown(_report())


def test_json_summary_exposes_the_status_for_machines() -> None:
    payload = json.loads(render_json(_report(status=RunStatus.INVALID, findings=())))
    assert payload["summary"]["status"] == "invalid"
    assert payload["schema_version"] == 1


# --------------------------------------------------------------------------- #
# HTML safety
# --------------------------------------------------------------------------- #


def test_hostile_response_content_cannot_inject_markup() -> None:
    """Snippets are attacker-influenced by construction."""
    hostile = '<script>alert("xss")</script><img src=x onerror=1>'
    finding = _finding(evidence=Evidence(response_snippet=hostile))
    page = render_html(_report(findings=(finding,)))
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
    assert "onerror=1" not in page or "&lt;img" in page


def test_hostile_location_and_title_are_escaped() -> None:
    finding = _finding(location="GET /api/<img src=x>", title="<b>bold</b>")
    page = render_html(_report(findings=(finding,)))
    assert "<img src=x>" not in page
    assert "<b>bold</b>" not in page


def test_html_makes_no_external_requests() -> None:
    """It is opened from a container and from a CI artifact — no CDN, no fonts."""
    page = render_html(_report())
    for marker in ("<script", 'src="http', 'href="http', "@import", "cdn."):
        assert marker not in page
    assert "<style>" in page


def test_html_styles_both_colour_schemes() -> None:
    page = render_html(_report())
    assert "prefers-color-scheme: dark" in page
    assert "color-scheme: light dark" in page


# --------------------------------------------------------------------------- #
# Content
# --------------------------------------------------------------------------- #


def test_markdown_card_carries_evidence_and_remediation() -> None:
    rendered = render_markdown(_report())
    assert "GET /api/invoices/{invoice_id}" in rendered
    assert "Canary that proved it" in rendered
    assert "CWE-639" in rendered
    assert "Scope the query." in rendered


def test_coverage_section_distinguishes_zero_from_untested() -> None:
    """Zero findings over zero attempts is a different document."""
    with_coverage = render_markdown(_report(findings=()))
    assert "What was checked and held" in with_coverage
    assert "correctly refused" in with_coverage

    without = render_markdown(_report(findings=(), results=()))
    assert "no real coverage" in without


def test_inconclusive_attempts_are_listed_not_hidden() -> None:
    rendered = render_markdown(_report())
    assert "inconclusive" in rendered
    assert "not the same as enforcement" in rendered


def test_findings_are_ranked_by_severity_then_confidence() -> None:
    findings = (
        _finding(id="TT-0002", severity=Severity.LOW, location="GET /low"),
        _finding(
            id="TT-0003",
            severity=Severity.CRITICAL,
            confidence=Confidence.SUSPECTED,
            location="GET /suspected",
        ),
        _finding(id="TT-0001", severity=Severity.CRITICAL, location="GET /confirmed"),
    )
    rendered = render_markdown(_report(findings=findings))
    assert rendered.index("GET /confirmed") < rendered.index("GET /suspected")
    assert rendered.index("GET /suspected") < rendered.index("GET /low")


def test_empty_report_still_renders_in_every_format() -> None:
    report = _report(findings=(), results=(), controls=())
    for fmt in ("json", "md", "html"):
        assert render(report, fmt)


def test_static_finding_renders_its_source_location() -> None:
    finding = _finding(
        engine=Engine.STATIC,
        confidence=Confidence.SUSPECTED,
        category=Category.RAW_SQL_ESCAPE,
        location="app/reports.py::monthly",
        evidence=Evidence(
            file="app/reports.py",
            line=42,
            snippet="session.execute(text('SELECT ...'))",
            assumption="assumes raw SQL bypasses the global scope",
        ),
    )
    rendered = render_markdown(_report(findings=(finding,)))
    assert "app/reports.py" in rendered
    assert "line 42" in rendered
    assert "Assumption" in rendered


# --------------------------------------------------------------------------- #
# Writing
# --------------------------------------------------------------------------- #


def test_write_reports_writes_one_file_per_format(tmp_path: Path) -> None:
    written = write_reports(_report(), tmp_path, ["json", "md", "html"])
    assert {p.name for p in written} == {"report.json", "report.md", "report.html"}
    assert all(p.read_text(encoding="utf-8") for p in written)


def test_markdown_alias_writes_dot_md(tmp_path: Path) -> None:
    assert write_reports(_report(), tmp_path, ["markdown"])[0].name == "report.md"


def test_unknown_format_is_an_error() -> None:
    with pytest.raises(ValueError, match="unknown report format"):
        render(_report(), "pdf")


def test_json_round_trips_into_the_model() -> None:
    """`tenanttrace report --run …` re-renders a stored run, so this must hold."""
    restored = read_report(render_json(_report()))
    assert restored.status is RunStatus.VALID
    assert len(restored.findings) == 1


def test_a_stored_run_report_can_be_read_back(tmp_path: Path) -> None:
    """The recorder adds its own envelope keys; reading must tolerate them."""
    payload = json.loads(render_json(_report()))
    payload["run_id"] = "20260726T120000Z"
    payload["exchanges_recorded"] = 42
    path = tmp_path / "report.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert read_report(path).status is RunStatus.VALID
