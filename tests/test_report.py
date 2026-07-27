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
    _CSS,
    INVALID_HEADLINE,
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


# --------------------------------------------------------------------------- #
# Access graph
# --------------------------------------------------------------------------- #


def _leaked_result(path: str = "/api/invoices") -> ProbeResult:
    return ProbeResult(
        attack=AttackName.LISTING,
        endpoint=Endpoint(method=HttpMethod.GET, path=path, path_params=()),
        actor=TenantLabel.A,
        target=TenantLabel.B,
        verdict=Verdict.LEAKED,
        detail="canary found",
    )


def test_the_graph_draws_one_edge_per_proven_path() -> None:
    """Every edge is a result that already exists — nothing speculative."""
    page = render_html(_report(results=(_leaked_result(),)))
    assert "<h2>Access graph</h2>" in page
    assert page.count("class='edge") == 1


def test_the_same_endpoint_proven_twice_is_one_path() -> None:
    two = (_leaked_result(), _leaked_result())
    assert render_html(_report(results=two)).count("class='edge") == 1


def test_a_run_with_nothing_proven_draws_no_graph() -> None:
    """An empty diagram would imply a picture was worth drawing."""
    assert "<h2>Access graph</h2>" not in render_html(_report(results=(), findings=()))


def test_the_graph_is_inline_svg_not_a_library() -> None:
    page = render_html(_report(results=(_leaked_result(),)))
    assert "<script" not in page
    assert "viewBox" in page


def test_hostile_endpoint_names_cannot_break_out_of_the_svg() -> None:
    page = render_html(_report(results=(_leaked_result("/api/<script>x</script>"),)))
    assert "<script>x</script>" not in page
    assert "&lt;script&gt;" in page


def test_the_summary_leads_with_stat_tiles() -> None:
    """What needs attention has to read before the table that explains it."""
    page = render_html(_report())
    assert "class='tiles'" in page
    assert page.index("class='tiles'") < page.index("Findings")


# --------------------------------------------------------------------------- #
# The verdict — the answer, before the method that produced it
# --------------------------------------------------------------------------- #


def test_a_leaking_run_leads_with_the_leak_count() -> None:
    page = render_html(_report(results=(_leaked_result(),)))
    assert "class='verdict bad'" in page
    assert "1 confirmed cross-tenant leak</strong>" in page


def test_a_clean_run_says_what_it_does_and_does_not_cover() -> None:
    """'No findings' is not the same claim as 'this application is safe'."""
    page = render_html(_report(findings=()))
    assert "class='verdict good'" in page
    assert "No cross-tenant access proven" in page
    assert "not the whole application" in page


def test_a_run_that_refused_nothing_is_not_reported_as_clean() -> None:
    """Zero attempts and zero decisions are the same claim: no evidence."""
    page = render_html(_report(results=(), findings=()))
    assert "class='verdict good'" not in page
    assert "Nothing was proven either way" in page


def test_undecided_attempts_are_never_counted_as_refusals() -> None:
    """The defect this replaces: a page claiming 168 refusals beside a tile
    reading 26, because the verdict counted results instead of enforcement."""
    endpoint = Endpoint(method=HttpMethod.GET, path="/api/x", path_params=())

    def result(verdict: Verdict) -> ProbeResult:
        return ProbeResult(
            attack=AttackName.IDOR,
            endpoint=endpoint,
            actor=TenantLabel.A,
            target=TenantLabel.B,
            verdict=verdict,
            detail="d",
        )

    results = (result(Verdict.ENFORCED), *[result(Verdict.INCONCLUSIVE)] * 9)
    page = render_html(_report(results=results, findings=()))
    verdict = page[page.index("class='verdict") :].split("</div>")[0]

    assert "1 cross-tenant attempt" in verdict
    assert "was refused" in verdict
    assert "9 attempts could not be judged" in verdict
    # The total is still reported — as attempts, which is what it is.
    assert "10 cross-tenant attempts across" in page


def test_an_invalid_run_gets_the_banner_and_no_second_verdict() -> None:
    """Two verdicts on one page is one verdict too many."""
    page = render_html(_report(status=RunStatus.INVALID))
    assert INVALID_HEADLINE in page
    assert "class='verdict " not in page


def test_the_verdict_precedes_the_method() -> None:
    page = render_html(_report(results=(_leaked_result(),)))
    assert page.index("class='verdict") < page.index("<h2>Run integrity</h2>")
    assert page.index("<h2>Findings</h2>") < page.index("Positive controls")


# --------------------------------------------------------------------------- #
# Navigation and plain language
# --------------------------------------------------------------------------- #


def test_many_findings_get_a_jump_list_linking_to_anchors() -> None:
    findings = tuple(_finding(id=f"TT-000{i}", fingerprint=f"sha256:{i}") for i in range(1, 5))
    page = render_html(_report(findings=findings))
    assert "class='index'" in page
    for finding in findings:
        assert f"href='#{finding.id}'" in page
        assert f"id='{finding.id}'" in page


def test_a_short_report_is_not_padded_with_an_index() -> None:
    assert "class='index'" not in render_html(_report())


def test_the_report_explains_its_own_vocabulary() -> None:
    page = render_html(_report())
    assert "How to read this report" in page
    for term in ("Confirmed", "Suspected", "Positive control", "Inconclusive"):
        assert f"<dt>{term}</dt>" in page


def test_counts_read_as_english_not_as_a_debug_log() -> None:
    single = _report(
        results=(_leaked_result(),),
        endpoints_tested=1,
        endpoints_discovered=1,
    )
    assert "(s)" not in render_html(single)
    assert "1 cross-tenant attempt across 1 endpoint." in render_html(single)


def test_the_footer_stays_one_sentence() -> None:
    """A flex column would promote the inline <code> to its own row."""
    assert "flex" not in _CSS[_CSS.index("footer {") : _CSS.index("footer {") + 220]


def test_control_marks_are_glyphs_the_stylesheet_colours() -> None:
    page = render_html(_report())
    assert "class='mark'" in page
    assert "✅" not in page


def test_the_graph_carries_a_key_for_the_colours_it_uses() -> None:
    high = ProbeResult(
        attack=AttackName.AGGREGATE,
        endpoint=Endpoint(method=HttpMethod.GET, path="/api/stats", path_params=()),
        actor=TenantLabel.A,
        target=TenantLabel.B,
        verdict=Verdict.LEAKED,
        detail="count leak",
    )
    page = render_html(_report(results=(_leaked_result(), high)))
    assert "class='legend'" in page
    assert page.count("<span class='sev-") >= 2


def test_the_key_only_lists_severities_that_are_drawn() -> None:
    page = render_html(_report(results=(_leaked_result(),)))
    legend = page[page.index("class='legend'") :][:400]
    assert "sev-critical" in legend
    assert "sev-high" not in legend


# --------------------------------------------------------------------------- #
# The graph has to say what kind of path it is drawing
# --------------------------------------------------------------------------- #


def _leak(path: str, actor: TenantLabel, category: Category | None = None) -> ProbeResult:
    return ProbeResult(
        attack=AttackName.IDOR,
        endpoint=Endpoint(method=HttpMethod.GET, path=path, path_params=()),
        actor=actor,
        target=TenantLabel.B if actor is TenantLabel.A else TenantLabel.A,
        verdict=Verdict.LEAKED,
        detail="leak",
        category=category,
    )


def test_a_public_endpoint_is_drawn_from_anyone_not_from_a_tenant() -> None:
    """Drawing it tenant-to-tenant claims a boundary failed where none exists."""
    page = render_html(
        _report(results=(_leak("/api/assets/{id}", TenantLabel.A, Category.PUBLIC_ENDPOINT),))
    )
    assert ">anyone</text>" in page
    assert "edge sev-high public" in page
    assert "no credential needed" in page
    assert "tenant A</text>" not in page


def test_a_public_endpoint_does_not_also_get_per_tenant_edges() -> None:
    """The weaker claim is implied by the stronger one; drawing both triples
    the lines for a single fact."""
    results = (
        _leak("/api/assets/{id}", TenantLabel.A, Category.PUBLIC_ENDPOINT),
        _leak("/api/assets/{id}", TenantLabel.A),
        _leak("/api/assets/{id}", TenantLabel.B),
    )
    assert render_html(_report(results=results)).count("class='edge") == 1


def test_both_directions_on_one_endpoint_is_one_broken_endpoint() -> None:
    results = (_leak("/api/x", TenantLabel.A), _leak("/api/x", TenantLabel.B))
    page = render_html(_report(results=results))
    assert page.count("class='edge") == 1
    assert "tenant A↔B" in page
    assert "proven in both directions" in page


def test_one_direction_stays_one_direction() -> None:
    page = render_html(_report(results=(_leak("/api/x", TenantLabel.A),)))
    assert "tenant A</text>" in page
    assert "↔" not in page


def test_the_caption_says_what_is_not_drawn() -> None:
    """A short graph must not read as a thorough audit."""
    page = render_html(_report(results=(_leak("/api/x", TenantLabel.A),)))
    assert "could not be judged" in page
    assert "not the same as a thorough audit" in page


# --------------------------------------------------------------------------- #
# A deliverable, not only a web page
# --------------------------------------------------------------------------- #


def test_the_report_states_its_scope_before_its_findings() -> None:
    """Treating a report's scope as the whole system is the most common way to
    misread one."""
    page = render_html(_report())
    assert "<h2>Scope</h2>" in page
    assert page.index("<h2>Scope</h2>") < page.index("<h2>Findings</h2>")
    for label in ("Target", "Surface probed", "Attacks run", "Duration"):
        assert f"<dt>{label}</dt>" in page


def test_endpoints_that_were_never_reached_are_stated_not_implied() -> None:
    page = render_html(_report(endpoints_tested=4, endpoints_discovered=11))
    assert "4 endpoints of 11 discovered" in page
    assert "7 not reached" in page


def test_the_scope_is_not_repeated_in_the_header() -> None:
    page = render_html(_report())
    head = page[: page.index("<h2>Scope</h2>")]
    assert head.count("tenanttrace 0") == 0


def test_findings_are_indexed_by_the_control_they_map_to() -> None:
    """A reader working to a control framework wants the other axis."""
    page = render_html(_report())
    assert "<h2>Standards</h2>" in page
    assert "OWASP-API1:2023" in page
    assert "CWE-639" in page


def test_a_clean_run_carries_no_standards_table() -> None:
    assert "<h2>Standards</h2>" not in render_html(_report(findings=()))


def test_the_report_survives_leaving_the_browser() -> None:
    """It gets printed and attached to a ticket. A dark page prints as a black
    rectangle, and a closed <details> prints as a heading with nothing under
    it."""
    assert "@media print" in _CSS
    printed = _CSS[_CSS.index("@media print") :]
    assert "--bg:#FFF" in printed
    assert "details > summary { display:none; }" in printed
    assert "break-inside:avoid" in printed
