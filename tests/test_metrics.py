"""The measurement harness — the thing that turns a claim into a number.

The end-to-end case here *is* the project's quality gate: both fixture
applications are audited by both engines and scored against the answer key.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tenanttrace.core.models import (
    Category,
    Confidence,
    Engine,
    Finding,
    RunStatus,
    ScopingMode,
    Severity,
)
from tenanttrace.metrics import (
    CleanLabel,
    Label,
    MetricsReport,
    TargetScore,
    load_labels,
    score_findings,
    score_targets,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
LABELS = REPO_ROOT / "fixtures" / "labels.yaml"


def _finding(
    location: str,
    category: Category = Category.CROSS_TENANT_READ,
    confidence: Confidence = Confidence.CONFIRMED,
    engine: Engine = Engine.PROBE,
) -> Finding:
    return Finding(
        id="TT-0001",
        title="finding",
        category=category,
        severity=Severity.CRITICAL,
        confidence=confidence,
        engine=engine,
        location=location,
    )


def _label(location: str, category: str = "cross_tenant_read", engine: str = "probe") -> Label:
    return Label(
        id="X-01", location=location, category=category, severity="critical", engine=engine
    )


# --------------------------------------------------------------------------- #
# The answer key itself
# --------------------------------------------------------------------------- #


def test_labels_file_parses() -> None:
    targets = load_labels(LABELS)
    assert {"vulnerable_app", "safe_app"} <= set(targets)


def test_labels_file_is_not_malformed() -> None:
    with pytest.raises(ValueError, match="does not look like a labels file"):
        load_labels_from_text("just: a mapping")


def load_labels_from_text(text: str, tmp: Path | None = None) -> dict[str, object]:
    import tempfile

    directory = tmp or Path(tempfile.mkdtemp())
    path = directory / "labels.yaml"
    path.write_text(text, encoding="utf-8")
    return load_labels(path)


def test_every_label_agrees_with_the_severity_table() -> None:
    """A label that disagrees with severity.py is a bug in the label."""
    from tenanttrace.core.severity import severity_for

    for target in load_labels(LABELS).values():
        for item in target.get("expected", []) or []:
            category = Category(item["category"])
            assert item["severity"] == severity_for(category).value, item


def test_static_labels_carry_no_line_numbers() -> None:
    """Line numbers churn; a label that expires on an edit is worse than none."""
    for target in load_labels(LABELS).values():
        for item in target.get("expected", []) or []:
            if item.get("engine") == "static":
                assert "::" in item["location"]
                assert not any(part.isdigit() for part in item["location"].split(":") if part)


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #


def test_a_label_matches_its_finding() -> None:
    score = score_findings("t", [_finding("GET /api/x/{id}")], [_label("GET /api/x/{id}")], [])
    assert score.recall == 1.0
    assert not score.missed


def test_matching_ignores_concrete_identifiers() -> None:
    score = score_findings("t", [_finding("GET /api/x/7")], [_label("GET /api/x/{id}")], [])
    assert score.recall == 1.0


def test_a_different_category_is_not_a_match() -> None:
    score = score_findings(
        "t",
        [_finding("GET /api/x", category=Category.LISTING_LEAK)],
        [_label("GET /api/x", category="cross_tenant_read")],
        [],
    )
    assert score.recall == 0.0
    assert score.missed


def test_a_probe_finding_does_not_satisfy_a_static_label() -> None:
    score = score_findings(
        "t",
        [_finding("app/routes.py::get_x", category=Category.RAW_SQL_ESCAPE)],
        [_label("app/routes.py::get_x", category="raw_sql_escape", engine="static")],
        [],
    )
    assert score.recall == 0.0


def test_a_static_label_matches_a_static_finding() -> None:
    score = score_findings(
        "t",
        [
            _finding(
                "app/routes.py::get_x",
                category=Category.RAW_SQL_ESCAPE,
                confidence=Confidence.SUSPECTED,
                engine=Engine.STATIC,
            )
        ],
        [_label("app/routes.py::get_x", category="raw_sql_escape", engine="static")],
        [],
    )
    assert score.recall == 1.0


def test_one_finding_satisfies_only_one_label() -> None:
    """Two labels at one location must not both be claimed by a single finding."""
    score = score_findings(
        "t",
        [_finding("GET /api/x")],
        [_label("GET /api/x"), _label("GET /api/x")],
        [],
    )
    assert len(score.matched) == 1
    assert len(score.missed) == 1


# --------------------------------------------------------------------------- #
# False positives
# --------------------------------------------------------------------------- #


def test_a_finding_at_an_expect_clean_location_is_a_false_positive() -> None:
    """The cry-wolf test."""
    score = score_findings(
        "t", [_finding("GET /api/admin/all")], [], [CleanLabel(location="GET /api/admin/all")]
    )
    assert len(score.false_positives) == 1


def test_a_suspected_finding_at_a_clean_location_still_counts() -> None:
    score = score_findings(
        "t",
        [
            _finding(
                "GET /api/admin/all",
                confidence=Confidence.SUSPECTED,
                engine=Engine.STATIC,
            )
        ],
        [],
        [CleanLabel(location="GET /api/admin/all")],
    )
    assert len(score.false_positives) == 1


def test_an_unlabelled_confirmed_finding_is_a_false_positive() -> None:
    """A confirmed finding claims a leak we did not build into the fixture."""
    score = score_findings("t", [_finding("GET /api/surprise")], [], [])
    assert len(score.false_positives) == 1


def test_an_unlabelled_hypothesis_is_not_a_false_positive() -> None:
    """Extra hypotheses are the expected cost of a hypothesis generator."""
    score = score_findings(
        "t",
        [_finding("GET /api/surprise", confidence=Confidence.SUSPECTED, engine=Engine.STATIC)],
        [],
        [],
    )
    assert score.false_positives == []


def test_harness_errors_are_not_counted_as_false_positives() -> None:
    score = score_findings(
        "t",
        [
            _finding(
                "http://127.0.0.1",
                category=Category.HARNESS_ERROR,
                confidence=Confidence.CONFIRMED,
            )
        ],
        [],
        [],
    )
    assert score.false_positives == []


# --------------------------------------------------------------------------- #
# Report arithmetic
# --------------------------------------------------------------------------- #


def test_report_fails_when_recall_is_below_the_floor() -> None:
    score = TargetScore(target="t", expected=(_label("GET /a"), _label("GET /b")))
    score.matched.append(_label("GET /a"))
    report = MetricsReport(targets=[score], min_recall=0.90)
    assert report.recall == 0.5
    assert report.passed is False
    assert "FAIL" in report.render()


def test_report_fails_on_any_false_positive() -> None:
    score = TargetScore(target="t")
    score.false_positives.append(_finding("GET /api/x"))
    assert MetricsReport(targets=[score]).passed is False


def test_report_fails_when_a_run_was_invalid() -> None:
    """A perfect score from a broken harness is the worst possible pass."""
    score = TargetScore(target="t", status=RunStatus.INVALID)
    report = MetricsReport(targets=[score])
    assert report.passed is False
    assert "cannot be trusted" in report.render()


def test_report_fails_when_scoping_detection_is_wrong() -> None:
    """The wrong mode inverts the static rule set and makes the engine useless."""
    score = TargetScore(
        target="t",
        scoping_expected=ScopingMode.GLOBAL,
        scoping_detected=ScopingMode.MANUAL,
    )
    report = MetricsReport(targets=[score])
    assert report.passed is False
    assert "WRONG" in report.render()


def test_render_names_what_was_missed() -> None:
    """'Recall 87%' is not actionable; the name of the missed hole is."""
    score = TargetScore(target="t", expected=(_label("GET /api/missed"),))
    score.missed.append(_label("GET /api/missed"))
    assert "GET /api/missed" in MetricsReport(targets=[score]).render()


def test_empty_expectations_score_as_perfect_recall() -> None:
    assert TargetScore(target="t").recall == 1.0


# --------------------------------------------------------------------------- #
# End to end — this is the gate
# --------------------------------------------------------------------------- #


@pytest.mark.slow
def test_the_tool_scores_itself_against_the_fixtures() -> None:
    report = score_targets(LABELS, min_recall=0.90)
    rendered = report.render()
    assert report.recall >= 0.90, rendered
    assert report.false_positives == 0, rendered
    assert report.passed, rendered
    # Both scoping modes must be identified correctly, or the static engine is
    # applying the wrong rule set entirely.
    modes = {t.target: t.scoping_detected for t in report.targets}
    assert modes["vulnerable_app"] is ScopingMode.MANUAL
    assert modes["safe_app"] is ScopingMode.GLOBAL


def test_labels_yaml_round_trips_through_yaml_safe_load() -> None:
    """Guards against a tab or a duplicate key sneaking into the answer key."""
    assert yaml.safe_load(LABELS.read_text(encoding="utf-8"))["version"] == 1
