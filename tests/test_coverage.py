"""Comparing one run against the last one.

Every other view answers "what did this run find?". A team running this weekly
needs the other question, and nothing answered it: an application that still
holds and an application the harness no longer reaches both report no findings.

Not hypothetical. Fixing `resource_name` moved EspoCRM's refused count from 656
to 236 in one commit. That was a correction; a regression of the same size —
a seeder that quietly stopped planting one record kind — would have been
invisible in every existing view.
"""

from __future__ import annotations

from tenanttrace.core.coverage import compare, coverage_of, rows, summarise
from tenanttrace.core.models import (
    AttackName,
    Endpoint,
    HttpMethod,
    ProbeResult,
    RunReport,
    RunStatus,
    TenantLabel,
    Verdict,
    utcnow,
)


def result(path: str, verdict: Verdict) -> ProbeResult:
    return ProbeResult(
        attack=AttackName.IDOR,
        endpoint=Endpoint(method=HttpMethod.GET, path=path, path_params=()),
        actor=TenantLabel.A,
        target=TenantLabel.B,
        verdict=verdict,
        detail="d",
    )


def report(*results: ProbeResult, status: RunStatus = RunStatus.VALID) -> RunReport:
    return RunReport(
        tool_version="0.1.0",
        status=status,
        started_at=utcnow(),
        target="http://app.test",
        results=results,
    )


REFUSED = Verdict.ENFORCED
UNDECIDED = Verdict.INCONCLUSIVE
LEAKED = Verdict.LEAKED


def test_an_endpoint_that_stops_being_tested_is_a_regression() -> None:
    diff = compare(
        report(result("/a", REFUSED), result("/b", REFUSED)), report(result("/a", REFUSED))
    )
    assert diff.regressed
    assert [was.key for was, _ in diff.lost] == ["GET /b"]
    assert ("GET /b", "1 refused", "nothing", "no longer tested") in rows(diff)


def test_an_endpoint_that_becomes_all_inconclusive_is_a_regression() -> None:
    """Visited is not tested. This is how coverage evaporates quietly."""
    diff = compare(report(result("/a", REFUSED)), report(result("/a", UNDECIDED)))
    assert diff.regressed
    assert rows(diff)[0][3] == "every attempt is now inconclusive"


def test_fewer_refusals_on_the_same_endpoint_is_a_regression() -> None:
    diff = compare(
        report(result("/a", REFUSED), result("/a", REFUSED), result("/a", REFUSED)),
        report(result("/a", REFUSED)),
    )
    assert [was.key for was, _ in diff.weakened] == ["GET /a"]
    assert diff.refused_delta == -2


def test_more_coverage_is_not_a_regression() -> None:
    diff = compare(
        report(result("/a", REFUSED)), report(result("/a", REFUSED), result("/b", REFUSED))
    )
    assert not diff.regressed
    assert [c.key for c in diff.gained] == ["GET /b"]
    assert summarise(diff) == "coverage grew by 1 endpoint(s)"


def test_unchanged_coverage_says_so() -> None:
    diff = compare(report(result("/a", REFUSED)), report(result("/a", REFUSED)))
    assert not diff.regressed
    assert summarise(diff) == "coverage held"


def test_a_leak_appearing_is_not_counted_as_coverage() -> None:
    """A leaked endpoint proves the boundary broke, not that it holds."""
    diff = compare(report(result("/a", REFUSED)), report(result("/a", LEAKED)))
    assert diff.regressed


def test_an_invalid_run_cannot_be_compared() -> None:
    """Comparing against a run that never happened is how a regression gets
    explained away."""
    diff = compare(
        report(result("/a", REFUSED), status=RunStatus.INVALID), report(result("/a", REFUSED))
    )
    assert not diff.comparable
    assert any("INVALID" in note for note in diff.notes)
    assert "cannot be compared" in summarise(diff)


def test_two_different_targets_are_flagged_rather_than_diffed_silently() -> None:
    earlier = report(result("/a", REFUSED))
    later = earlier.model_copy(update={"target": "http://other.test"})
    assert any("different targets" in note for note in compare(earlier, later).notes)


def test_coverage_counts_each_verdict_separately() -> None:
    tally = coverage_of([result("/a", REFUSED), result("/a", UNDECIDED), result("/a", LEAKED)])
    cover = tally["GET /a"]
    assert (cover.refused, cover.undecided, cover.leaked) == (1, 1, 1)
    assert cover.proven
