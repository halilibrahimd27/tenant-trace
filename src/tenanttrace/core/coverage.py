"""Comparing one run against the last one — what stopped being proven.

Every other view in this tool answers "what did this run find?". A team that
runs it weekly needs a different question answered, and nothing answered it:
**what did this run stop proving?**

The distinction matters because the two failures look identical in a finding
list. A run that returns to "no findings" after a refactor is either an
application that still holds, or an application whose endpoints the harness no
longer reaches. Last week's *34 attempts refused across 12 endpoints* becoming
this week's *4 refused across 2* is the second one, and by every existing
measure both runs are clean.

That is the sly version of exactly what this tool exists to catch, and it is
not hypothetical: fixing ``resource_name`` moved EspoCRM's refused count from
656 to 236 in a single commit. That change was a correction. A regression of
the same size, arriving through a seeder that silently stopped planting one
record kind, would have been invisible.

So the comparison here is **coverage-first**. Findings are compared too, but
the headline is the endpoints that used to refuse something and no longer do.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from tenanttrace.core.models import Finding, ProbeResult, RunReport, RunStatus, Verdict

__all__ = [
    "CoverageDiff",
    "EndpointCoverage",
    "compare",
    "coverage_of",
    "rows",
    "summarise",
]


@dataclass(frozen=True, slots=True)
class EndpointCoverage:
    """What one run proved about one endpoint."""

    key: str
    refused: int = 0
    undecided: int = 0
    leaked: int = 0

    @property
    def proven(self) -> bool:
        """Did the application actually decide anything here?

        Only ``ENFORCED`` counts. An endpoint whose every attempt was
        inconclusive was visited, not tested (ADR-0010).
        """
        return self.refused > 0


@dataclass(frozen=True, slots=True)
class CoverageDiff:
    """What changed between two runs, coverage first."""

    lost: tuple[tuple[EndpointCoverage, EndpointCoverage], ...] = ()
    weakened: tuple[tuple[EndpointCoverage, EndpointCoverage], ...] = ()
    gained: tuple[EndpointCoverage, ...] = ()
    new_findings: tuple[Finding, ...] = ()
    fixed_findings: tuple[Finding, ...] = ()
    before_refused: int = 0
    after_refused: int = 0
    before_status: RunStatus = RunStatus.VALID
    after_status: RunStatus = RunStatus.VALID
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def comparable(self) -> bool:
        """Both runs have to have happened for a difference to mean anything."""
        return self.before_status is RunStatus.VALID and self.after_status is RunStatus.VALID

    @property
    def regressed(self) -> bool:
        """Did this run prove less than the last one?"""
        return bool(self.lost or self.weakened)

    @property
    def refused_delta(self) -> int:
        return self.after_refused - self.before_refused


def coverage_of(results: Sequence[ProbeResult]) -> dict[str, EndpointCoverage]:
    """Per-endpoint tallies, keyed by ``METHOD /path``."""
    refused: dict[str, int] = {}
    undecided: dict[str, int] = {}
    leaked: dict[str, int] = {}
    for result in results:
        key = result.endpoint.key
        bucket = {
            Verdict.ENFORCED: refused,
            Verdict.INCONCLUSIVE: undecided,
            Verdict.LEAKED: leaked,
        }.get(result.verdict)
        if bucket is not None:
            bucket[key] = bucket.get(key, 0) + 1
    keys = set(refused) | set(undecided) | set(leaked)
    return {
        key: EndpointCoverage(
            key=key,
            refused=refused.get(key, 0),
            undecided=undecided.get(key, 0),
            leaked=leaked.get(key, 0),
        )
        for key in keys
    }


def compare(before: RunReport, after: RunReport) -> CoverageDiff:
    """Diff two runs of the same target.

    Neither run is trusted blindly: if either is INVALID the diff still
    computes, but :attr:`CoverageDiff.comparable` is false and callers must say
    so rather than present a difference as meaningful. Comparing against a run
    that never happened is how a regression gets explained away.
    """
    old = coverage_of(before.results)
    new = coverage_of(after.results)

    lost: list[tuple[EndpointCoverage, EndpointCoverage]] = []
    weakened: list[tuple[EndpointCoverage, EndpointCoverage]] = []
    for key, was in sorted(old.items()):
        if not was.proven:
            continue
        now = new.get(key, EndpointCoverage(key=key))
        if not now.proven:
            lost.append((was, now))
        elif now.refused < was.refused:
            weakened.append((was, now))

    gained = tuple(
        cover
        for key, cover in sorted(new.items())
        if cover.proven and not old.get(key, EndpointCoverage(key=key)).proven
    )

    old_prints = {f.fingerprint for f in before.findings}
    new_prints = {f.fingerprint for f in after.findings}

    notes: list[str] = []
    if before.target != after.target:
        notes.append(
            f"different targets: {before.target} then {after.target}. A coverage "
            "difference between two applications is not a regression."
        )
    for label, report in (("earlier", before), ("later", after)):
        if report.status is not RunStatus.VALID:
            notes.append(
                f"the {label} run is {report.status.value.upper()}, so it is not evidence "
                "of anything and this comparison cannot mean what it looks like."
            )

    return CoverageDiff(
        lost=tuple(lost),
        weakened=tuple(weakened),
        gained=gained,
        new_findings=tuple(f for f in after.ranked() if f.fingerprint not in old_prints),
        fixed_findings=tuple(f for f in before.ranked() if f.fingerprint not in new_prints),
        before_refused=sum(c.refused for c in old.values()),
        after_refused=sum(c.refused for c in new.values()),
        before_status=before.status,
        after_status=after.status,
        notes=tuple(notes),
    )


def summarise(diff: CoverageDiff) -> str:
    """One line for a CI log or a chat window."""
    if not diff.comparable:
        return "coverage cannot be compared — one of the runs did not happen"
    if diff.regressed:
        endpoints = len(diff.lost) + len(diff.weakened)
        return (
            f"coverage regressed: {endpoints} endpoint(s) prove less than before "
            f"({diff.before_refused} attempts refused then, {diff.after_refused} now)"
        )
    if diff.gained:
        return f"coverage grew by {len(diff.gained)} endpoint(s)"
    return "coverage held"


def rows(diff: CoverageDiff) -> list[tuple[str, str, str, str]]:
    """``(endpoint, before, after, what changed)`` for rendering."""
    out: list[tuple[str, str, str, str]] = []
    for was, now in diff.lost:
        detail = (
            "no longer tested"
            if not (now.refused or now.undecided or now.leaked)
            else "every attempt is now inconclusive"
        )
        out.append((was.key, f"{was.refused} refused", _describe(now), detail))
    for was, now in diff.weakened:
        out.append((was.key, f"{was.refused} refused", _describe(now), "fewer refusals"))
    return out


def _describe(cover: EndpointCoverage) -> str:
    if not (cover.refused or cover.undecided or cover.leaked):
        return "nothing"
    parts = []
    if cover.refused:
        parts.append(f"{cover.refused} refused")
    if cover.undecided:
        parts.append(f"{cover.undecided} undecided")
    if cover.leaked:
        parts.append(f"{cover.leaked} leaked")
    return ", ".join(parts)
