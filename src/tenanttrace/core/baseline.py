"""The baseline: findings a team has looked at and consciously accepted.

A merge gate that fails on every pre-existing finding gets switched off in a
week. A baseline is what makes the gate adoptable — it lets a team accept
today's reality and still be told about tomorrow's regression.

Three properties keep it from becoming blanket suppression:

* **It is committed and reviewed.** Accepting a finding is a diff somebody
  approves, not a flag somebody passes. That is the whole security control
  ([ADR-0007](../../docs/adr/0007-baseline-fingerprints.md)).
* **Stale entries are reported.** A baselined fingerprint that no longer
  appears means the finding was fixed — or that the endpoint stopped being
  tested. Either way the entry should go, and silence about it is how a
  baseline rots.
* **It carries no evidence.** Fingerprints, titles, and locations only. Never a
  canary, a token, or a response body — this file is in the repository.

Only ``confirmed`` findings can gate a build (rule 3). Suspected ones are
reported and never fail anything, so baselining them is unnecessary.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from tenanttrace import __version__
from tenanttrace.core.fingerprint import compute_fingerprint
from tenanttrace.core.models import Confidence, Finding, Severity, utcnow

__all__ = [
    "Baseline",
    "BaselineEntry",
    "BaselineResult",
    "GateDecision",
    "apply",
    "entry_for",
    "gate",
    "load_baseline",
    "save_baseline",
]

BASELINE_VERSION = 1


class BaselineEntry(BaseModel):
    """One accepted finding.

    Everything here is safe to commit: an endpoint or a source symbol, a title,
    and who accepted it. Nothing that came out of the target's responses.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    fingerprint: str
    title: str = ""
    location: str = ""
    severity: Severity | None = None
    category: str = ""
    accepted_by: str = ""
    accepted_on: str = ""
    reason: str = ""


class Baseline(BaseModel):
    """A file of accepted findings."""

    model_config = ConfigDict(extra="forbid")

    version: int = BASELINE_VERSION
    generated_by: str = f"tenanttrace {__version__}"
    entries: tuple[BaselineEntry, ...] = ()

    @property
    def fingerprints(self) -> frozenset[str]:
        return frozenset(entry.fingerprint for entry in self.entries)

    def accepts(self, finding: Finding) -> bool:
        return _fingerprint_of(finding) in self.fingerprints


def _fingerprint_of(finding: Finding) -> str:
    """A finding's fingerprint, computed if it was not carried."""
    return finding.fingerprint or compute_fingerprint(finding)


def entry_for(finding: Finding, *, accepted_by: str = "", reason: str = "") -> BaselineEntry:
    """Build an entry from a finding, carrying no evidence."""
    return BaselineEntry(
        fingerprint=_fingerprint_of(finding),
        title=finding.title,
        location=finding.location,
        severity=finding.severity,
        category=finding.category.value,
        accepted_by=accepted_by,
        accepted_on=utcnow().date().isoformat(),
        reason=reason,
    )


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #


def load_baseline(path: str | Path | None) -> Baseline:
    """Read a baseline. A missing file is an empty baseline, not an error.

    The first run in a repository has nothing to suppress, and making that an
    error would mean every new user's first experience is a crash.
    """
    if path is None:
        return Baseline()
    file = Path(path)
    if not file.is_file():
        return Baseline()
    try:
        raw: Any = json.loads(file.read_text(encoding="utf-8"))
    except ValueError as exc:
        msg = f"{file} is not valid JSON: {exc}"
        raise ValueError(msg) from exc
    if isinstance(raw, dict):
        raw.pop("$comment", None)
    return Baseline.model_validate(raw)


def save_baseline(baseline: Baseline, path: str | Path) -> Path:
    """Write a baseline, sorted so diffs stay readable."""
    file = Path(path)
    file.parent.mkdir(parents=True, exist_ok=True)
    payload = baseline.model_dump(mode="json")
    payload["entries"] = sorted(payload["entries"], key=lambda e: (e["location"], e["fingerprint"]))
    payload["$comment"] = (
        "Findings this project has accepted. Reviewed like code: adding an entry here "
        "suppresses a real finding. Contains no canaries, tokens, or response bodies."
    )
    file.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return file


def baseline_from(
    findings: Iterable[Finding], *, accepted_by: str = "", reason: str = ""
) -> Baseline:
    """Build a baseline accepting every confirmed finding given.

    Suspected findings are skipped: they cannot gate a build, so accepting them
    would be noise in a file whose whole value is that it stays reviewable.
    """
    return Baseline(
        entries=tuple(
            entry_for(f, accepted_by=accepted_by, reason=reason)
            for f in findings
            if f.confidence is Confidence.CONFIRMED
        )
    )


# --------------------------------------------------------------------------- #
# Applying
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class BaselineResult:
    """What the baseline did to this run's findings."""

    new: tuple[Finding, ...] = ()
    suppressed: tuple[Finding, ...] = ()
    stale: tuple[BaselineEntry, ...] = ()

    @property
    def summary(self) -> str:
        bits = [f"{len(self.new)} new"]
        if self.suppressed:
            bits.append(f"{len(self.suppressed)} baselined")
        if self.stale:
            bits.append(f"{len(self.stale)} stale baseline entr(y/ies)")
        return ", ".join(bits)


def apply(baseline: Baseline | None, findings: Sequence[Finding]) -> BaselineResult:
    """Split findings into new and suppressed, and report stale entries."""
    if baseline is None:
        return BaselineResult(new=tuple(findings))

    accepted = baseline.fingerprints
    seen: set[str] = set()
    new: list[Finding] = []
    suppressed: list[Finding] = []

    for finding in findings:
        fingerprint = _fingerprint_of(finding)
        seen.add(fingerprint)
        (suppressed if fingerprint in accepted else new).append(finding)

    stale = tuple(entry for entry in baseline.entries if entry.fingerprint not in seen)
    return BaselineResult(new=tuple(new), suppressed=tuple(suppressed), stale=stale)


# --------------------------------------------------------------------------- #
# Gating
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class GateDecision:
    """Whether this run should fail the build, and a sentence saying why."""

    failed: bool
    message: str
    gating: tuple[Finding, ...] = ()
    result: BaselineResult = field(default_factory=BaselineResult)

    @property
    def exit_code(self) -> int:
        return 1 if self.failed else 0


def gate(
    findings: Sequence[Finding],
    *,
    fail_on: Severity | None,
    baseline: Baseline | None = None,
) -> GateDecision:
    """Decide whether this run fails the build.

    Only ``confirmed`` findings are eligible. A hypothesis the prober has not
    confirmed must never break somebody's merge — that is what keeps the static
    engine's false-positive rate from becoming everyone's problem.
    """
    result = apply(baseline, findings)

    suspected = [f for f in findings if f.confidence is Confidence.SUSPECTED]
    confirmed_new = [f for f in result.new if f.confidence is Confidence.CONFIRMED]

    notes: list[str] = []
    if result.suppressed:
        notes.append(f"{len(result.suppressed)} finding(s) accepted by the baseline")
    if result.stale:
        notes.append(f"{len(result.stale)} baseline entr(y/ies) no longer reported — remove them")
    if suspected:
        notes.append(f"{len(suspected)} static hypothes(es) reported (never gate the build)")
    suffix = (" · " + " · ".join(notes)) if notes else ""

    if fail_on is None:
        return GateDecision(
            failed=False,
            message=f"gate disabled (fail_on = none): {len(confirmed_new)} new confirmed{suffix}",
            result=result,
        )

    gating = tuple(f for f in confirmed_new if f.severity.at_least(fail_on))
    if gating:
        worst = max(gating, key=lambda f: f.severity.rank).severity
        return GateDecision(
            failed=True,
            message=(
                f"{len(gating)} new confirmed finding(s) at or above {fail_on.value} "
                f"(worst: {worst.value}){suffix}"
            ),
            gating=gating,
            result=result,
        )

    return GateDecision(
        failed=False,
        message=(
            f"no new confirmed findings at or above {fail_on.value}"
            f" ({len(confirmed_new)} new confirmed in total){suffix}"
        ),
        result=result,
    )
