"""Join the two engines: static proposes, dynamic proves.

A static hypothesis and a probe-confirmed leak describing the same bug are more
useful together than apart. The probe knows *that* an endpoint leaks; the
static engine knows *which line* is responsible. Merging them produces the
finding an engineer can act on without going looking.

Merge rules:

===========================  ================================================
static + probe-confirmed     ``correlated`` — ranked highest, carries both the
                             endpoint and the source location
probe alone                  ``confirmed`` — unchanged
static alone                 ``suspected`` — unchanged, and never gates CI
===========================  ================================================

**The link is a heuristic, and an unsound one would be worse than none.** A
wrong link would attach `confirmed` confidence to a hypothesis about unrelated
code, which is precisely the failure mode this project refuses to ship. So the
rules below are conservative: a pairing requires both a compatible category and
a matching resource name, and anything that does not clear that bar is reported
as two separate findings rather than one confident guess.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from tenanttrace.core.fingerprint import compute_fingerprint, with_fingerprint
from tenanttrace.core.models import Category, Confidence, Engine, Finding

__all__ = ["CorrelationResult", "correlate", "resource_tokens"]

# Which static hypotheses a given confirmed leak can be evidence *for*.
# Read as: "if the prober confirmed X, a static finding of category Y about the
# same resource is describing the same bug."
_COMPATIBLE: dict[Category, frozenset[Category]] = {
    Category.CROSS_TENANT_READ: frozenset(
        {Category.MISSING_TENANT_FILTER, Category.RAW_SQL_ESCAPE, Category.SCOPE_BYPASS_FLAG}
    ),
    Category.LISTING_LEAK: frozenset(
        {Category.MISSING_TENANT_FILTER, Category.RAW_SQL_ESCAPE, Category.UNSCOPED_MODEL}
    ),
    Category.AGGREGATE_LEAK: frozenset({Category.MISSING_TENANT_FILTER, Category.RAW_SQL_ESCAPE}),
    Category.PARAM_OVERRIDE: frozenset({Category.MISSING_TENANT_FILTER}),
    Category.CACHE_KEY_LEAK: frozenset({Category.TENANTLESS_CACHE_KEY}),
    Category.CROSS_TENANT_WRITE: frozenset(
        {Category.MISSING_TENANT_FILTER, Category.UNSCOPED_MODEL}
    ),
}

# Words that appear in every route and every handler name and therefore carry
# no information about *which* resource is involved.
_STOPWORDS = frozenset(
    {
        "api",
        "v1",
        "v2",
        "get",
        "list",
        "read",
        "fetch",
        "create",
        "update",
        "delete",
        "post",
        "put",
        "patch",
        "handler",
        "route",
        "routes",
        "view",
        "views",
        "endpoint",
        "async",
        "def",
        "id",
        "by",
        "all",
        "detail",
        "py",
        "app",
        "src",
        "lib",
        "main",
    }
)

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def resource_tokens(location: str) -> frozenset[str]:
    """Meaningful words in a location, singularised.

    ``GET /api/invoices/{invoice_id}`` and
    ``fixtures/app/routes.py::get_invoice`` both reduce to ``{"invoice"}``,
    which is what makes them comparable.
    """
    lowered = location.lower().replace("::", "/").replace("_", " ").replace("-", " ")
    tokens = set()
    for raw in _TOKEN_RE.findall(lowered):
        if raw in _STOPWORDS or len(raw) < 3:
            continue
        tokens.add(_singular(raw))
    return frozenset(tokens)


def _singular(word: str) -> str:
    if word.endswith("ies") and len(word) > 3:
        return word[:-3] + "y"
    if word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    """Merged findings, plus a note of what was linked to what."""

    findings: tuple[Finding, ...] = ()
    links: tuple[tuple[str, str], ...] = ()
    unlinked_static: int = 0

    def ranked(self) -> tuple[Finding, ...]:
        return tuple(sorted(self.findings, key=lambda f: f.sort_key))


@dataclass
class _Pairing:
    probe: Finding
    static: list[Finding] = field(default_factory=list)


def correlate(
    probe_findings: Sequence[Finding],
    static_findings: Sequence[Finding],
) -> CorrelationResult:
    """Merge the two engines' findings.

    Returns every finding exactly once: a linked pair becomes one
    ``correlated`` finding, and everything else passes through untouched.
    """
    # Keyed by fingerprint so two reports of the same bug merge. Computed when
    # absent: an empty fingerprint would otherwise collapse every finding into
    # one entry and silently drop the rest.
    pairings = {_identity(f): _Pairing(probe=f) for f in probe_findings}
    linked_static: set[int] = set()
    links: list[tuple[str, str]] = []

    for index, hypothesis in enumerate(static_findings):
        if hypothesis.confidence is not Confidence.SUSPECTED:
            continue
        best = _best_match(hypothesis, probe_findings)
        if best is None:
            continue
        pairings[_identity(best)].static.append(hypothesis)
        linked_static.add(index)
        links.append((best.location, hypothesis.location))

    merged: list[Finding] = []
    for pairing in pairings.values():
        merged.append(_merge(pairing) if pairing.static else pairing.probe)

    unlinked = [f for i, f in enumerate(static_findings) if i not in linked_static]
    merged.extend(unlinked)

    merged.sort(key=lambda f: f.sort_key)
    renumbered = [f.model_copy(update={"id": f"TT-{i:04d}"}) for i, f in enumerate(merged, start=1)]
    return CorrelationResult(
        findings=tuple(renumbered),
        links=tuple(links),
        unlinked_static=len(unlinked),
    )


def _identity(finding: Finding) -> str:
    """The finding's fingerprint, computed if it was not carried."""
    return finding.fingerprint or compute_fingerprint(finding)


def _best_match(hypothesis: Finding, probe_findings: Iterable[Finding]) -> Finding | None:
    """Find the confirmed finding this hypothesis most likely explains."""
    hypothesis_tokens = resource_tokens(hypothesis.location)
    if not hypothesis_tokens:
        return None

    best: Finding | None = None
    best_score = 0
    for confirmed in probe_findings:
        if confirmed.confidence is not Confidence.CONFIRMED:
            continue
        if hypothesis.category not in _COMPATIBLE.get(confirmed.category, frozenset()):
            continue
        overlap = hypothesis_tokens & resource_tokens(confirmed.location)
        if not overlap:
            continue
        if len(overlap) > best_score:
            best, best_score = confirmed, len(overlap)
    return best


def _merge(pairing: _Pairing) -> Finding:
    """Build the correlated finding from a confirmed leak and its hypotheses."""
    probe = pairing.probe
    sources = tuple(sorted({h.location for h in pairing.static}))
    first = pairing.static[0]

    evidence = probe.evidence.model_copy(
        update={
            "file": first.evidence.file,
            "line": first.evidence.line,
            "snippet": first.evidence.snippet,
            "assumption": first.evidence.assumption,
        }
    )
    note = (probe.evidence.note or "").strip()
    joined = ", ".join(sources)
    detail = f"{note} Static analysis points at {joined}.".strip()

    merged = probe.model_copy(
        update={
            "engine": Engine.CORRELATED,
            "confidence": Confidence.CONFIRMED,
            "evidence": evidence.model_copy(update={"note": detail}),
            "related": sources,
            "tags": tuple(dict.fromkeys((*probe.tags, *first.tags))),
        }
    )
    # Fingerprint stays the probe's (see core/fingerprint.py): a finding that
    # was accepted into a baseline while probe-only must not re-alert simply
    # because the static engine started agreeing with it.
    return with_fingerprint(merged)
