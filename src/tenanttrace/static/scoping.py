"""Scoping-mode detection: manual, global, or honestly unknown.

This is the most consequential twenty lines of logic in the static engine,
because the correct rule is the *opposite* in each mode:

* **Manual (Mode A)** — every query is responsible for its own tenant predicate.
  A query without one is the bug.
* **Global (Mode B)** — a mechanism (``with_loader_criteria``, a
  ``do_orm_execute`` hook, a base-class scope) applies the predicate to every
  query. A handler with no predicate is *correct*, and reporting it is a false
  positive. What matters instead are the **escapes**: raw SQL, explicit
  bypasses, models that never joined the mechanism.

Get the mode wrong and the engine reports precisely the wrong half of the
codebase, so detection has to be conservative and it has to show its work. When
the signals conflict or are absent the answer is ``UNKNOWN``, and callers may
then emit only findings that hold under both rule sets.

``[tenancy] scoping_mode`` in the config file overrides detection outright;
``auto`` (the default) defers to it.

The scan itself walks ``ast`` because the only shipped adapter is Python (see
:mod:`tenanttrace.static.base`). The marker vocabulary below deliberately
includes names from other ecosystems: they cost nothing, and they document what
a second adapter would have to recognise.
"""

from __future__ import annotations

import ast
from collections.abc import Sequence
from dataclasses import dataclass

from tenanttrace.core.config import Config
from tenanttrace.core.models import ScopingMode
from tenanttrace.static.base import ParsedFile, ScopingSignal
from tenanttrace.static.dataflow import attribute_tail

__all__ = [
    "GLOBAL_MIXIN_NAMES",
    "GLOBAL_ORM_EVENTS",
    "GLOBAL_SCOPE_CALLS",
    "PREDICATE_CALLS",
    "ScopingEvidence",
    "decide",
    "detect_scoping",
    "resolve_scoping",
    "scope_mixin_names",
]

# --------------------------------------------------------------------------- #
# Marker vocabulary
# --------------------------------------------------------------------------- #
GLOBAL_SCOPE_CALLS: frozenset[str] = frozenset(
    {
        "with_loader_criteria",  # SQLAlchemy 1.4/2.0
        "add_global_scope",  # Django-ish / hand-rolled
        "addGlobalScope",  # Laravel Eloquent
        "bootTenantScope",  # Laravel multitenancy packages
        "global_scope",
    }
)
"""Calls that install a scope covering queries the author did not write."""

GLOBAL_ORM_EVENTS: frozenset[str] = frozenset(
    {"do_orm_execute", "before_execute", "before_compile", "before_compile_delete"}
)
"""SQLAlchemy events used to rewrite statements on their way to the database."""

GLOBAL_MIXIN_NAMES: frozenset[str] = frozenset(
    {
        "TenantScoped",
        "TenantScopedMixin",
        "TenantMixin",
        "TenantAware",
        "ScopedBase",
        "TenantBase",
        "BelongsToTenant",  # Laravel trait, by convention
    }
)
"""Base classes/traits that enrol a model in a global scope."""

PREDICATE_CALLS: frozenset[str] = frozenset({"where", "filter", "filter_by"})
"""Query-builder methods that can carry an inline tenant predicate."""

_CONTEXTVAR_CALLS: frozenset[str] = frozenset({"ContextVar", "contextvar"})

# Weights. A mechanism that rewrites statements is strong evidence; a naming
# convention is weak. They are summed and capped at 1.0 — this is a scoring
# heuristic for a report line, not a probability.
#
# A `with_loader_criteria`/`addGlobalScope` call has exactly one purpose, so one
# occurrence decides on its own. A `do_orm_execute` hook could be doing anything
# — logging, timing, sharding — so it needs corroboration to clear the bar.
_WEIGHT_SCOPE_CALL = 0.55
_WEIGHT_ORM_EVENT = 0.35
_WEIGHT_TENANT_CONTEXTVAR = 0.15
_WEIGHT_SCOPE_MIXIN = 0.10
_WEIGHT_INLINE_PREDICATE = 0.15

# A mechanism was found, not just a naming convention.
_GLOBAL_STRONG = 0.5
# ...and naming evidence alone can never get there, however much of it there is.
_CONVENTION_CEILING = _GLOBAL_STRONG - 0.05
# Enough handlers filter by hand that "everyone remembers" is the house style.
_MANUAL_MIN = 0.30
# Below this, a global marker is a coincidence rather than a mechanism.
_GLOBAL_NOISE = 0.30


@dataclass(frozen=True, slots=True)
class ScopingEvidence:
    """One observation pushing the verdict towards a mode.

    Attributes:
        mode: The mode this observation supports.
        weight: 0..1 contribution to that mode's score.
        reason: A sentence for the report, naming file and line.
        conventional: True when this is a naming convention rather than a
            mechanism that rewrites queries. Convention evidence is capped
            below the decision threshold, so no amount of well-named base
            classes can flip the mode on its own.
    """

    mode: ScopingMode
    weight: float
    reason: str
    conventional: bool = False


# --------------------------------------------------------------------------- #
# Evidence collection
# --------------------------------------------------------------------------- #
def _tenant_stems(tenant_columns: Sequence[str]) -> tuple[str, ...]:
    """``tenant_id`` -> ``tenant``: what a variable is likely to be named after."""
    stems = []
    for column in tenant_columns:
        stem = column[:-3] if column.endswith("_id") else column
        if stem:
            stems.append(stem.lower())
    return tuple(stems)


def _mentions_tenant_column(node: ast.AST, tenant_columns: Sequence[str]) -> bool:
    """True when ``node`` names an ownership column as an attribute or keyword."""
    columns = set(tenant_columns)
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute) and child.attr in columns:
            return True
        if isinstance(child, ast.keyword) and child.arg in columns:
            return True
        if isinstance(child, ast.Name) and child.id in columns:
            return True
    return False


def _collect_global(file: ParsedFile, tenant_columns: Sequence[str]) -> list[ScopingEvidence]:
    """Global-scoping markers in one file, at most one per marker kind."""
    found: dict[str, ScopingEvidence] = {}
    stems = _tenant_stems(tenant_columns)

    for node in ast.walk(file.tree):
        if isinstance(node, ast.Call):
            tail = attribute_tail(node.func)

            if tail in GLOBAL_SCOPE_CALLS:
                found.setdefault(
                    "scope_call",
                    ScopingEvidence(
                        ScopingMode.GLOBAL,
                        _WEIGHT_SCOPE_CALL,
                        f"{tail}(...) at {file.rel_path}:{node.lineno} attaches a tenant "
                        "predicate to queries the handler did not write",
                    ),
                )
            elif tail == "listens_for":
                event = next(
                    (
                        arg.value
                        for arg in node.args
                        if isinstance(arg, ast.Constant) and arg.value in GLOBAL_ORM_EVENTS
                    ),
                    None,
                )
                if event is not None:
                    found.setdefault(
                        "orm_event",
                        ScopingEvidence(
                            ScopingMode.GLOBAL,
                            _WEIGHT_ORM_EVENT,
                            f"an ORM {event!r} hook is registered at "
                            f"{file.rel_path}:{node.lineno}, which rewrites statements "
                            "before they reach the database",
                        ),
                    )
            elif tail in _CONTEXTVAR_CALLS:
                label = (
                    node.args[0].value
                    if node.args and isinstance(node.args[0], ast.Constant)
                    else ""
                )
                if isinstance(label, str) and any(stem in label.lower() for stem in stems):
                    found.setdefault(
                        "contextvar",
                        ScopingEvidence(
                            ScopingMode.GLOBAL,
                            _WEIGHT_TENANT_CONTEXTVAR,
                            f"a ContextVar named {label!r} at {file.rel_path}:{node.lineno} "
                            "carries the request's tenant out of band",
                            conventional=True,
                        ),
                    )

        elif isinstance(node, ast.ClassDef):
            for base in node.bases:
                tail = attribute_tail(base)
                if tail in GLOBAL_MIXIN_NAMES:
                    found.setdefault(
                        "mixin",
                        ScopingEvidence(
                            ScopingMode.GLOBAL,
                            _WEIGHT_SCOPE_MIXIN,
                            f"model {node.name} at {file.rel_path}:{node.lineno} inherits "
                            f"{tail}, the base a global scope usually attaches to",
                            conventional=True,
                        ),
                    )
    return list(found.values())


def _collect_manual(file: ParsedFile, tenant_columns: Sequence[str]) -> list[ScopingEvidence]:
    """Query expressions that filter by tenant inline, one evidence per file."""
    sites: list[int] = []
    for node in ast.walk(file.tree):
        if not isinstance(node, ast.Call):
            continue
        if attribute_tail(node.func) not in PREDICATE_CALLS:
            continue
        # Assumes a `.where(...)`/`.filter_by(...)` naming an ownership column is
        # a hand-written tenant predicate. It is wrong for a helper that filters
        # by tenant for some other reason (an admin report picking one tenant),
        # which would overstate how manual the codebase is.
        if _mentions_tenant_column(node, tenant_columns):
            sites.append(node.lineno)
    if not sites:
        return []
    return [
        ScopingEvidence(
            ScopingMode.MANUAL,
            _WEIGHT_INLINE_PREDICATE * len(sites),
            f"{len(sites)} quer{'y' if len(sites) == 1 else 'ies'} in {file.rel_path} "
            f"apply a tenant predicate by hand (first at line {min(sites)})",
        )
    ]


def scope_mixin_names(files: Sequence[ParsedFile]) -> tuple[str, ...]:
    """Base classes this codebase uses to enrol a model in a global scope.

    Two sources, both syntactic: a known mixin name used as a base class, and
    whatever class is handed to a global-scope call such as
    ``with_loader_criteria(TenantScoped, ...)``.
    """
    names: set[str] = set()
    for file in files:
        for node in ast.walk(file.tree):
            if isinstance(node, ast.ClassDef):
                for base in node.bases:
                    tail = attribute_tail(base)
                    if tail in GLOBAL_MIXIN_NAMES:
                        names.add(tail)
            elif isinstance(node, ast.Call) and (
                attribute_tail(node.func) in GLOBAL_SCOPE_CALLS and node.args
            ):
                target = attribute_tail(node.args[0])
                if target:
                    names.add(target)
    return tuple(sorted(names))


# --------------------------------------------------------------------------- #
# The decision
# --------------------------------------------------------------------------- #
def decide(evidence: Sequence[ScopingEvidence]) -> ScopingSignal:
    """Weigh collected evidence into a mode, with the reasons that decided it.

    Language-agnostic on purpose: a future adapter supplies its own evidence and
    reuses this rule ladder, so two languages cannot drift into two different
    definitions of "global scoping".
    """
    global_items = [e for e in evidence if e.mode is ScopingMode.GLOBAL]
    manual_items = [e for e in evidence if e.mode is ScopingMode.MANUAL]

    # Naming conventions are capped below the threshold, deliberately. A mixin
    # called `TenantScoped` is emitted once per file that mentions it, so five
    # model modules used to reach _GLOBAL_STRONG on names alone — and the
    # comment on that constant says "a mechanism was found, not just a naming
    # convention". Deciding GLOBAL switches off the missing-filter rule
    # entirely, so an application that merely *names* things well would have
    # had every unscoped query silently excused.
    #
    # Something that actually rewrites queries — with_loader_criteria, an ORM
    # event hook — must be present for the mode to flip.
    conventional = sum(e.weight for e in global_items if e.conventional)
    mechanical = sum(e.weight for e in global_items if not e.conventional)
    global_score = min(1.0, mechanical + min(conventional, _CONVENTION_CEILING))
    manual_score = min(1.0, sum(e.weight for e in manual_items))

    global_reasons = tuple(e.reason for e in global_items)
    manual_reasons = tuple(e.reason for e in manual_items)

    if global_score >= _GLOBAL_STRONG and manual_score >= _GLOBAL_STRONG:
        return ScopingSignal(
            ScopingMode.UNKNOWN,
            min(global_score, manual_score),
            (
                "signals conflict: a global scoping mechanism is present AND many "
                "queries still filter by tenant by hand. Set [tenancy] scoping_mode "
                "explicitly; until then only mode-independent findings are reported.",
                *global_reasons,
                *manual_reasons,
            ),
        )

    if global_score >= _GLOBAL_STRONG:
        return ScopingSignal(ScopingMode.GLOBAL, global_score, global_reasons)

    if manual_score >= _MANUAL_MIN and global_score < _GLOBAL_NOISE:
        return ScopingSignal(
            ScopingMode.MANUAL,
            manual_score,
            (*manual_reasons, "no global scoping mechanism was found in the scanned tree"),
        )

    return ScopingSignal(
        ScopingMode.UNKNOWN,
        max(global_score, manual_score),
        (
            "not enough evidence to tell manual from global scoping; only findings "
            "that hold under both rule sets are reported. Set [tenancy] scoping_mode "
            "to get the mode-specific checks.",
            *global_reasons,
            *manual_reasons,
        ),
    )


def detect_scoping(
    files: Sequence[ParsedFile],
    *,
    tenant_columns: Sequence[str] = ("tenant_id",),
) -> ScopingSignal:
    """Infer the scoping mode from every file in the scan.

    Args:
        files: The parsed files.
        tenant_columns: Ownership column candidates from ``[tenancy]``.

    Returns:
        The detected signal. ``UNKNOWN`` when evidence conflicts or is absent.
    """
    evidence: list[ScopingEvidence] = []
    for file in files:
        evidence.extend(_collect_global(file, tenant_columns))
        evidence.extend(_collect_manual(file, tenant_columns))
    return decide(evidence)


def resolve_scoping(config: Config, detected: ScopingSignal) -> ScopingSignal:
    """Apply the ``[tenancy] scoping_mode`` override to a detected signal.

    ``auto`` defers to detection. An explicit ``manual``/``global`` wins with
    confidence 1.0 — the operator knows their application better than a pattern
    match does, and pretending to second-guess them would just make the report
    argue with itself.
    """
    configured = config.tenancy.mode
    if configured is ScopingMode.UNKNOWN:
        return detected
    return ScopingSignal(
        configured,
        1.0,
        (
            f'[tenancy] scoping_mode = "{configured.value}" in the config file '
            "overrides detection",
            *(
                f"detection would have said {detected.mode.value}: {r}"
                for r in detected.reasons[:1]
            ),
        ),
    )
