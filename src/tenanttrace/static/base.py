"""The contract a language adapter implements, and the values it exchanges.

Everything framework-specific lives behind :class:`LanguageAdapter`. The static
core resolves an adapter through :mod:`tenanttrace.static.registry` and never
imports one directly, so adding a second language is a new module plus a
registry entry rather than an edit to the engine.

Two rules from CLAUDE.md shape this file:

* **Source is parsed, never imported or executed.** A :class:`ParsedFile`
  carries an already-parsed tree, so an adapter is handed data and has no reason
  to reach for ``importlib``.
* **Nothing here produces a verdict.** Adapters emit
  :class:`~tenanttrace.core.models.Finding` objects with
  ``confidence=SUSPECTED``; only the prober can promote a hypothesis.

``ParsedFile.tree`` is typed as :class:`ast.Module` because the only shipped
adapter parses Python with the stdlib ``ast`` module (ADR-0005). That is an
honest statement of today's scope rather than a design decision: when a second
language arrives, ``tree`` widens to a union and this docstring changes with it.
Faking generality now would only hide where the work actually is.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from tenanttrace.core.models import Category, Finding, ScopingMode
from tenanttrace.static.dataflow import Definition, FunctionNode

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance only
    from tenanttrace.core.config import Config

__all__ = [
    "Hit",
    "LanguageAdapter",
    "ParsedFile",
    "Scope",
    "ScopingSignal",
    "StaticContext",
]


@dataclass(frozen=True, slots=True)
class ParsedFile:
    """One source file that parsed cleanly, with its tree.

    Attributes:
        path: Absolute path on this machine. Never used in a finding location —
            it differs between a laptop and CI.
        rel_path: Repository-relative POSIX path. This is what reaches a
            finding, so that a fingerprint means the same thing everywhere.
        source: The full text, kept for evidence snippets.
        tree: The parsed module.
    """

    path: Path
    rel_path: str
    source: str
    tree: ast.Module

    def source_line(self, line: int) -> str:
        """Return line ``line`` (1-based), stripped, or ``""`` when out of range."""
        if line < 1:
            return ""
        lines = self.source.splitlines()
        if line > len(lines):
            return ""
        return lines[line - 1].strip()

    def symbol_location(self, symbol: str) -> str:
        """Build the ``<rel_path>::<symbol>`` location every static finding uses.

        A line number must never appear here: ``core.fingerprint`` identifies a
        static finding by file and symbol precisely so that a baseline survives
        somebody adding an import above the finding.
        """
        return f"{self.rel_path}::{symbol}"


@dataclass(frozen=True, slots=True)
class ScopingSignal:
    """How the application scopes queries, and why we think so.

    ``reasons`` is not decoration. Picking the wrong mode inverts the entire
    rule set — a missing filter is a bug under manual scoping and correct under
    global scoping — so a report that cannot explain its choice cannot be
    checked by the person reading it.

    Attributes:
        mode: The resolved mode.
        confidence: 0..1. How strong the evidence was, not how bad anything is.
        reasons: One sentence per piece of evidence, in the report's voice.
    """

    mode: ScopingMode
    confidence: float = 0.0
    reasons: tuple[str, ...] = ()

    def describe(self) -> str:
        """One-line summary: mode, confidence, and the leading reason."""
        head = f"{self.mode.value} (confidence {self.confidence:.2f})"
        return f"{head}: {self.reasons[0]}" if self.reasons else head


@dataclass(frozen=True, slots=True)
class StaticContext:
    """Everything an adapter needs to know about this application's vocabulary.

    Attributes:
        tenant_columns: Candidate ownership columns, most likely first.
        scoped_models: Models a cross-tenant audit cares about. Empty means the
            operator did not configure any; adapters may fall back to a
            heuristic and must say so in the finding.
        tenant_sources: Callables and dotted paths where a tenant enters a
            request (``get_current_tenant``, ``request.state.tenant_id``).
        jwt_claim: Claim name carrying the tenant in a token payload.
        mode: The resolved scoping mode. ``UNKNOWN`` means an adapter may only
            emit findings that hold under *both* rule sets.
        scope_mixins: Base classes that enrol a model in a global scope. Filled
            in from scoping detection rather than from config, because the name
            of the mixin is a fact about the codebase, not a preference.
    """

    tenant_columns: tuple[str, ...] = ("tenant_id",)
    scoped_models: tuple[str, ...] = ()
    tenant_sources: tuple[str, ...] = ()
    jwt_claim: str = "tenant_id"
    mode: ScopingMode = ScopingMode.UNKNOWN
    scope_mixins: tuple[str, ...] = ()

    @property
    def tenant_column(self) -> str:
        """The primary ownership column, used when rendering remediation."""
        return self.tenant_columns[0] if self.tenant_columns else "tenant_id"

    @classmethod
    def from_config(
        cls,
        config: Config,
        *,
        mode: ScopingMode,
        scope_mixins: Sequence[str] = (),
    ) -> StaticContext:
        """Build a context from a parsed ``tenanttrace.toml``.

        Args:
            config: The loaded configuration.
            mode: The resolved scoping mode (config override or detection).
            scope_mixins: Scoping base classes discovered in the scanned tree.

        Returns:
            The context handed to every adapter call in this scan.
        """
        return cls(
            tenant_columns=config.tenancy.columns(),
            scoped_models=tuple(config.tenancy.scoped_models),
            tenant_sources=tuple(config.static.tenant_sources),
            jwt_claim=config.static.jwt_claim,
            mode=mode,
            scope_mixins=tuple(scope_mixins),
        )


@dataclass(frozen=True, slots=True)
class Hit:
    """A rule fired. Becomes a Finding once the location is known.

    Shared rather than adapter-private because the rules in
    :mod:`tenanttrace.static.rules` return these, and every adapter consumes
    them (ADR-0012).
    """

    category: Category
    symbol: str
    line: int
    assumption: str
    note: str
    model: str = ""
    # Findings sharing a dedupe key are one defect reported once (a cache-key
    # template used by both a reader and a writer, say).
    dedupe_key: str = ""
    # Higher wins inside a dedupe group: report the write, not the read.
    priority: int = 0


@dataclass(frozen=True, slots=True)
class Scope:
    """One analysable unit: a module body, a class body, or a function body."""

    symbol: str
    root: ast.AST
    fn: FunctionNode | None = None
    definitions: dict[str, set[Definition]] = field(default_factory=dict)
    tainted: frozenset[str] = frozenset()


@runtime_checkable
class LanguageAdapter(Protocol):
    """Everything the static core needs from one language/framework.

    Attributes:
        name: Registry key, matching ``[static] adapter`` in the config file.
        file_globs: Patterns of files this adapter can parse.
    """

    name: str
    file_globs: tuple[str, ...]

    def detect_scoping(self, files: Sequence[ParsedFile]) -> ScopingSignal:
        """Infer how this codebase scopes queries to a tenant.

        Args:
            files: Every file in the scan that this adapter can read.

        Returns:
            The detected mode with the evidence behind it. ``UNKNOWN`` when the
            signals conflict or are absent — never a guess dressed as a fact.
        """
        ...

    def find_findings(self, file: ParsedFile, ctx: StaticContext) -> Iterable[Finding]:
        """Report isolation hypotheses for one file.

        Every finding must carry ``confidence=SUSPECTED``,
        ``engine=Engine.STATIC``, and a ``<rel_path>::<symbol>`` location.

        Args:
            file: The file to analyse.
            ctx: This application's tenancy vocabulary and the resolved mode.

        Returns:
            Findings, without fingerprints — the engine attaches those.
        """
        ...
