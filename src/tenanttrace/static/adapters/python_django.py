"""Static rules for Python applications using the Django ORM.

The second adapter, and deliberately small: everything that is about Python
rather than about a query builder now lives in :mod:`tenanttrace.static.rules`,
so what is left here is only what Django genuinely does differently
(ADR-0012).

Three things it does differently enough to matter:

* **A manager, not a session.** Queries start at ``Model.objects``, and the
  common shorthand ``get_object_or_404(Model, pk=…)`` hides the query entirely.
* **A different escape hatch.** Where SQLAlchemy has ``with_loader_criteria``
  and events, Django scopes globally by overriding ``Manager.get_queryset`` —
  and bypasses that scope through ``Model._base_manager`` or a manager
  explicitly named to be unfiltered.
* **Different raw SQL.** ``Model.objects.raw(...)`` and ``.extra(...)`` rather
  than ``text(...)``.

Everything the two adapters share — raw SQL by interpolation, tenant-less cache
keys, tenant-less job payloads, and all the AST scaffolding — is imported, not
repeated.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Sequence

from tenanttrace.core.models import Category, Finding, ScopingMode
from tenanttrace.static.base import Hit, ParsedFile, Scope, ScopingSignal, StaticContext
from tenanttrace.static.dataflow import dotted_name
from tenanttrace.static.rules import (
    cache_keys,
    dedupe,
    finding,
    job_payloads,
    parent_map,
    raw_sql,
    scope_nodes,
    scopes,
    tail,
)
from tenanttrace.static.scoping import detect_scoping

__all__ = ["ADAPTER_NAME", "DEFAULT_TENANT_COLUMNS", "PythonDjangoAdapter"]

ADAPTER_NAME = "python_django"

# Django projects name the boundary in their own vocabulary more often than
# SQLAlchemy ones do, because the framework encourages a `ForeignKey` to it.
DEFAULT_TENANT_COLUMNS: tuple[str, ...] = (
    "tenant_id",
    "tenant",
    "organization_id",
    "organization",
    "org_id",
    "account_id",
    "account",
    "company_id",
    "workspace_id",
    "site_id",
)

# Where a Django query begins. `objects` is the default manager; the rest are
# the shorthands that hide one.
_MANAGER_ATTRS: frozenset[str] = frozenset({"objects", "_default_manager"})
_QUERYSET_ENTRIES: frozenset[str] = frozenset(
    {
        "all",
        "filter",
        "exclude",
        "get",
        "first",
        "last",
        "count",
        "exists",
        "values",
        "values_list",
        "aggregate",
        "annotate",
        "iterator",
        "in_bulk",
        "earliest",
        "latest",
    }
)
_SHORTCUT_FUNCS: frozenset[str] = frozenset({"get_object_or_404", "get_list_or_404"})

# Raw SQL, Django spelling.
_RAW_METHODS: frozenset[str] = frozenset({"raw", "extra"})

# The documented way around a scoped default manager, and the names projects
# give a manager whose whole purpose is to skip it.
_BYPASS_ATTRS: frozenset[str] = frozenset({"_base_manager", "objects_unscoped", "all_objects"})
_BYPASS_NAMES: frozenset[str] = frozenset(
    {"unfiltered", "unscoped", "all_tenants", "across_tenants", "global_objects"}
)

_ASSUME_MISSING_FILTER = (
    "Assumes a manager query with no tenant keyword and no tenant-looking "
    "argument runs across tenants; wrong when the default manager is already "
    "scoped, when the queryset is narrowed by a caller, or when the view mixes "
    "in a per-request queryset — all of which are ordinary Django."
)

_ASSUME_SHORTCUT = (
    "Assumes get_object_or_404(Model, pk=…) resolves the identifier alone; "
    "wrong when the first argument is an already-scoped queryset rather than a "
    "model, which is the correct way to write it."
)

_ASSUME_BYPASS = (
    "Assumes _base_manager or a manager named unfiltered/unscoped is being used "
    "to step around a scoped default manager; sometimes that is deliberate and "
    "correct, in an admin view or a migration."
)


class PythonDjangoAdapter:
    """Static rules for Python applications using the Django ORM.

    Stateless, like its sibling: every method takes what it needs, so one
    instance can scan any number of trees.
    """

    name: str = ADAPTER_NAME
    file_globs: tuple[str, ...] = ("**/*.py",)

    # ------------------------------------------------------------------ mode
    def detect_scoping(self, files: Sequence[ParsedFile]) -> ScopingSignal:
        """Infer manual vs global scoping across the scanned tree.

        The shared detector already knows the vocabulary of several frameworks,
        Django's included, so this passes its own column names rather than
        reimplementing the search — the mismatch between an adapter's columns
        and the config's was a real defect once.
        """
        return detect_scoping(files, tenant_columns=DEFAULT_TENANT_COLUMNS)

    # -------------------------------------------------------------- findings
    def find_findings(self, file: ParsedFile, ctx: StaticContext) -> Iterable[Finding]:
        """Run every rule that applies in ``ctx.mode`` over one file."""
        parents = parent_map(file.tree)
        hits: list[Hit] = []

        for scope in scopes(file, ctx):
            nodes = tuple(scope_nodes(scope.root))
            # Shared with every Python adapter — see static/rules.py.
            hits.extend(raw_sql(scope, nodes, ctx))
            hits.extend(cache_keys(scope, nodes, ctx))
            hits.extend(job_payloads(scope, nodes, ctx))
            # Django's own.
            hits.extend(self._raw_queryset(scope, nodes, ctx))
            if ctx.mode is ScopingMode.MANUAL:
                hits.extend(self._missing_filter(scope, nodes, ctx, parents))
            elif ctx.mode is ScopingMode.GLOBAL:
                hits.extend(self._scope_bypass(scope, nodes))

        return [finding(hit, file, ctx) for hit in dedupe(hits)]

    # ------------------------------------------------------------- raw SQL
    def _raw_queryset(
        self, scope: Scope, nodes: Sequence[ast.AST], ctx: StaticContext
    ) -> list[Hit]:
        """``Model.objects.raw(...)`` and ``.extra(...)`` — RAW_SQL_ESCAPE."""
        hits: list[Hit] = []
        for node in nodes:
            if not isinstance(node, ast.Call) or tail(node.func) not in _RAW_METHODS:
                continue
            if not _from_manager(node.func):
                continue
            if any(_mentions_a_tenant_column(arg, ctx) for arg in _all_args(node)):
                continue
            hits.append(
                Hit(
                    category=Category.RAW_SQL_ESCAPE,
                    symbol=scope.symbol,
                    line=node.lineno,
                    assumption=_ASSUME_MISSING_FILTER,
                    note=f"{tail(node.func)}() on a manager with no tenant parameter",
                )
            )
        return hits

    # ------------------------------------------------- mode A: manual scoping
    def _missing_filter(
        self,
        scope: Scope,
        nodes: Sequence[ast.AST],
        ctx: StaticContext,
        parents: dict[int, ast.AST],
    ) -> list[Hit]:
        """Manager queries and 404 shortcuts with no tenant predicate."""
        hits: list[Hit] = []
        for node in nodes:
            if not isinstance(node, ast.Call):
                continue

            shortcut = tail(node.func) in _SHORTCUT_FUNCS
            if shortcut:
                model = _shortcut_model(node, ctx)
                if model is None:
                    # The first argument is a queryset, not a model — which is
                    # the correctly scoped way to write this.
                    continue
                assumption, note = _ASSUME_SHORTCUT, f"{tail(node.func)}({model}, …)"
            elif _is_manager_query(node, ctx):
                model = _manager_model(node.func) or "Model"
                assumption = _ASSUME_MISSING_FILTER
                note = f"{model}.objects.{tail(node.func)}() with no tenant predicate"
            else:
                continue

            if _chain_mentions_tenant(node, ctx, parents):
                continue
            hits.append(
                Hit(
                    category=Category.MISSING_TENANT_FILTER,
                    symbol=scope.symbol,
                    line=node.lineno,
                    assumption=assumption,
                    note=note,
                    model=model,
                )
            )
        return hits

    # ------------------------------------------------- mode B: global scoping
    def _scope_bypass(self, scope: Scope, nodes: Sequence[ast.AST]) -> list[Hit]:
        """Stepping around a scoped default manager — SCOPE_BYPASS_FLAG."""
        hits: list[Hit] = []
        for node in nodes:
            trigger = ""
            if isinstance(node, ast.Attribute) and node.attr in _BYPASS_ATTRS:
                trigger = node.attr
            elif isinstance(node, ast.Call) and tail(node.func) in _BYPASS_NAMES:
                trigger = tail(node.func)
            if not trigger or not isinstance(node, ast.expr):
                continue
            hits.append(
                Hit(
                    category=Category.SCOPE_BYPASS_FLAG,
                    symbol=scope.symbol,
                    line=node.lineno,
                    assumption=_ASSUME_BYPASS,
                    note=f"{trigger} steps around the scoped default manager",
                )
            )
        return hits


# --------------------------------------------------------------------------- #
# Django-shaped helpers
# --------------------------------------------------------------------------- #
def _columns(ctx: StaticContext) -> tuple[str, ...]:
    """The configured columns, widened by this adapter's own vocabulary.

    Detection and the rules must read the same list. They did not once before:
    `detect_scoping` used the adapter's names while the rules used the config's
    four defaults, so an application keyed on `workspace_id` was detected as
    MANUAL by evidence the rules then never looked for — and every correctly
    scoped query in it was reported.

    Widening rather than replacing, because the configured column is the
    operator's statement about their own application and outranks a guess.
    """
    return (*ctx.tenant_columns, *DEFAULT_TENANT_COLUMNS)


def _all_args(node: ast.Call) -> list[ast.expr]:
    return [*node.args, *(kw.value for kw in node.keywords if kw.value is not None)]


def _from_manager(func: ast.expr) -> bool:
    """True when this call hangs off ``.objects`` / ``._default_manager``."""
    current: ast.expr | None = func
    while isinstance(current, ast.Attribute):
        if current.attr in _MANAGER_ATTRS:
            return True
        current = current.value
    return False


def _is_manager_query(node: ast.Call, ctx: StaticContext) -> bool:
    """``Model.objects.filter(...)`` and friends."""
    if tail(node.func) not in _QUERYSET_ENTRIES:
        return False
    if not _from_manager(node.func):
        return False
    return _manager_model(node.func) is not None or not ctx.scoped_models


def _manager_model(func: ast.expr) -> str | None:
    """The model name a manager chain starts from, if it is written out."""
    current: ast.expr | None = func
    while isinstance(current, ast.Attribute):
        if current.attr in _MANAGER_ATTRS:
            name = dotted_name(current.value)
            return name.rsplit(".", 1)[-1] if name else None
        current = current.value
    return None


def _shortcut_model(node: ast.Call, ctx: StaticContext) -> str | None:
    """The model passed to ``get_object_or_404``, or None when it is a queryset.

    ``get_object_or_404(Invoice, pk=x)`` resolves the id alone.
    ``get_object_or_404(Invoice.objects.filter(tenant=t), pk=x)`` does not, and
    is the correct spelling — so a call whose first argument is anything other
    than a plain name is left alone.
    """
    if not node.args:
        return None
    first = node.args[0]
    if not isinstance(first, ast.Name | ast.Attribute):
        return None
    if isinstance(first, ast.Attribute) and first.attr in _MANAGER_ATTRS:
        return None
    name = dotted_name(first)
    if not name:
        return None
    leaf = name.rsplit(".", 1)[-1]
    if not leaf[:1].isupper():
        return None
    if ctx.scoped_models and leaf not in ctx.scoped_models:
        return None
    return leaf


def _mentions_a_tenant_column(node: ast.expr, ctx: StaticContext) -> bool:
    """True when an expression names one of the tenancy columns anywhere."""
    wanted = {c.lower().removesuffix("_id") for c in _columns(ctx)}
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            lowered = child.value.lower()
            if any(word and word in lowered for word in wanted):
                return True
        name = dotted_name(child) if isinstance(child, ast.Name | ast.Attribute) else None
        if name and any(word and word in name.lower() for word in wanted):
            return True
    return False


def _chain_mentions_tenant(node: ast.Call, ctx: StaticContext, parents: dict[int, ast.AST]) -> bool:
    """Does this query, or anything chained onto it, name the tenant?

    Django reads left to right and narrows as it goes, so
    ``Invoice.objects.filter(tenant=t).get(pk=x)`` scopes the ``get``. Walking
    up through the enclosing expression catches the other order too.
    """
    if any(kw.arg and _column_matches(kw.arg, ctx) for kw in node.keywords):
        return True
    if any(_mentions_a_tenant_column(arg, ctx) for arg in _all_args(node)):
        return True

    current: ast.AST | None = node
    seen = 0
    while current is not None and seen < 12:
        seen += 1
        current = parents.get(id(current))
        if isinstance(current, ast.Call):
            if any(kw.arg and _column_matches(kw.arg, ctx) for kw in current.keywords):
                return True
            if any(_mentions_a_tenant_column(arg, ctx) for arg in _all_args(current)):
                return True
    return False


def _column_matches(keyword: str, ctx: StaticContext) -> bool:
    """`tenant`, `tenant_id`, `tenant__slug`, `organization__in` all count."""
    head = keyword.split("__", 1)[0].lower()
    return any(head in {c.lower(), c.lower().removesuffix("_id")} for c in _columns(ctx))


def _sniff(files: Sequence[ParsedFile]) -> float:
    """Confidence that this tree is a Django application.

    Deliberately shallow, like its sibling: an import, not behaviour. A wrong
    guess produces a warning and no findings, which is recoverable; a clever
    guess that analysed a SQLAlchemy project with Django rules would produce
    confident nonsense.
    """
    for file in files:
        if not file.rel_path.endswith(".py"):
            continue
        for node in ast.walk(file.tree):
            if isinstance(node, ast.Import) and any(
                alias.name.split(".")[0] == "django" for alias in node.names
            ):
                return 1.0
            if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "django":
                return 1.0
    return 0.0
