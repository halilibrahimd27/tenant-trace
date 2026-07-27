"""Python + SQLAlchemy adapter: hypotheses about tenant isolation, from source.

Reads Python with the stdlib ``ast`` module and never imports or executes it
(CLAUDE.md rule 1 — this analyser has to be safe to point at hostile source).
The analysis is AST plus the single-function dataflow in
:mod:`tenanttrace.static.dataflow`; there is no call graph and no whole-program
reasoning anywhere in this file, on purpose.

The rules split by scoping mode, because the same code means opposite things:

============  =========================================================
Mode          What is a bug
============  =========================================================
``manual``    A read on a tenant-scoped model with no tenant predicate.
``global``    **Escapes** from the scope: raw SQL, an explicit bypass, a
              model that never joined the mechanism. A missing predicate
              is correct here and reporting it is a false positive.
``unknown``   Only what holds under both: raw SQL, cache keys, job
              payloads.
============  =========================================================

Every finding is ``confidence=SUSPECTED``. Each rule states what it assumes and
how it can be wrong, and that same sentence ships in ``Evidence.assumption`` so
the operator triaging the report reads the caveat we coded against.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Iterator, Sequence

from tenanttrace.core.models import Category, Finding, ScopingMode
from tenanttrace.static.base import (
    Hit,
    ParsedFile,
    Scope,
    ScopingSignal,
    StaticContext,
)
from tenanttrace.static.rules import (
    cache_keys,
    dedupe,
    finding,
    iter_definitions,
    job_payloads,
    parent_map,
    raw_sql,
    scope_nodes,
    scopes,
    tail,
)
from tenanttrace.static.scoping import PREDICATE_CALLS, detect_scoping

__all__ = ["ADAPTER_NAME", "DEFAULT_TENANT_COLUMNS", "PythonSQLAlchemyAdapter"]

ADAPTER_NAME = "python_sqlalchemy"

# Scoping detection runs before a StaticContext exists, so it works from this
# generous candidate list rather than the configured column. An application
# whose ownership column is outside it degrades to ScopingMode.UNKNOWN — fewer
# findings, never wrong ones — and the operator can set [tenancy] scoping_mode.
DEFAULT_TENANT_COLUMNS: tuple[str, ...] = (
    "tenant_id",
    "company_id",
    "org_id",
    "organization_id",
    "account_id",
    "workspace_id",
    "customer_id",
)

# --------------------------------------------------------------------------- #
# Vocabulary
# --------------------------------------------------------------------------- #
_QUERY_ROOT_FUNCS = frozenset({"select"})
_QUERY_ROOT_METHODS = frozenset({"query"})
_PRIMARY_KEY_LOOKUPS = frozenset({"get"})

# Calls that consume a statement without changing what it selects. Walking up
# through them keeps `session.scalars(select(X))` in one piece.
_CHAIN_CONSUMERS = frozenset(
    {
        "scalars",
        "scalar",
        "scalar_one",
        "scalar_one_or_none",
        "execute",
        "all",
        "one",
        "one_or_none",
        "first",
        "fetchall",
        "fetchone",
        "unique",
    }
)


_BYPASS_TOKENS = (
    "bypass",
    "unscoped",
    "without_scope",
    "without_tenant",
    "all_tenants",
    "cross_tenant",
    "skip_tenant",
    "skip_scope",
    "disable_scope",
    "unfiltered",
)
_BYPASS_KEYWORDS = frozenset(
    {
        "include_all_tenants",
        "all_tenants",
        "skip_tenant_scope",
        "bypass_tenant_scope",
        "without_tenant_scope",
        "no_tenant_scope",
        "unscoped",
    }
)

_MODEL_BASES = frozenset({"Base", "DeclarativeBase", "Model", "SQLModel"})


# --------------------------------------------------------------------------- #
# Assumptions. Each string is both the comment above its rule and the text the
# finding carries, so the operator reads exactly the caveat we coded against.
# --------------------------------------------------------------------------- #
_ASSUME_MISSING_FILTER = (
    "Assumes a query that never names the tenant column inside this function is "
    "unscoped; wrong when the predicate is applied by a repository wrapper, the "
    "caller, or an ORM scope a single-function analysis cannot see."
)
_ASSUME_MODEL_FALLBACK = (
    "No [tenancy] scoped_models is configured, so any CapWords name queried here "
    "is treated as a tenant-owned model; wrong for shared reference tables."
)

_ASSUME_SCOPE_BYPASS = (
    "Assumes a call or flag named for bypassing the tenant scope really disables "
    "it; often deliberate (platform admin, migrations), which is why this needs a "
    "human decision rather than a fix."
)
_ASSUME_UNSCOPED_MODEL = (
    "Assumes a model carrying a tenant column but not the scoping base class sits "
    "outside the global scope; wrong when the mechanism enrols models by table "
    "name or by an explicit registry instead of by inheritance."
)


# --------------------------------------------------------------------------- #
# Internal records
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# Generic AST helpers
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# The adapter
# --------------------------------------------------------------------------- #
class PythonSQLAlchemyAdapter:
    """Static rules for Python applications using SQLAlchemy.

    Stateless: every method takes everything it needs, so one instance can scan
    any number of trees and two scans cannot contaminate each other.
    """

    name: str = ADAPTER_NAME
    file_globs: tuple[str, ...] = ("**/*.py",)

    # ------------------------------------------------------------------ mode
    def detect_scoping(self, files: Sequence[ParsedFile]) -> ScopingSignal:
        """Infer manual vs global scoping across the scanned tree."""
        return detect_scoping(files, tenant_columns=DEFAULT_TENANT_COLUMNS)

    # -------------------------------------------------------------- findings
    def find_findings(self, file: ParsedFile, ctx: StaticContext) -> Iterable[Finding]:
        """Run every rule that applies in ``ctx.mode`` over one file."""
        parents = parent_map(file.tree)
        hits: list[Hit] = []

        for scope in scopes(file, ctx):
            nodes = tuple(scope_nodes(scope.root))
            # Mode-independent: true under manual and global scoping alike.
            hits.extend(raw_sql(scope, nodes, ctx))
            hits.extend(cache_keys(scope, nodes, ctx))
            hits.extend(job_payloads(scope, nodes, ctx))
            if ctx.mode is ScopingMode.MANUAL:
                hits.extend(self._missing_filter(scope, nodes, ctx, parents))
            elif ctx.mode is ScopingMode.GLOBAL:
                hits.extend(self._scope_bypass(scope, nodes))

        if ctx.mode is ScopingMode.GLOBAL:
            hits.extend(self._unscoped_models(file, ctx))

        return [finding(hit, file, ctx) for hit in dedupe(hits)]

    # ------------------------------------------------------------------ scopes

    def _missing_filter(
        self,
        scope: Scope,
        nodes: Sequence[ast.AST],
        ctx: StaticContext,
        parents: dict[int, ast.AST],
    ) -> list[Hit]:
        """Reads on a scoped model with no tenant predicate (manual mode only)."""
        hits: list[Hit] = []
        for node in nodes:
            if not isinstance(node, ast.Call) or not _is_query_root(node, ctx):
                continue
            outer = _outermost_chain(node, parents)
            closure = list(ast.walk(outer))
            # One hop of dataflow: a statement built over several assignments
            # (`stmt = select(X)` then `stmt = stmt.where(...)`) has its predicate
            # in a different statement from its model.
            # Every binding of the name, not the function's exit state and not
            # only the ones before this line. A query is routinely built across
            # statements (`stmt = select(X)` then `stmt = stmt.where(...)`), so
            # the predicate can live either side of the root — while the exit
            # state dropped the earlier binding entirely and invented a missing
            # filter on correctly-scoped code.
            #
            # Over-approximating is the safe direction here: an extra
            # definition can only make the tenant look present, which loses a
            # hypothesis rather than accusing correct code.
            for name in _assignment_targets(outer, parents):
                for definition in sorted(scope.definitions.get(name, ()), key=lambda d: d.line):
                    if definition.value is not None:
                        closure.extend(ast.walk(definition.value))

            models, guessed = _scoped_models_in(closure, ctx)
            if not models:
                continue
            # Assumes a query that never names the tenant column inside this
            # function is unscoped; wrong when the predicate is applied by a
            # repository wrapper, the caller, or a scope this cannot see.
            if _has_tenant_predicate(closure, ctx.tenant_columns, scope.tainted):
                continue
            hits.append(
                Hit(
                    category=Category.MISSING_TENANT_FILTER,
                    symbol=scope.symbol,
                    line=node.lineno,
                    assumption=(
                        f"{_ASSUME_MISSING_FILTER} {_ASSUME_MODEL_FALLBACK}"
                        if guessed
                        else _ASSUME_MISSING_FILTER
                    ),
                    note=(f"query on {', '.join(models)} with no {ctx.tenant_column} predicate"),
                    model=models[0],
                )
            )
        return hits

    # -------------------------------------------------------- mode B: escapes
    def _scope_bypass(self, scope: Scope, nodes: Sequence[ast.AST]) -> list[Hit]:
        """Explicit disabling of the global scope (global mode only)."""
        hits: list[Hit] = []
        for node in nodes:
            if not isinstance(node, ast.Call):
                continue
            # Assumes a call or flag named for bypassing the tenant scope really
            # disables it; often deliberate (platform admin, migrations), which is
            # why this needs a human decision rather than a fix.
            called = tail(node.func).lower()
            trigger = next((token for token in _BYPASS_TOKENS if token in called), None)
            if trigger is not None:
                hits.append(
                    Hit(
                        category=Category.SCOPE_BYPASS_FLAG,
                        symbol=scope.symbol,
                        line=node.lineno,
                        assumption=_ASSUME_SCOPE_BYPASS,
                        note=f"{tail(node.func)}(...) leaves the global tenant scope",
                    )
                )
                continue
            for keyword in node.keywords:
                if keyword.arg in _BYPASS_KEYWORDS and _may_be_truthy(keyword.value):
                    hits.append(
                        Hit(
                            category=Category.SCOPE_BYPASS_FLAG,
                            symbol=scope.symbol,
                            line=node.lineno,
                            assumption=_ASSUME_SCOPE_BYPASS,
                            note=f"{keyword.arg}= disables the global tenant scope",
                        )
                    )
        return hits

    def _unscoped_models(self, file: ParsedFile, ctx: StaticContext) -> list[Hit]:
        """Tenant-owned models outside the scoping base class (global mode only)."""
        if not ctx.scope_mixins:
            # Without a known mixin there is nothing to be missing from, and
            # flagging every model would bury the report.
            return []
        mixins = set(ctx.scope_mixins)
        hits: list[Hit] = []
        for node, symbol in iter_definitions(file.tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases = {tail(base) for base in node.bases}
            if bases & mixins or not _is_model(node, bases, ctx):
                continue
            # Assumes a model carrying a tenant column but not the scoping base
            # class sits outside the global scope; wrong when the mechanism
            # enrols models by table name or an explicit registry.
            if not _carries_tenant_column(node, ctx):
                continue
            hits.append(
                Hit(
                    category=Category.UNSCOPED_MODEL,
                    symbol=symbol,
                    line=node.lineno,
                    assumption=_ASSUME_UNSCOPED_MODEL,
                    note=(
                        f"{node.name} has a {ctx.tenant_column} column but does not "
                        f"inherit {' or '.join(sorted(mixins))}"
                    ),
                    model=node.name,
                )
            )
        return hits

    # ----------------------------------------------------------------- output


# --------------------------------------------------------------------------- #
# Rule helpers
# --------------------------------------------------------------------------- #


def _is_query_root(node: ast.Call, ctx: StaticContext) -> bool:
    """True when the call starts a query expression we can reason about."""
    name = tail(node.func)
    if name in _QUERY_ROOT_FUNCS or name in _QUERY_ROOT_METHODS:
        return True
    # `session.get(Model, pk)` resolves the primary key and nothing else. The
    # model argument is what tells it apart from `cache.get(key)`.
    if name in _PRIMARY_KEY_LOOKUPS and node.args:
        # `models.Invoice` as well as `Invoice`: `from app import models` is one
        # of the two standard SQLAlchemy import styles, and requiring a bare
        # Name here made the rule silently skip half of real codebases.
        return _looks_like_model(tail(node.args[0]), ctx)
    return False


def _looks_like_model(name: str, ctx: StaticContext) -> bool:
    if ctx.scoped_models:
        return name in ctx.scoped_models
    # Fallback when [tenancy] scoped_models is unset: CapWords means a class.
    return bool(name) and name[0].isupper() and not name.isupper()


def _scoped_models_in(closure: Sequence[ast.AST], ctx: StaticContext) -> tuple[list[str], bool]:
    """Scoped model names appearing in a query expression.

    Returns the names and whether they were guessed rather than configured, so
    the finding can admit which of the two it is.
    """
    guessed = not ctx.scoped_models
    found: list[str] = []
    for node in closure:
        # Attribute as well as Name, so `select(models.Invoice)` is seen. The
        # tail is what carries the model name in both styles.
        if not isinstance(node, (ast.Name, ast.Attribute)):
            continue
        name = tail(node)
        if name and _looks_like_model(name, ctx) and name not in found:
            found.append(name)
    return found, guessed


def _outermost_chain(root: ast.Call, parents: dict[int, ast.AST]) -> ast.AST:
    """Widen a query root to the whole expression that builds the statement.

    Walks up through method chaining (``select(X).where(...)``) and through
    calls that merely execute a statement (``session.scalars(...)``), and stops
    at anything else — a wrapper we do not recognise may belong to a sibling
    expression, and swallowing it would let an unrelated tenant predicate
    silence a real finding.
    """
    node: ast.AST = root
    while True:
        parent = parents.get(id(node))
        if isinstance(parent, ast.Attribute):
            node = parent
            continue
        if isinstance(parent, ast.Call) and (
            parent.func is node or tail(parent.func) in _CHAIN_CONSUMERS
        ):
            node = parent
            continue
        return node


def _assignment_targets(node: ast.AST, parents: dict[int, ast.AST]) -> tuple[str, ...]:
    """Names the enclosing statement assigns this expression to, if any."""
    parent = parents.get(id(node))
    if isinstance(parent, ast.Assign):
        return tuple(name for target in parent.targets for name in _target_names(target))
    if isinstance(parent, ast.AnnAssign):
        return tuple(_target_names(parent.target))
    return ()


def _target_names(target: ast.expr) -> Iterator[str]:
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, ast.Tuple | ast.List):
        for element in target.elts:
            yield from _target_names(element)


def _has_tenant_predicate(
    closure: Sequence[ast.AST], columns: Sequence[str], tainted: frozenset[str]
) -> bool:
    """True when the query expression constrains the ownership column."""
    column_set = set(columns)
    for node in closure:
        if isinstance(node, ast.Attribute) and node.attr in column_set:
            return True
        if isinstance(node, ast.keyword) and node.arg in column_set:
            return True
        if isinstance(node, ast.Name) and node.id in column_set:
            return True
    # A predicate can also read a tenant through a local carrying it:
    # `.where(Model.owner == scope)` where `scope` came from the credential.
    for node in closure:
        if not isinstance(node, ast.Call) or tail(node.func) not in PREDICATE_CALLS:
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Name) and inner.id in tainted:
                return True
    return False


def _may_be_truthy(node: ast.expr) -> bool:
    """True unless the value is a literal we can see is falsy."""
    if isinstance(node, ast.Constant):
        return bool(node.value)
    return True


def _is_model(node: ast.ClassDef, bases: set[str], ctx: StaticContext) -> bool:
    """True when a class looks like a mapped ORM model."""
    if node.name in ctx.scoped_models or bases & _MODEL_BASES:
        return True
    return any(
        isinstance(stmt, ast.Assign | ast.AnnAssign)
        and any(name == "__tablename__" for name in _statement_target_names(stmt))
        for stmt in node.body
    )


def _carries_tenant_column(node: ast.ClassDef, ctx: StaticContext) -> bool:
    """True when the class declares an ownership column, or was configured as scoped."""
    if node.name in ctx.scoped_models:
        return True
    columns = set(ctx.tenant_columns)
    return any(
        isinstance(stmt, ast.Assign | ast.AnnAssign)
        and any(name in columns for name in _statement_target_names(stmt))
        for stmt in node.body
    )


def _statement_target_names(stmt: ast.Assign | ast.AnnAssign) -> Iterator[str]:
    if isinstance(stmt, ast.AnnAssign):
        yield from _target_names(stmt.target)
    else:
        for target in stmt.targets:
            yield from _target_names(target)
