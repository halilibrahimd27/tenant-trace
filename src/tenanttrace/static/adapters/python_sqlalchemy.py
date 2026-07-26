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
import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field

from tenanttrace.core.models import Category, Confidence, Engine, Evidence, Finding, ScopingMode
from tenanttrace.core.severity import remediation_for, severity_for, tags_for, title_for
from tenanttrace.static.base import ParsedFile, ScopingSignal, StaticContext
from tenanttrace.static.dataflow import (
    Definition,
    FunctionNode,
    attribute_tail,
    dotted_name,
    reaching_definitions,
    taints_from,
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
_RAW_SQL_FUNCS = frozenset({"text"})

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

_CACHE_RECEIVER_SUBSTRINGS = ("cache", "redis", "memcache")
_CACHE_RECEIVER_TOKENS = frozenset({"kv", "rds"})
_CACHE_WRITE_METHODS = frozenset({"set", "setex", "psetex", "setnx", "add", "put", "hset", "mset"})
_CACHE_READ_METHODS = frozenset({"get", "mget", "hget", "getset", "delete", "hdel"})

_DISPATCH_METHODS = frozenset(
    {"delay", "apply_async", "send_task", "enqueue", "enqueue_in", "enqueue_at", "publish"}
)
_DISPATCH_NAME_PREFIXES = ("enqueue", "dispatch", "queue_", "schedule_", "publish_", "submit_")

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

_SCOPE_BOUNDARIES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_MODULE_SYMBOL = "<module>"

_ID_SUFFIX_RE = re.compile(r"(^|_)(id|pk|uuid|guid)$", re.IGNORECASE)
_SQL_TABLE_RE = re.compile(r"\b(from|join|into|update)\b", re.IGNORECASE)
_SQL_BIND_RE = re.compile(r"[:@](\w+)|%\((\w+)\)s")
_TENANT_STEM_RE = re.compile(r"tenant|org|company|account|workspace", re.IGNORECASE)

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
_ASSUME_RAW_SQL = (
    "Assumes raw SQL that binds no tenant parameter runs unscoped; wrong for a "
    "statement scoped by a database view, a session variable, or row-level "
    "security, and it cannot see through SQL built at runtime."
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
_ASSUME_CACHE_KEY = (
    "Assumes a cache key that interpolates an object id but never the tenant is "
    "shared between tenants; wrong when the id is globally unique and unguessable, "
    "which makes this hygiene rather than a proven leak."
)
_ASSUME_JOB_PAYLOAD = (
    "Assumes a dict handed to a dispatch call — or built in a function named "
    "enqueue_*/dispatch_* — is the worker's payload; wrong for a helper that never "
    "dispatches, and blind to payloads carried as objects rather than dicts."
)


# --------------------------------------------------------------------------- #
# Internal records
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class _Hit:
    """A rule fired. Becomes a Finding once the location is known."""

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
class _Scope:
    """One analysable unit: a module body, a class body, or a function body."""

    symbol: str
    root: ast.AST
    fn: FunctionNode | None = None
    definitions: dict[str, set[Definition]] = field(default_factory=dict)
    tainted: frozenset[str] = frozenset()


# --------------------------------------------------------------------------- #
# Generic AST helpers
# --------------------------------------------------------------------------- #
def _tail(node: ast.expr) -> str:
    """The called method or function name, chained calls included.

    Method chaining (``select(X).where(...)``) has no dotted path, so this
    reads the final attribute instead of insisting on a fully qualified name.
    """
    return attribute_tail(node)


def _parent_map(tree: ast.Module) -> dict[int, ast.AST]:
    """Map ``id(node) -> parent``. ``ast`` has no parent links and we need to
    walk up a method chain to find where a query expression really ends."""
    parents: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent
    return parents


def _iter_definitions(node: ast.AST, prefix: str = "") -> Iterator[tuple[ast.AST, str]]:
    """Yield every def/class in the tree with its dotted symbol name."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, _SCOPE_BOUNDARIES):
            qualified = f"{prefix}{child.name}"
            yield child, qualified
            yield from _iter_definitions(child, prefix=f"{qualified}.")
        else:
            yield from _iter_definitions(child, prefix=prefix)


def _scope_nodes(root: ast.AST) -> Iterator[ast.AST]:
    """Every node owned by this scope, never entering a nested def or class."""
    stack: list[ast.AST] = [root]
    while stack:
        current = stack.pop()
        for child in ast.iter_child_nodes(current):
            if isinstance(child, _SCOPE_BOUNDARIES):
                continue
            yield child
            stack.append(child)


def _static_string(node: ast.expr) -> str:
    """Best-effort literal text of a string expression, ``{}`` for holes."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else ""
    if isinstance(node, ast.JoinedStr):
        return "".join(
            part.value if isinstance(part, ast.Constant) and isinstance(part.value, str) else "{}"
            for part in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _static_string(node.left) + _static_string(node.right)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return _static_string(node.left)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return _static_string(node.func.value)
    return ""


def _is_string_shaped(node: ast.expr) -> bool:
    """True when ``node`` builds a string we can read the shape of."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp):
        return isinstance(node.op, ast.Add | ast.Mod) and bool(_static_string(node))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr == "format"
    return False


def _interpolated(node: ast.expr) -> list[ast.expr]:
    """The expressions a string template interpolates."""
    if isinstance(node, ast.JoinedStr):
        return [part.value for part in node.values if isinstance(part, ast.FormattedValue)]
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add):
            return _interpolated(node.left) + _interpolated(node.right)
        if isinstance(node.op, ast.Mod):
            right = node.right
            return list(right.elts) if isinstance(right, ast.Tuple) else [right]
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return [*node.args, *(kw.value for kw in node.keywords)]
    if isinstance(node, ast.Name | ast.Attribute):
        return [node]
    return []


def _mentions_tenant(text: str, columns: Sequence[str]) -> bool:
    """True when a literal string names an ownership column or its stem."""
    lowered = text.lower()
    return any(column.lower() in lowered for column in columns) or bool(
        _TENANT_STEM_RE.search(lowered)
    )


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
        parents = _parent_map(file.tree)
        hits: list[_Hit] = []

        for scope in self._scopes(file, ctx):
            nodes = tuple(_scope_nodes(scope.root))
            # Mode-independent: true under manual and global scoping alike.
            hits.extend(self._raw_sql(scope, nodes, ctx))
            hits.extend(self._cache_keys(scope, nodes, ctx))
            hits.extend(self._job_payloads(scope, nodes, ctx))
            if ctx.mode is ScopingMode.MANUAL:
                hits.extend(self._missing_filter(scope, nodes, ctx, parents))
            elif ctx.mode is ScopingMode.GLOBAL:
                hits.extend(self._scope_bypass(scope, nodes))

        if ctx.mode is ScopingMode.GLOBAL:
            hits.extend(self._unscoped_models(file, ctx))

        return [self._finding(hit, file, ctx) for hit in _dedupe(hits)]

    # ------------------------------------------------------------------ scopes
    def _scopes(self, file: ParsedFile, ctx: StaticContext) -> Iterator[_Scope]:
        """Yield the module scope, then every function and class body."""
        yield _Scope(_MODULE_SYMBOL, file.tree)
        for node, symbol in _iter_definitions(file.tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                yield _Scope(
                    symbol,
                    node,
                    fn=node,
                    definitions=reaching_definitions(node),
                    tainted=frozenset(
                        taints_from(
                            node,
                            set(ctx.tenant_sources),
                            tenant_names=set(ctx.tenant_columns),
                            claim_keys={ctx.jwt_claim},
                        )
                    ),
                )
            elif isinstance(node, ast.ClassDef):
                yield _Scope(symbol, node)

    # ---------------------------------------------------------------- raw SQL
    def _raw_sql(self, scope: _Scope, nodes: Sequence[ast.AST], ctx: StaticContext) -> list[_Hit]:
        """``text(...)`` that binds no tenant parameter — RAW_SQL_ESCAPE."""
        hits: list[_Hit] = []
        for node in nodes:
            if not isinstance(node, ast.Call) or _tail(node.func) not in _RAW_SQL_FUNCS:
                continue
            if not node.args:
                continue
            sql = _static_string(node.args[0])
            # A statement with no table reference cannot cross a tenant boundary
            # (`SELECT 1`, `PRAGMA ...`), and flagging it is pure noise.
            if not sql or not _SQL_TABLE_RE.search(sql):
                continue
            # Assumes raw SQL that binds no tenant parameter runs unscoped; wrong
            # for a statement scoped by a database view, a session variable, or
            # row-level security, and it cannot see through SQL built at runtime.
            if _binds_tenant(sql, ctx.tenant_columns):
                continue
            if any(
                _expr_mentions_tenant(part, ctx.tenant_columns, scope.tainted)
                for part in _interpolated(node.args[0])
            ):
                continue
            hits.append(
                _Hit(
                    category=Category.RAW_SQL_ESCAPE,
                    symbol=scope.symbol,
                    line=node.lineno,
                    assumption=_ASSUME_RAW_SQL,
                    note=(
                        "raw SQL with no tenant bind parameter: "
                        f"{_truncate(' '.join(sql.split()), 120)}"
                    ),
                )
            )
        return hits

    # ------------------------------------------------------------- cache keys
    def _cache_keys(
        self, scope: _Scope, nodes: Sequence[ast.AST], ctx: StaticContext
    ) -> list[_Hit]:
        """Cache keys carrying an id but no tenant — TENANTLESS_CACHE_KEY."""
        hits: list[_Hit] = []
        for node in nodes:
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            receiver = dotted_name(node.func.value)
            if receiver is None or not _is_cache_receiver(receiver):
                continue
            method = node.func.attr
            writes = method in _CACHE_WRITE_METHODS
            if not writes and method not in _CACHE_READ_METHODS:
                continue
            key_expr = _first_argument(node, ("key", "name"))
            if key_expr is None:
                continue

            candidates = _resolve_strings(key_expr, scope.definitions)
            if not candidates:
                continue
            # Assumes a cache key that interpolates an object id but never the
            # tenant is shared between tenants; wrong when the id is globally
            # unique and unguessable, which makes this hygiene not a proven leak.
            if any(_key_carries_tenant(c, ctx.tenant_columns, scope.tainted) for c in candidates):
                continue
            if not all(_key_carries_id(c) for c in candidates):
                continue

            template = _static_string(candidates[0]) or "<dynamic>"
            hits.append(
                _Hit(
                    category=Category.TENANTLESS_CACHE_KEY,
                    symbol=scope.symbol,
                    line=node.lineno,
                    assumption=_ASSUME_CACHE_KEY,
                    note=(
                        f"{receiver}.{method}(...) keys on {template!r}, which has no "
                        f"{ctx.tenant_column} component"
                    ),
                    dedupe_key=f"cache:{template}",
                    priority=1 if writes else 0,
                )
            )
        return hits

    # ----------------------------------------------------------- job payloads
    def _job_payloads(
        self, scope: _Scope, nodes: Sequence[ast.AST], ctx: StaticContext
    ) -> list[_Hit]:
        """Worker payloads with no tenant key — TENANTLESS_JOB_PAYLOAD."""
        dispatches = [
            node
            for node in nodes
            if isinstance(node, ast.Call) and _tail(node.func) in _DISPATCH_METHODS
        ]

        payloads: list[ast.Dict] = []
        if dispatches:
            for call in dispatches:
                for argument in (*call.args, *(kw.value for kw in call.keywords)):
                    payloads.extend(_resolve_dicts(argument, scope.definitions))
        elif scope.fn is not None and _is_dispatch_name(scope.fn.name):
            # Assumes a dict handed to a dispatch call — or built in a function
            # named enqueue_*/dispatch_* — is the worker's payload; wrong for a
            # helper that never dispatches, and blind to non-dict payloads.
            payloads = [node for node in nodes if isinstance(node, ast.Dict)]

        for payload in sorted(payloads, key=lambda d: d.lineno):
            if _dict_carries_tenant(payload, ctx.tenant_columns):
                continue
            keys = ", ".join(_dict_key_names(payload)) or "<none>"
            return [
                _Hit(
                    category=Category.TENANTLESS_JOB_PAYLOAD,
                    symbol=scope.symbol,
                    line=payload.lineno,
                    assumption=_ASSUME_JOB_PAYLOAD,
                    note=(
                        f"the dispatched payload carries {keys} but no "
                        f"{ctx.tenant_column}, so the worker has to re-derive the scope"
                    ),
                )
            ]
        return []

    # -------------------------------------------------------- mode A: filters
    def _missing_filter(
        self,
        scope: _Scope,
        nodes: Sequence[ast.AST],
        ctx: StaticContext,
        parents: dict[int, ast.AST],
    ) -> list[_Hit]:
        """Reads on a scoped model with no tenant predicate (manual mode only)."""
        hits: list[_Hit] = []
        for node in nodes:
            if not isinstance(node, ast.Call) or not _is_query_root(node, ctx):
                continue
            outer = _outermost_chain(node, parents)
            closure = list(ast.walk(outer))
            # One hop of dataflow: a statement built over several assignments
            # (`stmt = select(X)` then `stmt = stmt.where(...)`) has its predicate
            # in a different statement from its model.
            for name in _assignment_targets(outer, parents):
                for definition in scope.definitions.get(name, ()):
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
                _Hit(
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
    def _scope_bypass(self, scope: _Scope, nodes: Sequence[ast.AST]) -> list[_Hit]:
        """Explicit disabling of the global scope (global mode only)."""
        hits: list[_Hit] = []
        for node in nodes:
            if not isinstance(node, ast.Call):
                continue
            # Assumes a call or flag named for bypassing the tenant scope really
            # disables it; often deliberate (platform admin, migrations), which is
            # why this needs a human decision rather than a fix.
            called = _tail(node.func).lower()
            trigger = next((token for token in _BYPASS_TOKENS if token in called), None)
            if trigger is not None:
                hits.append(
                    _Hit(
                        category=Category.SCOPE_BYPASS_FLAG,
                        symbol=scope.symbol,
                        line=node.lineno,
                        assumption=_ASSUME_SCOPE_BYPASS,
                        note=f"{_tail(node.func)}(...) leaves the global tenant scope",
                    )
                )
                continue
            for keyword in node.keywords:
                if keyword.arg in _BYPASS_KEYWORDS and _may_be_truthy(keyword.value):
                    hits.append(
                        _Hit(
                            category=Category.SCOPE_BYPASS_FLAG,
                            symbol=scope.symbol,
                            line=node.lineno,
                            assumption=_ASSUME_SCOPE_BYPASS,
                            note=f"{keyword.arg}= disables the global tenant scope",
                        )
                    )
        return hits

    def _unscoped_models(self, file: ParsedFile, ctx: StaticContext) -> list[_Hit]:
        """Tenant-owned models outside the scoping base class (global mode only)."""
        if not ctx.scope_mixins:
            # Without a known mixin there is nothing to be missing from, and
            # flagging every model would bury the report.
            return []
        mixins = set(ctx.scope_mixins)
        hits: list[_Hit] = []
        for node, symbol in _iter_definitions(file.tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases = {_tail(base) for base in node.bases}
            if bases & mixins or not _is_model(node, bases, ctx):
                continue
            # Assumes a model carrying a tenant column but not the scoping base
            # class sits outside the global scope; wrong when the mechanism
            # enrols models by table name or an explicit registry.
            if not _carries_tenant_column(node, ctx):
                continue
            hits.append(
                _Hit(
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
    def _finding(self, hit: _Hit, file: ParsedFile, ctx: StaticContext) -> Finding:
        """Turn a rule hit into a suspected finding anchored to file::symbol."""
        location = file.symbol_location(hit.symbol)
        return Finding(
            # A placeholder id, matching the probe half: the report layer numbers
            # findings, and identity across runs is the fingerprint's job.
            id="TT-0000",
            title=title_for(hit.category, location),
            category=hit.category,
            severity=severity_for(hit.category),
            confidence=Confidence.SUSPECTED,
            engine=Engine.STATIC,
            location=location,
            tags=tags_for(hit.category),
            evidence=Evidence(
                file=file.rel_path,
                line=hit.line,
                snippet=_truncate(file.source_line(hit.line), 200),
                assumption=hit.assumption,
                note=hit.note,
            ),
            remediation=remediation_for(
                hit.category,
                location=location,
                model=hit.model or "Model",
                column=ctx.tenant_column,
            ),
        )


# --------------------------------------------------------------------------- #
# Rule helpers
# --------------------------------------------------------------------------- #
def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else f"{text[: limit - 1]}…"


def _dedupe(hits: Sequence[_Hit]) -> list[_Hit]:
    """Collapse duplicates: one defect, one finding.

    Two passes. First, hits sharing an explicit ``dedupe_key`` (the same cache
    key template read in one function and written in another) become one, the
    write preferred because that is where the fix goes. Then one hit per
    category per symbol, since a symbol is the finest granularity a fingerprint
    records — three unscoped aggregates in one handler are one thing to fix.
    """
    by_key: dict[str, _Hit] = {}
    keyless: list[_Hit] = []
    for hit in hits:
        if not hit.dedupe_key:
            keyless.append(hit)
            continue
        current = by_key.get(hit.dedupe_key)
        if current is None or (hit.priority, -hit.line) > (current.priority, -current.line):
            by_key[hit.dedupe_key] = hit

    by_symbol: dict[tuple[Category, str], _Hit] = {}
    for hit in sorted([*keyless, *by_key.values()], key=lambda h: (h.line, h.symbol)):
        by_symbol.setdefault((hit.category, hit.symbol), hit)
    return sorted(by_symbol.values(), key=lambda h: (h.symbol, h.line))


def _binds_tenant(sql: str, columns: Sequence[str]) -> bool:
    """True when the statement binds a tenant-looking parameter."""
    names = {
        match.group(1) or match.group(2) for match in _SQL_BIND_RE.finditer(sql) if match.group(0)
    }
    return any(name and _mentions_tenant(name, columns) for name in names)


def _expr_mentions_tenant(expr: ast.expr, columns: Sequence[str], tainted: frozenset[str]) -> bool:
    """True when an expression names, or carries, the tenant."""
    for node in ast.walk(expr):
        if isinstance(node, ast.Attribute) and node.attr in columns:
            return True
        if isinstance(node, ast.Name) and (node.id in columns or node.id in tainted):
            return True
        if isinstance(node, ast.Constant) and node.value in columns:
            return True
    return False


def _is_cache_receiver(receiver: str) -> bool:
    """True when a call receiver looks like a cache client.

    Assumes a cache is reached through something named for one (``cache``,
    ``redis``, ``kv``); it misses a client named ``client`` or ``backend``, which
    costs recall rather than precision — the alternative, treating every
    ``.get()``/``.set()`` as a cache call, would flag ``ContextVar.set``.
    """
    lowered = receiver.lower()
    if any(token in lowered for token in _CACHE_RECEIVER_SUBSTRINGS):
        return True
    parts = re.split(r"[^a-z0-9]+", lowered)
    return any(part in _CACHE_RECEIVER_TOKENS for part in parts)


def _first_argument(call: ast.Call, keywords: Sequence[str]) -> ast.expr | None:
    """The first positional argument, or the first matching keyword."""
    if call.args:
        return call.args[0]
    for keyword in call.keywords:
        if keyword.arg in keywords:
            return keyword.value
    return None


def _resolve_strings(expr: ast.expr, definitions: dict[str, set[Definition]]) -> list[ast.expr]:
    """String-shaped expressions ``expr`` may be, following names one hop.

    One hop only: chasing a name through several assignments is where an
    intraprocedural analysis starts pretending to be an interprocedural one.
    """
    if _is_string_shaped(expr):
        return [expr]
    if isinstance(expr, ast.Name):
        return [
            definition.value
            for definition in sorted(definitions.get(expr.id, ()), key=lambda d: d.line)
            if definition.value is not None and _is_string_shaped(definition.value)
        ]
    return []


def _key_carries_tenant(expr: ast.expr, columns: Sequence[str], tainted: frozenset[str]) -> bool:
    """True when a key template names the tenant, literally or by interpolation."""
    if _mentions_tenant(_static_string(expr), columns):
        return True
    return any(_expr_mentions_tenant(part, columns, tainted) for part in _interpolated(expr))


def _key_carries_id(expr: ast.expr) -> bool:
    """True when a key template interpolates something that looks like an id."""
    for part in _interpolated(expr):
        name = dotted_name(part)
        if name and _ID_SUFFIX_RE.search(name.rsplit(".", 1)[-1]):
            return True
    return False


def _is_dispatch_name(name: str) -> bool:
    return name.lower().startswith(_DISPATCH_NAME_PREFIXES)


def _resolve_dicts(expr: ast.expr, definitions: dict[str, set[Definition]]) -> list[ast.Dict]:
    """Dict literals ``expr`` may be, unwrapping one serialisation call."""
    if isinstance(expr, ast.Dict):
        return [expr]
    if isinstance(expr, ast.Name):
        return [
            definition.value
            for definition in definitions.get(expr.id, ())
            if isinstance(definition.value, ast.Dict)
        ]
    if isinstance(expr, ast.Call) and _tail(expr.func) in {"dumps", "dump", "encode"}:
        return [d for argument in expr.args for d in _resolve_dicts(argument, definitions)]
    return []


def _dict_key_names(node: ast.Dict) -> list[str]:
    return [
        key.value
        for key in node.keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    ]


def _dict_carries_tenant(node: ast.Dict, columns: Sequence[str]) -> bool:
    """True when a payload names the tenant, or hides keys behind ``**spread``."""
    if any(key is None for key in node.keys):
        # `{**base, "id": x}` — we cannot see what `base` contains, so we say
        # nothing rather than accuse it of being tenant-less.
        return True
    return any(_mentions_tenant(name, columns) for name in _dict_key_names(node))


def _is_query_root(node: ast.Call, ctx: StaticContext) -> bool:
    """True when the call starts a query expression we can reason about."""
    tail = _tail(node.func)
    if tail in _QUERY_ROOT_FUNCS or tail in _QUERY_ROOT_METHODS:
        return True
    # `session.get(Model, pk)` resolves the primary key and nothing else. The
    # model argument is what tells it apart from `cache.get(key)`.
    if tail in _PRIMARY_KEY_LOOKUPS and node.args:
        first = node.args[0]
        return isinstance(first, ast.Name) and _looks_like_model(first.id, ctx)
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
        if isinstance(node, ast.Name) and _looks_like_model(node.id, ctx) and node.id not in found:
            found.append(node.id)
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
            parent.func is node or _tail(parent.func) in _CHAIN_CONSUMERS
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
        if not isinstance(node, ast.Call) or _tail(node.func) not in PREDICATE_CALLS:
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
