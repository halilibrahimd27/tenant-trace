"""Isolation rules that are about Python, not about an ORM.

Three of the static engine's rules never mention a query builder: raw SQL built
by interpolation, a cache key that carries an object id but no tenant, and a job
payload dispatched without one. They are patterns in the language and its
ecosystem — f-strings, ``cache.set``, ``.delay()`` — and every Python adapter
needs all three, expressed identically.

They lived inside ``python_sqlalchemy`` until a second adapter was attempted, at
which point the only options were to duplicate them or to import from a sibling
adapter — the exact coupling ``static/registry.py`` exists to prevent. Nothing
distinguishes the language half of an adapter from the framework half until
something else needs the language half (ADR-0012).

What stays in an adapter is what genuinely differs: how a query is recognised,
what a model looks like, and how that framework expresses a global scope.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator, Sequence

from tenanttrace.core.models import Category, Confidence, Engine, Evidence, Finding
from tenanttrace.core.severity import remediation_for, severity_for, tags_for, title_for
from tenanttrace.static.base import Hit, ParsedFile, Scope, StaticContext
from tenanttrace.static.dataflow import (
    Definition,
    all_definitions,
    attribute_tail,
    definitions_reaching,
    dotted_name,
    taints_from,
)

__all__ = [
    "cache_keys",
    "dedupe",
    "finding",
    "iter_definitions",
    "job_payloads",
    "parent_map",
    "raw_sql",
    "scope_nodes",
    "scopes",
    "tail",
    "truncate",
]

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

_ASSUME_RAW_SQL = (
    "Assumes raw SQL that binds no tenant parameter runs unscoped; wrong for a "
    "statement scoped by a database view, a session variable, or row-level "
    "security, and it cannot see through SQL built at runtime."
)

_CACHE_READ_METHODS = frozenset({"get", "mget", "hget", "getset", "delete", "hdel"})

_CACHE_RECEIVER_SUBSTRINGS = ("cache", "redis", "memcache")

_CACHE_RECEIVER_TOKENS = frozenset({"kv", "rds"})

_CACHE_WRITE_METHODS = frozenset({"set", "setex", "psetex", "setnx", "add", "put", "hset", "mset"})

_DISPATCH_METHODS = frozenset(
    {"delay", "apply_async", "send_task", "enqueue", "enqueue_in", "enqueue_at", "publish"}
)

_DISPATCH_NAME_PREFIXES = ("enqueue", "dispatch", "queue_", "schedule_", "publish_", "submit_")

_ID_SUFFIX_RE = re.compile(r"(^|_)(id|pk|uuid|guid)$", re.IGNORECASE)

_RAW_SQL_FUNCS = frozenset({"text"})

_SQL_BIND_RE = re.compile(r"[:@](\w+)|%\((\w+)\)s")

_SQL_TABLE_RE = re.compile(r"\b(from|join|into|update)\b", re.IGNORECASE)

_TENANT_STEM_RE = re.compile(r"tenant|org|company|account|workspace", re.IGNORECASE)


_MODULE_SYMBOL = "<module>"

_SCOPE_BOUNDARIES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def raw_sql(scope: Scope, nodes: Sequence[ast.AST], ctx: StaticContext) -> list[Hit]:
    """``text(...)`` that binds no tenant parameter — RAW_SQL_ESCAPE."""
    hits: list[Hit] = []
    for node in nodes:
        if not isinstance(node, ast.Call) or tail(node.func) not in _RAW_SQL_FUNCS:
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
            Hit(
                category=Category.RAW_SQL_ESCAPE,
                symbol=scope.symbol,
                line=node.lineno,
                assumption=_ASSUME_RAW_SQL,
                note=(
                    "raw SQL with no tenant bind parameter: "
                    f"{truncate(' '.join(sql.split()), 120)}"
                ),
            )
        )
    return hits


# ------------------------------------------------------------- cache keys


def cache_keys(scope: Scope, nodes: Sequence[ast.AST], ctx: StaticContext) -> list[Hit]:
    """Cache keys carrying an id but no tenant — TENANTLESS_CACHE_KEY."""
    hits: list[Hit] = []
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

        candidates = _resolve_strings(key_expr, scope.definitions, node.lineno)
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
            Hit(
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


def job_payloads(scope: Scope, nodes: Sequence[ast.AST], ctx: StaticContext) -> list[Hit]:
    """Worker payloads with no tenant key — TENANTLESS_JOB_PAYLOAD."""
    dispatches = [
        node
        for node in nodes
        if isinstance(node, ast.Call) and tail(node.func) in _DISPATCH_METHODS
    ]

    payloads: list[ast.Dict] = []
    if dispatches:
        for call in dispatches:
            for argument in (*call.args, *(kw.value for kw in call.keywords)):
                payloads.extend(_resolve_dicts(argument, scope.definitions, call.lineno))
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
            Hit(
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


def _binds_tenant(sql: str, columns: Sequence[str]) -> bool:
    """True when the statement binds a tenant-looking parameter."""
    names = {
        match.group(1) or match.group(2) for match in _SQL_BIND_RE.finditer(sql) if match.group(0)
    }
    return any(name and _mentions_tenant(name, columns) for name in names)


def _dict_carries_tenant(node: ast.Dict, columns: Sequence[str]) -> bool:
    """True when a payload names the tenant, or hides keys behind ``**spread``."""
    if any(key is None for key in node.keys):
        # `{**base, "id": x}` — we cannot see what `base` contains, so we say
        # nothing rather than accuse it of being tenant-less.
        return True
    return any(_mentions_tenant(name, columns) for name in _dict_key_names(node))


def _dict_key_names(node: ast.Dict) -> list[str]:
    return [
        key.value
        for key in node.keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    ]


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


def _first_argument(call: ast.Call, keywords: Sequence[str]) -> ast.expr | None:
    """The first positional argument, or the first matching keyword."""
    if call.args:
        return call.args[0]
    for keyword in call.keywords:
        if keyword.arg in keywords:
            return keyword.value
    return None


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


def _is_dispatch_name(name: str) -> bool:
    return name.lower().startswith(_DISPATCH_NAME_PREFIXES)


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


def _key_carries_id(expr: ast.expr) -> bool:
    """True when a key template interpolates something that looks like an id."""
    for part in _interpolated(expr):
        name = dotted_name(part)
        if name and _ID_SUFFIX_RE.search(name.rsplit(".", 1)[-1]):
            return True
    return False


def _key_carries_tenant(expr: ast.expr, columns: Sequence[str], tainted: frozenset[str]) -> bool:
    """True when a key template names the tenant, literally or by interpolation."""
    if _mentions_tenant(_static_string(expr), columns):
        return True
    return any(_expr_mentions_tenant(part, columns, tainted) for part in _interpolated(expr))


def _mentions_tenant(text: str, columns: Sequence[str]) -> bool:
    """True when a literal string names an ownership column or its stem."""
    lowered = text.lower()
    return any(column.lower() in lowered for column in columns) or bool(
        _TENANT_STEM_RE.search(lowered)
    )


def _resolve_dicts(
    expr: ast.expr, definitions: dict[str, set[Definition]], line: int | None = None
) -> list[ast.Dict]:
    """Dict literals ``expr`` may be, unwrapping one serialisation call."""
    if isinstance(expr, ast.Dict):
        return [expr]
    if isinstance(expr, ast.Name):
        bound = line if line is not None else getattr(expr, "lineno", 0)
        return [
            definition.value
            for definition in definitions_reaching(definitions, expr.id, bound)
            if isinstance(definition.value, ast.Dict)
        ]
    if isinstance(expr, ast.Call) and tail(expr.func) in {"dumps", "dump", "encode"}:
        return [d for argument in expr.args for d in _resolve_dicts(argument, definitions, line)]
    return []


def _resolve_strings(
    expr: ast.expr, definitions: dict[str, set[Definition]], line: int | None = None
) -> list[ast.expr]:
    """String-shaped expressions ``expr`` may be, following names one hop.

    One hop only: chasing a name through several assignments is where an
    intraprocedural analysis starts pretending to be an interprocedural one.
    """
    if _is_string_shaped(expr):
        return [expr]
    if isinstance(expr, ast.Name):
        bound = line if line is not None else getattr(expr, "lineno", 0)
        return [
            definition.value
            for definition in definitions_reaching(definitions, expr.id, bound)
            if definition.value is not None and _is_string_shaped(definition.value)
        ]
    return []


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


def tail(node: ast.expr) -> str:
    """The called method or function name, chained calls included.

    Method chaining (``select(X).where(...)``) has no dotted path, so this
    reads the final attribute instead of insisting on a fully qualified name.
    """
    return attribute_tail(node)


def truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else f"{text[: limit - 1]}…"


# --------------------------------------------------------------------------- #
# Scaffolding: walking a Python file, and turning hits into findings.
#
# None of this mentions an ORM either. It walks an AST, builds the analysable
# units, collapses duplicate hits, and renders a Finding — the same in every
# Python adapter, and the second thing writing a second adapter revealed
# (ADR-0012).
# --------------------------------------------------------------------------- #


def parent_map(tree: ast.Module) -> dict[int, ast.AST]:
    """Map ``id(node) -> parent``. ``ast`` has no parent links and we need to
    walk up a method chain to find where a query expression really ends."""
    parents: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent
    return parents


def iter_definitions(node: ast.AST, prefix: str = "") -> Iterator[tuple[ast.AST, str]]:
    """Yield every def/class in the tree with its dotted symbol name."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, _SCOPE_BOUNDARIES):
            qualified = f"{prefix}{child.name}"
            yield child, qualified
            yield from iter_definitions(child, prefix=f"{qualified}.")
        else:
            yield from iter_definitions(child, prefix=prefix)


def scope_nodes(root: ast.AST) -> Iterator[ast.AST]:
    """Every node owned by this scope, never entering a nested def or class."""
    stack: list[ast.AST] = [root]
    while stack:
        current = stack.pop()
        for child in ast.iter_child_nodes(current):
            if isinstance(child, _SCOPE_BOUNDARIES):
                continue
            yield child
            stack.append(child)


def scopes(file: ParsedFile, ctx: StaticContext) -> Iterator[Scope]:
    """Yield the module scope, then every function and class body."""
    yield Scope(_MODULE_SYMBOL, file.tree)
    for node, symbol in iter_definitions(file.tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            yield Scope(
                symbol,
                node,
                fn=node,
                definitions=all_definitions(node),
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
            yield Scope(symbol, node)


# ---------------------------------------------------------------- raw SQL


def dedupe(hits: Sequence[Hit]) -> list[Hit]:
    """Collapse duplicates: one defect, one finding.

    Two passes. First, hits sharing an explicit ``dedupe_key`` (the same cache
    key template read in one function and written in another) become one, the
    write preferred because that is where the fix goes. Then one hit per
    category per symbol, since a symbol is the finest granularity a fingerprint
    records — three unscoped aggregates in one handler are one thing to fix.
    """
    by_key: dict[str, Hit] = {}
    keyless: list[Hit] = []
    for hit in hits:
        if not hit.dedupe_key:
            keyless.append(hit)
            continue
        current = by_key.get(hit.dedupe_key)
        if current is None or (hit.priority, -hit.line) > (current.priority, -current.line):
            by_key[hit.dedupe_key] = hit

    by_symbol: dict[tuple[Category, str], Hit] = {}
    for hit in sorted([*keyless, *by_key.values()], key=lambda h: (h.line, h.symbol)):
        by_symbol.setdefault((hit.category, hit.symbol), hit)
    return sorted(by_symbol.values(), key=lambda h: (h.symbol, h.line))


def finding(hit: Hit, file: ParsedFile, ctx: StaticContext) -> Finding:
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
            snippet=truncate(file.source_line(hit.line), 200),
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
