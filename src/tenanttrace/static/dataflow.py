"""Intraprocedural reaching definitions over a Python ``ast`` function body.

This is the only dataflow machinery in the project, and it is deliberately the
cheapest thing that answers the questions the adapters actually ask:

* "this ``cache.set(key, ...)`` was handed a name — what string was ``key``
  built from?"
* "does anything in this function carry a value that came from the tenant?"

It is a **MAY** analysis: at a join, definitions from *either* branch reach the
merge point. Over-approximating is the right direction here — the adapters use
these answers mostly to *suppress* findings ("the tenant is present, so this is
fine"), so an extra definition costs precision at worst, while a missing one
would invent a leak that is not there.

Hard limits, from CLAUDE.md rule 2:

* Single function. Nested ``def``/``class`` bodies are a different scope and are
  never entered; the *name* they bind is recorded and nothing else.
* No call graph, no symbolic execution, no SMT, no whole-program anything.
"""

from __future__ import annotations

import ast
import enum
from collections.abc import Iterator, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass

__all__ = [
    "LOOP_PASSES",
    "DefKind",
    "Definition",
    "FunctionNode",
    "assigned_names",
    "attribute_tail",
    "dotted_name",
    "reaching_definitions",
    "taints_from",
]

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef
"""The two shapes a Python function body comes in."""

Env = dict[str, set["Definition"]]

# A loop body is walked twice. A reaching-definitions MAY analysis over this
# shape converges in two passes — the first records the body's own definitions,
# the second lets a definition written late in the body reach a read earlier in
# it — so the cap is a guard against pathological input, not an approximation.
LOOP_PASSES = 2

# A chain of assignments needs at most one pass per assignment to settle. The
# extra ceiling stops a generated file with tens of thousands of assignments
# from turning a lint run into a coffee break.
_MAX_TAINT_PASSES = 32

_SCOPE_BOUNDARIES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


class DefKind(enum.StrEnum):
    """Where a binding came from. Coarse on purpose — adapters only branch on
    a few of these, and a finer taxonomy would be untested detail."""

    PARAMETER = "parameter"
    ASSIGNMENT = "assignment"
    FOR_TARGET = "for-target"
    WITH_TARGET = "with-target"
    COMPREHENSION = "comprehension"
    IMPORT = "import"


@dataclass(frozen=True, slots=True)
class Definition:
    """One binding of one name.

    Attributes:
        name: The bound name.
        node: The AST node responsible. For an assignment this is the statement,
            so ``node.value`` is the expression the name was bound to.
        line: 1-based source line, for evidence. Never for identity — see
            :mod:`tenanttrace.core.fingerprint`.
        kind: How the binding happened.
    """

    name: str
    node: ast.AST
    line: int
    kind: DefKind

    @property
    def value(self) -> ast.expr | None:
        """The expression assigned, when the binding was a plain assignment."""
        node = self.node
        if isinstance(node, ast.Assign | ast.AnnAssign | ast.AugAssign | ast.NamedExpr):
            return node.value
        return None


# --------------------------------------------------------------------------- #
# Small AST helpers, shared with the adapters
# --------------------------------------------------------------------------- #
def dotted_name(node: ast.AST) -> str | None:
    """Render ``a.b.c`` for a Name/Attribute chain, or ``None``.

    Returns ``None`` as soon as the chain is rooted in anything but a plain name
    (``get_session().query`` has no stable name), because a partial answer here
    would be silently wrong rather than usefully approximate.
    """
    parts: list[str] = []
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def attribute_tail(node: ast.AST) -> str:
    """Final component of a name or attribute, whatever the chain is rooted in.

    ``dotted_name`` gives up on ``select(X).where`` because the root is a call
    and there is no honest dotted path to report. Method chaining is the normal
    way to write a query, though, so the *method* still has to be readable:
    this returns ``"where"`` where ``dotted_name`` returns ``None``.
    """
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def assigned_names(target: ast.expr) -> Iterator[str]:
    """Yield the local names an assignment target binds.

    Tuple and list targets recurse, starred targets unwrap. Attribute and
    subscript targets bind nothing local (``obj.x = 1`` does not create ``x``).
    """
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, ast.Tuple | ast.List):
        for element in target.elts:
            yield from assigned_names(element)
    elif isinstance(target, ast.Starred):
        yield from assigned_names(target.value)


def _all_args(fn: FunctionNode) -> Iterator[ast.arg]:
    """Every parameter of ``fn``, positional-only through ``**kwargs``."""
    args = fn.args
    yield from args.posonlyargs
    yield from args.args
    yield from args.kwonlyargs
    if args.vararg is not None:
        yield args.vararg
    if args.kwarg is not None:
        yield args.kwarg


def _owned_statements(body: Sequence[ast.stmt]) -> Iterator[ast.stmt]:
    """Yield statements belonging to this scope, never entering a nested def."""
    for stmt in body:
        yield stmt
        if isinstance(stmt, _SCOPE_BOUNDARIES):
            continue
        yield from _owned_statements(tuple(_child_statements(stmt)))


def _child_statements(node: ast.AST) -> Iterator[ast.stmt]:
    """Statements directly inside a compound statement, handlers included."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.stmt):
            yield child
        elif isinstance(child, ast.excepthandler | ast.match_case):
            yield from (sub for sub in ast.iter_child_nodes(child) if isinstance(sub, ast.stmt))


# --------------------------------------------------------------------------- #
# Reaching definitions
# --------------------------------------------------------------------------- #
def reaching_definitions(fn: FunctionNode) -> dict[str, set[Definition]]:
    """Definitions that reach the end of ``fn``, keyed by name.

    A binding kills earlier bindings of the same name on a straight-line path;
    at a branch join the surviving sets are unioned. Parameters are definitions
    too, so a function that only reads its arguments still reports them.

    Args:
        fn: The function to analyse. Its nested definitions are not entered.

    Returns:
        Name to the set of definitions that may be live at the function's exit.
    """
    return _run_block(fn.body, _parameter_defs(fn))


def _parameter_defs(fn: FunctionNode) -> Env:
    env: Env = {}
    for arg in _all_args(fn):
        _bind(env, arg.arg, arg, DefKind.PARAMETER)
    return env


def _copy(env: Env) -> Env:
    return {name: set(defs) for name, defs in env.items()}


def _merge(left: Env, right: Env) -> Env:
    """Union both sides — the join of a MAY analysis."""
    merged = _copy(left)
    for name, defs in right.items():
        merged.setdefault(name, set()).update(defs)
    return merged


def _bind(env: Env, name: str, node: ast.AST, kind: DefKind) -> Env:
    """Record a binding, killing earlier definitions of the same name."""
    env[name] = {Definition(name, node, getattr(node, "lineno", 0), kind)}
    return env


def _bind_target(env: Env, target: ast.expr, node: ast.AST, kind: DefKind) -> Env:
    for name in assigned_names(target):
        _bind(env, name, node, kind)
    return env


def _scan_expr(env: Env, expr: ast.expr | None) -> Env:
    """Record bindings hidden inside an expression: walrus and comprehensions.

    Comprehension targets get their own scope in Python 3, so recording them in
    the enclosing function over-approximates. That is the safe direction for a
    MAY analysis, and the alternative — dropping them — would lose the only
    binding site a reader can see for the name.
    """
    if expr is None:
        return env
    for node in ast.walk(expr):
        if isinstance(node, ast.NamedExpr):
            _bind_target(env, node.target, node, DefKind.ASSIGNMENT)
        elif isinstance(node, ast.comprehension):
            _bind_target(env, node.target, node.target, DefKind.COMPREHENSION)
    return env


def _run_block(body: Sequence[ast.stmt], env: Env) -> Env:
    current = env
    for stmt in body:
        current = _run_stmt(stmt, current)
    return current


def _run_stmt(stmt: ast.stmt, env: Env) -> Env:
    if isinstance(stmt, ast.Assign):
        _scan_expr(env, stmt.value)
        for target in stmt.targets:
            _bind_target(env, target, stmt, DefKind.ASSIGNMENT)
        return env

    if isinstance(stmt, ast.AnnAssign):
        # A bare annotation (`x: int`) declares a type, not a value.
        if stmt.value is not None:
            _scan_expr(env, stmt.value)
            _bind_target(env, stmt.target, stmt, DefKind.ASSIGNMENT)
        return env

    if isinstance(stmt, ast.AugAssign):
        _scan_expr(env, stmt.value)
        return _bind_target(env, stmt.target, stmt, DefKind.ASSIGNMENT)

    if isinstance(stmt, ast.For | ast.AsyncFor):
        _scan_expr(env, stmt.iter)
        entry = _bind_target(_copy(env), stmt.target, stmt, DefKind.FOR_TARGET)
        return _run_loop(stmt.body, stmt.orelse, env, entry)

    if isinstance(stmt, ast.While):
        _scan_expr(env, stmt.test)
        return _run_loop(stmt.body, stmt.orelse, env, _copy(env))

    if isinstance(stmt, ast.If):
        _scan_expr(env, stmt.test)
        taken = _run_block(stmt.body, _copy(env))
        skipped = _run_block(stmt.orelse, _copy(env))
        return _merge(taken, skipped)

    if isinstance(stmt, ast.With | ast.AsyncWith):
        for item in stmt.items:
            _scan_expr(env, item.context_expr)
            if item.optional_vars is not None:
                _bind_target(env, item.optional_vars, stmt, DefKind.WITH_TARGET)
        return _run_block(stmt.body, env)

    if isinstance(stmt, ast.Try | ast.TryStar):
        return _run_try(stmt, env)

    if isinstance(stmt, ast.Import | ast.ImportFrom):
        for alias in stmt.names:
            _bind(env, alias.asname or alias.name.split(".")[0], stmt, DefKind.IMPORT)
        return env

    if isinstance(stmt, _SCOPE_BOUNDARIES):
        # Intraprocedural: the name is bound here, the body is another scope.
        return _bind(env, stmt.name, stmt, DefKind.ASSIGNMENT)

    if isinstance(stmt, ast.Match):
        return _run_match(stmt, env)

    # Everything else (return, raise, expression statements, asserts) can still
    # bind through a walrus or a comprehension.
    for child in ast.iter_child_nodes(stmt):
        if isinstance(child, ast.expr):
            _scan_expr(env, child)
    return env


def _run_loop(
    body: Sequence[ast.stmt],
    orelse: Sequence[ast.stmt],
    entry: Env,
    first_pass: Env,
) -> Env:
    """Walk a loop body to a (capped) fixed point.

    ``entry`` is the state before the loop, kept in the result because a loop
    may run zero times — dropping it would claim the body always executes.
    """
    result = _merge(entry, first_pass)
    for _ in range(LOOP_PASSES):
        result = _merge(result, _run_block(body, _copy(result)))
    if orelse:
        result = _merge(result, _run_block(orelse, _copy(result)))
    return result


def _run_try(stmt: ast.Try | ast.TryStar, env: Env) -> Env:
    body_env = _run_block(stmt.body, _copy(env))
    # An exception can fire anywhere in the body, so a handler starts from
    # either the entry state or whatever the body managed to bind first.
    handler_entry = _merge(env, body_env)
    result = body_env
    for handler in stmt.handlers:
        scoped = _copy(handler_entry)
        if handler.name:
            # Python deletes the bound name at the end of the block; a MAY
            # analysis keeps it, which over-approximates in the safe direction.
            _bind(scoped, handler.name, handler, DefKind.ASSIGNMENT)
        result = _merge(result, _run_block(handler.body, scoped))
    if stmt.orelse:
        result = _merge(result, _run_block(stmt.orelse, _copy(body_env)))
    if stmt.finalbody:
        result = _run_block(stmt.finalbody, result)
    return result


def _run_match(stmt: ast.Match, env: Env) -> Env:
    _scan_expr(env, stmt.subject)
    # No case is guaranteed to run, so the entry state survives the statement.
    result = _copy(env)
    for case in stmt.cases:
        scoped = _copy(env)
        for name in _pattern_names(case.pattern):
            _bind(scoped, name, case.pattern, DefKind.ASSIGNMENT)
        _scan_expr(scoped, case.guard)
        result = _merge(result, _run_block(case.body, scoped))
    return result


def _pattern_names(pattern: ast.pattern) -> Iterator[str]:
    """Capture names bound by a match pattern (``as`` targets, ``*rest``)."""
    for node in ast.walk(pattern):
        name = getattr(node, "name", None)
        if isinstance(name, str):
            yield name
        rest = getattr(node, "rest", None)
        if isinstance(rest, str):
            yield rest


# --------------------------------------------------------------------------- #
# Taint: which names carry the tenant
# --------------------------------------------------------------------------- #
def taints_from(
    fn: FunctionNode,
    sources: AbstractSet[str],
    *,
    tenant_names: AbstractSet[str] = frozenset(),
    claim_keys: AbstractSet[str] = frozenset(),
) -> set[str]:
    """Names in ``fn`` that transitively carry a value from a tenant source.

    A source is any of:

    * a call to a configured ``tenant_sources`` entry (``get_current_tenant()``),
    * an attribute path listed in ``tenant_sources`` (``request.state.tenant_id``),
    * an attribute whose final component is a tenant column
      (``principal.tenant_id``),
    * a subscript of a claims mapping (``claims["tenant_id"]``),
    * a parameter named or annotated as the tenant.

    Args:
        fn: The function to analyse; nested definitions are not entered.
        sources: Callable names and dotted paths that yield a tenant.
        tenant_names: Ownership column names (``tenant_id``, ``org_id``).
        claim_keys: Token-claim keys carrying the tenant.

    Returns:
        The set of tainted local names. Approximate by construction: it is used
        to *suppress* findings, so it errs towards claiming a tenant is present.
    """
    tainted: set[str] = set()
    for arg in _all_args(fn):
        if arg.arg in tenant_names:
            tainted.add(arg.arg)
            continue
        annotation = dotted_name(arg.annotation) if arg.annotation is not None else None
        if annotation and annotation.split(".")[-1] in sources:
            tainted.add(arg.arg)

    bindings = list(_taint_bindings(fn))
    for _ in range(min(len(bindings) + 1, _MAX_TAINT_PASSES)):
        changed = False
        for names, value in bindings:
            if not _expr_is_tainted(value, tainted, sources, tenant_names, claim_keys):
                continue
            for name in names:
                if name not in tainted:
                    tainted.add(name)
                    changed = True
        if not changed:
            break
    return tainted


def _taint_bindings(fn: FunctionNode) -> Iterator[tuple[tuple[str, ...], ast.expr]]:
    """Yield ``(bound names, source expression)`` for every binding in ``fn``."""
    for stmt in _owned_statements(fn.body):
        if isinstance(stmt, ast.Assign):
            names = tuple(n for target in stmt.targets for n in assigned_names(target))
            if names:
                yield names, stmt.value
        elif isinstance(stmt, ast.AnnAssign | ast.AugAssign):
            if stmt.value is not None:
                names = tuple(assigned_names(stmt.target))
                if names:
                    yield names, stmt.value
        elif isinstance(stmt, ast.For | ast.AsyncFor):
            names = tuple(assigned_names(stmt.target))
            if names:
                yield names, stmt.iter
        elif isinstance(stmt, ast.With | ast.AsyncWith):
            for item in stmt.items:
                if item.optional_vars is None:
                    continue
                names = tuple(assigned_names(item.optional_vars))
                if names:
                    yield names, item.context_expr


def _expr_is_tainted(
    expr: ast.expr,
    tainted: AbstractSet[str],
    sources: AbstractSet[str],
    tenant_names: AbstractSet[str],
    claim_keys: AbstractSet[str],
) -> bool:
    """True when any part of ``expr`` reads a tenant source or a tainted name."""
    for node in ast.walk(expr):
        if isinstance(node, ast.Call):
            name = dotted_name(node.func)
            if name and (name in sources or name.split(".")[-1] in sources):
                return True
        elif isinstance(node, ast.Attribute):
            name = dotted_name(node)
            if name and name in sources:
                return True
            if node.attr in tenant_names:
                return True
        elif isinstance(node, ast.Subscript):
            key = node.slice
            if isinstance(key, ast.Constant) and key.value in claim_keys:
                return True
        elif isinstance(node, ast.Name) and (node.id in tainted or node.id in sources):
            return True
    return False
