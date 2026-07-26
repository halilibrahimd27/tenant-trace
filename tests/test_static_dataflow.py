"""Tests for the intraprocedural reaching-definitions helper.

The unit tests pin the shapes the adapters actually rely on. The property tests
pin the invariants that must hold for *any* function body, because this helper
is the piece most likely to be quietly wrong on code nobody wrote a fixture for:
a dropped definition turns into a finding that is not there.
"""

from __future__ import annotations

import ast

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tenanttrace.static.dataflow import (
    DefKind,
    assigned_names,
    attribute_tail,
    dotted_name,
    reaching_definitions,
    taints_from,
)


def parse_fn(source: str) -> ast.FunctionDef:
    """Parse a single function definition from ``source``."""
    node = ast.parse(source).body[0]
    assert isinstance(node, ast.FunctionDef)
    return node


def kinds(source: str, name: str) -> set[DefKind]:
    fn = parse_fn(source)
    return {d.kind for d in reaching_definitions(fn).get(name, set())}


# --------------------------------------------------------------------------- #
# Shapes the adapters depend on
# --------------------------------------------------------------------------- #
def test_parameters_are_definitions():
    fn = parse_fn("def f(a, /, b, *args, c=1, **kwargs):\n    pass\n")
    defs = reaching_definitions(fn)
    assert set(defs) == {"a", "b", "args", "c", "kwargs"}
    assert all(d.kind is DefKind.PARAMETER for group in defs.values() for d in group)


def test_assignment_kills_the_previous_definition():
    defs = reaching_definitions(parse_fn("def f():\n    x = 1\n    x = 2\n"))
    assert len(defs["x"]) == 1
    assert next(iter(defs["x"])).line == 3


def test_both_branches_reach_the_join():
    """A MAY analysis: an ``if`` contributes definitions from either side."""
    defs = reaching_definitions(
        parse_fn("def f(flag):\n    if flag:\n        x = 1\n    else:\n        x = 2\n")
    )
    assert {d.line for d in defs["x"]} == {3, 5}


def test_definition_before_a_branch_survives_a_one_sided_if():
    defs = reaching_definitions(parse_fn("def f(flag):\n    x = 1\n    if flag:\n        x = 2\n"))
    assert {d.line for d in defs["x"]} == {2, 4}


def test_tuple_unpacking_binds_every_name():
    defs = reaching_definitions(parse_fn("def f(pair):\n    a, (b, *rest) = pair\n"))
    assert {"a", "b", "rest"} <= set(defs)


def test_target_kinds():
    assert kinds("def f(xs):\n    for row in xs:\n        pass\n", "row") == {DefKind.FOR_TARGET}
    assert kinds("def f():\n    with open('x') as fh:\n        pass\n", "fh") == {
        DefKind.WITH_TARGET
    }
    assert kinds("def f():\n    import os.path\n", "os") == {DefKind.IMPORT}
    assert kinds("def f():\n    from a import b as c\n", "c") == {DefKind.IMPORT}
    assert kinds("def f(xs):\n    ys = [y for y in xs]\n", "y") == {DefKind.COMPREHENSION}
    assert kinds("def f():\n    if (n := 1):\n        pass\n", "n") == {DefKind.ASSIGNMENT}
    assert kinds("def f():\n    x: int = 1\n", "x") == {DefKind.ASSIGNMENT}
    assert kinds("def f(x):\n    x += 1\n", "x") == {DefKind.ASSIGNMENT}


def test_bare_annotation_binds_nothing():
    assert "x" not in reaching_definitions(parse_fn("def f():\n    x: int\n"))


def test_loop_body_definitions_survive_and_so_does_the_zero_trip_case():
    defs = reaching_definitions(
        parse_fn("def f(xs):\n    total = 0\n    for x in xs:\n        total = total + x\n")
    )
    # The loop may run zero times, so the pre-loop definition must still reach.
    assert {d.line for d in defs["total"]} == {2, 4}


def test_try_except_contributes_both_paths():
    defs = reaching_definitions(
        parse_fn(
            "def f():\n"
            "    try:\n"
            "        value = load()\n"
            "    except ValueError as exc:\n"
            "        value = None\n"
        )
    )
    assert {d.line for d in defs["value"]} == {3, 5}
    assert "exc" in defs


def test_match_captures_are_definitions():
    defs = reaching_definitions(
        parse_fn("def f(cmd):\n    match cmd:\n        case [head, *tail]:\n            pass\n")
    )
    assert {"head", "tail"} <= set(defs)


def test_nested_function_body_is_not_analysed():
    """Intraprocedural means intraprocedural — CLAUDE.md rule 2."""
    defs = reaching_definitions(
        parse_fn("def outer():\n    def inner():\n        secret = 1\n    return inner\n")
    )
    assert "inner" in defs
    assert "secret" not in defs


def test_definition_value_exposes_the_assigned_expression():
    fn = parse_fn("def f():\n    key = 'doc:1'\n")
    definition = next(iter(reaching_definitions(fn)["key"]))
    assert isinstance(definition.value, ast.Constant)
    assert definition.value.value == "doc:1"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def test_dotted_name_and_attribute_tail():
    expr = ast.parse("request.state.tenant_id", mode="eval").body
    assert dotted_name(expr) == "request.state.tenant_id"
    assert attribute_tail(expr) == "tenant_id"

    chained = ast.parse("select(Invoice).where(x)", mode="eval").body
    assert isinstance(chained, ast.Call)
    # A chained call has no honest dotted path, but the method name is still
    # readable — that distinction is what the adapters key on.
    assert dotted_name(chained.func) is None
    assert attribute_tail(chained.func) == "where"


def test_assigned_names_ignores_attribute_targets():
    target = ast.parse("obj.field = 1").body[0]
    assert isinstance(target, ast.Assign)
    assert list(assigned_names(target.targets[0])) == []


# --------------------------------------------------------------------------- #
# Taint
# --------------------------------------------------------------------------- #
TENANT_COLUMNS = frozenset({"tenant_id"})
SOURCES = frozenset({"get_current_tenant", "request.state.tenant_id"})


def taints(source: str) -> set[str]:
    return taints_from(
        parse_fn(source),
        SOURCES,
        tenant_names=TENANT_COLUMNS,
        claim_keys=frozenset({"tenant_id"}),
    )


def test_taint_from_a_call_to_a_configured_source():
    assert "scope" in taints("def f():\n    scope = get_current_tenant()\n")


def test_taint_from_a_dotted_source_and_an_attribute_column():
    assert "scope" in taints("def f(request):\n    scope = request.state.tenant_id\n")
    assert "scope" in taints("def f(principal):\n    scope = principal.tenant_id\n")


def test_taint_from_a_claims_subscript():
    assert "scope" in taints("def f(claims):\n    scope = claims['tenant_id']\n")


def test_taint_from_a_parameter_named_as_the_tenant():
    assert "tenant_id" in taints("def f(tenant_id):\n    pass\n")


def test_taint_is_transitive_but_never_interprocedural():
    result = taints(
        "def f(principal):\n    a = principal.tenant_id\n    b = a\n    c = helper(b)\n"
    )
    assert {"a", "b", "c"} <= result
    assert taints("def f():\n    a = unrelated()\n") == set()


def test_taint_follows_for_and_with_targets():
    assert "row" in taints("def f():\n    for row in get_current_tenant():\n        pass\n")
    assert "scope" in taints("def f():\n    with get_current_tenant() as scope:\n        pass\n")


# --------------------------------------------------------------------------- #
# Property tests
# --------------------------------------------------------------------------- #
_NAMES = ["a", "b", "c", "d"]

# Small statement shapes, each one a construct the analysis has to handle. They
# are never executed — only parsed — so undefined reads are harmless.
_TEMPLATES: list[list[str]] = [
    ["{n} = 1"],
    ["{n} = {m}"],
    ["{n} += 1"],
    ["{n}, {m} = 1, 2"],
    ["{n} = {m}.get('x')"],
    ["{n} = ({m} := 1)"],
    ["{n} = [{m} for {m} in range(3)]"],
    ["import os"],
    ["from json import dumps as {n}"],
    ["for {n} in range(3):", "    {m} = {n}"],
    ["if flag:", "    {n} = 1", "else:", "    {m} = 2"],
    ["while flag:", "    {n} = 1"],
    ["with ctx() as {n}:", "    {m} = 1"],
    ["try:", "    {n} = 1", "except ValueError as {m}:", "    pass"],
    ["return {n}"],
]


@st.composite
def _block(draw: st.DrawFn) -> list[str]:
    template = draw(st.sampled_from(_TEMPLATES))
    first = draw(st.sampled_from(_NAMES))
    second = draw(st.sampled_from(_NAMES))
    return [line.format(n=first, m=second) for line in template]


@st.composite
def _function(draw: st.DrawFn) -> ast.FunctionDef:
    blocks = draw(st.lists(_block(), min_size=1, max_size=6))
    params = draw(st.lists(st.sampled_from(["p", "q"]), min_size=0, max_size=2, unique=True))
    body = "\n".join(f"    {line}" for block in blocks for line in block)
    return parse_fn(f"def sample({', '.join(params)}):\n{body}\n")


def _bound_names(fn: ast.FunctionDef) -> set[str]:
    """Names ``fn`` binds, computed independently of the module under test."""
    names = {arg.arg for arg in fn.args.args}
    for node in ast.walk(fn):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, ast.alias):
            names.add(node.asname or node.name.split(".")[0])
    return names


@pytest.mark.property
@given(_function())
@settings(max_examples=200)
def test_every_bound_name_has_a_reaching_definition(fn: ast.FunctionDef):
    """Nothing may fall out of the analysis: a binding always reaches the exit.

    This is the invariant a MAY analysis exists to guarantee. Break it and the
    adapters stop being able to tell "no tenant here" from "we lost track".
    """
    defs = reaching_definitions(fn)
    assert _bound_names(fn) <= set(defs)
    for name, group in defs.items():
        assert group, f"{name} has an empty definition set"
        assert all(d.name == name for d in group)
        assert all(d.line >= 0 for d in group)


@pytest.mark.property
@given(_function())
@settings(max_examples=200)
def test_a_name_that_is_never_read_is_still_defined(fn: ast.FunctionDef):
    read = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    defs = reaching_definitions(fn)
    assert _bound_names(fn) - read <= set(defs)


@pytest.mark.property
@given(_function())
@settings(max_examples=200)
def test_appending_an_unrelated_statement_never_removes_a_definition(fn: ast.FunctionDef):
    before = set(reaching_definitions(fn))
    extra = ast.parse("zzz_unrelated = 1").body[0]
    extended = ast.parse(ast.unparse(fn))
    target = extended.body[0]
    assert isinstance(target, ast.FunctionDef)
    target.body.append(extra)
    ast.fix_missing_locations(extended)
    assert before <= set(reaching_definitions(target))


@pytest.mark.property
@given(_function())
@settings(max_examples=100)
def test_analysis_is_deterministic(fn: ast.FunctionDef):
    first = reaching_definitions(fn)
    second = reaching_definitions(fn)
    assert first == second


@pytest.mark.property
@given(_function())
@settings(max_examples=200)
def test_taint_without_sources_taints_nothing(fn: ast.FunctionDef):
    assert taints_from(fn, frozenset()) == set()


@pytest.mark.property
@given(_function(), st.sets(st.sampled_from(_NAMES), max_size=2))
@settings(max_examples=200)
def test_taint_is_monotone_in_its_sources(fn: ast.FunctionDef, extra: set[str]):
    """More sources can only taint more names — never fewer."""
    narrow = taints_from(fn, frozenset({"a"}))
    wide = taints_from(fn, frozenset({"a"}) | frozenset(extra))
    assert narrow <= wide
