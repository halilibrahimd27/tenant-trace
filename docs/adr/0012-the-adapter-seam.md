# ADR-0012 — The language/framework seam must be separated before a second adapter

- **Status:** accepted, implemented
- **Date:** 2026-07-27

## Context

`LanguageAdapter` has had exactly one implementation since it was written.
Writing the second one — Django ORM, chosen because it needs no new parser and
so does not disturb ADR-0005 — was meant to test whether the Protocol
abstracts at the right seams. It answered that question immediately, and the
answer is no.

`PythonSQLAlchemyAdapter` implements six rules. Three of them never mention a
query builder:

| Rule | What it actually looks for |
| --- | --- |
| `_raw_sql` | SQL built by interpolation that binds no tenant parameter |
| `_cache_keys` | A cache key carrying an object id and no tenant |
| `_job_payloads` | A dict dispatched to a worker with no tenant key |

These are patterns in **Python and its ecosystem** — f-strings, `cache.set`,
`.delay()` — not in SQLAlchemy. A Django application has all three, expressed
identically. So a Django adapter had two options, and both are wrong:

1. **Duplicate them.** Six rules become twelve, and the next fix to the cache
   rule lands in one copy.
2. **Import them from `adapters/python_sqlalchemy`.** A sibling adapter
   becomes a library. That is precisely the coupling
   `static/registry.py` exists to prevent — its own docstring says adding a new
   framework "should touch a new package and one line here".

The three remaining rules — `_missing_filter`, `_scope_bypass`,
`_unscoped_models` — *are* framework-specific: they turn on what a query root
looks like, what a model is, and how that ORM expresses a global scope. Those
belong in an adapter. Their helpers (`_is_query_root`, `_is_model`,
`_scoped_models_in`) do too.

This is the thing a Protocol with one implementation cannot tell you. Nothing
distinguishes the language half of an adapter from the framework half until
something else needs the language half.

The same shape had already appeared once, in a smaller way, and was fixed
without the general lesson being drawn: `detect_scoping` used the adapter's own
seven-name `DEFAULT_TENANT_COLUMNS` while `_missing_filter` used the config's
four-name list, so an application keyed on `workspace_id` could be detected as
MANUAL by evidence the rules then never looked for.

## Decision

**Separate the seam before the second adapter, not during it.**

- Move `Hit` and `Scope` from the adapter to `static/base.py`. Every adapter
  produces them, and shared rules must be able to return them.
- Move the three language-level rules, with their helpers and assumption
  strings, into `static/rules.py`. That module knows about Python, ASTs and
  `StaticContext`, and nothing about any ORM.
- Leave the ORM rules where they are. An adapter should be the part that
  genuinely differs.
- Then write `python_django`: `detect_scoping` over Django's vocabulary
  (a manager overriding `get_queryset`, `TenantMixin`, thread-local middleware),
  plus `Model.objects.get/filter` without a tenant field,
  `get_object_or_404(Model, pk=…)`, and `.raw()`/`.extra()`.

**A first attempt at this was made by scripted extraction and reverted.** The
three rules pull in fifteen helpers which themselves pull in constants and
dataflow utilities, and a regex-driven move left a tree that neither imported
nor type-checked. Recording that here because the next person will reach for
the same shortcut: the move is mechanical in shape and not in practice, and it
wants doing by hand in one pass with the gate run after each step.

## Consequences

**Good.** The Django adapter becomes small — the part of it that is really
about Django — and the language rules get one home, one set of tests, and one
place to fix.

**Good.** The registry's promise becomes true. Today "adding PHP/Laravel should
touch a new package and one line here" is aspirational; a PHP adapter would
need its own copies of nothing, because the shared rules are Python-specific
and a PHP adapter would bring its own.

**Bad.** It is a refactor with no user-visible effect, landing before the
feature that motivates it. That ordering is the point: doing it during the
Django adapter would mix a mechanical move with new behaviour in one diff, and
a regression in either would be hard to attribute.

**Bad.** `static/rules.py` is Python-specific despite living outside
`adapters/`. A future non-Python adapter will want a sibling, not this one. The
name says `rules`, not `python_rules`, and that will need revisiting rather
than stretching.

**Rejected.** Writing the Django adapter first and deduplicating afterwards.
The duplicate would be the reference for anyone reading the code in between,
and "we will extract it later" is how six rules become twelve permanently.

## Outcome

Done in three commits, each gated on its own.

The seam turned out to be one layer deeper than this record first claimed. After
the three rules moved, the Django adapter still needed `scopes`, `scope_nodes`,
`parent_map`, `iter_definitions`, `dedupe` and `finding` — walking a Python file
into analysable units, collapsing duplicate hits, rendering a `Hit` as a
`Finding`. None of that mentions an ORM either, and it was missed while
deliberately looking for exactly this. Worth recording: a seam is not obvious
even to someone hunting for it, which is the argument for a second
implementation rather than a careful reading.

`python_sqlalchemy` went from 590 lines to 478, and what remains is genuinely
about SQLAlchemy. `python_django` is 340 lines, of which the ORM-specific rules
are about half: manager queries, the `get_object_or_404` shortcut, `.raw()` and
`.extra()`, and `_base_manager` as the scope bypass.

The Protocol itself needed no change, which is the one part of the original
design that held.

And the defect the exercise was meant to surface surfaced immediately, in the
new adapter: `detect_scoping` read the adapter's ten column names while the
rules read the config's four, so `filter(organization__slug=…)` — correctly
scoped — was reported. The same mismatch had already been fixed once in
`python_sqlalchemy` without the general lesson being drawn. `_columns()` now
widens the configured list with the adapter's own, and the operator's
configuration still outranks the guess.
