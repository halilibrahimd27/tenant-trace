# ADR-0005 — The static engine parses with the stdlib `ast` module

- **Status:** accepted
- **Date:** 2026-07-26

## Context

The original plan named `tree-sitter-languages` as a core dependency, on the
reasoning that the static engine will eventually need to parse PHP, Ruby, and
C# as well as Python.

Two problems. The practical one: `tree-sitter-languages` is unmaintained, pins
`tree_sitter<0.22`, and does not install cleanly on Python 3.12+ — which is the
project's minimum. Shipping a security tool that fails at `pip install` is not
a promising start.

The design one: the MVP adapter targets Python and SQLAlchemy. Python's own
`ast` module parses Python. Adding a C-extension parser to do what the standard
library already does is exactly the kind of dependency the project's own rules
forbid.

There is also a safety argument that cuts in `ast`'s favour. Rule 1 is *never
import or execute code under analysis*. `ast.parse` compiles source to a syntax
tree without executing a single statement of it, including at module level —
the guarantee is a documented property of the function, not something we
maintain by being careful.

## Decision

Parse Python with `ast`. Drop `tree-sitter-languages` entirely; it is not in
`pyproject.toml` at all.

When a non-Python adapter is built, it brings its own parser as an **optional
extra** (`tenanttrace[php]`, and so on) resolved through the adapter registry.
The core never imports a parser directly, so the core never grows a dependency
on one.

`ast` is also version-locked in a way that helps: it parses the syntax of the
interpreter running it. Source using syntax newer than the running interpreter
raises `SyntaxError`, which the engine records as a skipped file with a warning
rather than a crash.

## Consequences

**Good:** no native build step, no unmaintained dependency, no install failure
on a supported Python. The parse-never-execute guarantee is provided by the
standard library. Core runtime dependencies are down to six packages.

**Bad:** the engine is Python-only until somebody writes an adapter with its own
parser, and `ast` cannot parse source written for a newer Python than the
interpreter running TenantTrace. Those files are skipped and reported as
skipped, never silently treated as clean.

**Neutral:** `ast` gives a Python-specific tree rather than a uniform one across
languages, so the `LanguageAdapter` protocol is defined in terms of findings
rather than in terms of a shared node type. That is the right boundary anyway —
"what counts as an unscoped query" is language-specific all the way down.

## Alternatives considered

- **`tree-sitter` + `tree-sitter-python` directly** — maintained, but still a
  native dependency to do what `ast` does natively for the only language we
  currently support.
- **LibCST or Parso** — better at preserving formatting, which matters for
  codemods and not at all for analysis.
- **Shell out to Semgrep** — the project explicitly exists to not be that
  (PROJECT brief §3): a static-only tenancy rule set with no confirmation step.
