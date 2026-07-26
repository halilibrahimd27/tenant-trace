# Contributing

## Before you write code

Open an issue describing the problem first. For anything architectural, write
an ADR under `docs/adr/` (copy `docs/adr/template.md`) and open it as a PR on
its own — design review before implementation review.

## The gate

```bash
uv sync --extra dev --extra fixtures
make verify
```

`make verify` runs ruff, black, mypy --strict, pytest (≥85% coverage), and the
fixture precision/recall check (recall ≥90%). CI runs the same command. A PR
that doesn't pass it won't be reviewed.

## House rules

These are load-bearing, not style preferences — see `CLAUDE.md` for the full set:

1. The static engine **parses** code, it never imports or executes it.
2. No symbolic execution or whole-program analysis. AST + intraprocedural
   dataflow only.
3. Static findings are `suspected` until the prober confirms them. Only
   `confirmed` findings fail CI by default.
4. Every probe run asserts A→A self-access first. A run whose positive controls
   fail is `INVALID`, never "clean".
5. New attack module, new dependency, or new language adapter → propose first.

## Adding an attack module

1. Add the module under `src/tenanttrace/probe/attacks/`.
2. Add the matching hole to `fixtures/vulnerable_app/` **and** the correct
   handling to `fixtures/safe_app/`.
3. Add both to `fixtures/labels.yaml` — a positive case and a negative case.
4. Recall must stay ≥90% and safe_app must stay at zero false positives.

An attack module without a labelled fixture case will be rejected. The metric
is how we know the tool works.
