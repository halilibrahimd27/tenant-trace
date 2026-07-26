# CLAUDE.md — TenantTrace

Claude Code loads this file every session. It is the contract. If a request
conflicts with this file, say so before acting.

## What this is

**TenantTrace** — a multi-tenant isolation auditor. It proves whether tenant A
can reach tenant B's data in a SaaS application, and reports every leak as a
pentest-grade finding.

Two engines:

| Engine | Language-agnostic? | Role |
| --- | --- | --- |
| **`probe/`** (dynamic) | **YES** — pure HTTP | Confirms real leaks with an exact oracle. **The product.** |
| **`static/`** (static) | No — per-adapter | Generates *hypotheses* for the prober. **Supporting act.** |

The differentiator is the combination: static proposes, dynamic proves, the
report ships confirmed findings with near-zero false positives.

## Non-negotiable rules

1. **Never `import` or execute code under static analysis.** Parse it. The
   analyzer must be safe to point at hostile source.
2. **No symbolic execution, no SMT solver, no whole-program abstract
   interpretation.** AST + intraprocedural (single-function) dataflow only.
   Over-engineering the static engine is this project's #1 failure mode.
3. **The static engine never emits a standalone verdict.** Its findings are
   `confidence: suspected` until the prober confirms them. Only
   `confidence: confirmed` may fail CI by default.
4. **Every probe run includes positive controls.** A→A self-access MUST succeed.
   If it doesn't, the run is `INVALID`, not "clean" — a broken harness that
   403s everything must never be reported as "no leaks found."
5. **The prober is dangerous. Guard it.**
   - Read-only by default. Mutating attacks require `--allow-mutation`.
   - Target host must be in `allowed_hosts` in config; non-loopback targets
     additionally require `--i-have-authorization`.
   - Log every request/response pair into the run artifact.
   - Clean up objects the prober created.
6. **`make verify` green or the milestone is not done.** No exceptions.
7. **Ask before scope-creeping.** New attack module, new dependency, new
   adapter → propose first, wait for approval.

## Architecture

```
src/tenanttrace/
  core/      models.py  config.py  severity.py  fingerprint.py
             report.py  baseline.py                       # shared vocabulary
  probe/     spec.py  seeder.py  session.py  oracle.py  runner.py
             asgi.py       # sync ASGI transport — in-process auditing
             recorder.py   # run artifacts
             attacks/  base.py  idor.py  listing.py  aggregate.py
                       param_override.py  mass_assign.py  cache.py
  static/    base.py  dataflow.py  scoping.py  registry.py  engine.py
             adapters/python_sqlalchemy.py
  correlate/ linker.py                                   # static ↔ dynamic
  metrics.py                                             # the precision/recall gate
  cli.py                                                 # Typer
fixtures/    vulnerable_app/  safe_app/  seeder.py  labels.yaml
tests/       unit + Hypothesis property tests
docs/adr/    MADR decision records
Dockerfile   docker-compose.yml   # one-command demo; `docker compose up -d`
```

**The dependency arrow points inward.** `core/` never imports from `probe/` or
`static/`. Anything both halves need — the canary format, the finding model —
lives in `core/models.py`.

`static/base.py` defines the `LanguageAdapter` Protocol. All framework-specific
logic lives behind it — the core must never import an adapter directly, only
resolve one through `static/registry.py`.

The prober takes its transport by injection, so the same code audits a socket
in production and an in-process ASGI app in the test suite (ADR-0004). That is
what makes `make verify` hermetic: no Docker, no Redis, no network.

## The oracle (understand this before writing probe code)

Findings are exact, not heuristic, because we seed the ground truth:

- Every tenant-B record carries a unique **canary string** (`tt-canary-B-<uuid>`)
  in a text field. If a canary appears in a response to tenant A → **confirmed
  cross-tenant read.**
- B's object **IDs** are secondary canaries (lower confidence — a bare integer
  can collide; prefer UUID/ULID ids in fixtures).
- **Counts are exact too:** we know how many rows A owns. `count > expected`
  on an aggregate endpoint → confirmed leak.

Never fall back to response-similarity heuristics. If the oracle can't decide,
emit `inconclusive`, not a guess.

## Stack

Python 3.12 · Typer · httpx · pydantic v2 · rich · PyYAML · pytest + Hypothesis
· Docker Compose. Dependency manager: `uv`.

Six runtime dependencies, on purpose. The static engine parses with the stdlib
`ast` — no tree-sitter (ADR-0005) — and SQLAlchemy is a *fixtures-only* extra,
because the adapter reads SQLAlchemy code without ever importing SQLAlchemy.

## Quality gate — `make verify`

`ruff` · `black --check` · `mypy --strict` · `pytest` (≥85% coverage) ·
fixture precision/recall check (recall ≥90% on `labels.yaml`).

Property-test the fragile parts specifically: URL/path normalization, the canary
scanner, and the reaching-definitions helper.

## Working agreement

- **Plan first, then build.** Before each phase: show the plan, wait for "go".
- **One phase at a time.** Do not jump ahead to a later phase's work.
- Small atomic commits, Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`).
- Write an ADR under `docs/adr/` (MADR format) for every significant decision.
- **Be honest about false positives.** Mark them via `confidence`; never hide
  them. A finding the operator can't trust is worse than no finding.
- Don't add a dependency to do something the stdlib does fine.

## Definition of done (per phase)

- [ ] `make verify` green
- [ ] New behaviour covered by tests (unit + property where it applies)
- [ ] Fixture precision/recall unchanged or improved
- [ ] ADR written if a real decision was made
- [ ] README updated if the user-facing surface changed
