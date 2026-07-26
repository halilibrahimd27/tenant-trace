# ADR-0002 — The dynamic prober ships before the static engine

- **Status:** accepted
- **Date:** 2026-07-19

## Context

TenantTrace has two engines: a static analyser that reads source, and a dynamic
prober that sends real requests. The obvious build order is static-first —
analysis feels like the "core" and probing feels like validation.

Two facts invert that instinct:

1. **The prober is language-agnostic.** It speaks HTTP, so it works against a
   FastAPI, Laravel, or .NET target on day one. The static engine is locked to
   one language per adapter and only helps codebases in that language.
2. **The prober has an exact oracle** (see ADR-0003), while the static engine
   is heuristic and false-positive-prone — especially against the repository /
   service-layer pattern, where the tenant filter lives far from the query.

There is also a strategic risk: a static-only tenancy checker is close enough to
a Semgrep or CodeQL rule set that the project would have little reason to exist.

## Decision

Build the dynamic prober first (Phase 2–3) and the static engine after (Phase 4).
The static engine is scoped as a **hypothesis generator** whose findings are
`suspected` until the prober confirms them — never a standalone verdict.

## Consequences

**Good:** the tool is useful against every application we own after Phase 2
rather than after Phase 4. The riskiest, least differentiated component is
deferred until the valuable one is proven. Confirmed findings carry near-zero
false positives, which is what makes a CI gate tolerable.

**Bad:** the prober needs a per-application seeder adapter before it can run,
so the first-use cost is higher than "point it at a repo". Findings that HTTP
probing structurally cannot see — cache keys, job payloads, raw SQL — stay
invisible until Phase 4.

**Neutral:** the static engine's design is pulled toward "what would help the
prober aim?" rather than "what can we detect?".

## Alternatives considered

- **Static-first** — delays real value, front-loads the false-positive problem,
  and risks landing as a worse Semgrep.
- **Static-only** — no confirmation step, so findings can't gate CI without
  drowning the user.
- **Dynamic-only** — misses cache keys, job payloads, and raw SQL entirely, and
  probes blindly instead of aiming at suspicious paths.
