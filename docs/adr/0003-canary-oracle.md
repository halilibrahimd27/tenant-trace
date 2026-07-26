# ADR-0003 — Seeded canaries as the leak oracle

- **Status:** accepted
- **Date:** 2026-07-19

## Context

The prober must decide whether a response to tenant A contains tenant B's data.
Existing tools in this space (Burp Autorize and friends) compare responses
between two identities and score them by similarity. That approach is noisy: it
produces both false alarms on dynamic content and silent misses on partial
leaks, and it can't judge aggregates at all.

We control the seeding, which means we can manufacture certainty instead of
inferring it.

## Decision

Seed tenant B's records with a unique canary string (`tt-canary-B-<uuid>`) in a
human-text field, and use UUID primary keys. A leak is confirmed when a canary
string, or a B-owned UUID, appears in a response served to tenant A. Aggregates
are judged against A's known-owned counts, which we also seeded.

When the oracle cannot decide — 5xx, timeout, unparseable body — the verdict is
`inconclusive`. There is no similarity fallback.

Every run asserts A→A self-access before attempting anything cross-tenant. If
the positive controls fail, the run is `INVALID`; it is never reported as clean.

## Consequences

**Good:** confirmed findings are facts, not scores, which is what allows them to
fail a build. The oracle is format-agnostic — it works on JSON, HTML, CSV, or a
PDF export, because it is looking for a string. It extends naturally to new
attack modules.

**Bad:** the tool cannot audit an application it wasn't allowed to seed, which
rules out black-box testing of third-party systems. It also requires a writable
text field on seeded entities.

**Neutral:** canary hygiene becomes a real concern — canaries must be cleaned up,
and must never be mistaken for production data.

## Alternatives considered

- **Response-similarity scoring** — the Autorize approach; noisy in both
  directions and useless for aggregates.
- **Status-code-only** (200 vs 403) — misses partial leaks inside a 200, and
  misreads a soft-404 as enforcement.
- **Schema-aware field comparison** — needs per-app knowledge of which field
  holds the owner, and breaks on nested or computed responses.
