# ADR-0001 — Use MADR for architecture decisions

- **Status:** accepted
- **Date:** 2026-07-19

## Context

TenantTrace is built incrementally across phases, largely with an AI coding
agent. Decisions made in one phase are invisible by the next unless they are
written down, and "why is it like this?" is the most expensive question to
re-answer six weeks later.

## Decision

Record every significant technical decision as a Markdown ADR in MADR format
under `docs/adr/`, numbered sequentially. An accepted ADR is immutable; changing
course means writing a new ADR that supersedes it.

## Consequences

**Good:** the reasoning survives context resets. New contributors — human or
agent — can read the decision history instead of reverse-engineering it.

**Bad:** small friction on every decision, and a temptation to write ADRs for
choices that don't warrant one.

**Neutral:** the ADR index becomes the de-facto architecture documentation.

## Alternatives considered

- **Comments in code** — lost during refactors, and can't record rejected options.
- **A design doc per phase** — goes stale silently; no supersession trail.
