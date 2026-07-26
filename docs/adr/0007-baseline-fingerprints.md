# ADR-0007 — What goes into a finding's fingerprint

- **Status:** accepted
- **Date:** 2026-07-26

## Context

A CI gate needs a baseline: a list of findings a team has looked at and
consciously accepted, which stay quiet, while anything new fails the build.
That only works if a finding can be recognised as *the same finding* across
runs.

Everything about a finding changes between runs. Seeded ids and canaries are
freshly generated. Line numbers move whenever code above them is edited.
Endpoints get reordered in an OpenAPI document. Path parameters get renamed.
Naively hashing the finding would expire the entire baseline within a day, and
a baseline that has to be regenerated constantly is one nobody reviews — which
turns the whole mechanism into blanket suppression.

## Decision

Fingerprint = `sha256(version, engine, category, canonical location)`, truncated
to 32 hex characters and prefixed `sha256:`.

Canonical location, by engine:

- **Dynamic:** `METHOD` + normalised path. Every concrete identifier — numeric,
  UUID, ULID, long hex — and every `{parameter}` collapses to `{}`. So
  `/api/invoices/018f4c1e-…`, `/api/invoices/7`, and `/api/invoices/{invoice_id}`
  are one location. Query strings, schemes, and hosts are dropped, so staging
  and CI agree.
- **Static:** `path/to/file.py::enclosing_symbol`. **The line number is
  discarded and replaced by the symbol.** This is the single most important
  choice in the scheme: the symbol is what identifies the code, and line
  numbers churn constantly. The path is anchored at the first `src/`, `app/`,
  or `lib/` boundary so a laptop and a CI runner produce the same hash.

Deliberately **excluded**, each for its own reason:

| Excluded | Why |
| --- | --- |
| `severity` | Re-rating a category in a tool release must not silently un-accept every baselined finding of that category. |
| line numbers | See above — the reason the scheme exists. |
| canaries, ids, response bodies, timestamps | Different every run *and* must never be written to a file that gets committed. |
| `engine` for correlated findings | A correlated finding fingerprints as its probe half, so a finding accepted while probe-only stays accepted once the static engine starts agreeing with it. |

`FINGERPRINT_VERSION` is part of the hash. Bumping it invalidates every existing
baseline entry on purpose, and is reserved for a change that would otherwise
mis-match old findings to new ones.

The baseline file **is committed to the repository**, which resolves a
contradiction in the original brief (it listed the baseline under "never
committed" while also making it the CI gate's input). Its diffs are the review
surface for accepting a finding, so they belong in code review. The file stores
fingerprints, titles, locations, and acceptance metadata — never a canary, a
token, or a response body. A test asserts that.

## Consequences

**Good:** a baseline survives refactoring, re-seeding, and endpoint reordering.
Accepting a finding is a reviewable one-line diff. `apply()` also reports
**stale** entries — baselined fingerprints no longer produced — so a baseline
cannot quietly rot into permanent suppression.

**Bad:** coarse by construction. Two findings of the same category in the same
function share a fingerprint, so accepting one accepts both. That is the
deliberate trade against a baseline that expires when somebody adds an import.
Moving a function to another file changes its fingerprint and the finding
re-alerts, which is arguably correct and occasionally annoying.

**Neutral:** the fingerprint says nothing about severity, so a finding whose
rating changes stays suppressed. Combined with reporting the *current* severity
in the output, that seems right: the team accepted the finding, not the number.

## Alternatives considered

- **Hash the rendered finding** — expires on every wording change to a
  remediation template.
- **Include the line number** — the failure mode described above; baselines
  become worthless within days.
- **Content-hash the surrounding source** — survives moves but expires on any
  edit near the finding, including the edit that fixes something else.
- **Have the user assign ids by hand** — accurate, and nobody would do it.
