# ADR-0008 — Attacks establish a baseline before claiming a finding

- **Status:** accepted
- **Date:** 2026-07-26

## Context

Three attack modules can all observe the same leaked byte, and the first
implementation let all three report it. Two concrete misattributions showed up
the first time the prober ran against the fixtures:

1. **A cache leak reported as a plain cross-tenant read.** The fixture's
   document-detail route queries correctly — it returns 404 for another
   tenant's document — but caches the response under `doc:{id}` with no tenant
   in the key. The positive control for tenant B read B's own document, which
   populated that entry. The IDOR module then requested the same id as tenant A
   and got B's document back. Verdict: correct. Category: wrong. The
   remediation attached to `cross_tenant_read` tells the reader to add a tenant
   predicate to a query that already has one.

2. **A listing leak reported a second time as a parameter override.** The
   document collection returns every tenant's rows unconditionally. Adding
   `?tenant_id=B` therefore also returned B's rows, so the parameter-override
   module reported a finding too — with a remediation about not trusting
   request data, for an endpoint whose actual problem is a missing `WHERE`
   clause.

Both are the same underlying mistake: an attack claimed causation from a leak it
merely *observed*, without establishing that its own manipulation was what
caused it.

## Decision

An attack that claims a *mechanism* must first establish that the mechanism is
load-bearing.

- **`param_override`** sends the plain request first. If the endpoint already
  leaks without any override, the module stays silent and the listing module
  owns the finding. An override only means something against a clean baseline.

- **`cache`** runs cold → warm → hot. It requests the victim's object as the
  actor on a cold cache (must be refused), has the victim read its own object
  (an ordinary authorised request that populates the cache), then repeats the
  first request. A response that was refused and is now served came from the
  cache, not the database.

- **Positive controls and attacks never touch the same record.** The control
  takes the *last* seeded id of a kind, attacks start from the *first*, and
  every id read during controls is excluded from every attack via
  `AttackContext.excluded_ids`. Without this, a control read populates the
  shared cache entry and the cache bug resurfaces as a false `cross_tenant_read`
  — which is exactly how misattribution (1) happened.

  This is why a seeder should create **at least two records per kind**. The
  requirement is documented on the `SeederAdapter` protocol.

A related decision in the same spirit: the aggregate module judges `*_count`
fields only, never `*_total`. `invoice_total` is a sum of money in most
applications, and comparing `303.00` against "this tenant owns 3 rows" reports
a critical against correct code. The first run against the *safe* fixture
produced exactly that false positive. Sums cannot be judged without knowing
what is being summed, and this tool does not guess.

## Consequences

**Good:** each finding names the mechanism that actually caused it, so the
remediation points at the line that needs changing. One bug produces one
finding. The cache-key leak — the failure mode that is hardest to catch any
other way, because the query looks correct and the leak is order-dependent —
gets reported as itself.

**Bad:** more requests. `param_override` costs one extra request per collection
endpoint, and `cache` costs three per object endpoint. At the default 10 rps
that is measurable on a large API, and it is the price of not guessing.

**Neutral:** the "at least two records per kind" requirement is a real
constraint on seeder authors. A seeder that plants one record still works; it
just risks the misattribution above on an application with tenant-less cache
keys, which is a narrow enough case to document rather than enforce.

## Alternatives considered

- **Report all three and let the reader sort it out** — three findings for one
  bug, two with wrong remediations. Precision against `labels.yaml` drops, and
  so does trust.
- **Priority ordering only (first attack to fire wins)** — fixes the duplicate
  but not the attribution: whichever module happens to run first claims the
  finding regardless of which mechanism caused it.
- **Merge overlapping findings in the correlator** — too late. By then the
  category, severity, and remediation have already been chosen.
