# ADR-0006 — The seeder's credentials win over configured ones

- **Status:** accepted
- **Date:** 2026-07-26

## Context

There are two places a tenant's credentials can come from, and the original
design shipped both without saying which wins:

- `[auth] tenant_a = { token_env = "TT_TOKEN_A" }` — a token the operator
  exported before the run.
- `SeederAdapter.auth_headers(tenant)` — headers for a tenant the seeder just
  created.

For a seeded run these are not two ways of doing the same thing. The seeder
creates the tenant *during the run*, so a token exported beforehand cannot
possibly authenticate as it. Silently preferring the configured token would
produce a run where the credentials and the seeded data belong to different
tenants — and the symptom would be a positive-control failure with no obvious
cause, or worse, a clean-looking run against a tenant with no seeded data in it.

## Decision

**The seeder wins.** If a seeder is configured and returns non-empty headers for
a tenant, those headers are used and `[auth]` is ignored for that tenant.

`[auth]` remains the path for targets whose tenants cannot be created through
the API — a system where onboarding is manual, or a staging environment with
two long-lived tenants somebody set up by hand. In that mode the operator seeds
the canaries themselves and the seeder's `seed_records` does the planting
through whatever API exists.

The precedence lives in one function, `runner._headers_for`, and is documented
in `tenanttrace.example.toml` where an operator will actually read it.

## Consequences

**Good:** the common case (a seeder creating fresh tenants) works with no auth
configuration at all, and the failure mode where credentials and data disagree
is impossible by construction.

**Bad:** an operator who sets `token_env` and *also* configures a seeder gets
their token ignored, which could be surprising. The config file says so, and
`tenanttrace validate-config` prints which seeder is in play.

**Neutral:** `cleanup(tenant)` receives the tenant's metadata, which deliberately
excludes credentials so a token cannot reach a run artifact. A seeder that needs
to authenticate during cleanup keeps its own record of what it created — the
bundled `fixtures/seeder.py` shows the pattern in about five lines.

## Alternatives considered

- **Config wins** — inverts the failure into a silent one: the run appears to
  work and audits a tenant with no canaries in it.
- **Merge both** — two `Authorization` headers is not a thing, and picking one
  at merge time is the same decision made less visibly.
- **Refuse when both are set** — punishes a config that is merely redundant, and
  makes a shared organisational config file harder to reuse across targets.
