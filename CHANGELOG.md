# Changelog

## 0.2.0 — 2026-07-27

Six real open-source applications were seeded and audited end to end —
Chatwoot, Baserow, Squidex, EspoCRM, Keycloak and Teable, on six backend
stacks. Every agent doing it was also a first-time user, and reported what
broke. Most of this release is what they found.

### The refused count was not true

The number a clean verdict rests on — *"N attempts refused"* — was inflated
four separate ways, and one artifact said *"168 attempts … the application
refused them"* beside a tile reading `26`.

- Verdicts count `ENFORCED`, not every result. Throttled, redirected and
  skipped attempts are reported as undecided, on purpose (ADR-0010).
- HTTP 429 is never a refusal; past half the attempts throttled, the run is
  `INVALID`.
- A 404 from a route that answers 404 for the caller's own record too is
  absence, not enforcement.
- A request that addressed no record we know about — an id of the wrong kind,
  or several slots sharing one — proves nothing either way.

### The gate between VALID and INVALID

- The positive control was the only caller that did not pass the tenant, so on
  an application carrying its tenant in a path segment every control went to a
  wrong URL. On Keycloak, 418 of 420 control requests 404'd.
- Controls are re-asserted when the run finishes: a long audit outlives
  short-lived tokens, and the second half was being refused for the wrong
  reason.
- The seeder gets its own HTTP client. A shared cookie jar made the prober
  attack as the seeder's user.
- `--dry-run` writes no artifact. It used to write a `VALID` report with no
  controls, which renders as an audit that passed.

### New

- `tenanttrace diff` — what a run *stopped* proving, with
  `--fail-on-regression` to gate a build on coverage alone.
- A Claude Code plugin: a hook that flags unscoped queries as you write, and a
  skill for running a real audit.
- A second static adapter, `python_django`, and `adapter = "auto"`.
- `Category.PUBLIC_ENDPOINT` — if an anonymous request gets the same data,
  tenant scoping is not the control that failed (ADR-0011).
- `[tenancy] path_params` and `path_literals`, and per-record `path` values:
  endpoint shapes that were unprobeable now probe.
- `[target] spec_headers` for APIs that serve their spec only to an admin.
- `SeederClient`, whose value is failure messages that name the request.
- The report states its scope, the evidence signals it could use, and maps
  findings to CWE / OWASP / ASVS. It prints.

### Security

- Credential-looking values are stripped from request and response **bodies**,
  not only headers, in every mode. A `/profile` endpoint echoing the caller's
  own token wrote it into the artifact CI uploads.

### Internal

- The language/framework seam is separated: rules that are about Python rather
  than an ORM live in `static/rules.py` (ADR-0012).
- `max_endpoints` thins across resources instead of cutting a sorted path list,
  which used to delete whole subsystems silently.

## 0.1.0

First release.
