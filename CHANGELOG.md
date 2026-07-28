# Changelog

## 0.3.0 — 2026-07-28

The gate ran on one platform and skipped what it could not reach, so a set of
defects sat in a repository whose whole claim is that silence is not evidence.

### Fixed

- The plugin manifest declared `displayName`, which `claude plugin validate`
  rejects outright — the plugin did not validate. The test written to catch
  exactly that skips wherever the Claude Code CLI is absent, which includes CI,
  so it had never once run. The key set is now checked everywhere.
- `[static] adapter = "python_django"` was rejected as invalid. The adapter
  shipped registered, sniffable, tested and documented; only the loader's
  literal was never widened, so the name the README told you to use did not
  parse. A test now ties the loader to the registry.
- An ownership field naming a tenant is no longer read as evidence when that
  tenant selector is a value **we** sent as a query parameter or body field.
  The parameter-override attack asks for `?tenant_id=<victim>`, so an endpoint
  that echoes its filters back could confirm a critical cross-tenant read whose
  response carried no rows. Path segments still count — the positive controls
  on a tenant-in-path application depend on them.
- `tenanttrace metrics` exited 1 on a run whose verdict was PASS, because a
  Windows console on a legacy codepage cannot encode the box drawing the
  scorecard is built from. The gate failed for a font.
- The test suite could not run on Windows at all: paths were interpolated into
  TOML strings and into generated Python source, where `C:\Users\…` is a
  sequence of escapes. One of those made a *hostile-code* test pass for the
  wrong reason — nothing executed because nothing was ever parsed.

### Tests

The three least-covered modules were the three worth covering most, and what
was missing in each was the failure path rather than the happy one.

- **`mass_assign`** (66% → 99%), the only module that writes to a target. Its
  untested half was every way a write can go wrong: a response with no id in
  it, a resource with no delete route, a delete both tenants refuse. Each ends
  with a record this run created sitting inside somebody else's tenant, and the
  promise is that the finding says so out loud. That promise is now a test.
- **`seeder`** (73% → 98%). `load_seeder`, `seed_tenant` and
  `normalize_records` — the entire contract a user writes against, and the
  first thing a first run touches — had no direct test at all. Its stated value
  is its error messages; none of them was checked.
- **`idor`** (79% → 100%) and **`listing`** (78% → 100%). The uncovered lines
  were the two places these modules decide *which control failed*: the public
  endpoint reclassification (ADR-0011) and the shared-reference-data guard. Get
  either wrong and the report sends somebody to fix a query that is already
  correct.

Attack modules are now testable against a target that misbehaves on cue
(`tests/attack_harness.py`) — only the target is faked, so a recorded exchange
is the exchange a real run would record. The coverage floor moves 85% → 88%.

### Internal

- CI runs the gate on Windows as well as Linux. Every defect above was invisible
  to a one-platform gate, which is the same failure this tool reports about
  applications.

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
