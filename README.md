[![verify](https://github.com/halilibrahimd27/tenant-trace/actions/workflows/verify.yml/badge.svg)](https://github.com/halilibrahimd27/tenant-trace/actions/workflows/verify.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](pyproject.toml)

# TenantTrace

**Proves whether tenant A can reach tenant B's data.**

Your test suite runs as one tenant, so the one query that forgot its tenant
filter looks fine. TenantTrace seeds two tenants into your application, asks for
one while authenticated as the other, and reports what came back.

```
✗ [critical/confirmed] Cross-tenant read on GET /api/invoices/{invoice_id}
    GET /api/invoices/018f4c1e-3a9b-7c2d-9e5f-1a2b3c4d5e6f
    200 · body contains tt-canary-B-…3f7a91c2
```

That is not a similarity score or a heuristic. We planted that string in tenant
B's invoice ninety milliseconds earlier, and it came back to tenant A.

---

## See it work

```bash
git clone https://github.com/halilibrahimd27/tenant-trace
cd tenant-trace
docker compose up -d
```

That boots two multi-tenant applications — one deliberately leaky, one
correctly isolated — audits both over real HTTP with a real Redis, and serves
the reports at **http://127.0.0.1:8088**. Nothing else to install.

Reports live in a named volume, so the demo runs as a non-root user on every
platform. To pull them onto your disk: `make reports` (or
`docker compose cp report:/reports ./reports`).

Without Docker:

```bash
uv sync --extra dev --extra fixtures
uv run tenanttrace demo          # audits both fixtures in-process, writes HTML
```

## How it decides

Findings are facts, not scores. Every record belonging to tenant B is seeded
with a unique canary string. If that canary appears in a response served to
tenant A, the leak is **confirmed** — there is nothing to interpret.

Aggregates work the same way: we seeded tenant A's rows, so we know the correct
count. Anything higher is a confirmed leak.

When the oracle cannot decide — a 5xx, a timeout, an unparseable body — the
verdict is `inconclusive`. It is never silently a pass.

**Every run checks its controls first.** Tenant A must be able to read tenant
A's own data. If that fails, authentication or seeding is broken and the run is
marked `INVALID` with exit code 3. A run that could not reach anything is not a
run that found nothing — that distinction is the difference between a security
tool and a placebo.

## What it catches

| | | proven by |
| --- | --- | --- |
| **Object reads** | A fetches B's record by id | B's canary in the response |
| **Collection leaks** | A's own list contains B's rows | B's canary in the response |
| **Aggregate leaks** | counts computed over every tenant | arithmetic against seeded rows |
| **Parameter override** | `?tenant_id=B`, `X-Tenant-Id: B`, body fields | canary, after a clean baseline |
| **Cache-key leaks** | correct query, tenant-less cache key | refused cold, served after B warms it |
| **Cross-tenant writes** | A creates a record inside B | reading it back as B |

The cache case is the one worth pausing on. The query is correct — code review
sees a proper `WHERE tenant_id = …`, and a single-tenant test suite passes — but
the result is cached under `invoice:{id}`, so whichever tenant asks first wins.
TenantTrace finds it by requesting the object cold (refused), having the owner
read it (populating the cache), then repeating the first request. See
[ADR-0008](docs/adr/0008-differential-attribution.md).

## Two engines

| | | |
| --- | --- | --- |
| **probe** | dynamic, language-agnostic | Sends real requests. Works against FastAPI, Laravel, Rails, .NET — anything speaking HTTP. Findings are `confirmed`. |
| **static** | per-language adapter | Reads source to find suspicious paths and the leaks HTTP cannot see: raw SQL, cache keys, job payloads. Findings are `suspected` until the prober confirms them. |

Static proposes, dynamic proves. Only confirmed findings fail your build by
default — that is what keeps the gate tolerable. See
[ADR-0002](docs/adr/0002-dynamic-first-architecture.md).

The static engine parses with the standard library's `ast`. It never imports or
executes the code under analysis
([ADR-0005](docs/adr/0005-stdlib-ast-over-tree-sitter.md)).

## Wiring it to your app

TenantTrace cannot guess how your application creates a tenant, authenticates
one, or creates an owned record. You write that once, in about thirty lines —
start from [`seeders/example_seeder.py`](seeders/example_seeder.py) or the
working [`fixtures/seeder.py`](fixtures/seeder.py):

```python
class MySeeder:
    def __init__(self, client): self.client = client

    def create_tenant(self, label):          # -> {"tenant_id": ..., "access_token": ...}
    def auth_headers(self, tenant):          # -> {"Authorization": f"Bearer {...}"}
    def seed_records(self, tenant, canary):  # -> records carrying the canary
    def cleanup(self, tenant):               # -> remove what you created
```

Put the canary in a field the API actually returns — a title, name, or
description. Create **at least two records per kind**: the harness keeps its
control reads and its attack reads on different records
([ADR-0008](docs/adr/0008-differential-attribution.md)).

Then point at it:

```toml
[target]
base_url      = "http://127.0.0.1:8000"
allowed_hosts = ["127.0.0.1", "localhost"]

[seeder]
adapter = "seeders.my_app:MySeeder"

[tenancy]
column                 = "tenant_id"
cross_tenant_allowlist = ["/api/admin/*"]   # endpoints that cross tenants on purpose
```

```bash
tenanttrace validate-config -c tenanttrace.toml   # says exactly what it will do
tenanttrace probe -c tenanttrace.toml --dry-run   # lists attempts, sends nothing
tenanttrace probe -c tenanttrace.toml
```

`tenanttrace.example.toml` documents every key, and a test asserts the loader
accepts it — so it cannot drift.

### From your own test suite

The prober takes an injected transport, so it can drive an ASGI application
in-process with no server, no port, and no container:

```python
from tenanttrace.probe.asgi import SyncASGITransport
from tenanttrace.probe.runner import ProbeOptions, run_probe

def test_tenants_are_isolated():
    with SyncASGITransport(my_app) as transport:
        report = run_probe(config, ProbeOptions(transport=transport)).report
    assert report.status is RunStatus.VALID     # controls passed — the run is real
    assert report.confirmed == ()
```

## In CI

```yaml
- uses: halilibrahimd27/tenant-trace@v1
  with:
    config: tenanttrace.toml
    fail-on: high
    baseline: .tenanttrace-baseline.json
```

Accepted findings live in the baseline and stay quiet; new ones fail the check.
Fingerprints survive re-seeding, endpoint reordering, parameter renames, and
line-number churn — they are built from the endpoint or the source *symbol*,
never a line number ([ADR-0007](docs/adr/0007-baseline-fingerprints.md)). The
baseline holds fingerprints and titles only: never a canary, a token, or a
response body.

Exit codes: `0` clean · `1` findings at or above `fail-on` · `2` usage or
config error · `3` **run INVALID**, positive controls failed.

## What it will not find

Being specific about this is part of the tool being trustworthy.

- **Anything it cannot seed.** The oracle works because TenantTrace plants the
  data it later goes looking for. It cannot audit a system you are not allowed
  to write to.
- **Leaks with no HTTP surface.** A report generator writing the wrong tenant's
  rows to a file nobody fetches is invisible to probing. The static engine can
  flag the code path; it cannot prove the leak.
- **Routes it never hears about.** Coverage comes from your OpenAPI document or
  a hand-written route list. Undocumented endpoints go untested, and the report
  says how many endpoints it knew about.
- **Sums.** The aggregate oracle judges `*_count` fields against seeded row
  counts. It does **not** judge `*_total`, because that is usually money and
  comparing it to a row count would report a critical against correct code.
- **Authorization beyond tenancy.** Whether a viewer can act like an admin
  *within* one tenant is a different question, and this tool does not ask it.
- **Non-Python codebases, statically.** The prober is language-agnostic; the
  static engine currently ships one adapter (Python + SQLAlchemy).

## Safety

The prober sends adversarial requests and, with `--allow-mutation`, writes data.

- **Read-only by default.** Mutating attacks require `--allow-mutation` on the
  command line *and* `allow_mutation = true` in config. Neither alone is enough.
- **Host allowlist.** The target host must appear in `allowed_hosts`.
- **Non-loopback targets additionally require `--i-have-authorization`.** That
  flag is a statement you are making, not a permission this tool grants you.
- **Redirects are not followed** — a redirect could move a request to a host
  outside the allowlist.
- **Rate limited** to `max_rps`, shared across both tenant sessions.
- **Credentials are redacted where the record is created**, not at render time,
  so a token has no path to an artifact. A test asserts no JWT reaches
  `exchanges.jsonl`.
- Every request and response is captured to `.tenanttrace/`, which is gitignored
  because it contains real findings.

Mutating attacks clean up after themselves, and say so in the finding when they
could not.

See [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

## Development

```bash
make install       # uv sync --extra dev --extra fixtures
make verify        # ruff · black · mypy --strict · pytest ≥85% · recall ≥90%
make demo          # audit both fixtures, write reports
make fixtures-up   # boot the fixtures in Docker (only needed for the HTTP demo)
```

`make verify` is the gate and CI runs the same command. It is **hermetic** — no
Docker, no Redis, no network — because the fixtures are driven in-process over
ASGI ([ADR-0004](docs/adr/0004-hermetic-in-process-auditing.md)).

The gate includes a precision/recall score against
[`fixtures/labels.yaml`](fixtures/labels.yaml), the answer key describing every
hole in the fixture applications. Recall below 90%, or any false positive on the
correctly-isolated app, fails the build. That is what turns "I think it works"
into a number.

[`CONTRIBUTING.md`](CONTRIBUTING.md) has the house rules, [`CLAUDE.md`](CLAUDE.md)
has the non-negotiables, and every significant decision is recorded in
[`docs/adr/`](docs/adr/).

## License

MIT — see [LICENSE](LICENSE).
