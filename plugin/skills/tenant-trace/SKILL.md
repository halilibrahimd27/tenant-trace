---
name: tenant-trace
description: Audit whether one tenant can reach another tenant's data in a multi-tenant application. Use when asked to check tenant isolation, investigate a cross-tenant leak or BOLA/IDOR, review a query for a missing tenant filter, or run TenantTrace.
---

# Auditing tenant isolation

TenantTrace answers one question: **can tenant A reach tenant B's data?** It
answers it by seeding two tenants with canary strings, asking for one while
authenticated as the other, and reporting what came back.

The distinction that governs everything below: a **static** finding is a
hypothesis, a **dynamic** finding is a fact. Never present them as the same
thing, and never let a hypothesis drive a code change on its own.

## Reading a suspected finding

The static engine flags queries with no visible tenant predicate. It cannot see
a filter applied at a repository boundary or by a global scope — which is
exactly where well-built applications put it — so **it fires on correct code**.

When you see one, do not add a tenant predicate. Do this instead:

1. Read the call sites. If they go through a repository or service that scopes
   the query, the finding is a false positive and the right answer is to say so.
2. If the project uses SQLAlchemy's `with_loader_criteria` or an equivalent
   global scope, the same applies.
3. If neither, it is worth confirming — see below.

```bash
tenanttrace scan --path src/            # hypotheses, never a verdict
tenanttrace scan --path src/ --format json
```

## Confirming over HTTP

Only a probe run produces `confirmed` findings, and only those should fail a
build. It needs a running instance and a seeder — the ~30 lines that teach the
tool how your application creates a tenant, authenticates one, and creates an
owned record.

```bash
tenanttrace init                        # scaffold a config and a seeder stub
tenanttrace validate-config tenanttrace.toml
tenanttrace probe --config tenanttrace.toml --dry-run   # what it would send
tenanttrace probe --config tenanttrace.toml
```

**The prober sends real traffic.** It is read-only unless given
`--allow-mutation`, the target host must be in `allowed_hosts`, and anything
outside loopback additionally needs `--i-have-authorization`. Never point it at
an application the user has not said they own or are authorised to test. If in
doubt, ask — do not infer authorisation from a URL being present in a config.

## Reading a run

Three things decide whether a result means anything:

- **`INVALID` is not a clean result.** It means the audit did not happen — the
  positive controls failed, the target throttled the run, or the seeder broke.
  An empty finding list under `INVALID` says nothing about the application.
- **"Refused" counts only what the application decided.** Attempts that were
  throttled, redirected, or aimed at a route that serves nothing are
  `inconclusive` and are reported separately, on purpose.
- **Scope is not the whole system.** The report states how many endpoints were
  discovered and never reached. Quote that number when summarising.

## Comparing runs

The question a weekly run needs answered is not "what did this find?" but
"what did it stop proving?" — an application that still holds and one the
harness no longer reaches both report no findings.

```bash
tenanttrace diff <earlier-run> <later-run> --fail-on-regression
```

## What it will not find

Say this plainly when summarising; a security tool that lists only its
strengths is telling half of something.

- Anything it cannot seed. The oracle works because TenantTrace planted the
  data it later looks for.
- Endpoints missing from the spec. Undocumented routes go untested, and the
  report says how many were discovered versus probed.
- Leaks with no HTTP surface — a report generator writing to shared storage, a
  job queue — unless the static engine catches them as hypotheses.

## Interpreting the categories

| Category | What it means | Where the fix goes |
| --- | --- | --- |
| `cross_tenant_read` | Another tenant's record came back | The data-access boundary, not the route |
| `cross_tenant_write` | A record was created inside another tenant | Derive the tenant from the credential |
| `listing_leak` | A collection returned another tenant's rows | A missing `WHERE`, usually |
| `aggregate_leak` | A count spanned every tenant | The aggregate query |
| `param_override` | `?tenant_id=` was honoured | Never read the tenant from request data |
| `cache_key_leak` | Correct query, tenant-less cache key | The cache key |
| `public_endpoint` | The same data comes back with **no credential** | Authentication, not tenant scoping |

The last one matters: if an anonymous request gets the same data, adding a
tenant predicate fixes nothing, because there is no caller to scope to.
