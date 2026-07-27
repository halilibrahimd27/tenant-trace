# ADR-0011 — An endpoint that serves everyone is not an endpoint that mis-scopes

- **Status:** accepted
- **Date:** 2026-07-27

## Context

Auditing Squidex produced two confirmed criticals:

```
GET /api/assets/81c65434-9b89-4b12-8585-6ded074efb33
→ 200   tt-canary-B-…3c242e14 asset 0
```

(The canary is shortened here for the same reason the report shortens it: a
seeded value is not something to publish, even from an instance that no longer
exists.)

Tenant A, holding its own credential, read tenant B's asset. By the oracle's
rules that is a proven cross-tenant read, and the finding was true. The
remediation attached to it was not:

> The lookup resolves the identifier without constraining it to the caller's
> tenant. Fix it at the data-access boundary: `.where(Asset.app_id == ctx.app_id)`

Checked by hand, the same request with **no credential at all** returns the
same 200 and the same canary, while the tenant-scoped route
`/api/apps/tt-tenant-b/assets/{id}` returns 404 unauthenticated. The route is
public. There is no caller to scope to, so the suggested fix is not merely
imprecise — it cannot be applied. An engineer following it would add a
predicate to a query that has no session, find it does not compile, and lose
confidence in the report.

This is the same class of error ADR-0008 addressed for cache leaks: the verdict
was right and the *category* was wrong, so the reader was sent to the wrong
line. The remedy there was a differential — establish a baseline before
claiming a mechanism. The baseline that was missing here is the simplest one
available: ask nobody.

## Decision

**Before an attack reports a cross-tenant read, it asks whether an
unauthenticated request gets the same data.** If it does, the result carries
`Category.PUBLIC_ENDPOINT` instead.

- `AttackContext` gains an `anonymous` session — the same client and rate
  limiter, no credentials.
- `serves_anyone()` in `attacks/base.py` replays the exact request without
  credentials and judges the response with the same oracle. It errs towards
  *not* reclaiming the finding: a transport failure answers `False` and the
  cross-tenant category stands.
- `ProbeResult` gains an optional `category` override, and everything
  downstream reads `result.category_of()`. Normally the attack decides; an
  attack that has established a differential may overrule itself.
- The check runs **only when there is a leak to explain**, so a clean run costs
  no extra requests. This matters: most runs are clean.
- `PUBLIC_ENDPOINT` is rated **high**, tagged CWE-306 and CWE-200, and its
  remediation says what actually applies — authenticate the route, or, if
  serving it publicly is deliberate, put it in `cross_tenant_allowlist` so the
  decision is recorded rather than missed. It also states the thing teams get
  wrong about this shape: an unguessable id is not access control.

## Consequences

**Good.** The two findings on Squidex now read
*"Unauthenticated access to tenant data"* with a fix that can be carried out.
A reader can tell in one line whether they have an authorisation bug or a
missing-authentication bug.

**Good.** The mechanism generalises. Any attack can now correct its own
category once it has evidence, which is the shape ADR-0008 established and this
reuses rather than reinvents.

**Bad.** `high` rather than `critical` is arguable in the other direction:
data reachable by *anybody* is worse than data reachable by one authenticated
tenant. The rating reflects that public asset routes are frequently deliberate
and the tool cannot know intent, so it is placed one step below the finding it
is certain about. The remediation states the severity question plainly and
leaves the call to the operator.

**Bad.** One extra request per proven leak. Negligible in practice — leaks are
rare and the check is skipped entirely when there are none — but it is not free
on a target that is already rate-limiting the audit.

**Rejected.** Suppressing these findings entirely as "probably deliberate".
Whether a public route is intended is the operator's judgement, not the tool's,
and silently dropping a finding is the failure mode this project exists to
avoid.
