# ADR-0010 — A result is evidence of isolation only if the application decided

- **Status:** accepted
- **Date:** 2026-07-27

## Context

The tool's value is concentrated in one sentence, printed on the majority of
runs: *"No cross-tenant access proven — N attempts refused."* That sentence is
a claim about the application. Auditing a real, rate-limited target showed that
four independent mechanisms were inflating N with attempts the application
never ruled on.

The evidence, from `.tenanttrace/syneris/runs/20260726T221259Z/`:

- 168 results, of which **26 were `ENFORCED` and 142 `INCONCLUSIVE`**.
- **134 of the responses were HTTP 429.** The target throttled the audit.
- 17 of 86 discovered endpoints were reached.
- The run was reported **`VALID`** and clean.
- The HTML report said *"168 attempts … the application refused them"* in the
  verdict and **`26 refused`** in the tile directly above it. One page, two
  numbers, same word.

Four causes, one shape — a result that is not a decision being counted as one:

1. **The verdict counted `results`, not `ENFORCED`.** A recently added
   convenience that passed every test, because on the fixtures every result
   *is* enforced. The first real target with inconclusive results exposed it.
2. **429 was read as a refusal.** For `OBJECT` mode the catch-all branch
   returned `ENFORCED` for any status that was not 2xx/3xx/5xx/401/403/404;
   for `COLLECTION` mode the same status fell to `INCONCLUSIVE`. Both wrong,
   and inconsistently so.
3. **A 404 from a URL the tool invented was read as a refusal.**
   `build_path()` substitutes one seeded id into *every* path parameter, so
   `/api/tenants/{tenant_id}/invoices/{invoice_id}` becomes a path that very
   likely addresses no record. Its docstring already claimed the resulting 404
   was reported as inconclusive. The oracle did the opposite. 19 of Vikunja's
   123 results took this path.
4. **Allowlisted endpoints vanished.** Six attack modules did
   `if ctx.is_allowlisted(endpoint): continue`, emitting nothing — while
   `idor.py` seven lines below emitted an `INCONCLUSIVE` for a *different*
   skip, with the comment *"Saying nothing would imply the endpoint was checked
   and held."* The endpoint appeared in no finding, no count, and no coverage
   row.

Rule 4 of the project contract already covers the case where the harness is
broken. Every one of these arrived through a door it did not cover: the harness
worked perfectly and the *application* declined to participate.

## Decision

**A `ProbeResult` counts as evidence of isolation only when the application
made a decision about the request.** Applied uniformly:

- **`ENFORCED` means the application refused.** The verdict line, in both the
  HTML report and the CLI, counts `ENFORCED` and reports `INCONCLUSIVE`
  separately as *"could not be judged"*. A run with zero enforcement is never
  "clean"; it says **"Nothing was proven either way."**
- **429 is `INCONCLUSIVE` in every mode.** `THROTTLE_STATUSES` lives in
  `core/models.py` because the report needs it too. Positive evidence still
  outranks it — a canary inside a 429 body is a leak.
- **A 404 on a speculative path is `INCONCLUSIVE`.** Attacks pass
  `speculative_path=is_speculative_path(endpoint)` — true when the endpoint has
  more than one path parameter. `401` and `403` remain `ENFORCED` regardless:
  those are authorisation decisions whatever the URL looked like.
- **A deliberately skipped endpoint emits a result.** `skipped()` in
  `attacks/base.py` records it as `INCONCLUSIVE` with the setting that caused
  it named in the detail.
- **A run the target throttled is `INVALID`.** Past `THROTTLE_INVALID_RATIO`
  (0.5) of attempts answered 429, the run is not an audit. Below it, a run note
  states the count.

## Consequences

**Good.** The negative claim is now arithmetically true, and it is the same
number everywhere it appears. Coverage that was previously invisible —
throttling, skips, speculative paths — is stated rather than absorbed into a
number that looked like enforcement.

**Good.** Every downstream consumer inherits this for free: the Markdown
report, the JSON summary, the CI gate, and anything later built on them.

**Bad.** Reported refusal counts drop, in some cases sharply. A team that
recorded "168 refused" last week will see a smaller number for an unchanged
application. That is the correction working; the run note and this ADR are the
explanation.

**Bad.** `THROTTLE_INVALID_RATIO` is a threshold, and thresholds are arguable.
0.5 is deliberately blunt — the exact number matters far less than refusing to
call such a run clean, and an operator who disagrees can lower `[probe]
rate_limit` instead.

**Rejected.** Widening `ENFORCED` to cover 400/405/422. Those often mean the
request was malformed — the tool's fault — and folding them in would rebuild
the same defect with different status codes.
