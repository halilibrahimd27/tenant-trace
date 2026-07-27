"""Find leaks that live in the cache rather than in the query.

A cache key that omits the tenant defeats a perfectly correct query. The
application filters by tenant, gets the right answer, and then stores it under
``invoice:{id}`` — so whichever tenant asks first populates the entry and the
next tenant is served it.

This is the failure mode that is hardest to catch any other way. Code review
sees a correct ``WHERE`` clause. A single-tenant test suite passes. The leak
depends on request ordering and cache lifetime, so it reproduces
intermittently, in production, under load.

The attack is a three-step sequence and the order is the whole point:

1. **Cold read as the actor.** If the object comes back now, the endpoint has
   no tenant check at all — that is an IDOR, it belongs to that module, and
   this one stays quiet rather than reporting the same bug twice.
2. **Warm as the victim.** The victim reads its own object, legitimately,
   populating whatever cache sits behind the endpoint.
3. **Read again as the actor.** Data that was correctly refused in step 1 and
   arrives in step 3 came from the cache, not the database.

No cache is inspected and no Redis connection is needed: the evidence is
entirely in the observable behaviour, which means this works against any cache
implementation, including one inside the process.
"""

from __future__ import annotations

from collections.abc import Iterator

from tenanttrace.core.models import AttackName, ProbeResult, Verdict
from tenanttrace.probe.attacks.base import (
    ALLOWLISTED,
    AttackContext,
    build_path,
    candidate_ids,
    is_speculative_path,
    skipped,
)
from tenanttrace.probe.oracle import AccessMode

__all__ = ["CacheAttack"]


class CacheAttack:
    """Cold read, victim warms the cache, read again."""

    name = AttackName.CACHE

    def run(self, ctx: AttackContext) -> Iterator[ProbeResult]:
        for endpoint in ctx.inventory.objects():
            if ctx.is_allowlisted(endpoint):
                yield skipped(ctx, self.name, endpoint, reason=ALLOWLISTED)
                continue

            ids = candidate_ids(endpoint, ctx.victim_ctx, exclude=ctx.excluded_ids)
            if not ids:
                yield skipped(
                    ctx,
                    self.name,
                    endpoint,
                    reason="no seeded record matches this endpoint's resource",
                )
                continue
            identifier = ids[0]
            path = build_path(
                endpoint,
                identifier,
                tenant=ctx.victim_ctx,
                tenant_params=ctx.tenant_path_params,
                path_values=ids.path_for(identifier),
                literals=ctx.path_literals,
            )

            # Step 1 — cold. A leak here is an IDOR, not a cache bug.
            cold = ctx.actor.request(
                endpoint.method,
                path,
                attack=self.name.value,
                id_source="kind-matched" if ids.matched_kind else "blind",
            )
            cold_decision = ctx.oracle.judge(
                cold.facts(),
                mode=AccessMode.OBJECT,
                sent_ids=[identifier],
                speculative_path=is_speculative_path(
                    endpoint,
                    ctx.tenant_path_params,
                    matched_kind=ids.matched_kind,
                ),
            )
            if cold_decision.leaked:
                continue

            # Step 2 — the victim reads its own object. This is an ordinary,
            # authorised request; it is the application that turns it into a
            # shared cache entry.
            warm = ctx.victim.request(
                endpoint.method,
                path,
                attack=self.name.value,
                id_source="kind-matched" if ids.matched_kind else "blind",
            )
            if not warm.ok:
                # Nothing was cached, so step 3 could not distinguish a cache
                # leak from an ordinary refusal. On one real target this ended
                # 70 of 110 endpoints in silence, which reads as coverage.
                yield skipped(
                    ctx,
                    self.name,
                    endpoint,
                    reason=(
                        f"the owner could not read this object either (HTTP {warm.status}), "
                        "so no cache entry existed to test against"
                    ),
                )
                continue

            # Step 3 — the same request that was refused in step 1.
            hot = ctx.actor.request(
                endpoint.method,
                path,
                attack=self.name.value,
                id_source="kind-matched" if ids.matched_kind else "blind",
            )
            hot_decision = ctx.oracle.judge(
                hot.facts(),
                mode=AccessMode.OBJECT,
                sent_ids=[identifier],
                speculative_path=is_speculative_path(
                    endpoint,
                    ctx.tenant_path_params,
                    matched_kind=ids.matched_kind,
                ),
            )

            if not hot_decision.leaked:
                yield ProbeResult(
                    attack=self.name,
                    endpoint=endpoint,
                    actor=ctx.actor_ctx.label,
                    target=ctx.victim_ctx.label,
                    verdict=Verdict.ENFORCED,
                    evidence=hot.evidence(),
                    detail=(
                        "isolation held after the other tenant warmed the same object — "
                        "no shared cache entry observed"
                    ),
                )
                continue

            evidence = hot.evidence().model_copy(
                update={
                    "matched_canary": hot_decision.matched_canary,
                    "matched_ids": hot_decision.matched_ids,
                    "note": (
                        f"identical request was refused with {cold.status} before tenant "
                        f"{ctx.victim_ctx.label} read the same object; served after"
                    ),
                }
            )
            yield ProbeResult(
                attack=self.name,
                endpoint=endpoint,
                actor=ctx.actor_ctx.label,
                target=ctx.victim_ctx.label,
                verdict=Verdict.LEAKED,
                evidence=evidence,
                detail=(
                    f"{hot_decision.reason} — the same request returned "
                    f"{cold.status} on a cold cache, so the response came from a cache "
                    "entry keyed without the tenant"
                ),
            )
