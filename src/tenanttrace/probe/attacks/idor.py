"""Ask for the other tenant's objects by id.

The canonical broken-object-level-authorization test: take an identifier that
belongs to tenant B and request it while holding tenant A's credential. If the
object comes back, the application is treating the id as sufficient proof of
ownership.

Identifiers here are UUIDs we seeded, not guesses. That matters for what a
finding means: this module does not claim the ids are enumerable, it claims
that *possessing* one is enough — which is the actual bug, and is why "our ids
are random" is not a fix.
"""

from __future__ import annotations

from collections.abc import Iterator

from tenanttrace.core.models import AttackName, Category, ProbeResult, Verdict
from tenanttrace.probe.attacks.base import (
    ALLOWLISTED,
    AttackContext,
    build_path,
    candidate_ids,
    is_speculative_path,
    serves_anyone,
    skipped,
)
from tenanttrace.probe.oracle import AccessMode

__all__ = ["IdorAttack"]


class IdorAttack:
    """GET the victim's object ids with the actor's session."""

    name = AttackName.IDOR

    def run(self, ctx: AttackContext) -> Iterator[ProbeResult]:
        for endpoint in ctx.inventory.objects():
            if ctx.is_allowlisted(endpoint):
                yield skipped(ctx, self.name, endpoint, reason=ALLOWLISTED)
                continue

            ids = candidate_ids(endpoint, ctx.victim_ctx, exclude=ctx.excluded_ids)
            if not ids:
                # No seeded id fits this endpoint. Saying nothing would imply
                # the endpoint was checked and held, so the run records that it
                # was skipped instead.
                yield ProbeResult(
                    attack=self.name,
                    endpoint=endpoint,
                    actor=ctx.actor_ctx.label,
                    target=ctx.victim_ctx.label,
                    verdict=Verdict.INCONCLUSIVE,
                    detail=(
                        "no seeded record matches this endpoint's resource, so nothing "
                        "cross-tenant could be requested"
                    ),
                )
                continue

            for identifier in ids:
                path = build_path(
                    endpoint,
                    identifier,
                    tenant=ctx.victim_ctx,
                    tenant_params=ctx.tenant_path_params,
                )
                exchange = ctx.actor.request(endpoint.method, path, attack=self.name.value)
                decision = ctx.oracle.judge(
                    exchange.facts(),
                    mode=AccessMode.OBJECT,
                    sent_ids=[identifier],
                    speculative_path=is_speculative_path(endpoint, ctx.tenant_path_params),
                )

                # Before calling this a tenant-scoping failure, check whether
                # the route is simply public. Only asked when there is a leak
                # to explain, so a clean run costs no extra requests.
                category = None
                detail = decision.reason
                if decision.leaked and serves_anyone(
                    ctx,
                    endpoint.method,
                    path,
                    attack=self.name.value,
                    sent_ids=[identifier],
                ):
                    category = Category.PUBLIC_ENDPOINT
                    detail = (
                        f"{decision.reason}; the same record came back to a request "
                        "carrying no credential at all, so the route is public rather "
                        "than mis-scoped"
                    )

                evidence = exchange.evidence().model_copy(
                    update={
                        "matched_canary": decision.matched_canary,
                        "matched_ids": decision.matched_ids,
                    }
                )
                yield ProbeResult(
                    attack=self.name,
                    endpoint=endpoint,
                    actor=ctx.actor_ctx.label,
                    target=ctx.victim_ctx.label,
                    verdict=decision.verdict,
                    evidence=evidence,
                    detail=detail,
                    category=category,
                )

                # One proven leak per endpoint is enough. Continuing would add
                # identical findings for every remaining id and bury the rest
                # of the report.
                if decision.leaked:
                    break
