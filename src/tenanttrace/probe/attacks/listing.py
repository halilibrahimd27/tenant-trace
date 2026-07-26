"""Read the actor's own collections and look for the victim's rows in them.

No identifier is sent and nothing unusual is requested: this is the response an
ordinary, well-behaved client receives. That makes a finding here strictly
worse than an IDOR — the caller does not need to know anything, the data simply
arrives.

It is also the most common shape of the bug in practice. A developer scopes the
detail endpoint, remembers the ``WHERE`` clause there, and writes the list
query as ``select(Model)``.
"""

from __future__ import annotations

from collections.abc import Iterator

from tenanttrace.core.models import AttackName, ProbeResult
from tenanttrace.probe.attacks.base import AttackContext
from tenanttrace.probe.oracle import AccessMode

__all__ = ["ListingAttack"]


class ListingAttack:
    """GET every collection endpoint as the actor and scan for victim data."""

    name = AttackName.LISTING

    def run(self, ctx: AttackContext) -> Iterator[ProbeResult]:
        for endpoint in ctx.inventory.collections():
            if ctx.is_allowlisted(endpoint):
                continue

            exchange = ctx.actor.request(endpoint.method, endpoint.path, attack=self.name.value)
            decision = ctx.oracle.judge(exchange.facts(), mode=AccessMode.COLLECTION)

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
                detail=decision.reason,
            )
