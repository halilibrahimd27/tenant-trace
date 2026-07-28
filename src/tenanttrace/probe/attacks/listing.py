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

from tenanttrace.core.config import _normalise_param
from tenanttrace.core.models import AttackName, ProbeResult, Verdict
from tenanttrace.probe.attacks.base import ALLOWLISTED, AttackContext, build_path, skipped
from tenanttrace.probe.oracle import AccessMode, OracleDecision
from tenanttrace.probe.session import Exchange

__all__ = ["ListingAttack"]


def _is_ownership_only(decision: OracleDecision) -> bool:
    """True when the verdict rests on an ownership field and nothing stronger."""
    return decision.matched_canary is None and all("=" in marker for marker in decision.matched_ids)


def _same_payload(left: Exchange, right: Exchange) -> bool:
    """True when two responses carry the same data.

    Compared as decoded JSON so key order and whitespace do not matter, and
    falling back to the raw text for anything that is not JSON.
    """
    left_facts, right_facts = left.facts(), right.facts()
    if left_facts.json_body is not None and right_facts.json_body is not None:
        return bool(left_facts.json_body == right_facts.json_body)
    return left.response_text == right.response_text


class ListingAttack:
    """GET every collection endpoint as the actor and scan for victim data."""

    name = AttackName.LISTING

    def run(self, ctx: AttackContext) -> Iterator[ProbeResult]:
        for endpoint in ctx.inventory.collections(ctx.tenant_path_params):
            if ctx.is_allowlisted(endpoint):
                yield skipped(ctx, self.name, endpoint, reason=ALLOWLISTED)
                continue

            # A collection can live under a tenant segment —
            # /admin/realms/{realm}/groups — and asking for the victim's is the
            # canonical BOLA swap. Sending `endpoint.path` raw put a literal
            # %7Brealm%7D in the URL and turned the resulting 404 into evidence
            # of enforcement.
            tenant_slot = any(
                _normalise_param(p) in ctx.tenant_path_params for p in endpoint.path_params
            )
            path = build_path(
                endpoint, "", tenant=ctx.victim_ctx, tenant_params=ctx.tenant_path_params
            )
            exchange = ctx.actor.request(endpoint.method, path, attack=self.name.value)
            decision = ctx.oracle.judge(exchange.facts(), mode=AccessMode.COLLECTION)

            # The shared-reference-data differential compares this response
            # against the victim's for the *same* URL. When that URL names the
            # victim's tenant, the victim is reading its own data by
            # definition — so identical payloads mean the actor was served the
            # victim's rows, which is the leak, not a phone book. Running the
            # differential there would suppress the finding it exists beside.
            if decision.leaked and not tenant_slot and _is_ownership_only(decision):
                # Ownership-field evidence is the weakest of the three signals
                # and it has one specific failure mode: a *shared* resource
                # whose rows carry a `user_id` that refers to somebody rather
                # than owning the row. A company-wide expert directory listing
                # `userId: 3` is not tenant 3's private data — it is a phone
                # book, and every tenant is supposed to see it.
                #
                # The differential settles it: if the victim is served the same
                # rows, nothing crossed a boundary. Only a canary or an
                # identifier can carry a finding on its own.
                mirror = ctx.victim.request(endpoint.method, path, attack=self.name.value)
                if mirror.ok and _same_payload(exchange, mirror):
                    yield ProbeResult(
                        attack=self.name,
                        endpoint=endpoint,
                        actor=ctx.actor_ctx.label,
                        target=ctx.victim_ctx.label,
                        verdict=Verdict.ENFORCED,
                        evidence=exchange.evidence(),
                        detail=(
                            "both tenants are served identical rows, so this is shared "
                            "reference data rather than one tenant's records — the "
                            f"{decision.matched_ids[0] if decision.matched_ids else 'ownership'} "
                            "field refers to a person, it does not own the row"
                        ),
                    )
                    continue

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
