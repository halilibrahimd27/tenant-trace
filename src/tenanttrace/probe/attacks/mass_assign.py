"""Try to create a record *inside* the other tenant.

Every other attack asks whether data comes out. This one asks whether data can
be put in, which is a different and often worse bug: a cross-tenant write can
plant a record, corrupt a balance, or seed content that another tenant's users
will later trust.

The mechanism is mass assignment — a handler that binds the whole request body
onto its model, so a column the API never meant to expose becomes
attacker-controlled. The ownership column is exactly the column you least want
bound.

**This module writes to the target.** It is skipped unless the operator passes
``--allow-mutation`` *and* enables it in config, and it deletes what it creates.
Cleanup is best-effort by nature: if the application offers no delete route, the
record stays, and the result says so rather than pretending otherwise.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from tenanttrace.core.models import AttackName, Endpoint, HttpMethod, ProbeResult, Verdict
from tenanttrace.probe.attacks.base import (
    ALLOWLISTED,
    AttackContext,
    build_path,
    candidate_ids,
    resource_name,
    skipped,
)

__all__ = ["MassAssignAttack"]

# A body just plausible enough to pass validation on a typical create endpoint.
# Values are inferred from the field name, since we have no schema types here.
_STRING_HINTS = ("name", "title", "label", "subject", "body", "description", "text")
_EMAIL_HINTS = ("email", "mail")
_NUMBER_HINTS = ("amount", "count", "qty", "quantity", "price", "total", "value")


def _sample_value(field: str, canary: str) -> Any:
    lowered = field.lower()
    if any(hint in lowered for hint in _EMAIL_HINTS):
        return "tenanttrace@example.invalid"
    if any(hint in lowered for hint in _NUMBER_HINTS):
        return 1
    if any(hint in lowered for hint in _STRING_HINTS):
        return f"{canary} (created by TenantTrace, safe to delete)"
    return f"{canary}"


class MassAssignAttack:
    """POST a record with the victim's tenant id in the body."""

    name = AttackName.MASS_ASSIGN

    def run(self, ctx: AttackContext) -> Iterator[ProbeResult]:
        if not ctx.allow_mutation:
            # Reaching this module without permission is a bug in the runner,
            # not something to work around quietly.
            return

        columns = ctx.tenancy_columns()
        if not columns or not ctx.victim_ctx.tenant_id:
            return

        column = columns[0]
        for endpoint in ctx.inventory.creators():
            if ctx.is_allowlisted(endpoint):
                yield skipped(ctx, self.name, endpoint, reason=ALLOWLISTED)
                continue

            # creators() includes POSTs that carry path parameters, and the
            # raw template was sent verbatim: 190 of 218 exchanges in one run
            # had a literal %7Bid%7D in the URL, and their 404s were reported
            # as "target rejected the cross-tenant write" — an authorization
            # claim about a URL that cannot exist.
            ids = candidate_ids(endpoint, ctx.actor_ctx)
            if endpoint.path_params and not ids:
                yield skipped(
                    ctx,
                    self.name,
                    endpoint,
                    reason=(
                        "no seeded record fits this endpoint's path parameters, so no "
                        "real URL could be built to write to"
                    ),
                )
                continue
            path = (
                build_path(
                    endpoint,
                    ids[0],
                    tenant=ctx.actor_ctx,
                    tenant_params=ctx.tenant_path_params,
                    path_values=ids.path_for(ids[0]),
                    literals=ctx.path_literals,
                )
                if endpoint.path_params
                else endpoint.path
            )

            body = self._build_body(endpoint, ctx, column)
            exchange = ctx.actor.request(
                endpoint.method, path, json_body=body, attack=self.name.value
            )

            decision = ctx.oracle.judge_ownership(exchange.facts(), tenant_field=column)
            created_id = self._created_id(exchange.facts().json_body)

            # A response that does not echo the owner proves nothing on its
            # own, so confirm by reading the record back as the victim: if the
            # victim can see it, it landed in the victim's tenant.
            #
            # Only INCONCLUSIVE is escalated. An ENFORCED verdict here is a
            # positive statement — the application told us the record stayed
            # with its creator — and overriding that on a follow-up read
            # reported a confirmed critical cross-tenant write against an
            # application that had behaved correctly.
            if decision.verdict is Verdict.INCONCLUSIVE and created_id:
                confirmed = self._confirm_via_victim(ctx, endpoint, created_id)
                if confirmed is not None:
                    decision = confirmed

            evidence = exchange.evidence().model_copy(
                update={
                    "matched_ids": decision.matched_ids,
                    "note": f"body carried {column}={ctx.victim_ctx.tenant_id}",
                }
            )
            cleanup_note = self._cleanup(ctx, endpoint, created_id, accepted=exchange.ok)
            yield ProbeResult(
                attack=self.name,
                endpoint=endpoint,
                actor=ctx.actor_ctx.label,
                target=ctx.victim_ctx.label,
                verdict=decision.verdict,
                evidence=evidence,
                detail=f"{decision.reason}{cleanup_note}",
            )

    # ------------------------------------------------------------------ #
    def _build_body(self, endpoint: Endpoint, ctx: AttackContext, column: str) -> dict[str, Any]:
        """Fill the declared fields, then add the ownership column.

        The column is added whether or not the schema declares it: undeclared
        fields being silently bound is the entire vulnerability.
        """
        canary = ctx.actor_ctx.canary
        body: dict[str, Any] = {
            field: _sample_value(field, canary)
            for field in endpoint.body_fields
            if field not in {column}
        }
        if not body:
            body = {"title": f"{canary} (created by TenantTrace, safe to delete)", "name": canary}
        body[column] = ctx.victim_ctx.tenant_id
        return body

    def _created_id(self, payload: Any) -> str | None:
        if isinstance(payload, dict):
            for key in ("id", "uuid", "pk"):
                value = payload.get(key)
                if isinstance(value, (str, int)):
                    return str(value)
        return None

    def _confirm_via_victim(
        self, ctx: AttackContext, endpoint: Endpoint, created_id: str
    ) -> Any | None:
        """Read the new record as the victim to settle who owns it."""
        detail_path = self._detail_path(ctx, endpoint)
        if detail_path is None:
            return None
        path = detail_path.replace("{}", created_id)
        exchange = ctx.victim.request(HttpMethod.GET, path, attack=self.name.value)
        if not exchange.ok:
            return None

        from tenanttrace.probe.oracle import OracleDecision, iter_json_scalars

        # A 2xx is not enough. The route may ignore the id, return a
        # collection, or answer with an unrelated object — all of which would
        # make "the victim can read it" true of a request that never reached
        # the record we created. The response has to actually present that id.
        body = exchange.facts().json_body
        if body is None or created_id not in set(iter_json_scalars(body)):
            return None

        return OracleDecision(
            verdict=Verdict.LEAKED,
            reason=(
                f"record created by tenant {ctx.actor_ctx.label} is readable by tenant "
                f"{ctx.victim_ctx.label}, so the write crossed the tenant boundary"
            ),
            matched_ids=(created_id,),
        )

    def _detail_path(self, ctx: AttackContext, endpoint: Endpoint) -> str | None:
        """Find the matching detail route for a create endpoint, as a template."""
        wanted = resource_name(endpoint)
        for candidate in ctx.inventory.objects(ctx.tenant_path_params):
            if resource_name(candidate) == wanted and candidate.path.startswith(endpoint.path):
                from tenanttrace.probe.spec import substitute_path

                return substitute_path(candidate.path, {}, fallback="{}")
        return None

    def _cleanup(
        self,
        ctx: AttackContext,
        endpoint: Endpoint,
        created_id: str | None,
        *,
        accepted: bool = False,
    ) -> str:
        """Delete what we created, and say plainly when we could not.

        The record was written into somebody else's tenant, so leaving it there
        is a real side effect of running the audit. It is reported in the
        finding rather than logged and forgotten.
        """
        if created_id is None:
            # The write was accepted but the response carried no id we could
            # read, so there is a record somewhere — possibly inside the other
            # tenant — that this run created and cannot remove. Saying nothing
            # would leave the operator to discover it later, which is the worst
            # way to find out an audit wrote to their data.
            if accepted:
                return (
                    " (WARNING: the write was accepted but the response exposed no id, so "
                    "the created record could not be located or removed — check the target)"
                )
            return ""
        wanted = resource_name(endpoint)
        for candidate in ctx.inventory.endpoints:
            if candidate.method is not HttpMethod.DELETE:
                continue
            if resource_name(candidate) != wanted:
                continue
            from tenanttrace.probe.spec import substitute_path

            path = substitute_path(candidate.path, dict.fromkeys(candidate.path_params, created_id))
            # Try as the victim first: if the write really did cross tenants,
            # the victim is the one authorised to remove it.
            for session in (ctx.victim, ctx.actor):
                exchange = session.request(HttpMethod.DELETE, path, attack=self.name.value)
                if exchange.ok or exchange.status == 204:
                    return f" (created record {created_id} was deleted)"
            return (
                f" (WARNING: created record {created_id} could not be deleted — "
                "remove it manually)"
            )
        return (
            f" (WARNING: created record {created_id} was left in place — the API exposes "
            "no delete route for this resource)"
        )
