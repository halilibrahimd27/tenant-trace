"""Try to select the victim's tenant through the request itself.

Some applications take the tenant from the credential; some take it from
whatever the caller sent and only *usually* pass the credential's value. The
second kind looks identical in a single-tenant test suite, because the client
always sends its own tenant.

Three channels are tried, because applications differ in which one they trust:
a query parameter, a request header, and — for endpoints that accept a body —
a body field. All three are sent with the actor's real credential attached, so
a success means the application preferred request data over the authenticated
identity.
"""

from __future__ import annotations

from collections.abc import Iterator

from tenanttrace.core.models import AttackName, Endpoint, ProbeResult, Verdict
from tenanttrace.probe.attacks.base import ALLOWLISTED, AttackContext, build_path, skipped
from tenanttrace.probe.oracle import AccessMode

__all__ = ["ParamOverrideAttack"]

# Header spellings of the same idea. Cheap to try, and each one is a real
# convention somebody's gateway uses.
_HEADER_TEMPLATES = ("X-{}", "X-{}-Id", "{}")


def _header_names(column: str) -> tuple[str, ...]:
    """Header spellings for a tenancy column: tenant_id -> X-Tenant-Id, ..."""
    base = column.removesuffix("_id").replace("_", "-").title()
    names = {template.format(base) for template in _HEADER_TEMPLATES}
    names.add(f"X-{base}-ID")
    return tuple(sorted(names))


class ParamOverrideAttack:
    """Send the victim's tenant id as a parameter, a header, and a body field."""

    name = AttackName.PARAM_OVERRIDE

    def run(self, ctx: AttackContext) -> Iterator[ProbeResult]:
        victim_id = ctx.victim_ctx.tenant_id
        if not victim_id:
            return

        columns = ctx.tenancy_columns()
        for endpoint in ctx.inventory.collections(ctx.tenant_path_params):
            if ctx.is_allowlisted(endpoint):
                yield skipped(ctx, self.name, endpoint, reason=ALLOWLISTED)
                continue

            # Differential test. An endpoint that already returns the victim's
            # rows without any override is a listing leak, and that module owns
            # it. Reporting it here too would produce two findings for one bug
            # with two different remediations — and the parameter-override
            # remediation ("stop trusting request data") would be the wrong
            # advice for a query that simply has no WHERE clause. So the
            # baseline has to be clean before an override means anything.
            # The caller's *own* collection, with its own tenant in any path
            # slot. The override then asks whether request data can move the
            # answer to somebody else's tenant — which is only a question worth
            # asking from a URL that legitimately belongs to the caller.
            # `endpoint.path` was sent raw, so on an API carrying its tenant in
            # the path this requested a literal %7Brealm%7D.
            path = build_path(
                endpoint, "", tenant=ctx.actor_ctx, tenant_params=ctx.tenant_path_params
            )
            baseline = ctx.actor.request(endpoint.method, path, attack=self.name.value)
            if ctx.oracle.judge(baseline.facts(), mode=AccessMode.COLLECTION).leaked:
                continue

            yield from self._query_channel(ctx, endpoint, path, columns, victim_id)
            yield from self._header_channel(ctx, endpoint, path, columns, victim_id)

    # ------------------------------------------------------------------ #
    def _query_channel(
        self,
        ctx: AttackContext,
        endpoint: Endpoint,
        path: str,
        columns: tuple[str, ...],
        victim_id: str,
    ) -> Iterator[ProbeResult]:
        # Try the declared parameters first — an endpoint that documents
        # `?tenant_id=` is the highest-yield case — then the configured column
        # even when undeclared, because frameworks routinely bind query
        # parameters that no specification mentions.
        refused = 0
        declared = [c for c in columns if c in endpoint.query_params]
        undeclared = [columns[0]] if columns and columns[0] not in declared else []

        for column in [*declared, *undeclared]:
            exchange = ctx.actor.request(
                endpoint.method,
                path,
                params={column: victim_id},
                attack=self.name.value,
            )
            decision = ctx.oracle.judge(exchange.facts(), mode=AccessMode.COLLECTION)
            if decision.verdict is Verdict.ENFORCED:
                # A rejected override on every spelling would flood the
                # transcript — 134 rows on one real target, burying the six
                # results that needed a human. Collapsed into one row after the
                # loop instead, because emitting nothing at all reads exactly
                # like an endpoint nobody tried.
                refused += 1
                continue
            evidence = exchange.evidence().model_copy(
                update={
                    "matched_canary": decision.matched_canary,
                    "matched_ids": decision.matched_ids,
                    "note": f"query parameter {column}={victim_id}",
                }
            )
            yield ProbeResult(
                attack=self.name,
                endpoint=endpoint,
                actor=ctx.actor_ctx.label,
                target=ctx.victim_ctx.label,
                verdict=decision.verdict,
                evidence=evidence,
                detail=f"{decision.reason} (via query parameter {column!r})",
            )
            if decision.leaked:
                return

        if refused:
            yield skipped(
                ctx,
                self.name,
                endpoint,
                reason=(
                    f"every one of {refused} query-parameter spellings was refused; "
                    "the endpoint does not honour a client-supplied tenant"
                ),
            )

    def _header_channel(
        self,
        ctx: AttackContext,
        endpoint: Endpoint,
        path: str,
        columns: tuple[str, ...],
        victim_id: str,
    ) -> Iterator[ProbeResult]:
        if not columns:
            return
        refused = 0
        for header in _header_names(columns[0]):
            session = ctx.actor.with_headers({header: victim_id})
            exchange = session.request(endpoint.method, path, attack=self.name.value)
            decision = ctx.oracle.judge(exchange.facts(), mode=AccessMode.COLLECTION)
            if decision.verdict is Verdict.ENFORCED:
                refused += 1
                continue
            evidence = exchange.evidence().model_copy(
                update={
                    "matched_canary": decision.matched_canary,
                    "matched_ids": decision.matched_ids,
                    "note": f"request header {header}: {victim_id}",
                }
            )
            yield ProbeResult(
                attack=self.name,
                endpoint=endpoint,
                actor=ctx.actor_ctx.label,
                target=ctx.victim_ctx.label,
                verdict=decision.verdict,
                evidence=evidence,
                detail=f"{decision.reason} (via request header {header!r})",
            )
            if decision.leaked:
                return
