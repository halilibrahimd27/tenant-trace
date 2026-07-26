"""Shared plumbing for attack modules.

An attack takes the endpoint inventory and the two tenant sessions and yields
:class:`~tenanttrace.core.models.ProbeResult` values. It does not decide
severity, it does not write findings, and it does not know whether it is
talking to a socket or to an in-process ASGI application. Keeping attacks that
narrow is what makes adding one cheap.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Protocol

from tenanttrace.core.config import Config
from tenanttrace.core.models import (
    AttackName,
    Endpoint,
    ProbeResult,
    TenantContext,
    Verdict,
)
from tenanttrace.probe.oracle import TenantOracle
from tenanttrace.probe.session import TenantSession
from tenanttrace.probe.spec import EndpointInventory, substitute_path

__all__ = ["Attack", "AttackContext", "candidate_ids", "resource_name", "result_from"]

# How many of the victim's ids to try per endpoint when the resource cannot be
# matched by name. Trying every id against every endpoint turns a 20-endpoint
# audit into thousands of requests for no extra signal: if an endpoint leaks,
# it leaks on the first id.
MAX_BLIND_IDS = 3


@dataclass(frozen=True, slots=True)
class AttackContext:
    """Everything an attack is allowed to touch."""

    config: Config
    inventory: EndpointInventory
    actor: TenantSession
    victim: TenantSession
    actor_ctx: TenantContext
    victim_ctx: TenantContext
    oracle: TenantOracle
    allow_mutation: bool = False
    # Record ids their own tenant already read during the positive controls.
    #
    # These are excluded from every attack, and the reason is subtle enough to
    # be worth stating: if the application caches responses under a key that
    # omits the tenant, then an object the victim just read is sitting in a
    # shared cache entry. Probing *that* id would return the victim's data from
    # any endpoint, and the run would report a plain cross-tenant read on an
    # endpoint whose database query is entirely correct — sending the reader
    # off to add a WHERE clause that is already there. Keeping control reads
    # and attack reads on different records is what lets the cache attack own
    # that finding, with the right remediation attached.
    excluded_ids: frozenset[str] = frozenset()

    def is_allowlisted(self, endpoint: Endpoint) -> bool:
        """True when this endpoint is meant to cross tenants.

        Checked by every attack before it reports. An application with a
        genuine platform-admin endpoint must be able to say so once, in config,
        instead of seeing the same false positive on every run.
        """
        return self.config.is_allowlisted(endpoint.path)

    def tenancy_columns(self) -> tuple[str, ...]:
        return self.config.tenancy.columns()


class Attack(Protocol):
    """One family of cross-tenant attempts."""

    name: AttackName

    def run(self, ctx: AttackContext) -> Iterator[ProbeResult]:
        """Yield one result per attempt — enforced attempts included."""
        ...


def resource_name(endpoint: Endpoint) -> str:
    """Guess the resource an endpoint addresses, e.g. ``invoice``.

    Assumption, and how it can be wrong: REST paths name their collection
    immediately before the identifier (``/api/invoices/{id}``), and the plural
    is formed by adding ``s``. Applications that nest deeply or use irregular
    plurals will not match, in which case the caller falls back to trying a few
    ids blindly — a missed name costs requests, never correctness.
    """
    segments = [s for s in endpoint.path.split("/") if s]
    last_static = ""
    for segment in segments:
        if segment.startswith("{"):
            break
        last_static = segment
    if not last_static:
        return ""
    name = last_static.replace("-", "_").lower()
    if name.endswith("ies") and len(name) > 3:
        return name[:-3] + "y"
    if name.endswith("s") and not name.endswith("ss"):
        return name[:-1]
    return name


def candidate_ids(
    endpoint: Endpoint,
    tenant: TenantContext,
    *,
    exclude: frozenset[str] = frozenset(),
) -> tuple[str, ...]:
    """Which of the tenant's record ids are worth sending to this endpoint."""
    kind = resource_name(endpoint)
    matched = tuple(i for i in tenant.record_ids(kind) if i not in exclude) if kind else ()
    if matched:
        return matched
    remaining = tuple(i for i in tenant.record_ids() if i not in exclude)
    return remaining[:MAX_BLIND_IDS]


def build_path(endpoint: Endpoint, identifier: str) -> str:
    """Substitute one identifier into every path parameter of an endpoint.

    Multi-parameter paths (``/api/tenants/{tenant_id}/invoices/{invoice_id}``)
    get the same value everywhere, which is wrong often enough to matter — the
    resulting 404 is reported as ``inconclusive``, never as enforcement.
    """
    return substitute_path(endpoint.path, dict.fromkeys(endpoint.path_params, identifier))


def result_from(
    *,
    attack: AttackName,
    endpoint: Endpoint,
    ctx: AttackContext,
    verdict: Verdict,
    detail: str,
    evidence_source: Sequence[object] = (),
) -> ProbeResult:  # pragma: no cover - thin helper kept for symmetry
    """Small convenience wrapper so attacks read declaratively."""
    del evidence_source
    return ProbeResult(
        attack=attack,
        endpoint=endpoint,
        actor=ctx.actor_ctx.label,
        target=ctx.victim_ctx.label,
        verdict=verdict,
        detail=detail,
    )
