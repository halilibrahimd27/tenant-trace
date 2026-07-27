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

from tenanttrace.core.config import Config, _normalise_param
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

    @property
    def tenant_path_params(self) -> frozenset[str]:
        """Path parameter names that select a tenant, from the config."""
        return self.config.tenancy.tenant_path_params()

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
    of_kind = tenant.record_ids(kind) if kind else ()
    matched = tuple(i for i in of_kind if i not in exclude)
    if matched:
        return matched

    remaining = tuple(i for i in tenant.record_ids() if i not in exclude)
    if remaining:
        return remaining[:MAX_BLIND_IDS]

    # Every candidate was used by a positive control, which happens when the
    # seeder plants a single record per kind. Falling back to those ids is the
    # lesser evil: the attribution caveat in ADR-0008 costs a category, while
    # skipping the endpoint costs the finding entirely — and a skipped endpoint
    # in a report full of enforced results reads like coverage.
    return of_kind[:MAX_BLIND_IDS] or tenant.record_ids()[:MAX_BLIND_IDS]


def build_path(
    endpoint: Endpoint,
    identifier: str,
    *,
    tenant: TenantContext | None = None,
    tenant_params: frozenset[str] = frozenset(),
) -> str:
    """Fill an endpoint's path parameters for a cross-tenant request.

    Two kinds of slot, and conflating them was a real gap. A slot that names a
    *tenant* — ``{account_id}``, ``{app}``, ``{realm}`` — takes the victim
    tenant's own selector, because swapping exactly that segment while keeping
    the caller's credential is the canonical BOLA test. Every other slot takes
    the object identifier.

    Before this, one id went into every slot, so
    ``/api/v1/accounts/{account_id}/conversations/{id}`` became
    ``/api/v1/accounts/7/conversations/7`` — a URL addressing nothing, whose
    404 said nothing about isolation. Three of the six applications this tool
    has been pointed at carry the tenant in the path.
    """
    values: dict[str, str] = {}
    for param in endpoint.path_params:
        if tenant is not None and _normalise_param(param) in tenant_params:
            values[param] = tenant.tenant_id
        else:
            values[param] = identifier
    return substitute_path(endpoint.path, values)


def object_params(endpoint: Endpoint, tenant_params: frozenset[str] = frozenset()) -> int:
    """How many slots had to be filled with an object id we only guessed at."""
    return sum(1 for p in endpoint.path_params if _normalise_param(p) not in tenant_params)


def is_speculative_path(endpoint: Endpoint, tenant_params: frozenset[str] = frozenset()) -> bool:
    """Did :func:`build_path` have to invent part of this URL?

    One object slot, one seeded id: the URL is exactly what we meant. Two or
    more object slots and the same id goes into each, so the path very likely
    addresses no record at all — and its 404 says nothing about isolation. A
    tenant slot never counts, because that one is filled with a real value.
    """
    return object_params(endpoint, tenant_params) > 1


def skipped(
    ctx: AttackContext,
    attack: AttackName,
    endpoint: Endpoint,
    *,
    reason: str,
) -> ProbeResult:
    """Record that an endpoint was deliberately not attacked.

    Six attack modules used to ``continue`` past an allowlisted endpoint
    without emitting anything. The endpoint then appeared nowhere: not in the
    findings, not in the refused count, not in the coverage table — which reads
    exactly like an endpoint that was checked and held. Silence is the one
    thing a coverage report may never say.
    """
    return ProbeResult(
        attack=attack,
        endpoint=endpoint,
        actor=ctx.actor_ctx.label,
        target=ctx.victim_ctx.label,
        verdict=Verdict.INCONCLUSIVE,
        detail=reason,
    )


ALLOWLISTED = "excluded by [tenancy] cross_tenant_allowlist, so it was not attacked"


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
