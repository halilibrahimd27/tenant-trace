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
    HttpMethod,
    ProbeResult,
    TenantContext,
    Verdict,
)
from tenanttrace.probe.oracle import AccessMode, TenantOracle
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
    # A session carrying no credential at all. Used to tell "tenant A can read
    # tenant B's record" from "anybody can read tenant B's record" — two
    # different bugs whose fixes have nothing in common (ADR-0011).
    anonymous: TenantSession | None = None
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


def _singular(word: str) -> str:
    """`invoices` -> `invoice`, `inboxes` -> `inbox`, `entries` -> `entry`."""
    name = word.replace("-", "_").lower()
    if name.endswith("ies") and len(name) > 3:
        return name[:-3] + "y"
    # -xes, -ses, -ches, -shes, -zes: the `e` belongs to the plural, not the
    # stem. Without this `inboxes` became `inboxe`, which no seeded kind could
    # ever match.
    if any(name.endswith(e) for e in ("xes", "ses", "ches", "shes", "zes")):
        return name[:-2]
    if name.endswith("s") and not name.endswith("ss"):
        return name[:-1]
    return name


def resource_name(endpoint: Endpoint) -> str:
    """Guess the resource an endpoint addresses, e.g. ``invoice``.

    REST paths name their collection immediately before the identifier, so the
    segment that matters is the last static one before the **last** path
    parameter — not before the first.

    That distinction is the whole function. Breaking at the first ``{`` meant
    ``/api/v1/accounts/{account_id}/contacts/{id}`` resolved to ``account``, and
    on an application carrying its tenant in the path *every* endpoint resolved
    to the tenant's own collection: all 209 of Keycloak's object endpoints came
    back as ``realm``. Kind matching then never fired anywhere, every endpoint
    fell back to blind id guessing, and the seeder contract — "return a kind
    matching the resource segment" — was unsatisfiable.

    Assumption, and how it can be wrong: the plural is regular. Irregular
    plurals will not match, in which case the caller guesses blindly and says
    so — a missed name costs requests and confidence, never correctness.
    """
    segments = [s for s in endpoint.path.split("/") if s]
    last_param = max((i for i, seg in enumerate(segments) if seg.startswith("{")), default=-1)
    if last_param < 0:
        return _singular(segments[-1]) if segments else ""

    for segment in reversed(segments[:last_param]):
        if not segment.startswith("{"):
            return _singular(segment)
    return ""


@dataclass(frozen=True, slots=True)
class Candidates:
    """Ids to try against an endpoint, and whether they belong to it.

    ``matched_kind`` is the difference between "this endpoint refused a real
    record of its own resource" and "this endpoint 404'd on an id belonging to
    something else entirely". Only the first is evidence of isolation.
    """

    ids: tuple[str, ...]
    matched_kind: bool

    def __bool__(self) -> bool:
        return bool(self.ids)

    def __iter__(self) -> Iterator[str]:
        return iter(self.ids)

    def __len__(self) -> int:
        return len(self.ids)

    def __getitem__(self, index: int) -> str:
        return self.ids[index]


def candidate_ids(
    endpoint: Endpoint,
    tenant: TenantContext,
    *,
    exclude: frozenset[str] = frozenset(),
) -> Candidates:
    """Which of the tenant's record ids are worth sending to this endpoint."""
    kind = resource_name(endpoint)
    of_kind = tenant.record_ids(kind) if kind else ()
    matched = tuple(i for i in of_kind if i not in exclude)
    if matched:
        return Candidates(matched, matched_kind=True)

    remaining = tuple(i for i in tenant.record_ids() if i not in exclude)
    if remaining:
        return Candidates(remaining[:MAX_BLIND_IDS], matched_kind=False)

    # Every candidate was used by a positive control, which happens when the
    # seeder plants a single record per kind. Falling back to those ids is the
    # lesser evil: the attribution caveat in ADR-0008 costs a category, while
    # skipping the endpoint costs the finding entirely — and a skipped endpoint
    # in a report full of enforced results reads like coverage.
    fallback = of_kind[:MAX_BLIND_IDS] or tenant.record_ids()[:MAX_BLIND_IDS]
    return Candidates(fallback, matched_kind=bool(of_kind))


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


def is_speculative_path(
    endpoint: Endpoint,
    tenant_params: frozenset[str] = frozenset(),
    *,
    matched_kind: bool = True,
) -> bool:
    """Did this request address a record we actually know about?

    Two ways it does not, and both used to score as enforcement:

    **The id belongs to something else.** When no seeded record matches the
    endpoint's resource, :func:`candidate_ids` guesses — and a Contact id sent
    to ``/Campaign/{id}`` returns 404 because no such campaign exists, not
    because the application refused it. On EspoCRM that turned 420 blind
    attempts into "refused"; on Squidex a content-item UUID landed in a
    ``{schema}`` slot and the report claimed the endpoint was tested and held.

    **Several slots share one id.** Two or more object parameters get the same
    value, so the path very likely addresses nothing.

    A tenant slot never counts either way — it is filled with a real value.
    """
    if not matched_kind:
        return True
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


def serves_anyone(
    ctx: AttackContext,
    method: HttpMethod,
    path: str,
    *,
    attack: str,
    sent_ids: Sequence[str] = (),
) -> bool:
    """Would a request carrying no credential get the same data?

    A leak proved with tenant A's token says isolation failed. The same leak
    reproduced with *no* token says something different and more basic: the
    route is public, and tenant scoping is not the control that broke. The two
    need unrelated fixes, so the attack asks before it names the category.

    Found on a real target — Squidex serves asset content from an unscoped
    ``/api/assets/{id}``, and the report told the reader to add a tenant
    predicate to a query that has no caller to scope to.

    Errs towards *not* reclaiming the finding: if the anonymous request fails
    to go out at all, the answer is False and the original cross-tenant
    category stands.
    """
    if ctx.anonymous is None:
        return False
    probe = ctx.anonymous.request(method, path, attack=attack)
    if probe.transport_error is not None:
        return False
    return ctx.oracle.judge(probe.facts(), mode=AccessMode.OBJECT, sent_ids=sent_ids).leaked


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
