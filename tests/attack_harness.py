"""An AttackContext wired to a function instead of an application.

The fixture apps prove the attacks find real bugs — that is what `make metrics`
scores. What they cannot easily produce is the *other* half: a target that
answers 429, echoes a filter, returns a body with no id, serves the same rows to
everybody, or has no delete route. Those paths decide whether a finding is
reported honestly, and every one of them needs a target that misbehaves on cue.

Only the target is faked. The session, the rate limiter, the redaction and the
oracle are the real ones, so an exchange recorded here is the exchange a real
run would record.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

import httpx

from tenanttrace.core.config import Config, ProbeConfig, TargetConfig, TenancyConfig
from tenanttrace.core.models import Endpoint, TenantLabel
from tenanttrace.probe.attacks.base import AttackContext
from tenanttrace.probe.oracle import TenantOracle
from tenanttrace.probe.session import RateLimiter, TenantSession, build_client
from tenanttrace.probe.spec import EndpointInventory
from tests.conftest import make_tenant

__all__ = ["BASE_URL", "Handler", "build_context", "replace"]

BASE_URL = "http://127.0.0.1:9"

Handler = Callable[[httpx.Request], httpx.Response]


def build_context(
    handler: Handler,
    *,
    endpoints: Sequence[Endpoint],
    allow_mutation: bool = False,
    allowlist: tuple[str, ...] = (),
    with_anonymous: bool = False,
    actor_records: tuple[str, ...] = ("a-1",),
    victim_records: tuple[str, ...] = ("b-1",),
    kind: str = "invoice",
) -> AttackContext:
    """Build a context whose target is ``handler``."""
    config = Config(
        target=TargetConfig(base_url=BASE_URL),
        probe=ProbeConfig(allow_mutation=True),
        tenancy=TenancyConfig(cross_tenant_allowlist=allowlist),
    )
    client = build_client(config, transport=httpx.MockTransport(handler))
    limiter = RateLimiter(max_rps=0)  # no sleeping in a unit test
    actor_ctx = make_tenant(TenantLabel.A, record_ids=actor_records, kind=kind)
    victim_ctx = make_tenant(TenantLabel.B, record_ids=victim_records, kind=kind)

    def session(label: TenantLabel, credential: bool = True) -> TenantSession:
        return TenantSession(
            label=label,
            client=client,
            headers={"Authorization": f"Bearer {label.value}"} if credential else {},
            limiter=limiter,
        )

    return AttackContext(
        config=config,
        inventory=EndpointInventory(tuple(endpoints)),
        actor=session(TenantLabel.A),
        victim=session(TenantLabel.B),
        actor_ctx=actor_ctx,
        victim_ctx=victim_ctx,
        oracle=TenantOracle(actor=actor_ctx, victim=victim_ctx),
        anonymous=session(TenantLabel.A, credential=False) if with_anonymous else None,
        allow_mutation=allow_mutation,
    )


def replace(ctx: AttackContext, **changes: object) -> AttackContext:
    """A copy of ``ctx`` with fields swapped. AttackContext is frozen and slotted,
    so ``dataclasses.replace`` is the only way to vary one field in a test."""
    import dataclasses

    return dataclasses.replace(ctx, **changes)  # type: ignore[arg-type]
