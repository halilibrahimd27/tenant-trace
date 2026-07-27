"""Orchestration: seed, prove the harness works, attack, report.

The order of operations here is the tool's central safety property, so it is
worth stating plainly:

    rails → seed → POSITIVE CONTROLS → attack → collect → clean up

**Positive controls come before any attack, and a failure stops the run.** If
tenant A cannot read tenant A's own data, then every 403 that follows means
"the harness is broken", not "the application is secure". A tool that reported
that as *no leaks found* would be worse than no tool at all: it would hand
somebody a clean report for an application nobody actually tested. That is what
``RunStatus.INVALID`` exists to prevent, and why it is a distinct status rather
than an empty finding list.

Both directions are probed. A→B alone can miss an application whose isolation
depends on which tenant was created first, or on row ordering — B→A is cheap
and turns "we did not observe a leak" into a stronger claim.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import httpx

from tenanttrace import __version__
from tenanttrace.core.config import Config
from tenanttrace.core.fingerprint import with_fingerprint
from tenanttrace.core.models import (
    THROTTLE_STATUSES,
    AttackName,
    Category,
    Confidence,
    ControlResult,
    Endpoint,
    Engine,
    Evidence,
    Finding,
    ProbeResult,
    RunReport,
    RunStatus,
    Severity,
    TenantContext,
    TenantLabel,
    Verdict,
    utcnow,
)
from tenanttrace.core.severity import remediation_for, severity_for, tags_for, title_for
from tenanttrace.core.text import count
from tenanttrace.probe.attacks import AttackContext, build_attacks
from tenanttrace.probe.attacks.base import (
    MAX_BLIND_IDS,
    build_path,
    candidate_ids,
    resource_name,
)
from tenanttrace.probe.oracle import TenantOracle, scan_for_markers
from tenanttrace.probe.recorder import RunRecorder
from tenanttrace.probe.seeder import SeederAdapter, SeederError, load_seeder, seed_tenant
from tenanttrace.probe.session import Exchange, RateLimiter, TenantSession, build_client
from tenanttrace.probe.spec import EndpointInventory, SpecError, load_inventory

__all__ = ["ProbeOptions", "ProbeOutcome", "run_probe"]

# Attack ordering. Read-only attacks run first so that a mutating attack cannot
# perturb the counts an aggregate check depends on.
# Order is load-bearing, and for one reason: **the cache attack must run before
# anything that reads an object as its owner.** Its whole method is to request
# an object cold, have the owner read it, then request it again — so any
# earlier owner-read has already populated a tenant-less cache entry, the cold
# step leaks, and the cache finding is reported as a plain IDOR or lost.
#
# Three separate changes tripped over this: a route-liveness check inside the
# attack loop (twice), and extending the aggregate attack to object endpoints.
# The fixture tests caught all three within minutes; this comment exists so the
# fourth does not have to be caught at all.
#
# Mutating attacks still run last, so nothing this run created can be counted
# as a row the application leaked.
_ATTACK_ORDER: tuple[AttackName, ...] = (
    AttackName.IDOR,
    AttackName.LISTING,
    AttackName.PARAM_OVERRIDE,
    AttackName.CACHE,
    AttackName.AGGREGATE,
    AttackName.MASS_ASSIGN,
)

_DIRECTIONS: tuple[tuple[TenantLabel, TenantLabel], ...] = (
    (TenantLabel.A, TenantLabel.B),
    (TenantLabel.B, TenantLabel.A),
)


@dataclass(frozen=True, slots=True)
class ProbeOptions:
    """Per-run decisions that config alone must never be able to make."""

    allow_mutation: bool = False
    i_have_authorization: bool = False
    dry_run: bool = False
    redact: bool = True
    write_artifacts: bool = True
    # Injected by the test suite and by `tenanttrace demo` to drive a fixture
    # application in-process. Production runs leave both as None and go over a
    # socket; the attacks cannot tell the difference (ADR-0004).
    transport: httpx.BaseTransport | None = None
    seeder: SeederAdapter | None = None


@dataclass(frozen=True, slots=True)
class ProbeOutcome:
    """The run report plus where its artifacts landed."""

    report: RunReport
    artifact_dir: Path | None = None
    plan: tuple[str, ...] = ()


@dataclass
class _RunState:
    """Mutable bookkeeping for one run."""

    controls: list[ControlResult] = field(default_factory=list)
    results: list[ProbeResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    endpoints_tested: set[str] = field(default_factory=set)


def run_probe(config: Config, options: ProbeOptions | None = None) -> ProbeOutcome:
    """Audit one target end to end."""
    opts = options or ProbeOptions()
    started = utcnow()

    # Rails first: nothing is sent, not even a spec fetch, before the target
    # has been checked against allowed_hosts.
    config.check_target_allowed(i_have_authorization=opts.i_have_authorization)

    state = _RunState()
    client = build_client(config, transport=opts.transport)
    # The seeder gets its own client, and the reason is a silent-invalidity
    # bug rather than tidiness: a seeder that registers a user over an API
    # which authenticates by cookie leaves that cookie in the shared jar, and
    # the prober then attacks *already authenticated as the seeder's user*.
    # Every request would carry an identity nobody configured, both tenant
    # sessions would be the same principal, and the run would look ordinary.
    # Found on Teable, which sets HttpOnly `auth_session` on signup.
    seed_client = build_client(config, transport=opts.transport)
    limiter = RateLimiter(config.probe.max_rps)

    sessions: dict[TenantLabel, TenantSession] = {}
    tenants: dict[TenantLabel, TenantContext] = {}
    seeder: SeederAdapter | None = None
    inventory = EndpointInventory()
    attack_names: tuple[AttackName, ...] = ()
    findings: list[Finding] = []
    invalid_reason: str | None = None
    dry_plan: tuple[str, ...] = ()

    try:
        try:
            inventory = load_inventory(config, client)
        except SpecError as exc:
            invalid_reason = f"could not build an endpoint inventory: {exc}"
            raise _Abort from None

        state.errors.extend(inventory.warnings)

        if opts.dry_run:
            attack_names = config.probe.enabled_attacks(allow_mutation=opts.allow_mutation)
            dry_plan = _plan(config, inventory, attack_names)
            # INVALID, not VALID-with-nothing-in-it. A dry run left
            # invalid_reason unset, so it fell through to the VALID branch and
            # wrote a report with no controls and no findings — which renders,
            # in every format, as an audit that passed.
            invalid_reason = (
                "dry run: no tenants were seeded and no request was sent, so this is a "
                "plan rather than an audit and says nothing about tenant isolation."
            )
            raise _Abort

        seeder = opts.seeder or _resolve_seeder(config, seed_client)
        if seeder is None:
            invalid_reason = (
                "no seeder configured. TenantTrace cannot manufacture ground truth without "
                "one — set [seeder] adapter in your config. See seeders/example_seeder.py."
            )
            raise _Abort

        try:
            for label in (TenantLabel.A, TenantLabel.B):
                tenants[label] = seed_tenant(seeder, label)
        except SeederError as exc:
            invalid_reason = str(exc)
            raise _Abort from None

        sessions = {
            label: TenantSession(
                label=label,
                client=client,
                headers=_headers_for(config, label, tenants[label]),
                limiter=limiter,
                redact=opts.redact,
            )
            for label in (TenantLabel.A, TenantLabel.B)
        }

        # The same client and rate limiter, carrying no credential. Labelled A
        # only because TenantLabel has no "nobody" — nothing reads the label,
        # and it never appears in a finding.
        anonymous = TenantSession(
            label=TenantLabel.A,
            client=client,
            headers={},
            limiter=limiter,
            redact=opts.redact,
        )

        # ---- POSITIVE CONTROLS -------------------------------------------
        # Per tenant. A shared set let one tenant's control ids delete the
        # other tenant's records from every attack, and with per-type integer
        # sequences an application id silently removed an identically numbered
        # table (Baserow).
        control_ids: dict[TenantLabel, set[str]] = {
            TenantLabel.A: set(),
            TenantLabel.B: set(),
        }
        for label in (TenantLabel.A, TenantLabel.B):
            state.controls.append(
                _self_access_control(
                    sessions[label],
                    tenants[label],
                    inventory,
                    control_ids[label],
                    config.tenancy.columns(),
                    config.tenancy.tenant_path_params(),
                )
            )

        # Warn when the seeder left the harness nothing to work with. With one
        # record per kind, control reads and attack reads share an object, and
        # a tenant-less cache can then make a correctly-scoped endpoint look
        # like a plain IDOR (ADR-0008).
        for label, tenant in tenants.items():
            kinds = {record.kind for record in tenant.records}
            thin = sorted(k for k in kinds if tenant.count_of(k) < 2)
            if thin:
                state.errors.append(
                    f"tenant {label.value} has only one record of: {', '.join(thin)}. "
                    "Seed at least two per kind — the harness keeps control reads and "
                    "attack reads on different records, and cannot here."
                )

        if not all(control.passed for control in state.controls):
            invalid_reason = (
                "positive controls failed: a tenant could not read its own seeded data. "
                "Authentication or seeding is broken, so nothing this run observed can be "
                "read as evidence of isolation."
            )
            raise _Abort

        # ---- ATTACKS ------------------------------------------------------
        enabled = config.probe.enabled_attacks(allow_mutation=opts.allow_mutation)
        attack_names = tuple(name for name in _ATTACK_ORDER if name in enabled)
        attacks = build_attacks(attack_names)

        contexts = {
            actor_label: AttackContext(
                config=config,
                inventory=inventory,
                actor=sessions[actor_label],
                victim=sessions[victim_label],
                actor_ctx=tenants[actor_label],
                victim_ctx=tenants[victim_label],
                oracle=TenantOracle(
                    actor=tenants[actor_label],
                    victim=tenants[victim_label],
                    tenant_columns=config.tenancy.columns(),
                ),
                anonymous=anonymous,
                allow_mutation=opts.allow_mutation and config.probe.allow_mutation,
                excluded_ids=frozenset(control_ids[victim_label]),
            )
            for actor_label, victim_label in _DIRECTIONS
        }

        # Attack outermost, direction innermost. Nesting it the other way
        # defeats the ordering guarantee: the first direction's mass-assignment
        # would run before the second direction's aggregate check, so a row
        # this run created could be counted as a row the application leaked.
        # Every read-only attack now finishes, in both directions, before
        # anything writes.
        attempted = 0
        crashed = 0
        for attack in attacks:
            for actor_label, _ in _DIRECTIONS:
                attempted += 1
                try:
                    for result in attack.run(contexts[actor_label]):
                        state.results.append(result)
                        state.endpoints_tested.add(result.endpoint.key)
                except Exception as exc:  # noqa: BLE001 - one attack must not end the run
                    crashed += 1
                    state.errors.append(
                        f"attack {attack.name.value} raised {type(exc).__name__}: {exc}"
                    )

        # A run in which every attack crashed produced no results, and "no
        # results" renders identically to "nothing leaked". One attack failing
        # is a gap worth noting; all of them failing means the audit did not
        # happen, and reporting that as a clean VALID run is the exact failure
        # RunStatus.INVALID exists to prevent.
        if attempted and crashed == attempted:
            invalid_reason = (
                f"every attack module failed ({crashed}/{attempted}). No cross-tenant "
                "access was ever attempted, so this run is not evidence of isolation."
            )
            raise _Abort

        # A target that answers 429 to most of the audit has not refused
        # anything — it has declined to take part. The results still render as
        # a tidy list of attempts, which is precisely why this has to be caught
        # here: a run where the application never decided is indistinguishable
        # from a clean one in every downstream view. Same reasoning as the
        # positive controls, arriving through a different door.
        throttled = sum(1 for r in state.results if r.evidence.response_status in THROTTLE_STATUSES)
        if state.results and throttled / len(state.results) >= THROTTLE_INVALID_RATIO:
            invalid_reason = (
                f"the target throttled {throttled} of {len(state.results)} attempts "
                f"({throttled / len(state.results):.0%}). It never decided whether "
                "these requests were allowed, so this run is not evidence of "
                "isolation. Lower [probe] rate_limit or raise the target's limit "
                "and run again."
            )
            raise _Abort
        if throttled:
            state.errors.append(
                f"{throttled} of {len(state.results)} attempts were throttled (HTTP 429) "
                "and count as neither refused nor leaked"
            )

        # Getting `kind` wrong errors nowhere: the run just degrades to trying
        # a few ids blindly at every endpoint, losing both coverage and
        # confidence, and looks entirely normal in the report. Say it out loud.
        seeded_kinds = {record.kind for tenant in tenants.values() for record in tenant.records}
        endpoint_kinds = {resource_name(endpoint) for endpoint in inventory.objects()} - {""}
        if seeded_kinds and endpoint_kinds and not (seeded_kinds & endpoint_kinds):
            state.errors.append(
                "no seeded record kind matches any endpoint's resource, so every object "
                "endpoint was probed with blindly chosen ids. Seeded "
                f"{sorted(seeded_kinds)}; the API's resources are "
                f"{sorted(endpoint_kinds)[:8]}. See SeederAdapter.seed_records."
            )

        # ---- CONTROLS, AGAIN ---------------------------------------------
        # The controls passing at the start proves the credential worked then.
        # A long audit outlives short-lived tokens — Baserow's live 600
        # seconds, and a run that exceeds that spends its second half being
        # refused for the wrong reason while reporting "refused" as evidence of
        # isolation. Re-asserting at the end costs two requests and turns that
        # from an invisible false-clean into an INVALID run.
        for label in (TenantLabel.A, TenantLabel.B):
            closing = _self_access_control(
                sessions[label],
                tenants[label],
                inventory,
                set(),  # nothing to spend: the attacks are already over
                config.tenancy.columns(),
                config.tenancy.tenant_path_params(),
            )
            closing = closing.model_copy(update={"name": f"{closing.name}:closing"})
            state.controls.append(closing)
            if not closing.passed:
                invalid_reason = (
                    f"tenant {label.value} could no longer read its own data when the run "
                    "finished, although it could at the start. The credential expired or "
                    "was revoked mid-run, so the attempts after that point were refused "
                    "for the wrong reason and are not evidence of isolation."
                )
                raise _Abort

        # A 404 from an endpoint that serves nothing is not a refusal. Done
        # here, after every attack, so the reads it makes cannot warm a cache
        # that a later attack depends on being cold (ADR-0008).
        absent = _reclassify_absent_routes(
            state.results, sessions, tenants, config.tenancy.tenant_path_params()
        )
        if absent:
            state.errors.append(
                f"{count(absent, 'endpoint')} answered 404 for their own tenant too; "
                "those attempts were recorded as inconclusive rather than refused"
            )

        findings = _findings_from(state.results, config)

    except _Abort:
        pass
    finally:
        if seeder is not None and tenants:
            for label, tenant in tenants.items():
                try:
                    seeder.cleanup(dict(tenant.metadata))
                except Exception as exc:  # noqa: BLE001 - cleanup is best effort
                    state.errors.append(
                        f"cleanup for tenant {label.value} failed: {type(exc).__name__}: {exc}"
                    )
        client.close()
        seed_client.close()

    if invalid_reason is not None:
        report = _invalid_report(config, started, state, reason=invalid_reason)
    else:
        report = RunReport(
            tool_version=__version__,
            status=RunStatus.VALID,
            started_at=started,
            finished_at=utcnow(),
            target=config.target.base_url,
            controls=tuple(state.controls),
            findings=tuple(findings),
            results=tuple(state.results),
            endpoints_tested=len(state.endpoints_tested),
            endpoints_discovered=len(inventory),
            attacks_run=attack_names,
            errors=tuple(state.errors),
        )

    # A dry run has nothing to record: no tenant was seeded, no request was
    # sent. Writing an artifact for it put a report.json on disk that `report`
    # and every downstream reader would happily render as a completed audit.
    artifact_dir = (
        None
        if opts.dry_run
        else _write_artifacts(config, opts, report, list(sessions.values()), started)
    )
    return ProbeOutcome(report=report, artifact_dir=artifact_dir, plan=dry_plan)


# Past this share of throttled attempts the run is not an audit, it is a
# rate-limit test. Half is deliberately blunt: the exact number matters far
# less than refusing to call such a run clean.
THROTTLE_INVALID_RATIO = 0.5


class _Abort(Exception):
    """Internal control flow: stop the run but still clean up and report."""


# --------------------------------------------------------------------------- #
# Positive controls
# --------------------------------------------------------------------------- #


def _self_access_control(
    session: TenantSession,
    tenant: TenantContext,
    inventory: EndpointInventory,
    touched: set[str],
    tenant_columns: tuple[str, ...] = ("tenant_id",),
    tenant_path_params: frozenset[str] = frozenset(),
) -> ControlResult:
    """Assert that a tenant can read its own seeded data.

    Two ways to satisfy it, because applications differ: fetching one of the
    tenant's own objects by id, or finding its canary in one of its own
    collections. Either proves the credential works and that the seeding landed
    somewhere the API actually returns.

    Ids read here are collected into ``touched`` and excluded from every
    subsequent attack. See ``AttackContext.excluded_ids`` for why that
    separation matters — in short, a control read can populate a tenant-less
    cache entry and turn a correctly-scoped endpoint into an apparent IDOR.
    This is also why a seeder should create at least two records per kind.
    """
    name = f"self-access:{tenant.label.value}"

    if not session.authenticated:
        return ControlResult(
            name=name,
            passed=False,
            detail=(
                f"no credential resolved for tenant {tenant.label.value}. Check [auth] in "
                "your config, or the headers your seeder returns."
            ),
        )

    markers = [tenant.canary, *(r.canary for r in tenant.records if r.canary)]
    own = TenantOracle(actor=tenant, victim=tenant, tenant_columns=tenant_columns)

    def proves_self_access(exchange: Exchange) -> bool:
        """Did this response actually return data belonging to this tenant?

        A canary is the strongest signal, but plenty of applications have no
        field a caller can write and read back. An ownership column naming this
        tenant proves the same thing, and without it those applications could
        not clear the controls at all — so every run against them would be
        INVALID, which is not the same as untestable.
        """
        facts = exchange.facts()
        return bool(scan_for_markers(facts, markers) or own.owner_fields(facts, tenant))

    for endpoint in inventory.objects():
        ids = candidate_ids(endpoint, tenant)
        if not ids:
            continue
        # Take the LAST id: attacks start from the first, so with two or more
        # seeded records per kind the two never touch the same object.
        identifier = ids[-1]
        # The control is the one caller that knows the tenant for certain — it
        # is the caller's own. It used to be the only caller of build_path that
        # did not pass it, so on an application carrying the tenant in the path
        # every control went to a structurally wrong URL. Three of six real
        # targets are that shape; on Keycloak 418 of 420 control requests 404'd
        # and the run only reached VALID through an unrelated endpoint.
        exchange = session.request(
            endpoint.method,
            build_path(endpoint, identifier, tenant=tenant, tenant_params=tenant_path_params),
            attack="positive-control",
        )
        # ...and the id is spent only once it has actually been read. Marking
        # it before the request burned ids on attempts that returned 403, and
        # those ids are excluded from every later attack — which removed whole
        # record kinds from the attack surface while the report still showed
        # those endpoints as tested and enforced.
        if exchange.ok and proves_self_access(exchange):
            touched.add(identifier)
            return ControlResult(
                name=name,
                passed=True,
                detail=f"tenant {tenant.label.value} read its own object via {endpoint.key}",
                evidence=exchange.evidence(snippet_chars=400),
            )

    for endpoint in inventory.collections():
        exchange = session.request(endpoint.method, endpoint.path, attack="positive-control")
        if exchange.ok and proves_self_access(exchange):
            return ControlResult(
                name=name,
                passed=True,
                detail=f"tenant {tenant.label.value} saw its own data in {endpoint.key}",
                evidence=exchange.evidence(snippet_chars=400),
            )

    return ControlResult(
        name=name,
        passed=False,
        detail=(
            f"tenant {tenant.label.value} could not read back any of its own seeded records. "
            "Either the credential is not being accepted, or the canary was planted in a "
            "field the API never returns."
        ),
    )


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


def _reclassify_absent_routes(
    results: list[ProbeResult],
    sessions: Mapping[TenantLabel, TenantSession],
    tenants: Mapping[TenantLabel, TenantContext],
    tenant_path_params: frozenset[str],
) -> int:
    """Downgrade 404s from endpoints that serve nothing to anyone.

    A 404 is genuinely ambiguous, and this tool's own remediation is why: it
    tells applications to answer 404 rather than 403 for another tenant's
    object so the response does not confirm the id exists. Reading every 404 as
    absence would punish exactly the applications that took the advice.

    So each endpoint that produced a 404-based ENFORCED is asked once, with the
    caller's **own** record: if that 404s too, the route serves nothing here and
    the cross-tenant 404 was never evidence. Teable's
    ``/api/space/{spaceId}/billing`` is not mounted in the community build and
    404s for the space's own owner.

    **This runs after every attack, and that placement is the design.** Asking
    mid-attack means somebody reads an object they own, which populates a
    tenant-less cache entry and hides the cache leak the next attack exists to
    find — the side effect ADR-0008 was written about. Two attempts to put this
    check inside the attack loop were caught by the fixture tests within
    minutes; afterwards, warming a cache can affect nothing.

    Errs towards keeping the enforcement claim: no usable id, or a request that
    could not be made, leaves the result alone.
    """
    suspect = {
        r.endpoint.key: r.endpoint
        for r in results
        if r.verdict is Verdict.ENFORCED and r.evidence.response_status == 404
    }
    if not suspect:
        return 0

    label = TenantLabel.A
    session, tenant = sessions[label], tenants[label]
    absent: set[str] = set()
    for key, endpoint in suspect.items():
        own = candidate_ids(endpoint, tenant)
        if not own:
            continue
        path = build_path(endpoint, own[0], tenant=tenant, tenant_params=tenant_path_params)
        probe = session.request(endpoint.method, path, attack="route-check")
        if probe.transport_error is None and probe.status == 404:
            absent.add(key)

    if not absent:
        return 0

    for index, result in enumerate(results):
        if (
            result.endpoint.key in absent
            and result.verdict is Verdict.ENFORCED
            and result.evidence.response_status == 404
        ):
            results[index] = result.model_copy(
                update={
                    "verdict": Verdict.INCONCLUSIVE,
                    "detail": (
                        "target answered 404, but this endpoint answers 404 for the "
                        "caller's own record too, so the route serves nothing here; "
                        "this is absence, not enforcement"
                    ),
                }
            )
    return len(absent)


def _findings_from(results: Sequence[ProbeResult], config: Config) -> list[Finding]:
    """Turn leaked results into ranked, deduplicated, fingerprinted findings.

    Deduplication is by fingerprint, which means one finding per endpoint and
    category no matter how many ids or which direction proved it. The number of
    corroborating attempts goes into the evidence note instead — a report with
    the same critical repeated eleven times is a report nobody reads to the end.
    """
    by_fingerprint: dict[str, Finding] = {}
    corroborations: dict[str, int] = {}

    for result in results:
        if result.verdict is not Verdict.LEAKED:
            continue

        category = result.category_of()
        location = result.endpoint.key
        finding = with_fingerprint(
            Finding(
                id="TT-0000",
                title=title_for(category, location),
                category=category,
                severity=severity_for(category),
                confidence=Confidence.CONFIRMED,
                engine=Engine.PROBE,
                location=location,
                tags=tags_for(category),
                evidence=result.evidence.model_copy(
                    update={"note": result.detail or result.evidence.note}
                ),
                remediation=remediation_for(
                    category,
                    location=location,
                    model=_model_name(result.endpoint),
                    column=config.tenancy.column,
                ),
            )
        )
        key = finding.fingerprint
        corroborations[key] = corroborations.get(key, 0) + 1
        by_fingerprint.setdefault(key, finding)

    findings: list[Finding] = []
    for key, finding in by_fingerprint.items():
        count = corroborations[key]
        if count > 1:
            note = (finding.evidence.note or "").strip()
            finding = finding.model_copy(
                update={
                    "evidence": finding.evidence.model_copy(
                        update={"note": f"{note} [reproduced {count}×]".strip()}
                    )
                }
            )
        findings.append(finding)

    findings.sort(key=lambda f: f.sort_key)
    return [f.model_copy(update={"id": f"TT-{i:04d}"}) for i, f in enumerate(findings, start=1)]


def _model_name(endpoint: Endpoint) -> str:
    """A plausible model name for the remediation snippet, e.g. ``Invoice``."""
    name = resource_name(endpoint)
    return "".join(part.capitalize() for part in name.split("_")) if name else "Model"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _headers_for(config: Config, label: TenantLabel, tenant: TenantContext) -> dict[str, str]:
    """Resolve a tenant's auth headers.

    Precedence (ADR-0006): the seeder wins. It created the tenant during this
    run, so its credentials are the only ones that can possibly be valid;
    ``[auth]`` is the fallback for targets whose tenants already exist.
    """
    if tenant.headers:
        return dict(tenant.headers)
    return config.auth.headers_for(label)


def _resolve_seeder(config: Config, client: httpx.Client) -> SeederAdapter | None:
    if not config.seeder.adapter:
        return None
    return load_seeder(
        config.seeder.adapter,
        client=client,
        base_url=config.target.base_url,
        config=config,
    )


def _plan(
    config: Config, inventory: EndpointInventory, attack_names: tuple[AttackName, ...]
) -> tuple[str, ...]:
    """What a real run would attempt, endpoint by endpoint, plus a total.

    The total used to count ``(attack, endpoint)`` pairs, which under-reported
    a real run by roughly six times: it ignored the id fan-out per endpoint,
    the cache attack's three-request sequence, that every attack runs in both
    directions, and the positive controls entirely. A dry run exists to size a
    rate limit and a blast radius before pointing this at something real, and a
    number six times too small is worse than no number.

    Still an estimate — the fan-out depends on what the seeder plants, which a
    dry run deliberately does not do. It is labelled as one.
    """
    lines: list[str] = []
    requests = 0
    for attack in attack_names:
        if attack in {AttackName.IDOR, AttackName.CACHE}:
            targets = inventory.objects()
        elif attack is AttackName.MASS_ASSIGN:
            targets = inventory.creators()
        else:
            targets = inventory.collections()
        # Requests one endpoint costs in one direction.
        per_endpoint = {
            AttackName.IDOR: MAX_BLIND_IDS,
            AttackName.CACHE: 3,  # cold, warm, hot
            AttackName.PARAM_OVERRIDE: 1 + len(config.tenancy.columns()),  # baseline + spellings
        }.get(attack, 1)
        for endpoint in targets:
            skipped = config.is_allowlisted(endpoint.path)
            verb = "skip " if skipped else "probe"
            suffix = "  (cross_tenant_allowlist)" if skipped else ""
            lines.append(f"{verb} {attack.value:<15} {endpoint.key}{suffix}")
            if not skipped:
                requests += per_endpoint * len(_DIRECTIONS)

    controls = len(inventory.objects()) * len(_DIRECTIONS)
    lines.append("")
    lines.append(
        f"≈{requests + controls} requests: {requests} attack (both directions, id fan-out "
        f"included) + up to {controls} positive-control. Estimate — the real fan-out "
        "depends on what the seeder plants."
    )
    return tuple(lines)


def _invalid_report(
    config: Config,
    started: datetime,
    state: _RunState,
    *,
    reason: str,
) -> RunReport:
    """Build an INVALID run report.

    An invalid run reports one INFO finding describing the harness failure and
    no isolation findings at all. Emitting "0 findings" without that marker is
    the single output this tool must never produce.
    """
    state.errors.append(reason)
    harness_finding = with_fingerprint(
        Finding(
            id="TT-0000",
            title=f"Run INVALID — {reason.split('.')[0].split(':')[0]}",
            category=Category.HARNESS_ERROR,
            severity=Severity.INFO,
            confidence=Confidence.INCONCLUSIVE,
            engine=Engine.PROBE,
            location=config.target.base_url,
            evidence=Evidence(note=reason),
            remediation=(
                "Fix the harness and re-run. Until the positive controls pass, this run "
                "says nothing about the application's tenant isolation — in particular it "
                "does NOT say the application is clean."
            ),
        )
    )
    return RunReport(
        tool_version=__version__,
        status=RunStatus.INVALID,
        started_at=started,
        finished_at=utcnow(),
        target=config.target.base_url,
        controls=tuple(state.controls),
        findings=(harness_finding,),
        results=tuple(state.results),
        endpoints_tested=len(state.endpoints_tested),
        errors=tuple(state.errors),
    )


def _write_artifacts(
    config: Config,
    opts: ProbeOptions,
    report: RunReport,
    sessions: Sequence[TenantSession],
    started: datetime,
) -> Path | None:
    """Persist the transcript and the machine-readable report."""
    if not opts.write_artifacts:
        return None
    recorder = RunRecorder(config.out_path(), redact=opts.redact, started_at=started)
    for session in sessions:
        recorder.record_all(session.exchanges)
    recorder.write_report(report)
    return recorder.paths.root
