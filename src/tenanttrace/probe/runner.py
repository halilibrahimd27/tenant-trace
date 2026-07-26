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

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import httpx

from tenanttrace import __version__
from tenanttrace.core.config import Config
from tenanttrace.core.fingerprint import with_fingerprint
from tenanttrace.core.models import (
    ATTACK_CATEGORIES,
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
from tenanttrace.probe.attacks import AttackContext, build_attacks
from tenanttrace.probe.attacks.base import build_path, candidate_ids, resource_name
from tenanttrace.probe.oracle import TenantOracle, scan_for_markers
from tenanttrace.probe.recorder import RunRecorder
from tenanttrace.probe.seeder import SeederAdapter, SeederError, load_seeder, seed_tenant
from tenanttrace.probe.session import RateLimiter, TenantSession, build_client
from tenanttrace.probe.spec import EndpointInventory, SpecError, load_inventory

__all__ = ["ProbeOptions", "ProbeOutcome", "run_probe"]

# Attack ordering. Read-only attacks run first so that a mutating attack cannot
# perturb the counts an aggregate check depends on.
_ATTACK_ORDER: tuple[AttackName, ...] = (
    AttackName.IDOR,
    AttackName.LISTING,
    AttackName.AGGREGATE,
    AttackName.PARAM_OVERRIDE,
    AttackName.CACHE,
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
            state.errors.append("dry run: no attack requests were sent")
            raise _Abort

        seeder = opts.seeder or _resolve_seeder(config, client)
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

        # ---- POSITIVE CONTROLS -------------------------------------------
        control_ids: set[str] = set()
        for label in (TenantLabel.A, TenantLabel.B):
            state.controls.append(
                _self_access_control(sessions[label], tenants[label], inventory, control_ids)
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
                oracle=TenantOracle(actor=tenants[actor_label], victim=tenants[victim_label]),
                allow_mutation=opts.allow_mutation and config.probe.allow_mutation,
                excluded_ids=frozenset(control_ids),
            )
            for actor_label, victim_label in _DIRECTIONS
        }

        # Attack outermost, direction innermost. Nesting it the other way
        # defeats the ordering guarantee: the first direction's mass-assignment
        # would run before the second direction's aggregate check, so a row
        # this run created could be counted as a row the application leaked.
        # Every read-only attack now finishes, in both directions, before
        # anything writes.
        for attack in attacks:
            for actor_label, _ in _DIRECTIONS:
                try:
                    for result in attack.run(contexts[actor_label]):
                        state.results.append(result)
                        state.endpoints_tested.add(result.endpoint.key)
                except Exception as exc:  # noqa: BLE001 - one attack must not end the run
                    state.errors.append(
                        f"attack {attack.name.value} raised {type(exc).__name__}: {exc}"
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

    artifact_dir = _write_artifacts(config, opts, report, list(sessions.values()), started)
    return ProbeOutcome(report=report, artifact_dir=artifact_dir, plan=dry_plan)


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

    for endpoint in inventory.objects():
        ids = candidate_ids(endpoint, tenant)
        if not ids:
            continue
        # Take the LAST id: attacks start from the first, so with two or more
        # seeded records per kind the two never touch the same object.
        identifier = ids[-1]
        touched.add(identifier)
        exchange = session.request(
            endpoint.method, build_path(endpoint, identifier), attack="positive-control"
        )
        if exchange.ok and scan_for_markers(exchange.facts(), markers):
            return ControlResult(
                name=name,
                passed=True,
                detail=f"tenant {tenant.label.value} read its own object via {endpoint.key}",
                evidence=exchange.evidence(snippet_chars=400),
            )

    for endpoint in inventory.collections():
        exchange = session.request(endpoint.method, endpoint.path, attack="positive-control")
        if exchange.ok and scan_for_markers(exchange.facts(), markers):
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

        category = ATTACK_CATEGORIES[result.attack]
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
    """What a real run would attempt, endpoint by endpoint."""
    lines: list[str] = []
    for attack in attack_names:
        if attack in {AttackName.IDOR, AttackName.CACHE}:
            targets = inventory.objects()
        elif attack is AttackName.MASS_ASSIGN:
            targets = inventory.creators()
        else:
            targets = inventory.collections()
        for endpoint in targets:
            verb = "skip " if config.is_allowlisted(endpoint.path) else "probe"
            suffix = "  (cross_tenant_allowlist)" if verb == "skip " else ""
            lines.append(f"{verb} {attack.value:<15} {endpoint.key}{suffix}")
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
            title="Run INVALID — the audit could not be trusted",
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
