"""Regressions from the adversarial review of the first shipped version.

Every test here corresponds to a defect that was found by attacking the tool
rather than by reading it, and each one is the kind that a passing fixture
suite happily hides: the fixtures use UUID keys, always load their spec from
the same host, and never crash an attack module.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from tenanttrace.cli import EXIT_OK, EXIT_USAGE, app
from tenanttrace.core.config import ConfigError, load_config
from tenanttrace.core.models import (
    Category,
    Confidence,
    Engine,
    Evidence,
    Finding,
    HttpMethod,
    RunStatus,
    Severity,
    TenantLabel,
    Verdict,
)
from tenanttrace.core.report import render_html, render_markdown
from tenanttrace.probe.asgi import SyncASGITransport
from tenanttrace.probe.oracle import AccessMode, TenantOracle, facts_from_parts
from tenanttrace.probe.runner import ProbeOptions, run_probe
from tenanttrace.probe.session import Exchange
from tests.conftest import make_tenant

REPO_ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


def write_config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "t.toml"
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# The safety rails covered less than they claimed
# --------------------------------------------------------------------------- #


def test_spec_path_host_is_checked_against_the_allowlist(tmp_path: Path) -> None:
    """Fetching a spec is an outbound request, and it skipped both rails."""
    config = load_config(
        write_config(
            tmp_path,
            '[target]\nbase_url = "http://127.0.0.1:8000"\n'
            'allowed_hosts = ["127.0.0.1"]\n'
            'spec_path = "https://evil.example/openapi.json"\n',
        )
    )
    with pytest.raises(ConfigError, match="spec_path host"):
        config.check_target_allowed(i_have_authorization=True)


def test_a_non_loopback_spec_path_needs_authorization(tmp_path: Path) -> None:
    config = load_config(
        write_config(
            tmp_path,
            '[target]\nbase_url = "http://127.0.0.1:8000"\n'
            'allowed_hosts = ["127.0.0.1", "specs.example.com"]\n'
            'spec_path = "https://specs.example.com/openapi.json"\n',
        )
    )
    with pytest.raises(ConfigError, match="i-have-authorization"):
        config.check_target_allowed(i_have_authorization=False)
    config.check_target_allowed(i_have_authorization=True)


def test_probe_traffic_does_not_follow_proxy_environment_variables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An exported HTTPS_PROXY would route credentials somewhere unlisted."""
    from tenanttrace.probe.session import build_client

    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
    config = load_config(write_config(tmp_path, '[target]\nbase_url = "http://127.0.0.1:8000"\n'))
    client = build_client(config)
    try:
        assert client.trust_env is False
    finally:
        client.close()


# --------------------------------------------------------------------------- #
# Ways a run could look clean without being one
# --------------------------------------------------------------------------- #


def test_a_truncated_body_is_never_read_as_enforcement() -> None:
    """The part we did not scan is exactly where the leak would be."""
    oracle = TenantOracle(actor=make_tenant(TenantLabel.A), victim=make_tenant(TenantLabel.B))
    facts = facts_from_parts(status=200, text="x" * (5 * 1024 * 1024))
    assert facts.truncated is True
    decision = oracle.judge(facts, mode=AccessMode.COLLECTION)
    assert decision.verdict is Verdict.INCONCLUSIVE
    assert "scan limit" in decision.reason


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirect_is_not_a_refusal(status: int) -> None:
    """Redirects are not followed, so where they lead is unknown, not refused."""
    oracle = TenantOracle(actor=make_tenant(TenantLabel.A), victim=make_tenant(TenantLabel.B))
    decision = oracle.judge(facts_from_parts(status=status, text=""), mode=AccessMode.OBJECT)
    assert decision.verdict is Verdict.INCONCLUSIVE


def test_a_run_where_every_attack_crashed_is_invalid(
    vulnerable_config, vulnerable_transport: SyncASGITransport
) -> None:  # type: ignore[no-untyped-def]
    """ "No results" renders exactly like "nothing leaked"."""
    import tenanttrace.probe.attacks as attacks_module

    class Exploding:
        name = attacks_module.ATTACKS[next(iter(attacks_module.ATTACKS))].name  # type: ignore[attr-defined]

        def run(self, ctx: Any) -> Any:
            msg = "boom"
            raise RuntimeError(msg)

    original = attacks_module.build_attacks
    try:
        attacks_module.build_attacks = lambda names: (Exploding(),)  # type: ignore[assignment]
        import tenanttrace.probe.runner as runner_module

        runner_module.build_attacks = attacks_module.build_attacks  # type: ignore[assignment]
        report = run_probe(
            vulnerable_config,
            ProbeOptions(transport=vulnerable_transport, write_artifacts=False),
        ).report
    finally:
        attacks_module.build_attacks = original  # type: ignore[assignment]
        import tenanttrace.probe.runner as runner_module

        runner_module.build_attacks = original  # type: ignore[assignment]

    assert report.status is RunStatus.INVALID
    assert any("every attack module failed" in e for e in report.errors)


def test_the_invalid_banner_states_the_actual_reason() -> None:
    """It always blamed the positive controls, whatever had really happened."""
    from tenanttrace.core.models import RunReport, utcnow

    report = RunReport(
        tool_version="0.1.0",
        status=RunStatus.INVALID,
        started_at=utcnow(),
        findings=(
            Finding(
                id="TT-0000",
                title="Run INVALID",
                category=Category.HARNESS_ERROR,
                severity=Severity.INFO,
                confidence=Confidence.INCONCLUSIVE,
                engine=Engine.PROBE,
                location="http://127.0.0.1:8000",
                evidence=Evidence(note="could not build an endpoint inventory: connection refused"),
            ),
        ),
    )
    for rendered in (render_markdown(report), render_html(report)):
        assert "could not build an endpoint inventory" in rendered
        assert "positive controls failed" not in rendered


# --------------------------------------------------------------------------- #
# Wiring the docs promised
# --------------------------------------------------------------------------- #


def test_fail_on_can_be_overridden_from_the_command_line(tmp_path: Path) -> None:
    """The Action declared this input and never passed it anywhere."""
    config = load_config(
        write_config(tmp_path, '[target]\nbase_url = "http://127.0.0.1:8000"\n'),
        overrides={"report": {"fail_on": "critical"}},
    )
    assert config.report.fail_on == "critical"


def test_probe_correlates_the_static_pass_when_a_source_tree_is_configured(
    vulnerable_config, vulnerable_transport: SyncASGITransport
) -> None:  # type: ignore[no-untyped-def]
    """The correlated finding the README sells was unreachable from the CLI."""
    from tenanttrace.cli import _correlate_with_static

    report = run_probe(
        vulnerable_config,
        ProbeOptions(allow_mutation=True, transport=vulnerable_transport, write_artifacts=False),
    ).report
    merged = _correlate_with_static(report, vulnerable_config, None)

    engines = {f.engine for f in merged.findings}
    assert Engine.CORRELATED in engines
    correlated = next(f for f in merged.findings if f.engine is Engine.CORRELATED)
    assert correlated.related, "a correlated finding must name the source it came from"
    assert correlated.evidence.file


def test_summary_never_prints_response_bodies(tmp_path: Path) -> None:
    """A job summary and a PR comment are public on a public repository."""
    from tenanttrace.core.models import RunReport, utcnow

    canary = "tt-canary-B-0123456789abcdef"
    report = RunReport(
        tool_version="0.1.0",
        status=RunStatus.VALID,
        started_at=utcnow(),
        findings=(
            Finding(
                id="TT-0001",
                title="Cross-tenant read",
                category=Category.CROSS_TENANT_READ,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                engine=Engine.PROBE,
                location="GET /api/invoices/{id}",
                evidence=Evidence(
                    response_snippet=f'{{"title": "{canary}", "ssn": "111-22-3333"}}',
                    matched_canary=canary,
                    request_headers={"Authorization": "Bearer eyJsecret"},
                ),
            ),
        ),
    )
    run_dir = tmp_path / "runs" / "20260101T000000Z"
    run_dir.mkdir(parents=True)
    from tenanttrace.core.report import render_json

    (run_dir / "report.json").write_text(render_json(report), encoding="utf-8")

    result = runner.invoke(app, ["summary", "--run", str(run_dir), "-c", "missing.toml"])
    assert result.exit_code == EXIT_OK, result.output
    assert "111-22-3333" not in result.output
    assert "eyJsecret" not in result.output
    assert canary not in result.output
    # ...but it must still be actionable.
    assert "GET /api/invoices/{id}" in result.output
    assert "critical" in result.output


def test_summary_reports_an_invalid_run_as_invalid(tmp_path: Path) -> None:
    from tenanttrace.core.models import RunReport, utcnow
    from tenanttrace.core.report import render_json

    report = RunReport(
        tool_version="0.1.0",
        status=RunStatus.INVALID,
        started_at=utcnow(),
        findings=(
            Finding(
                id="TT-0000",
                title="Run INVALID",
                category=Category.HARNESS_ERROR,
                severity=Severity.INFO,
                confidence=Confidence.INCONCLUSIVE,
                engine=Engine.PROBE,
                location="http://127.0.0.1:8000",
                evidence=Evidence(note="the seeder planted no records"),
            ),
        ),
    )
    run_dir = tmp_path / "runs" / "20260101T000000Z"
    run_dir.mkdir(parents=True)
    (run_dir / "report.json").write_text(render_json(report), encoding="utf-8")

    result = runner.invoke(app, ["summary", "--run", str(run_dir), "-c", "missing.toml"])
    assert "RUN INVALID" in result.output
    assert "the seeder planted no records" in result.output


def test_summary_without_a_run_is_a_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(app, ["summary", "-c", "missing.toml"]).exit_code == EXIT_USAGE


# --------------------------------------------------------------------------- #
# Measurement
# --------------------------------------------------------------------------- #


def test_a_correlated_finding_satisfies_a_static_label() -> None:
    """The gate failed exactly when the correlator did its job."""
    from tenanttrace.metrics import Label, score_findings

    finding = Finding(
        id="TT-0001",
        title="raw sql",
        category=Category.RAW_SQL_ESCAPE,
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        engine=Engine.CORRELATED,
        location="GET /api/stats",
        related=("app/reports.py::monthly",),
    )
    label = Label(
        id="X-01",
        location="app/reports.py::monthly",
        category="raw_sql_escape",
        severity="high",
        engine="static",
    )
    score = score_findings("t", [finding], [label], [])
    assert score.recall == 1.0
    assert not score.missed


# --------------------------------------------------------------------------- #
# The documented seeder has to work
# --------------------------------------------------------------------------- #


def test_the_example_seeder_cleanup_does_not_raise() -> None:
    """It is the file the README tells people to copy."""
    import httpx
    from seeders.example_seeder import ExampleSeeder

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.path == "/api/signup":
            return httpx.Response(
                201, json={"tenant_id": "t-1", "access_token": "tok", "user_id": "u-1"}
            )
        return httpx.Response(204)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://x.invalid")
    seeder = ExampleSeeder(client)
    tenant = seeder.create_tenant("A")
    # The runner hands cleanup the tenant's *metadata*, without credentials.
    seeder.cleanup({"tenant_id": tenant["tenant_id"]})
    client.close()
    assert any("/api/tenants/t-1" in url for url in calls)


def test_a_thin_seeder_is_warned_about_not_silently_tolerated(
    vulnerable_config, vulnerable_transport: SyncASGITransport
) -> None:  # type: ignore[no-untyped-def]
    """One record per kind makes control reads and attack reads collide."""

    class ThinSeeder:
        def __init__(self, client: Any, **_: Any) -> None:
            from fixtures.seeder import FixtureSeeder

            self._real = FixtureSeeder(client)

        def create_tenant(self, label: str) -> dict[str, Any]:
            return self._real.create_tenant(label)

        def auth_headers(self, tenant: dict[str, Any]) -> dict[str, str]:
            return self._real.auth_headers(tenant)

        def seed_records(self, tenant: dict[str, Any], canary: str) -> list[dict[str, Any]]:
            records = self._real.seed_records(tenant, canary)
            return [next(r for r in records if r["kind"] == "invoice")]

        def cleanup(self, tenant: dict[str, Any]) -> None:
            return None

    from tenanttrace.probe.session import build_client

    client = build_client(vulnerable_config, transport=vulnerable_transport)
    try:
        report = run_probe(
            vulnerable_config,
            ProbeOptions(
                transport=vulnerable_transport,
                write_artifacts=False,
                seeder=ThinSeeder(client),  # type: ignore[arg-type]
            ),
        ).report
    finally:
        client.close()

    assert any("only one record of" in e for e in report.errors), report.errors
    # ...and the endpoint is still probed rather than silently skipped.
    assert any(f.category is Category.CROSS_TENANT_READ for f in report.findings)


def test_json_report_still_round_trips_after_the_changes(tmp_path: Path) -> None:
    from tenanttrace.core.models import RunReport, utcnow
    from tenanttrace.core.report import read_report, render_json

    report = RunReport(tool_version="0.1.0", status=RunStatus.VALID, started_at=utcnow())
    assert read_report(render_json(report)).status is RunStatus.VALID


def test_makefile_targets_reference_files_that_exist() -> None:
    """`make fixtures-up` pointed at a compose file that had moved."""
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    recipes = [
        line
        for line in makefile.splitlines()
        if line.startswith("\t") and not line.lstrip().startswith("#")
    ]
    for line in recipes:
        assert "fixtures/docker-compose.yml" not in line, line
    assert (REPO_ROOT / "docker-compose.yml").is_file()


def test_the_action_has_no_unterminated_heredocs() -> None:
    """An indented `PY` never terminates a `<<'PY'` heredoc."""
    action = (REPO_ROOT / "action.yml").read_text(encoding="utf-8")
    opened = [
        line
        for line in action.splitlines()
        if "<<'PY'" in line and not line.lstrip().startswith("#")
    ]
    assert not opened, f"embedded heredocs are fragile here; call the CLI instead: {opened}"


def test_the_action_passes_fail_on_to_the_cli() -> None:
    action = (REPO_ROOT / "action.yml").read_text(encoding="utf-8")
    assert "--fail-on" in action


def test_the_action_publishes_only_the_safe_summary() -> None:
    action = (REPO_ROOT / "action.yml").read_text(encoding="utf-8")
    assert "tenanttrace summary" in action
    assert "report --format md" not in action, "the full report carries response bodies"


def test_release_workflow_builds_the_runtime_target() -> None:
    """Without `target`, Docker builds the last stage — the vulnerable one."""
    workflow = json.dumps(
        __import__("yaml").safe_load((REPO_ROOT / ".github/workflows/release.yml").read_text())
    )
    assert '"target": "runtime"' in workflow


# --------------------------------------------------------------------------- #
# Static engine
# --------------------------------------------------------------------------- #


def _parse(name: str, source: str):  # type: ignore[no-untyped-def]
    import ast as ast_module

    from tenanttrace.static.base import ParsedFile

    return ParsedFile(path=Path(name), rel_path=name, source=source, tree=ast_module.parse(source))


def test_a_naming_convention_alone_never_decides_global_scoping() -> None:
    """Deciding GLOBAL switches off the missing-filter rule entirely.

    Mixin evidence was emitted once per file, so five well-named model modules
    reached the threshold on names alone and silenced every unscoped query.
    """
    from tenanttrace.core.models import ScopingMode
    from tenanttrace.static.scoping import detect_scoping

    convention = [
        _parse(f"models/m{i}.py", f"class M{i}(Base, TenantScoped):\n    pass\n") for i in range(6)
    ]
    convention.append(
        _parse("ctx.py", 'from contextvars import ContextVar\ncur = ContextVar("current_tenant")\n')
    )
    assert detect_scoping(convention).mode is not ScopingMode.GLOBAL

    with_mechanism = [
        *convention,
        _parse(
            "scope.py",
            "def install(s):\n"
            "    s.add(with_loader_criteria(TenantScoped, lambda c: c.tenant_id == 1))\n",
        ),
    ]
    assert detect_scoping(with_mechanism).mode is ScopingMode.GLOBAL


def _scan_source(tmp_path: Path, source: str, **tenancy: Any):  # type: ignore[no-untyped-def]
    from tenanttrace.core.config import Config, TargetConfig, TenancyConfig
    from tenanttrace.static.engine import scan

    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    config = Config(
        target=TargetConfig(base_url="http://127.0.0.1"),
        tenancy=TenancyConfig(scoping_mode="manual", **tenancy),
    )
    return scan(tmp_path, config)


def test_qualified_model_references_are_seen(tmp_path: Path) -> None:
    """`from app import models` is half of real SQLAlchemy codebases."""
    result = _scan_source(
        tmp_path,
        "from sqlalchemy import select\n"
        "from app import models\n\n"
        "def listing(session):\n"
        "    return session.scalars(select(models.Invoice)).all()\n\n"
        "def detail(session, invoice_id):\n"
        "    return session.get(models.Invoice, invoice_id)\n",
        scoped_models=("Invoice",),
    )
    symbols = {f.location.split("::")[-1] for f in result.findings}
    assert {"listing", "detail"} <= symbols, result.findings


def test_a_reused_statement_variable_keeps_each_querys_own_predicate(tmp_path: Path) -> None:
    """The exit-state map made a later reuse erase an earlier predicate."""
    result = _scan_source(
        tmp_path,
        "from sqlalchemy import select\n\n"
        "def two_queries(session, principal):\n"
        "    stmt = select(Invoice).where(Invoice.tenant_id == principal.tenant_id)\n"
        "    first = session.scalars(stmt).all()\n"
        "    stmt = select(Invoice).where(Invoice.tenant_id == principal.tenant_id)\n"
        "    return first, session.scalars(stmt).all()\n",
        scoped_models=("Invoice",),
    )
    assert result.findings == (), [f.location for f in result.findings]


def test_a_reused_payload_variable_does_not_hide_a_tenantless_dispatch(tmp_path: Path) -> None:
    """The later payload carried a tenant and covered for the earlier one."""
    result = _scan_source(
        tmp_path,
        "def enqueue_two(queue, invoice_id, tenant_id):\n"
        '    payload = {"invoice_id": invoice_id}\n'
        "    queue.publish(payload)\n"
        '    payload = {"invoice_id": invoice_id, "tenant_id": tenant_id}\n'
        "    queue.publish(payload)\n",
    )
    categories = [f.category for f in result.findings]
    assert Category.TENANTLESS_JOB_PAYLOAD in categories, [
        f.category.value for f in result.findings
    ]


def test_the_landing_page_tags_match_the_severity_table() -> None:
    """The site listed a CWE the code does not assign."""
    from tenanttrace.core.models import Category
    from tenanttrace.core.severity import tags_for

    page = (REPO_ROOT / "docs/site/index.html").read_text(encoding="utf-8")
    for category in (
        Category.TENANTLESS_JOB_PAYLOAD,
        Category.CACHE_KEY_LEAK,
        Category.CROSS_TENANT_READ,
    ):
        cwe = next(tag for tag in tags_for(category) if tag.startswith("CWE-"))
        assert cwe in page, f"{category.value} is tagged {cwe}, which the page does not mention"


def test_the_landing_page_does_not_promise_totals() -> None:
    """The aggregate oracle judges counts and deliberately never totals."""
    page = (REPO_ROOT / "docs/site/index.html").read_text(encoding="utf-8")
    assert "counts and totals reach past" not in page


# --------------------------------------------------------------------------- #
# From the first real-world target (a Spring Boot app, per-user ownership)
# --------------------------------------------------------------------------- #


def test_an_ownership_field_proves_a_leak_without_a_canary() -> None:
    """Plenty of applications offer no writable text field and no entropy in ids.

    Before this signal existed, those applications could not be audited at all:
    the positive controls could never pass, so every run was INVALID.
    """
    from tenanttrace.probe.oracle import TenantOracle

    actor = make_tenant(TenantLabel.A, tenant_id="2", record_ids=("1",))
    victim = make_tenant(TenantLabel.B, tenant_id="3", record_ids=("2",))
    oracle = TenantOracle(actor=actor, victim=victim, tenant_columns=("user_id",))

    body = json.dumps([{"id": 7, "userId": 3, "action": "USER_LOGIN"}])
    decision = oracle.judge(facts_from_parts(status=200, text=body), mode=AccessMode.COLLECTION)
    assert decision.verdict is Verdict.LEAKED
    assert decision.matched_ids == ("userId=3",)


def test_an_unrelated_numeric_field_is_not_an_ownership_field() -> None:
    """`{"amount": 3}` is not evidence that tenant 3 owns anything."""
    from tenanttrace.probe.oracle import TenantOracle

    oracle = TenantOracle(
        actor=make_tenant(TenantLabel.A, tenant_id="2"),
        victim=make_tenant(TenantLabel.B, tenant_id="3"),
        tenant_columns=("user_id",),
    )
    body = json.dumps([{"id": 7, "amount": 3, "quantity": 3}])
    decision = oracle.judge(facts_from_parts(status=200, text=body), mode=AccessMode.COLLECTION)
    assert decision.verdict is Verdict.ENFORCED


def test_a_shared_directory_is_not_a_leak(
    vulnerable_config, vulnerable_transport: SyncASGITransport
) -> None:  # type: ignore[no-untyped-def]
    """The false positive the first real target produced.

    A company-wide expert directory carries `userId` on every row because that
    is *who the expert is*, not who owns the row. Both tenants are served the
    same list, so nothing crossed a boundary — and only the differential can
    tell that apart from a genuine listing leak.
    """
    from tenanttrace.probe.attacks.listing import _is_ownership_only, _same_payload
    from tenanttrace.probe.oracle import OracleDecision

    ownership_only = OracleDecision(
        verdict=Verdict.LEAKED, reason="…", matched_ids=("userId=3",), matched_canary=None
    )
    canary_backed = OracleDecision(
        verdict=Verdict.LEAKED, reason="…", matched_canary="tt-canary-B-0123456789abcdef"
    )
    assert _is_ownership_only(ownership_only) is True
    # A canary-backed finding must never be downgraded by the differential.
    assert _is_ownership_only(canary_backed) is False

    shared = json.dumps([{"id": 8, "userId": 8}, {"id": 3, "userId": 3}])
    left = Exchange(
        label=TenantLabel.A,
        method=HttpMethod.GET,
        url="http://x/api/experts",
        status=200,
        request_headers={},
        request_body=None,
        response_text=shared,
        elapsed_ms=1.0,
    )
    right = dataclasses.replace(left, label=TenantLabel.B)
    assert _same_payload(left, right) is True
    assert _same_payload(left, dataclasses.replace(left, response_text="[]")) is False
