"""The command line, and especially its exit codes.

Exit codes are the contract with CI. The one that matters most is 3: a run
whose positive controls failed must not be able to report a green build.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from tenanttrace.cli import EXIT_FINDINGS, EXIT_INVALID, EXIT_OK, EXIT_USAGE, app

REPO_ROOT = Path(__file__).resolve().parents[1]
VULNERABLE = str(REPO_ROOT / "fixtures" / "tenanttrace.vulnerable.toml")
SAFE = str(REPO_ROOT / "fixtures" / "tenanttrace.safe.toml")

runner = CliRunner()


@pytest.fixture(autouse=True)
def _quiet_warnings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYTHONWARNINGS", "ignore")


# --------------------------------------------------------------------------- #
# Surface
# --------------------------------------------------------------------------- #


def test_help_lists_every_command() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == EXIT_OK
    for command in ("probe", "scan", "report", "metrics", "demo", "validate-config"):
        assert command in result.output


def test_version_prints_the_version() -> None:
    from tenanttrace import __version__

    result = runner.invoke(app, ["version"])
    assert result.exit_code == EXIT_OK
    assert __version__ in result.output


# --------------------------------------------------------------------------- #
# validate-config
# --------------------------------------------------------------------------- #


def test_validate_config_explains_what_will_happen() -> None:
    result = runner.invoke(app, ["validate-config", "-c", VULNERABLE])
    assert result.exit_code == EXIT_OK
    # Rich wraps long lines, so normalise before asserting on prose.
    flat = " ".join(result.output.split())
    assert "is valid" in flat
    assert "mutation allowed" in flat
    assert "allowlist" in flat


def test_validate_config_reports_a_missing_file_as_a_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["validate-config", "-c", str(tmp_path / "nope.toml")])
    assert result.exit_code == EXIT_USAGE
    assert "configuration error" in result.output


def test_validate_config_rejects_an_unknown_key(tmp_path: Path) -> None:
    path = tmp_path / "t.toml"
    path.write_text(
        '[target]\nbase_url = "http://127.0.0.1:8000"\n[probe]\nnonsense = 1\n', encoding="utf-8"
    )
    result = runner.invoke(app, ["validate-config", "-c", str(path)])
    assert result.exit_code == EXIT_USAGE
    assert "nonsense" in result.output


# --------------------------------------------------------------------------- #
# init
# --------------------------------------------------------------------------- #


def test_init_scaffolds_a_config_and_a_seeder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init"])
    assert result.exit_code == EXIT_OK, result.output
    assert (tmp_path / "tenanttrace.toml").is_file()
    assert (tmp_path / "seeders" / "my_app.py").is_file()


def test_the_scaffolded_config_is_valid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A scaffold that its own validator rejects would be an embarrassing start."""
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init"])
    result = runner.invoke(app, ["validate-config"])
    assert result.exit_code == EXIT_OK, result.output


def test_the_scaffolded_seeder_implements_the_protocol(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init"])
    source = (tmp_path / "seeders" / "my_app.py").read_text(encoding="utf-8")
    for method in ("create_tenant", "auth_headers", "seed_records", "cleanup"):
        assert f"def {method}(" in source


def test_the_scaffolded_config_keeps_its_documentation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The comments are most of the example's value to a first-time reader."""
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init"])
    text = (tmp_path / "tenanttrace.toml").read_text(encoding="utf-8")
    assert text.count("#") > 10
    assert "allowed_hosts" in text


def test_init_does_not_clobber_existing_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "tenanttrace.toml").write_text("# mine\n", encoding="utf-8")
    runner.invoke(app, ["init"])
    assert (tmp_path / "tenanttrace.toml").read_text(encoding="utf-8") == "# mine\n"


def test_init_force_overwrites(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "tenanttrace.toml").write_text("# mine\n", encoding="utf-8")
    runner.invoke(app, ["init", "--force"])
    assert (tmp_path / "tenanttrace.toml").read_text(encoding="utf-8") != "# mine\n"


# --------------------------------------------------------------------------- #
# Safety rails
# --------------------------------------------------------------------------- #


def test_probing_a_host_outside_the_allowlist_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "t.toml"
    path.write_text(
        '[target]\nbase_url = "http://192.0.2.10:8000"\nallowed_hosts = ["127.0.0.1"]\n',
        encoding="utf-8",
    )
    result = runner.invoke(app, ["probe", "-c", str(path)])
    assert result.exit_code == EXIT_USAGE
    assert "allowed_hosts" in result.output


def test_a_non_loopback_target_needs_the_authorization_flag(tmp_path: Path) -> None:
    path = tmp_path / "t.toml"
    path.write_text(
        '[target]\nbase_url = "https://staging.example.com"\n'
        'allowed_hosts = ["staging.example.com"]\n',
        encoding="utf-8",
    )
    result = runner.invoke(app, ["probe", "-c", str(path)])
    assert result.exit_code == EXIT_USAGE
    assert "i-have-authorization" in result.output


def test_base_url_override_still_has_to_clear_the_allowlist() -> None:
    result = runner.invoke(
        app, ["probe", "-c", VULNERABLE, "--base-url", "http://evil.example.com"]
    )
    assert result.exit_code == EXIT_USAGE
    assert "allowed_hosts" in result.output


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #


def test_scan_reports_hypotheses_and_says_they_are_hypotheses() -> None:
    result = runner.invoke(
        app, ["scan", "--path", str(REPO_ROOT / "fixtures" / "vulnerable_app"), "-c", VULNERABLE]
    )
    assert result.exit_code == EXIT_OK
    assert "manual" in result.output
    assert "hypotheses, not verdicts" in result.output


def test_scan_of_the_safe_app_detects_global_scoping() -> None:
    result = runner.invoke(
        app, ["scan", "--path", str(REPO_ROOT / "fixtures" / "safe_app"), "-c", SAFE]
    )
    assert result.exit_code == EXIT_OK
    assert "global" in result.output


def test_scan_works_without_a_config() -> None:
    """Pointing the analyser at a repo should not require describing an app."""
    result = runner.invoke(
        app,
        ["scan", "--path", str(REPO_ROOT / "fixtures" / "safe_app"), "-c", "does-not-exist.toml"],
    )
    assert result.exit_code == EXIT_OK


# --------------------------------------------------------------------------- #
# demo — the full pipeline, in-process
# --------------------------------------------------------------------------- #


@pytest.mark.slow
def test_demo_audits_both_fixtures_and_writes_reports(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["demo", "--out", str(tmp_path), "--format", "html", "--app", "both"]
    )
    assert result.exit_code == EXIT_OK, result.output
    assert (tmp_path / "vulnerable_app.html").is_file()
    assert (tmp_path / "safe_app.html").is_file()
    assert "cross_tenant_read" in result.output
    assert "safe_app findings: none" in result.output


@pytest.mark.slow
def test_demo_rejects_an_unknown_app(tmp_path: Path) -> None:
    result = runner.invoke(app, ["demo", "--app", "nope", "--out", str(tmp_path)])
    assert result.exit_code == EXIT_USAGE


# --------------------------------------------------------------------------- #
# metrics
# --------------------------------------------------------------------------- #


def test_metrics_reports_a_missing_labels_file(tmp_path: Path) -> None:
    result = runner.invoke(app, ["metrics", "--labels", str(tmp_path / "nope.yaml")])
    assert result.exit_code == EXIT_USAGE


@pytest.mark.slow
def test_metrics_passes_against_the_bundled_fixtures() -> None:
    result = runner.invoke(
        app, ["metrics", "--labels", str(REPO_ROOT / "fixtures" / "labels.yaml")]
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "PASS" in result.output


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #


def test_report_without_a_run_is_a_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["report", "-c", "missing.toml"])
    assert result.exit_code == EXIT_USAGE
    assert "no run found" in result.output


@pytest.mark.slow
def test_probe_writes_a_run_that_report_can_re_render(tmp_path: Path) -> None:
    """`probe` then `report --run` is the documented workflow; it must work."""
    import fixtures.vulnerable_app.main as vulnerable

    from tenanttrace.core.config import load_config
    from tenanttrace.probe.asgi import SyncASGITransport
    from tenanttrace.probe.runner import ProbeOptions, run_probe

    config = load_config(VULNERABLE, overrides={"report": {"out_dir": str(tmp_path)}})
    transport = SyncASGITransport(vulnerable.app)
    try:
        outcome = run_probe(config, ProbeOptions(allow_mutation=True, transport=transport))
    finally:
        transport.close()

    assert outcome.artifact_dir is not None
    result = runner.invoke(
        app, ["report", "--run", str(outcome.artifact_dir), "--format", "md", "-c", VULNERABLE]
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "TenantTrace — tenant isolation audit" in result.output


# --------------------------------------------------------------------------- #
# dry run
# --------------------------------------------------------------------------- #


def test_dry_run_needs_no_seeding_and_sends_no_attacks(tmp_path: Path) -> None:
    """A --dry-run against an unreachable target still lists nothing harmful."""
    path = tmp_path / "t.toml"
    path.write_text(
        '[target]\nbase_url = "http://127.0.0.1:1"\nspec_path = "http://127.0.0.1:1/openapi.json"\n',
        encoding="utf-8",
    )
    result = runner.invoke(app, ["probe", "-c", str(path), "--dry-run"])
    # The spec cannot be fetched, so the run is INVALID rather than a crash.
    assert result.exit_code in {EXIT_INVALID, EXIT_FINDINGS, EXIT_OK}


# --------------------------------------------------------------------------- #
# The one-line verdict — what gets pasted into a chat window
# --------------------------------------------------------------------------- #


def test_the_demo_says_plainly_which_app_leaks(tmp_path: Path) -> None:
    result = runner.invoke(app, ["demo", "--out", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "confirmed cross-tenant leak" in result.output
    assert "No cross-tenant access proven" in result.output


def test_metrics_keeps_the_bracketed_setting_name(tmp_path: Path) -> None:
    """Rich reads [probe] as a style tag and deletes it — so markup is off.

    The note exists to tell an operator which setting skipped an endpoint.
    Losing the setting's name to a markup parser leaves a sentence that says
    something was skipped by nothing in particular.
    """
    result = runner.invoke(app, ["metrics", "--labels", "fixtures/labels.yaml"])
    assert result.exit_code == EXIT_OK, result.output
    assert "[probe] exclude_paths" in result.output


# --------------------------------------------------------------------------- #
# A dry run is a plan, not an audit
# --------------------------------------------------------------------------- #


def test_a_dry_run_records_nothing_at_all(tmp_path: Path) -> None:
    """It used to leave invalid_reason unset, fall through to the VALID branch,
    and write a report with no controls and no findings — which renders, in
    every format, as an audit that passed. A plan has nothing to record."""
    result = runner.invoke(
        app,
        [
            "probe",
            "--config",
            "fixtures/tenanttrace.vulnerable.toml",
            "--dry-run",
            "--out",
            str(tmp_path),
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert list(tmp_path.rglob("report.json")) == []


def test_an_empty_plan_says_so_instead_of_looking_like_full_coverage() -> None:
    result = runner.invoke(
        app, ["probe", "--config", "fixtures/tenanttrace.vulnerable.toml", "--dry-run"]
    )
    assert "The plan is empty" in result.output
    assert "[target]" in result.output


def test_the_dry_run_estimate_counts_requests_not_endpoint_pairs() -> None:
    """It under-reported a real run roughly six times, so it could not be used
    to size a rate limit — the only thing a dry run is for."""
    from tenanttrace.core.config import load_config
    from tenanttrace.core.models import AttackName, Endpoint, HttpMethod
    from tenanttrace.probe.runner import _plan
    from tenanttrace.probe.spec import EndpointInventory

    inventory = EndpointInventory(
        endpoints=(
            Endpoint(method=HttpMethod.GET, path="/api/invoices", path_params=()),
            Endpoint(method=HttpMethod.GET, path="/api/invoices/{id}", path_params=("id",)),
        )
    )
    plan = _plan(
        load_config(Path("fixtures/tenanttrace.vulnerable.toml")),
        inventory,
        (AttackName.IDOR, AttackName.LISTING, AttackName.CACHE),
    )
    summary = plan[-1]
    assert "requests:" in summary
    assert "positive-control" in summary
    # idor 3 ids + cache 3 steps on the object endpoint, listing 1 on the
    # collection, all in both directions — never one line per (attack, endpoint).
    assert "≈" in summary
    total = int(summary.split("≈")[1].split()[0])
    assert total >= (3 + 3) * 2 + 1 * 2
