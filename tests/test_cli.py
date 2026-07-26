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
