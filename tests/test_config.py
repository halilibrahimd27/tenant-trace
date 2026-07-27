"""Configuration loading, and the safety rails it enforces.

The rails are the reason this file matters more than a normal settings test: a
misconfigured prober does not fail quietly, it sends adversarial traffic at
whatever host it was pointed at.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tenanttrace.core.config import Config, ConfigError, load_config
from tenanttrace.core.models import AttackName, ScopingMode, Severity, TenantLabel

REPO_ROOT = Path(__file__).resolve().parents[1]


def write(tmp_path: Path, body: str, name: str = "tenanttrace.toml") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


MINIMAL = """
[target]
base_url = "http://127.0.0.1:8000"
"""


# --------------------------------------------------------------------------- #
# The shipped example is the contract
# --------------------------------------------------------------------------- #


def test_the_shipped_example_config_parses() -> None:
    """tenanttrace.example.toml documents every key the loader accepts.

    If this fails, the example and the loader have drifted — and the example is
    the only thing most users will read.
    """
    config = load_config(REPO_ROOT / "tenanttrace.example.toml")
    assert config.target.base_url == "http://127.0.0.1:8000"
    assert config.seeder.adapter == "seeders.example_seeder:ExampleSeeder"


@pytest.mark.parametrize(
    "config_file",
    ["fixtures/tenanttrace.vulnerable.toml", "fixtures/tenanttrace.safe.toml"],
)
def test_bundled_fixture_configs_parse(config_file: str) -> None:
    assert load_config(REPO_ROOT / config_file).target.base_url.startswith("http://127.0.0.1")


# --------------------------------------------------------------------------- #
# Error messages
# --------------------------------------------------------------------------- #


def test_missing_file_says_what_to_do(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="tenanttrace.example.toml"):
        load_config(tmp_path / "nope.toml")


def test_invalid_toml_is_reported_as_such(tmp_path: Path) -> None:
    path = write(tmp_path, "[target\nbase_url = 1")
    with pytest.raises(ConfigError, match="not valid TOML"):
        load_config(path)


def test_unknown_key_is_an_error_naming_the_key(tmp_path: Path) -> None:
    """A silently ignored typo is a setting that does nothing for six months."""
    path = write(tmp_path, MINIMAL + "\n[probe]\nmax_rpss = 4\n")
    with pytest.raises(ConfigError, match="max_rpss"):
        load_config(path)


def test_relative_base_url_is_rejected(tmp_path: Path) -> None:
    path = write(tmp_path, '[target]\nbase_url = "127.0.0.1:8000"\n')
    with pytest.raises(ConfigError, match="absolute http"):
        load_config(path)


def test_custom_auth_requires_a_resolver(tmp_path: Path) -> None:
    path = write(tmp_path, MINIMAL + '\n[auth]\nstrategy = "custom"\n')
    with pytest.raises(ConfigError, match="resolver"):
        load_config(path)


def test_seeder_path_must_be_dotted(tmp_path: Path) -> None:
    path = write(tmp_path, MINIMAL + '\n[seeder]\nadapter = "seeders.example_seeder"\n')
    with pytest.raises(ConfigError, match="module.path:ClassName"):
        load_config(path)


# --------------------------------------------------------------------------- #
# Safety rails
# --------------------------------------------------------------------------- #


def test_loopback_target_needs_no_authorization_flag(tmp_path: Path) -> None:
    config = load_config(write(tmp_path, MINIMAL))
    config.check_target_allowed(i_have_authorization=False)


def test_host_outside_the_allowlist_is_refused(tmp_path: Path) -> None:
    body = """
[target]
base_url = "http://192.0.2.10:8000"
allowed_hosts = ["127.0.0.1"]
"""
    config = load_config(write(tmp_path, body))
    with pytest.raises(ConfigError, match="allowed_hosts"):
        config.check_target_allowed(i_have_authorization=True)


def test_non_loopback_target_needs_the_authorization_flag(tmp_path: Path) -> None:
    body = """
[target]
base_url = "https://staging.example.com"
allowed_hosts = ["staging.example.com"]
"""
    config = load_config(write(tmp_path, body))
    with pytest.raises(ConfigError, match="i-have-authorization"):
        config.check_target_allowed(i_have_authorization=False)
    # ...and passes once the operator states it.
    config.check_target_allowed(i_have_authorization=True)


def test_ipv6_loopback_counts_as_loopback(tmp_path: Path) -> None:
    body = """
[target]
base_url = "http://[::1]:8000"
allowed_hosts = ["::1"]
"""
    config = load_config(write(tmp_path, body))
    assert config.target.is_loopback is True
    config.check_target_allowed(i_have_authorization=False)


# --------------------------------------------------------------------------- #
# Mutation gating
# --------------------------------------------------------------------------- #


def test_config_alone_cannot_enable_a_write(tmp_path: Path) -> None:
    """`allow_mutation = true` in a file is necessary but never sufficient."""
    body = MINIMAL + '\n[probe]\nallow_mutation = true\nattacks = ["idor", "mass_assign"]\n'
    config = load_config(write(tmp_path, body))
    assert AttackName.MASS_ASSIGN not in config.probe.enabled_attacks(allow_mutation=False)
    assert AttackName.MASS_ASSIGN in config.probe.enabled_attacks(allow_mutation=True)


def test_command_line_flag_alone_cannot_enable_a_write(tmp_path: Path) -> None:
    body = MINIMAL + '\n[probe]\nallow_mutation = false\nattacks = ["mass_assign"]\n'
    config = load_config(write(tmp_path, body))
    assert config.probe.enabled_attacks(allow_mutation=True) == ()


# --------------------------------------------------------------------------- #
# Allowlisting and tenancy
# --------------------------------------------------------------------------- #


def test_allowlist_supports_globs(tmp_path: Path) -> None:
    body = MINIMAL + '\n[tenancy]\ncross_tenant_allowlist = ["/api/admin/*"]\n'
    config = load_config(write(tmp_path, body))
    assert config.is_allowlisted("/api/admin/all-invoices") is True
    assert config.is_allowlisted("/api/invoices") is False


def test_configured_tenant_column_comes_first(tmp_path: Path) -> None:
    body = MINIMAL + '\n[tenancy]\ncolumn = "org_id"\n'
    config = load_config(write(tmp_path, body))
    assert config.tenancy.columns()[0] == "org_id"
    assert "tenant_id" in config.tenancy.columns()


def test_scoping_mode_auto_defers_to_detection(tmp_path: Path) -> None:
    config = load_config(write(tmp_path, MINIMAL))
    assert config.tenancy.mode is ScopingMode.UNKNOWN


def test_explicit_scoping_mode_is_honoured(tmp_path: Path) -> None:
    body = MINIMAL + '\n[tenancy]\nscoping_mode = "global"\n'
    assert load_config(write(tmp_path, body)).tenancy.mode is ScopingMode.GLOBAL


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #


def test_token_is_read_from_the_environment(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TT_TEST_TOKEN", "s3cret")
    body = MINIMAL + '\n[auth]\ntenant_a = { token_env = "TT_TEST_TOKEN" }\n'
    config = load_config(write(tmp_path, body))
    assert config.auth.headers_for(TenantLabel.A) == {"Authorization": "Bearer s3cret"}


def test_missing_credential_yields_no_headers_rather_than_a_crash(tmp_path: Path) -> None:
    body = MINIMAL + '\n[auth]\ntenant_a = { token_env = "TT_DEFINITELY_UNSET" }\n'
    config = load_config(write(tmp_path, body))
    assert config.auth.headers_for(TenantLabel.A) == {}


def test_header_strategy_uses_the_configured_header(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TT_KEY", "abc")
    body = (
        MINIMAL
        + '\n[auth]\nstrategy = "header"\nheader_name = "X-Api-Key"\n'
        + 'tenant_b = { token_env = "TT_KEY" }\n'
    )
    config = load_config(write(tmp_path, body))
    assert config.auth.headers_for(TenantLabel.B) == {"X-Api-Key": "abc"}


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


def test_fail_on_none_disables_the_gate(tmp_path: Path) -> None:
    body = MINIMAL + '\n[report]\nfail_on = "none"\n'
    assert load_config(write(tmp_path, body)).report.fail_threshold is None


def test_fail_on_maps_to_a_severity(tmp_path: Path) -> None:
    body = MINIMAL + '\n[report]\nfail_on = "medium"\n'
    assert load_config(write(tmp_path, body)).report.fail_threshold is Severity.MEDIUM


def test_out_dir_is_relative_to_the_config_file(tmp_path: Path) -> None:
    """A config in fixtures/ must not write artifacts into the current shell's cwd."""
    nested = tmp_path / "conf"
    nested.mkdir()
    config = load_config(write(nested, MINIMAL))
    assert config.out_path() == nested / ".tenanttrace"


def test_overrides_apply_on_top_of_the_file(tmp_path: Path) -> None:
    config = load_config(
        write(tmp_path, MINIMAL),
        overrides={"target": {"base_url": "http://localhost:9999"}},
    )
    assert config.target.base_url == "http://localhost:9999"


def test_config_is_frozen(tmp_path: Path) -> None:
    config: Config = load_config(write(tmp_path, MINIMAL))
    with pytest.raises(Exception):  # noqa: B017,PT011 - pydantic raises its own error type
        config.target.base_url = "http://evil.example"  # type: ignore[misc]


def test_the_spec_request_can_carry_a_credential(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """Some applications serve their OpenAPI document only to an authenticated
    admin. Without this the inventory comes back empty and the run reports
    nothing rather than saying it could not look."""
    monkeypatch.setenv("TT_SPEC_TOKEN", "s3cret")
    config_file = tmp_path / "t.toml"
    config_file.write_text(
        '[target]\nbase_url = "http://127.0.0.1:8000"\n'
        'spec_headers = { Authorization = "TT_SPEC_TOKEN" }\n',
        encoding="utf-8",
    )
    assert load_config(config_file).target.spec_auth() == {"Authorization": "s3cret"}


def test_a_spec_credential_names_an_env_var_not_a_secret(tmp_path: Path) -> None:
    """A config file gets committed; a token in one is a token in the repo."""
    config_file = tmp_path / "t.toml"
    config_file.write_text(
        '[target]\nbase_url = "http://127.0.0.1:8000"\n'
        'spec_headers = { Authorization = "TT_UNSET_VAR" }\n',
        encoding="utf-8",
    )
    assert load_config(config_file).target.spec_auth() == {}
