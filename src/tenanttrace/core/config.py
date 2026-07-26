"""``tenanttrace.toml`` loader.

The per-target integration surface. It is small on purpose: if auditing an
application takes two hundred lines of configuration, the tool has failed and
nobody will run it twice.

Validation errors are written for the person holding the config file, not for
the person who wrote the loader — every message names the key, what was wrong
with it, and what a working value looks like.
"""

from __future__ import annotations

import os
import tomllib
from ipaddress import ip_address
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from tenanttrace.core.models import AttackName, ScopingMode, Severity, TenantLabel

__all__ = [
    "AuthConfig",
    "Config",
    "ConfigError",
    "ProbeConfig",
    "ReportConfig",
    "StaticConfig",
    "TargetConfig",
    "TenancyConfig",
    "load_config",
]

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "0.0.0.0"})  # noqa: S104


class ConfigError(Exception):
    """Raised with a message meant to be printed straight to the operator."""


class _Section(BaseModel):
    # extra="forbid" turns a typo into an error naming the key, instead of a
    # setting that silently does nothing for the next six months.
    model_config = ConfigDict(extra="forbid", frozen=True)


class TargetConfig(_Section):
    """What we are auditing, and the guard rails around reaching it."""

    base_url: str
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost")
    spec: Literal["openapi", "har", "postman", "routes"] = "openapi"
    spec_path: str | None = None
    timeout_seconds: float = Field(default=10.0, gt=0, le=300)

    @field_validator("base_url")
    @classmethod
    def _absolute_http_url(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            msg = (
                f"[target] base_url must be an absolute http(s) URL, got {value!r}. "
                'Example: base_url = "http://127.0.0.1:8000"'
            )
            raise ValueError(msg)
        return value.rstrip("/")

    @property
    def host(self) -> str:
        """Hostname of ``base_url``, without the port."""
        return urlsplit(self.base_url).hostname or ""

    @property
    def is_loopback(self) -> bool:
        """True when the target is on this machine.

        Loopback targets are the safe default: probing them cannot reach a
        system somebody else depends on.
        """
        host = self.host
        if host in LOOPBACK_HOSTS:
            return True
        try:
            return ip_address(host).is_loopback
        except ValueError:
            return False

    def host_allowed(self) -> bool:
        """True when the target host appears in ``allowed_hosts``."""
        return self.host in set(self.allowed_hosts)


class TenantAuth(_Section):
    """Where one tenant's credential comes from.

    The value itself never lives in the config file — only the name of the
    environment variable holding it.
    """

    token_env: str | None = None
    token: str | None = None
    cookie_env: str | None = None

    @model_validator(mode="after")
    def _one_source(self) -> TenantAuth:
        if self.token is not None and self.token_env is not None:
            msg = "[auth] give either token_env or token for a tenant, not both"
            raise ValueError(msg)
        return self

    def resolve(self) -> str | None:
        """Read the credential, or return None when it is not configured."""
        if self.token is not None:
            return self.token
        for var in (self.token_env, self.cookie_env):
            if var:
                return os.environ.get(var)
        return None


class AuthConfig(_Section):
    """How the prober authenticates as each tenant.

    Precedence (ADR-0006): when a seeder is configured and returns headers for
    a tenant, the seeder wins. It created the tenant, so it holds the only
    credentials that can exist for it. This section is the fallback for targets
    whose tenants cannot be created through the API.
    """

    strategy: Literal["bearer", "cookie", "header", "custom"] = "bearer"
    header_name: str = "Authorization"
    tenant_a: TenantAuth = Field(default_factory=TenantAuth)
    tenant_b: TenantAuth = Field(default_factory=TenantAuth)
    resolver: str | None = None

    @model_validator(mode="after")
    def _custom_needs_resolver(self) -> AuthConfig:
        if self.strategy == "custom" and not self.resolver:
            msg = (
                '[auth] strategy = "custom" needs a resolver, e.g. '
                'resolver = "seeders.my_app:auth_headers"'
            )
            raise ValueError(msg)
        return self

    def for_label(self, label: TenantLabel) -> TenantAuth:
        return self.tenant_a if label is TenantLabel.A else self.tenant_b

    def headers_for(self, label: TenantLabel) -> dict[str, str]:
        """Build the auth headers for a tenant from configuration alone.

        Returns an empty mapping when no credential is configured — the caller
        decides whether that is fatal, because a seeder may supply them.
        """
        token = self.for_label(label).resolve()
        if not token:
            return {}
        if self.strategy == "bearer":
            return {"Authorization": f"Bearer {token}"}
        if self.strategy == "cookie":
            return {"Cookie": token}
        if self.strategy == "header":
            return {self.header_name: token}
        return {}


class SeederConfig(_Section):
    """Dotted path to the per-application seeder adapter."""

    adapter: str | None = None

    @field_validator("adapter")
    @classmethod
    def _dotted_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if ":" not in value:
            msg = (
                f"[seeder] adapter must be 'module.path:ClassName', got {value!r}. "
                'Example: adapter = "seeders.example_seeder:ExampleSeeder"'
            )
            raise ValueError(msg)
        return value


class TenancyConfig(_Section):
    """What "tenant" means in this application's vocabulary."""

    column: str = "tenant_id"
    candidate_columns: tuple[str, ...] = ("tenant_id", "company_id", "org_id", "account_id")
    scoping_mode: Literal["auto", "manual", "global"] = "auto"
    scoped_models: tuple[str, ...] = ()
    cross_tenant_allowlist: tuple[str, ...] = ()

    @property
    def mode(self) -> ScopingMode:
        """Configured mode, or UNKNOWN when detection should decide."""
        if self.scoping_mode == "manual":
            return ScopingMode.MANUAL
        if self.scoping_mode == "global":
            return ScopingMode.GLOBAL
        return ScopingMode.UNKNOWN

    def columns(self) -> tuple[str, ...]:
        """The configured column first, then the other candidates."""
        rest = tuple(c for c in self.candidate_columns if c != self.column)
        return (self.column, *rest)


class ProbeConfig(_Section):
    """Dynamic-engine behaviour and its safety rails."""

    allow_mutation: bool = False
    max_rps: float = Field(default=10.0, gt=0, le=1000)
    exclude_paths: tuple[str, ...] = ()
    attacks: tuple[AttackName, ...] = (
        AttackName.IDOR,
        AttackName.LISTING,
        AttackName.AGGREGATE,
        AttackName.PARAM_OVERRIDE,
        AttackName.CACHE,
    )
    max_endpoints: int = Field(default=500, gt=0)

    @model_validator(mode="after")
    def _mutating_attacks_need_the_flag(self) -> ProbeConfig:
        # Config alone must never enable a write. --allow-mutation is a
        # decision made at the command line, per run, by a human.
        return self

    def enabled_attacks(self, *, allow_mutation: bool) -> tuple[AttackName, ...]:
        """Attacks to run, with mutating modules dropped unless permitted."""
        permitted = allow_mutation and self.allow_mutation
        return tuple(a for a in self.attacks if permitted or not a.is_mutating)


class StaticConfig(_Section):
    """Static-engine inputs. Everything it emits stays ``suspected``."""

    path: str | None = None
    adapter: Literal["auto", "python_sqlalchemy"] = "auto"
    tenant_sources: tuple[str, ...] = (
        "get_current_tenant",
        "get_tenant_id",
        "current_tenant",
        "request.state.tenant_id",
    )
    jwt_claim: str = "tenant_id"
    exclude_globs: tuple[str, ...] = ("**/migrations/**", "**/tests/**", "**/.venv/**")


class ReportConfig(_Section):
    """Output shape and the CI gate threshold."""

    fail_on: Literal["critical", "high", "medium", "low", "none"] = "high"
    formats: tuple[Literal["json", "md", "html"], ...] = ("json", "md")
    baseline: str | None = ".tenanttrace-baseline.json"
    out_dir: str = ".tenanttrace"
    redact_evidence: bool = True

    @property
    def fail_threshold(self) -> Severity | None:
        """Minimum severity that fails the build, or None to never fail."""
        if self.fail_on == "none":
            return None
        return Severity(self.fail_on)


class Config(BaseModel):
    """A parsed ``tenanttrace.toml``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target: TargetConfig
    auth: AuthConfig = Field(default_factory=AuthConfig)
    seeder: SeederConfig = Field(default_factory=SeederConfig)
    tenancy: TenancyConfig = Field(default_factory=TenancyConfig)
    probe: ProbeConfig = Field(default_factory=ProbeConfig)
    static: StaticConfig = Field(default_factory=StaticConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    source_path: Annotated[Path | None, Field(exclude=True)] = None

    # ----------------------------------------------------------------- rails
    def check_target_allowed(self, *, i_have_authorization: bool) -> None:
        """Enforce CLAUDE.md rule 5 before a single request is sent.

        Two independent gates, because they answer different questions:
        ``allowed_hosts`` answers "did the operator mean to point at this
        host?", and ``--i-have-authorization`` answers "is the operator
        allowed to attack it?". A typo cannot satisfy both.
        """
        if not self.target.host_allowed():
            msg = (
                f"target host {self.target.host!r} is not in [target] allowed_hosts "
                f"{list(self.target.allowed_hosts)}. Add it deliberately — this list "
                "is what stops a copy-pasted config from probing the wrong system."
            )
            raise ConfigError(msg)
        if not self.target.is_loopback and not i_have_authorization:
            msg = (
                f"{self.target.base_url} is not a loopback address. Re-run with "
                "--i-have-authorization to state that you are authorised to test it. "
                "That flag is a statement you are making, not a permission this tool grants."
            )
            raise ConfigError(msg)

    def is_allowlisted(self, path: str) -> bool:
        """True when an endpoint is expected to cross tenants by design."""
        from fnmatch import fnmatch

        return any(fnmatch(path, pattern) for pattern in self.tenancy.cross_tenant_allowlist)

    def out_path(self) -> Path:
        """Directory for run artifacts, resolved relative to the config file."""
        base = self.source_path.parent if self.source_path else Path.cwd()
        return base / self.report.out_dir


def _apply_overrides(raw: dict[str, Any], overrides: dict[str, Any]) -> None:
    """Merge command-line overrides into the parsed file, in place.

    ``base_url`` gets one extra piece of care: an absolute ``spec_path``
    pointing at the *old* base URL is rebased onto the new one. Without that,
    ``--base-url http://app:8000`` moves the probe traffic but leaves the
    OpenAPI fetch aimed at the address in the file, and the run fails with a
    connection error that has nothing to do with the flag the operator used.
    A ``spec_path`` on some other host, or a local file, is left alone — that
    is a deliberate choice somebody made.
    """
    original_base = str((raw.get("target") or {}).get("base_url", "")).rstrip("/")
    new_base = str((overrides.get("target") or {}).get("base_url") or "").rstrip("/")

    for section, values in overrides.items():
        merged = dict(raw.get(section) or {})
        merged.update({k: v for k, v in values.items() if v is not None})
        raw[section] = merged

    if not new_base or new_base == original_base:
        return
    target = raw.get("target") or {}
    spec_path = target.get("spec_path")
    if isinstance(spec_path, str) and original_base and spec_path.startswith(original_base):
        target["spec_path"] = new_base + spec_path[len(original_base) :]
        raw["target"] = target


def _format_validation_error(error: ValidationError, path: Path) -> str:
    lines = [f"{path} is not valid:"]
    for item in error.errors():
        location = ".".join(str(p) for p in item["loc"]) or "<root>"
        lines.append(f"  • {location}: {item['msg']}")
    lines.append(
        "\nCompare against tenanttrace.example.toml, which is kept in sync with the loader."
    )
    return "\n".join(lines)


def load_config(path: str | Path, *, overrides: dict[str, Any] | None = None) -> Config:
    """Read and validate a ``tenanttrace.toml``.

    ``overrides`` applies command-line flags on top of the file, one nested
    dict per section, so ``--allow-mutation`` does not have to be duplicated
    into the config to take effect.
    """
    config_path = Path(path)
    if not config_path.is_file():
        msg = (
            f"config file not found: {config_path}\n"
            "Copy tenanttrace.example.toml to tenanttrace.toml and edit it."
        )
        raise ConfigError(msg)

    try:
        raw: dict[str, Any] = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        msg = f"{config_path} is not valid TOML: {exc}"
        raise ConfigError(msg) from exc

    _apply_overrides(raw, overrides or {})

    raw["source_path"] = config_path
    try:
        return Config.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(_format_validation_error(exc, config_path)) from exc
