"""Shared test fixtures.

Everything here runs in-process: the fixture applications are driven over a
synchronous ASGI transport, so the suite needs no server, no port, no Redis and
no Docker (ADR-0004).
"""

from __future__ import annotations

import importlib
from collections.abc import Iterator
from pathlib import Path

import pytest

from tenanttrace.core.config import Config, load_config
from tenanttrace.core.models import SeededRecord, TenantContext, TenantLabel
from tenanttrace.probe.asgi import SyncASGITransport

REPO_ROOT = Path(__file__).resolve().parents[1]
VULNERABLE_CONFIG = REPO_ROOT / "fixtures" / "tenanttrace.vulnerable.toml"
SAFE_CONFIG = REPO_ROOT / "fixtures" / "tenanttrace.safe.toml"


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    """Async tests in this suite run on asyncio only."""
    return "asyncio"


def _fresh_app(module_name: str):  # type: ignore[no-untyped-def]
    """Import a fixture app with a clean database.

    Reloading the module rather than reusing the imported one matters: the
    fixture apps hold an in-memory SQLite database at module scope, so two
    tests sharing the import would share seeded rows and the second one would
    be measuring the first one's leftovers.
    """
    module = importlib.import_module(module_name)
    module = importlib.reload(module)
    return module.app


@pytest.fixture
def vulnerable_transport() -> Iterator[SyncASGITransport]:
    """A transport bound to a fresh copy of the deliberately leaky app."""
    transport = SyncASGITransport(_fresh_app("fixtures.vulnerable_app.main"))
    try:
        yield transport
    finally:
        transport.close()


@pytest.fixture
def safe_transport() -> Iterator[SyncASGITransport]:
    """A transport bound to a fresh copy of the correctly isolated app."""
    transport = SyncASGITransport(_fresh_app("fixtures.safe_app.main"))
    try:
        yield transport
    finally:
        transport.close()


@pytest.fixture
def vulnerable_config() -> Config:
    return load_config(VULNERABLE_CONFIG)


@pytest.fixture
def safe_config() -> Config:
    return load_config(SAFE_CONFIG)


def make_tenant(
    label: TenantLabel,
    *,
    canary: str | None = None,
    tenant_id: str | None = None,
    record_ids: tuple[str, ...] = ("id-1", "id-2"),
    kind: str = "invoice",
) -> TenantContext:
    """Build a TenantContext without touching an application."""
    resolved_canary = canary or f"tt-canary-{label.value}-deadbeefcafe0001"
    return TenantContext(
        label=label,
        tenant_id=tenant_id or f"tenant-{label.value.lower()}",
        canary=resolved_canary,
        headers={"Authorization": f"Bearer token-{label.value}"},
        records=tuple(
            SeededRecord(kind=kind, id=rid, canary=resolved_canary, owner=label)
            for rid in record_ids
        ),
    )


@pytest.fixture
def tenant_a() -> TenantContext:
    return make_tenant(TenantLabel.A, record_ids=("a-1", "a-2", "a-3"))


@pytest.fixture
def tenant_b() -> TenantContext:
    return make_tenant(TenantLabel.B, record_ids=("b-1", "b-2", "b-3"))
