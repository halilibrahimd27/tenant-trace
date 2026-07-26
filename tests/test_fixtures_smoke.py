"""Proof that the fixtures are real.

Every accuracy number TenantTrace publishes is measured against these two apps,
so "the vulnerable app leaks" and "the safe app does not" cannot be assumptions
documented in a README — they have to be assertions that fail when they stop
being true. This module exploits each labelled hole directly, without going
anywhere near the prober, and asserts the same attack bounces off the safe app.

Everything runs in-process over ``httpx.ASGITransport`` (ADR-0004): no server,
no Docker, no network, no Redis. Each test builds its own app, which means its
own in-memory database and its own cache.
"""

from __future__ import annotations

import ast
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from fastapi import FastAPI
from fixtures.cache import MemoryCache, build_cache
from fixtures.common.db import create_database
from fixtures.common.models import Invoice
from fixtures.safe_app.main import create_app as create_safe_app
from fixtures.vulnerable_app import jobs, reports, routes
from fixtures.vulnerable_app.main import create_app as create_vulnerable_app
from sqlalchemy import select

from tenanttrace.core.models import AttackName, Category, Engine
from tenanttrace.core.severity import severity_for

pytestmark = pytest.mark.anyio

REPO_ROOT = Path(__file__).resolve().parent.parent

AppFactory = Callable[..., FastAPI]

BOTH_APPS = pytest.mark.parametrize(
    "create_app",
    [create_vulnerable_app, create_safe_app],
    ids=["vulnerable", "safe"],
)


@pytest.fixture
def anyio_backend() -> str:
    """Run the async tests on asyncio only; the fixtures have no trio path."""
    return "asyncio"


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #
@asynccontextmanager
async def fixture_client(create_app: AppFactory) -> AsyncIterator[httpx.AsyncClient]:
    """A fresh app — fresh database, fresh cache — plus a client speaking to it.

    Per-test construction is not tidiness: the cache-key leak is a
    first-writer-wins bug, so a cache shared between tests would make the H5
    assertions depend on execution order.
    """
    app = create_app(cache=MemoryCache())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://fixture.invalid",
    ) as client:
        yield client


@dataclass
class Party:
    """One seeded tenant: its credentials, its canary, and what it owns."""

    label: str
    tenant_id: str
    token: str
    canary: str
    invoices: list[dict[str, Any]] = field(default_factory=list)
    documents: list[dict[str, Any]] = field(default_factory=list)
    customers: list[dict[str, Any]] = field(default_factory=list)

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}


async def onboard(
    client: httpx.AsyncClient,
    label: str,
    *,
    role: str = "user",
    invoices: int = 2,
) -> Party:
    """Sign up a tenant and seed it with canary-carrying records.

    The canary lands in ``Invoice.title``, ``Document.body`` and
    ``Customer.name`` — the fields the API contract promises to echo back
    verbatim, which is what makes them usable as an oracle.
    """
    canary = f"tt-canary-{label}-{uuid.uuid4().hex[:12]}"

    response = await client.post("/api/signup", json={"company": f"tt-{label}", "role": role})
    assert response.status_code == 201, response.text
    body = response.json()
    party = Party(
        label=label,
        tenant_id=body["tenant_id"],
        token=body["access_token"],
        canary=canary,
    )

    for index in range(invoices):
        created = await client.post(
            "/api/invoices",
            headers=party.headers,
            json={"title": f"{canary} invoice {index}", "amount": 100 + index},
        )
        assert created.status_code == 201, created.text
        party.invoices.append(created.json())

    created = await client.post(
        "/api/documents",
        headers=party.headers,
        json={"title": f"{label} notes", "body": f"{canary} document body"},
    )
    assert created.status_code == 201, created.text
    party.documents.append(created.json())

    created = await client.post(
        "/api/customers",
        headers=party.headers,
        json={"name": f"{canary} customer", "email": f"{label.lower()}@example.invalid"},
    )
    assert created.status_code == 201, created.text
    party.customers.append(created.json())

    return party


async def two_tenants(client: httpx.AsyncClient) -> tuple[Party, Party]:
    """Seed the attacker (A) and the victim (B)."""
    return await onboard(client, "A"), await onboard(client, "B")


# --------------------------------------------------------------------------- #
# Shape: both apps expose the same API
# --------------------------------------------------------------------------- #
@BOTH_APPS
async def test_health_names_the_fixture(create_app: AppFactory) -> None:
    async with fixture_client(create_app) as client:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert response.json()["app"] in {"vulnerable", "safe"}


@BOTH_APPS
async def test_signup_creates_two_isolated_tenants(create_app: AppFactory) -> None:
    async with fixture_client(create_app) as client:
        alice, bob = await two_tenants(client)

        assert alice.tenant_id != bob.tenant_id
        assert alice.token != bob.token
        assert uuid.UUID(alice.tenant_id) and uuid.UUID(bob.tenant_id)
        assert alice.canary != bob.canary


@BOTH_APPS
async def test_positive_control_self_access(create_app: AppFactory) -> None:
    """A→A must work. A harness that 403s everything reports a clean run.

    This is the control that decides whether every other assertion in this file
    means anything, which is why it runs against both apps.
    """
    async with fixture_client(create_app) as client:
        alice, bob = await two_tenants(client)

        for party in (alice, bob):
            own = party.invoices[0]
            response = await client.get(f"/api/invoices/{own['id']}", headers=party.headers)
            assert response.status_code == 200, response.text
            assert response.json()["id"] == own["id"]
            assert party.canary in response.json()["title"]

            listed = await client.get("/api/invoices", headers=party.headers)
            assert listed.status_code == 200
            assert {row["id"] for row in listed.json()} == {i["id"] for i in party.invoices}


@BOTH_APPS
async def test_api_requires_a_credential(create_app: AppFactory) -> None:
    async with fixture_client(create_app) as client:
        for path in ("/api/invoices", "/api/documents", "/api/customers", "/api/stats"):
            response = await client.get(path)
            assert response.status_code == 401, f"{path} -> {response.status_code}"

        bad = await client.get("/api/invoices", headers={"Authorization": "Bearer not-a-jwt"})
        assert bad.status_code == 401


@BOTH_APPS
async def test_openapi_documents_every_route_uniquely(create_app: AppFactory) -> None:
    """The prober reads the spec, so operation ids have to be unique and stable."""
    async with fixture_client(create_app) as client:
        spec = (await client.get("/openapi.json")).json()

        operation_ids = [
            operation["operationId"]
            for path in spec["paths"].values()
            for operation in path.values()
        ]
        assert len(operation_ids) == len(set(operation_ids)), operation_ids

        for path in ("/api/invoices", "/api/invoices/{invoice_id}", "/api/customers", "/api/stats"):
            assert path in spec["paths"], f"{path} missing from the spec"

        # H4's attack surface is only discoverable if the parameter is documented.
        params = spec["paths"]["/api/customers"]["get"].get("parameters", [])
        assert any(p["name"] == "tenant_id" and p["in"] == "query" for p in params), params


@BOTH_APPS
async def test_apps_do_not_share_state(create_app: AppFactory) -> None:
    """Two instances, two databases. Test isolation depends on this."""
    async with fixture_client(create_app) as first, fixture_client(create_app) as second:
        alice = await onboard(first, "A")
        listed = await second.get("/api/invoices", headers=alice.headers)
        # Same signing secret, so the token verifies — but the row is not there.
        assert listed.status_code == 200
        assert listed.json() == []


# --------------------------------------------------------------------------- #
# vulnerable_app — the holes must be real
# --------------------------------------------------------------------------- #
async def test_h1_cross_tenant_invoice_read() -> None:
    """H1: A fetches B's invoice by id and gets B's canary back."""
    async with fixture_client(create_vulnerable_app) as client:
        alice, bob = await two_tenants(client)
        victim = bob.invoices[0]

        response = await client.get(f"/api/invoices/{victim['id']}", headers=alice.headers)

        assert response.status_code == 200, response.text
        assert bob.canary in response.json()["title"]
        assert response.json()["tenant_id"] == bob.tenant_id


async def test_h2_document_listing_leak() -> None:
    """H2: A's document list contains every tenant's rows."""
    async with fixture_client(create_vulnerable_app) as client:
        alice, bob = await two_tenants(client)

        response = await client.get("/api/documents", headers=alice.headers)

        assert response.status_code == 200
        bodies = " ".join(row["body"] for row in response.json())
        assert bob.canary in bodies
        assert {row["tenant_id"] for row in response.json()} == {alice.tenant_id, bob.tenant_id}


async def test_h3_aggregate_leak() -> None:
    """H3: the counters count rows A does not own."""
    async with fixture_client(create_vulnerable_app) as client:
        alice, bob = await two_tenants(client)

        stats = (await client.get("/api/stats", headers=alice.headers)).json()

        assert stats["invoice_count"] > len(alice.invoices)
        assert stats["invoice_count"] == len(alice.invoices) + len(bob.invoices)
        assert stats["document_count"] == 2
        assert stats["customer_count"] == 2
        own_total = sum(i["amount"] for i in alice.invoices)
        assert stats["invoice_total"] > own_total


async def test_h4_client_supplied_tenant_is_honoured() -> None:
    """H4: one query parameter switches tenants."""
    async with fixture_client(create_vulnerable_app) as client:
        alice, bob = await two_tenants(client)

        leaked = await client.get(
            "/api/customers", params={"tenant_id": bob.tenant_id}, headers=alice.headers
        )
        assert leaked.status_code == 200
        assert any(bob.canary in row["name"] for row in leaked.json())

        # Without the parameter the endpoint looks correct — which is why a
        # single-tenant test suite never catches this one.
        own = await client.get("/api/customers", headers=alice.headers)
        assert all(row["tenant_id"] == alice.tenant_id for row in own.json())


async def test_h5_cache_key_leak_serves_bs_document_to_a() -> None:
    """H5: B warms the entry, A asks for the same id and gets B's document."""
    async with fixture_client(create_vulnerable_app) as client:
        alice, bob = await two_tenants(client)
        victim = bob.documents[0]

        warm = await client.get(f"/api/documents/{victim['id']}", headers=bob.headers)
        assert warm.status_code == 200
        assert bob.canary in warm.json()["body"]

        stolen = await client.get(f"/api/documents/{victim['id']}", headers=alice.headers)

        assert stolen.status_code == 200, stolen.text
        assert bob.canary in stolen.json()["body"]
        assert stolen.json()["tenant_id"] == bob.tenant_id


async def test_h5_the_query_itself_is_correctly_scoped() -> None:
    """H5, the other half: with a cold cache the same request 404s.

    This is what makes the hole worth having. The database query carries a
    correct tenant predicate, so nothing about the handler's SQL is wrong; the
    leak lives entirely in the cache key, and only a dynamic probe that warms
    the entry first can prove it.
    """
    async with fixture_client(create_vulnerable_app) as client:
        alice, bob = await two_tenants(client)
        victim = bob.documents[0]

        cold = await client.get(f"/api/documents/{victim['id']}", headers=alice.headers)

        assert cold.status_code == 404, cold.text


async def test_h6_mass_assignment_writes_into_another_tenant() -> None:
    """H6: a client-supplied tenant_id in the body places the row in B."""
    async with fixture_client(create_vulnerable_app) as client:
        alice, bob = await two_tenants(client)
        planted = f"tt-canary-A-{uuid.uuid4().hex[:12]} planted"

        created = await client.post(
            "/api/invoices",
            headers=alice.headers,
            json={"title": planted, "amount": 999, "tenant_id": bob.tenant_id},
        )

        assert created.status_code == 201, created.text
        assert created.json()["tenant_id"] == bob.tenant_id

        # And it really landed there: B's own correctly-scoped list shows it.
        bobs_view = await client.get("/api/invoices", headers=bob.headers)
        assert planted in [row["title"] for row in bobs_view.json()]


async def test_n1_invoice_list_is_correctly_scoped() -> None:
    """N1: a negative control inside the leaky app. Reporting it is a false positive."""
    async with fixture_client(create_vulnerable_app) as client:
        alice, bob = await two_tenants(client)

        listed = await client.get("/api/invoices", headers=alice.headers)

        assert listed.status_code == 200
        assert bob.canary not in " ".join(row["title"] for row in listed.json())
        assert all(row["tenant_id"] == alice.tenant_id for row in listed.json())


async def test_n3_delete_is_correctly_scoped() -> None:
    """N3: A cannot delete B's invoice, and gets a 404 rather than a 403."""
    async with fixture_client(create_vulnerable_app) as client:
        alice, bob = await two_tenants(client)
        victim = bob.invoices[0]

        denied = await client.delete(f"/api/invoices/{victim['id']}", headers=alice.headers)
        assert denied.status_code == 404

        still_there = await client.get(f"/api/invoices/{victim['id']}", headers=bob.headers)
        assert still_there.status_code == 200

        own = await client.delete(f"/api/invoices/{alice.invoices[0]['id']}", headers=alice.headers)
        assert own.status_code == 204


async def test_vulnerable_app_has_no_admin_endpoint() -> None:
    """The admin route is the safe app's alone; the fixtures must not diverge here."""
    async with fixture_client(create_vulnerable_app) as client:
        alice = await onboard(client, "A")
        response = await client.get("/api/admin/all-invoices", headers=alice.headers)
        assert response.status_code == 404


# --------------------------------------------------------------------------- #
# safe_app — every one of those attacks must fail
# --------------------------------------------------------------------------- #
async def test_safe_app_blocks_cross_tenant_read() -> None:
    async with fixture_client(create_safe_app) as client:
        alice, bob = await two_tenants(client)

        response = await client.get(f"/api/invoices/{bob.invoices[0]['id']}", headers=alice.headers)

        assert response.status_code == 404, response.text


async def test_safe_app_listing_is_scoped() -> None:
    async with fixture_client(create_safe_app) as client:
        alice, bob = await two_tenants(client)

        documents = (await client.get("/api/documents", headers=alice.headers)).json()

        assert [row["id"] for row in documents] == [alice.documents[0]["id"]]
        assert bob.canary not in " ".join(row["body"] for row in documents)


async def test_safe_app_aggregates_within_the_scope() -> None:
    async with fixture_client(create_safe_app) as client:
        alice, _bob = await two_tenants(client)

        stats = (await client.get("/api/stats", headers=alice.headers)).json()

        assert stats["invoice_count"] == len(alice.invoices)
        assert stats["document_count"] == 1
        assert stats["customer_count"] == 1
        assert stats["invoice_total"] == sum(i["amount"] for i in alice.invoices)


async def test_safe_app_ignores_a_client_supplied_tenant() -> None:
    async with fixture_client(create_safe_app) as client:
        alice, bob = await two_tenants(client)

        response = await client.get(
            "/api/customers", params={"tenant_id": bob.tenant_id}, headers=alice.headers
        )

        assert response.status_code == 200
        assert bob.canary not in " ".join(row["name"] for row in response.json())
        assert all(row["tenant_id"] == alice.tenant_id for row in response.json())


async def test_safe_app_cache_key_includes_the_tenant() -> None:
    async with fixture_client(create_safe_app) as client:
        alice, bob = await two_tenants(client)
        victim = bob.documents[0]

        warm = await client.get(f"/api/documents/{victim['id']}", headers=bob.headers)
        assert warm.status_code == 200

        stolen = await client.get(f"/api/documents/{victim['id']}", headers=alice.headers)
        assert stolen.status_code == 404, stolen.text


async def test_safe_app_rejects_mass_assignment() -> None:
    async with fixture_client(create_safe_app) as client:
        alice, bob = await two_tenants(client)
        planted = f"tt-canary-A-{uuid.uuid4().hex[:12]} planted"

        created = await client.post(
            "/api/invoices",
            headers=alice.headers,
            json={"title": planted, "amount": 999, "tenant_id": bob.tenant_id},
        )

        assert created.status_code == 201, created.text
        assert created.json()["tenant_id"] == alice.tenant_id

        bobs_view = await client.get("/api/invoices", headers=bob.headers)
        assert planted not in [row["title"] for row in bobs_view.json()]


async def test_safe_app_delete_is_scoped() -> None:
    async with fixture_client(create_safe_app) as client:
        alice, bob = await two_tenants(client)

        victim = bob.invoices[0]

        denied = await client.delete(f"/api/invoices/{victim['id']}", headers=alice.headers)
        assert denied.status_code == 404

        still_there = await client.get(f"/api/invoices/{victim['id']}", headers=bob.headers)
        assert still_there.status_code == 200


async def test_safe_app_admin_endpoint_crosses_tenants_only_for_admins() -> None:
    """The allowlisted exception: real cross-tenant data, behind a real check."""
    async with fixture_client(create_safe_app) as client:
        alice, bob = await two_tenants(client)
        admin = await onboard(client, "ADM", role="admin", invoices=0)

        forbidden = await client.get("/api/admin/all-invoices", headers=alice.headers)
        assert forbidden.status_code == 403

        allowed = await client.get("/api/admin/all-invoices", headers=admin.headers)
        assert allowed.status_code == 200
        titles = " ".join(row["title"] for row in allowed.json())
        assert alice.canary in titles
        assert bob.canary in titles

        # The bypass is scoped to that one block: the admin's ordinary list is
        # still confined to the admin's own (empty) tenant.
        own = await client.get("/api/invoices", headers=admin.headers)
        assert own.json() == []


# --------------------------------------------------------------------------- #
# Static-only holes: real code, no HTTP surface
# --------------------------------------------------------------------------- #
async def test_static_only_holes_are_unreachable_over_http() -> None:
    """S1 and S2 must stay invisible to the prober — that is what makes them S-cases.

    Checked by reading the import graph rather than by grepping: a mention of
    ``reports`` in a docstring is not a call, and a test that cannot tell the
    difference will eventually be silenced rather than fixed.
    """
    tree = ast.parse(Path(routes.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
            imported.update(f"{node.module}.{alias.name}" for alias in node.names)

    assert not [name for name in imported if name.endswith((".reports", ".jobs"))], imported


async def test_s1_raw_sql_report_really_crosses_tenants() -> None:
    """S1 is a real leak, not a decorative one."""
    factory = create_database()
    with factory() as session:
        session.add_all(
            [
                Invoice(id="inv-a", title="a", amount=10, tenant_id="tenant-a"),
                Invoice(id="inv-b", title="b", amount=25, tenant_id="tenant-b"),
            ]
        )
        session.commit()

        rows = dict(reports.monthly_revenue_report(session))
        assert rows == {"tenant-a": 10, "tenant-b": 25}

        # The correct counterpart in the same module, which must not be flagged.
        assert reports.revenue_for_tenant(session, "tenant-a") == 10


async def test_s2_job_payload_and_cache_key_carry_no_tenant() -> None:
    cache = MemoryCache()

    payload = jobs.enqueue_invoice_export(cache, "inv-1", requested_by="user-1")

    assert set(payload) == {"invoice_id", "requested_by"}
    assert not any("tenant" in key for key in payload)
    assert cache.get("export:inv-1") is not None
    # Any tenant asking about the same invoice id reads the same entry.
    assert jobs.export_status(cache, "inv-1") == payload


# --------------------------------------------------------------------------- #
# labels.yaml — the answer key has to agree with the code and with severity.py
# --------------------------------------------------------------------------- #
def load_labels() -> dict[str, Any]:
    """Parse the answer key."""
    text = (REPO_ROOT / "fixtures" / "labels.yaml").read_text(encoding="utf-8")
    parsed: dict[str, Any] = yaml.safe_load(text)
    return parsed


async def test_labels_agree_with_the_severity_table() -> None:
    """A label that disagrees with severity.py is a bug in the label.

    Severity is a property of the category, decided in one place. Letting the
    answer key carry its own opinion would mean the metrics harness could score
    the tool against a rating the tool does not use.
    """
    labels = load_labels()
    assert labels["version"] == 1

    seen: set[str] = set()
    for target in labels["targets"].values():
        for entry in target["expected"]:
            assert entry["id"] not in seen, f"duplicate label id {entry['id']}"
            seen.add(entry["id"])

            category = Category(entry["category"])
            assert entry["severity"] == severity_for(category).value, entry["id"]

            engine = Engine(entry["engine"])
            if engine is Engine.PROBE:
                AttackName(entry["attack"])
            else:
                # Static entries name a symbol, never an attack module.
                assert "attack" not in entry, entry["id"]


@BOTH_APPS
async def test_labelled_locations_exist(create_app: AppFactory) -> None:
    """Every labelled route is a real route, and safe_app labels all of its own."""
    labels = load_labels()
    async with fixture_client(create_app) as client:
        spec = (await client.get("/openapi.json")).json()
        app_name = (await client.get("/health")).json()["app"]

    served = {
        f"{method.upper()} {path}"
        for path, operations in spec["paths"].items()
        for method in operations
    }
    target = labels["targets"][f"{app_name}_app"]

    for entry in target["expected"]:
        if Engine(entry["engine"]) is Engine.PROBE:
            assert entry["location"] in served, entry
    for entry in target["expect_clean"]:
        if "::" not in entry["location"]:
            assert entry["location"] in served, entry

    if app_name == "safe":
        # safe_app must produce zero findings, so every route it serves is a
        # route the answer key claims is clean. A new route with no label would
        # otherwise silently stop counting against precision.
        declared = {entry["location"] for entry in target["expect_clean"]}
        assert served - declared == set(), sorted(served - declared)


async def test_static_labels_point_at_real_symbols() -> None:
    """Static locations are ``file::symbol`` with no line number (fingerprint rule)."""
    labels = load_labels()
    for target in labels["targets"].values():
        static = [e for e in target["expected"] if Engine(e["engine"]) is Engine.STATIC]
        for entry in static:
            file_part, separator, symbol = entry["location"].partition("::")
            assert separator and symbol, entry["location"]
            assert not any(part.isdigit() for part in entry["location"].split(":"))

            source = (REPO_ROOT / file_part).read_text(encoding="utf-8")
            defined = {
                node.name
                for node in ast.walk(ast.parse(source))
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            }
            assert symbol in defined, f"{symbol} is not defined in {file_part}"


# --------------------------------------------------------------------------- #
# The suite must never need a server
# --------------------------------------------------------------------------- #
async def test_cache_defaults_to_memory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REDIS_URL", raising=False)
    assert isinstance(build_cache(), MemoryCache)


async def test_memory_cache_round_trip() -> None:
    cache = MemoryCache()
    assert cache.get("missing") is None

    cache.set("k", "v")
    assert cache.get("k") == "v"

    cache.delete("k")
    assert cache.get("k") is None

    cache.set("k", "v", ttl_seconds=0)
    assert cache.get("k") is None  # already past its deadline

    cache.set("k", "v")
    cache.clear()
    assert len(cache) == 0


def test_scoping_is_not_leaked_between_apps() -> None:
    """The safe app's ORM hook must not follow a session factory it was not installed on."""
    factory = create_database()
    with factory() as session:
        session.add_all(
            [
                Invoice(id="inv-a", title="a", amount=1, tenant_id="tenant-a"),
                Invoice(id="inv-b", title="b", amount=1, tenant_id="tenant-b"),
            ]
        )
        session.commit()
        assert len(session.scalars(select(Invoice)).all()) == 2
