"""Worked example of a seeder adapter — the one file you write per target app.

TenantTrace needs three things from your application, and it cannot guess any
of them: how to create a tenant, how to authenticate as one, and how to create
an owned record carrying a canary. Implement those and the rest is automatic.

Register it in tenanttrace.toml:

    [seeder]
    adapter = "seeders.example_seeder:ExampleSeeder"

Two details here decide whether the rest of the run works, and both are easy to
get wrong without any error being raised:

* **``tenant_id`` is the tenant's identity as it appears in a URL path.** The
  prober substitutes it into tenant path parameters, so for an API shaped
  ``/api/v1/accounts/{account_id}/…`` it is the account id, and for
  ``/admin/realms/{realm}/…`` the realm *name*. Wrong value, and the canonical
  cross-tenant test never runs.
* **``kind`` must equal the endpoint's resource segment, lowercase and
  singular.** ``/api/invoices/{id}`` wants ``kind="invoice"``. Wrong value, and
  every endpoint silently falls back to trying a few ids blindly.

:class:`~tenanttrace.probe.seeder.SeederClient` is optional — a seeder is
ordinary code and may use httpx directly, a vendor SDK, or a database
connection. It is used here because every seeder written against a real
application hand-rolled the same call/check/decode dance, and because its
failures name the request, the status and what the application actually said.
"""

from __future__ import annotations

from typing import Any

import httpx

from tenanttrace.probe.seeder import SeederClient, unique


class ExampleSeeder:
    """Seeds two isolated tenants into a REST application."""

    def __init__(self, client: httpx.Client, **_: Any) -> None:
        self.api = SeederClient(client)
        # Kept so cleanup can still authenticate — see the note there.
        self._tokens: dict[str, str] = {}

    def create_tenant(self, label: str) -> dict[str, Any]:
        """Create a tenant and return whatever identifies it downstream.

        Declare a ``canary`` keyword argument here as well if the tenant's own
        name is the only writable free text your application has.
        """
        payload = self.api.post(
            "/api/signup",
            json={"company": unique(f"tt-{label}")},
            expect=201,
        )
        tenant_id = str(self.api.field(payload, "tenant_id", "id"))
        token = str(self.api.field(payload, "access_token", "token"))
        self._tokens[tenant_id] = token
        return {"tenant_id": tenant_id, "token": token}

    def auth_headers(self, tenant: dict[str, Any]) -> dict[str, str]:
        """Headers that authenticate a request as this tenant."""
        return {"Authorization": f"Bearer {tenant['token']}"}

    def seed_records(self, tenant: dict[str, Any], canary: str) -> list[dict[str, Any]]:
        """Create records owned by this tenant, each carrying the canary string.

        The canary must land in a field that comes back in API responses — a
        title, name, or description. One stored where the API never returns it
        cannot prove anything.

        Create **at least two records per kind**. The positive control reads one
        of them, and an object a tenant has just read may be sitting in a
        cache keyed without the tenant; probing that same id would then look
        like a plain cross-tenant read on a correctly scoped endpoint
        (ADR-0008). Two records keep the control and the attacks apart.
        """
        api = self.api.with_headers(**self.auth_headers(tenant))
        created: list[dict[str, Any]] = []
        for index in range(3):
            invoice = api.post(
                "/api/invoices",
                json={"title": f"{canary} invoice {index}", "amount": 100 + index},
                expect=201,
            )
            created.append({"kind": "invoice", "id": self.api.field(invoice, "id")})

            # A nested resource cannot be addressed from its own id: declare the
            # parents that lead to it and the prober fills every slot.
            line = api.post(
                f"/api/invoices/{created[-1]['id']}/lines",
                json={"description": f"{canary} line", "amount": 10},
                expect=201,
            )
            created.append(
                {
                    "kind": "line",
                    "id": self.api.field(line, "id"),
                    "path": {"invoice_id": created[-1]["id"]},
                }
            )
        return created

    def cleanup(self, tenant: dict[str, Any]) -> None:
        """Remove what this run created. Called even when the run fails.

        ``tenant`` here is the tenant's *metadata*, which deliberately excludes
        credentials so a token cannot reach a run artifact — so this cannot
        call :meth:`auth_headers`, which needs the token. A seeder that has to
        authenticate during cleanup keeps its own record of what it created, as
        this one does.
        """
        tenant_id = str(tenant.get("tenant_id", ""))
        token = self._tokens.get(tenant_id)
        if not token:
            return
        self.api.with_headers(Authorization=f"Bearer {token}").delete(
            f"/api/tenants/{tenant_id}",
            expect=(200, 204, 404),
        )
