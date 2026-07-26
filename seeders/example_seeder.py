"""Worked example of a seeder adapter — the one file you write per target app.

TenantTrace needs three things from your application, and it cannot guess any
of them: how to create a tenant, how to authenticate as one, and how to create
an owned record carrying a canary. Implement those and the rest is automatic.

Register it in tenanttrace.toml:

    [seeder]
    adapter = "seeders.example_seeder:ExampleSeeder"

Fleshed out in Phase 2 alongside the SeederAdapter Protocol.
"""

from __future__ import annotations

from typing import Any

import httpx


class ExampleSeeder:
    """Seeds two isolated tenants into a REST application."""

    def __init__(self, client: httpx.Client, **_: Any) -> None:
        self.client = client
        # Kept so cleanup can still authenticate — see the note there.
        self._tokens: dict[str, str] = {}

    def create_tenant(self, label: str) -> dict[str, Any]:
        """Create a tenant and return whatever identifies it downstream."""
        r = self.client.post("/api/signup", json={"company": f"tt-{label}"})
        r.raise_for_status()
        payload = r.json()
        self._tokens[str(payload["tenant_id"])] = payload["access_token"]
        return {"tenant_id": payload["tenant_id"], "token": payload["access_token"]}

    def auth_headers(self, tenant: dict[str, Any]) -> dict[str, str]:
        """Headers that authenticate a request as this tenant."""
        return {"Authorization": f"Bearer {tenant['token']}"}

    def seed_records(self, tenant: dict[str, Any], canary: str) -> list[dict[str, Any]]:
        """Create records owned by this tenant, each carrying the canary string.

        The canary must land in a field that shows up in API responses —
        a title, name, or description. Return the created objects so the oracle
        knows which ids belong to whom.
        """
        created: list[dict[str, Any]] = []
        headers = self.auth_headers(tenant)
        for i in range(3):
            r = self.client.post(
                "/api/invoices",
                headers=headers,
                json={"title": f"{canary} invoice {i}", "amount": 100 + i},
            )
            r.raise_for_status()
            created.append(r.json())
        return created

    def cleanup(self, tenant: dict[str, Any]) -> None:
        """Remove seeded data. Called even when a run fails.

        ``tenant`` here is the tenant's *metadata*, which deliberately excludes
        credentials so a token cannot reach a run artifact — so this cannot
        call :meth:`auth_headers`, which needs the token. A seeder that has to
        authenticate during cleanup keeps its own record of what it created,
        as this one does.
        """
        tenant_id = str(tenant.get("tenant_id", ""))
        token = self._tokens.get(tenant_id)
        if not token:
            return
        self.client.delete(
            f"/api/tenants/{tenant_id}", headers={"Authorization": f"Bearer {token}"}
        )
