"""Seeder adapter for the bundled fixture applications.

This is the reference implementation of the ``SeederAdapter`` protocol and the
one the project's own accuracy measurements run against. It is about as long as
a seeder for a real application should be — if yours is much longer, something
that belongs in your application's test helpers has leaked into it.

Note the token bookkeeping: ``cleanup`` receives the tenant's *metadata*, which
deliberately excludes credentials so that tokens cannot reach a run artifact.
A seeder that needs to authenticate during cleanup therefore keeps its own
record of what it created, as this one does.
"""

from __future__ import annotations

from typing import Any

import httpx


class FixtureSeeder:
    """Creates two tenants and plants canaries through the public API.

    Everything goes through HTTP rather than the database, on purpose: it
    exercises the same path a real user would, so a seeded record is one the
    application genuinely accepted.
    """

    # How many records of each kind. Small enough to keep runs fast, more than
    # one so an aggregate check has something to be wrong about.
    INVOICES = 3
    DOCUMENTS = 2
    CUSTOMERS = 2

    def __init__(self, client: httpx.Client, **_: Any) -> None:
        self.client = client
        self._tokens: dict[str, str] = {}
        self._created: dict[str, list[tuple[str, str]]] = {}

    # ------------------------------------------------------------------ #
    def create_tenant(self, label: str) -> dict[str, Any]:
        """Sign up a fresh tenant and remember its token for cleanup."""
        response = self.client.post("/api/signup", json={"company": f"tenanttrace-{label}"})
        response.raise_for_status()
        payload = response.json()
        tenant_id = str(payload["tenant_id"])
        self._tokens[tenant_id] = payload["access_token"]
        self._created[tenant_id] = []
        return {
            "tenant_id": tenant_id,
            "user_id": payload.get("user_id"),
            "label": label,
            "access_token": payload["access_token"],
        }

    def auth_headers(self, tenant: dict[str, Any]) -> dict[str, str]:
        """Bearer token for this tenant."""
        token = tenant.get("access_token") or self._tokens.get(str(tenant.get("tenant_id")), "")
        return {"Authorization": f"Bearer {token}"}

    def seed_records(self, tenant: dict[str, Any], canary: str) -> list[dict[str, Any]]:
        """Create records carrying the canary in a field the API returns.

        Each kind puts the canary in a different field — title, body, name —
        because a leak through a text field the API happens not to serialise
        would otherwise look like isolation.
        """
        headers = self.auth_headers(tenant)
        tenant_id = str(tenant["tenant_id"])
        records: list[dict[str, Any]] = []

        for index in range(self.INVOICES):
            created = self._create(
                "/api/invoices",
                headers,
                {"title": f"{canary} invoice {index}", "amount": 100 + index},
            )
            records.append({**created, "kind": "invoice", "canary": canary})
            self._created[tenant_id].append(("invoice", str(created["id"])))

        for index in range(self.DOCUMENTS):
            created = self._create(
                "/api/documents",
                headers,
                {"title": f"Document {index}", "body": f"{canary} document body {index}"},
            )
            records.append({**created, "kind": "document", "canary": canary})
            self._created[tenant_id].append(("document", str(created["id"])))

        for index in range(self.CUSTOMERS):
            created = self._create(
                "/api/customers",
                headers,
                {"name": f"{canary} customer {index}", "email": f"c{index}@example.invalid"},
            )
            records.append({**created, "kind": "customer", "canary": canary})
            self._created[tenant_id].append(("customer", str(created["id"])))

        return records

    def cleanup(self, tenant: dict[str, Any]) -> None:
        """Delete what this run created, as far as the API allows.

        The fixture API only exposes a delete route for invoices. Anything else
        stays, which is the honest outcome for most real applications too — a
        seeder can only clean up what the application lets it.
        """
        tenant_id = str(tenant.get("tenant_id", ""))
        token = self._tokens.get(tenant_id)
        if not token:
            return
        headers = {"Authorization": f"Bearer {token}"}
        for kind, record_id in reversed(self._created.get(tenant_id, [])):
            if kind != "invoice":
                continue
            try:
                self.client.delete(f"/api/invoices/{record_id}", headers=headers)
            except httpx.HTTPError:  # pragma: no cover - cleanup is best effort
                continue

    # ------------------------------------------------------------------ #
    def _create(self, path: str, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        response = self.client.post(path, headers=headers, json=body)
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
        return payload
