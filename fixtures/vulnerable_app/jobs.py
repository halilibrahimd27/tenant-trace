"""Background-job dispatch — static-only hole S2.

Nothing in ``routes.py`` imports this module either. Background work is the
blind spot of any HTTP-level audit: the request that enqueues a job can be
perfectly scoped while the worker that runs it has no idea which tenant it is
acting for.

The static engine is expected to flag :func:`enqueue_invoice_export` twice —
``tenantless_job_payload`` for the payload and ``tenantless_cache_key`` for the
key — both ``suspected``.
"""

from __future__ import annotations

import json
from typing import Any

from fixtures.cache import Cache


def enqueue_invoice_export(cache: Cache, invoice_id: str, requested_by: str) -> dict[str, Any]:
    """Queue an invoice export for a worker to pick up.

    HOLE S2 — two related omissions in four lines:

    * the payload carries no tenant, so the worker has to re-derive the scope
      from somewhere else (a default, a global, or nothing at all);
    * the cache key has no tenant component, so two tenants asking to export
      the same id share one entry.

    Args:
        cache: Where the pending job is parked.
        invoice_id: The invoice to export.
        requested_by: User id of the requester.

    Returns:
        The payload that was enqueued.
    """
    payload = {
        "invoice_id": invoice_id,
        "requested_by": requested_by,
    }
    key = f"export:{invoice_id}"
    cache.set(key, json.dumps(payload), ttl_seconds=3600)
    return payload


def export_status(cache: Cache, invoice_id: str) -> dict[str, Any] | None:
    """Read back a pending export, if any. Same tenant-less key, same problem."""
    raw = cache.get(f"export:{invoice_id}")
    if raw is None:
        return None
    return json.loads(raw)
