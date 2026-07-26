"""Reporting queries — static-only hole S1.

Nothing in ``routes.py`` imports this module. That is deliberate and it is the
whole point: the prober speaks HTTP, so code with no HTTP surface is invisible
to it by construction. An internal report, a management command, a nightly job —
this is where cross-tenant queries survive a dynamic audit unchanged.

The static engine is expected to flag :func:`monthly_revenue_report` as
``raw_sql_escape`` with ``confidence: suspected``. Suspected is the correct
outcome: nothing here proves the statement is ever executed for a tenant-facing
request, and only the prober can promote a hypothesis to a fact.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session


def monthly_revenue_report(session: Session) -> list[tuple[str, int]]:
    """Total invoiced amount per tenant.

    HOLE S1 (raw_sql_escape) — raw SQL with no tenant predicate. Raw SQL is also
    exactly where a global scoping mechanism stops applying: an ORM event hook
    or ``with_loader_criteria`` never sees this statement, so a reader who knows
    the app "has global scoping" is wrong about this line specifically.

    Args:
        session: An open database session.

    Returns:
        ``(tenant_id, total_amount)`` for every tenant in the database.
    """
    rows = session.execute(text("SELECT tenant_id, SUM(amount) FROM invoices GROUP BY tenant_id"))
    return [(str(row[0]), int(row[1] or 0)) for row in rows]


def revenue_for_tenant(session: Session, tenant_id: str) -> int:
    """Total invoiced amount for one tenant.

    The correct counterpart, in the same module and the same style: the tenant
    is a bound parameter, not string interpolation and not an omission. A static
    engine that flags this one is over-reporting.
    """
    total = session.execute(
        text("SELECT COALESCE(SUM(amount), 0) FROM invoices WHERE tenant_id = :tenant_id"),
        {"tenant_id": tenant_id},
    ).scalar()
    return int(total or 0)
