"""The safe fixture application.

Global scoping (Mode B): a ``do_orm_execute`` hook confines every ORM SELECT to
the tenant held in a ``ContextVar``, so no handler carries a tenant predicate
and none can forget one. It is the control in the experiment — a run against it
that reports anything is reporting a false positive, and that number is what
``make metrics`` calls precision.

``app`` at module level is what ``fixtures.safe_app.main:app`` in labels.yaml
resolves to.
"""

from __future__ import annotations

from fastapi import FastAPI

from fixtures.cache import Cache, build_cache
from fixtures.common.db import create_database
from fixtures.safe_app.routes import APP_NAME, router
from fixtures.safe_app.scoping import install_tenant_scope

__all__ = ["APP_NAME", "app", "create_app"]

DESCRIPTION = """
TenantTrace fixture with **global** tenant scoping and no isolation holes.

Identical routes and response shapes to the vulnerable fixture. The one endpoint
that crosses tenants — `GET /api/admin/all-invoices` — requires the admin role
and is expected to be allowlisted rather than reported.
"""


def create_app(*, cache: Cache | None = None) -> FastAPI:
    """Build a fresh application over a private in-memory database.

    Args:
        cache: Cache to use. Defaults to :func:`fixtures.cache.build_cache`,
            which is a dict unless ``REDIS_URL`` is set.

    Returns:
        A configured :class:`~fastapi.FastAPI` application.
    """
    session_factory = create_database()
    # The scope is installed on this factory, not on Session globally, so two
    # app instances in one process cannot inherit each other's listeners.
    install_tenant_scope(session_factory)

    app = FastAPI(
        title="TenantTrace fixture — safe",
        description=DESCRIPTION,
        version="0.1.0",
    )
    app.state.session_factory = session_factory
    app.state.cache = cache if cache is not None else build_cache()
    app.include_router(router)
    return app


app = create_app()
