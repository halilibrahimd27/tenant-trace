"""The vulnerable fixture application.

Manual scoping (Mode A): each handler applies its own tenant predicate, and six
of them get it wrong. See ``routes.py`` for the holes and ``fixtures/labels.yaml``
for what the tool is expected to report about each one.

``app`` at module level is what ``fixtures.vulnerable_app.main:app`` in
labels.yaml resolves to, and it is what lets the test suite drive the app
in-process over ``httpx.ASGITransport`` — no server, no Docker, no network
(ADR-0004).

.. warning::

   This application is deliberately insecure and stores real seeded canaries.
   Loopback only.
"""

from __future__ import annotations

from fastapi import FastAPI

from fixtures.cache import Cache, build_cache
from fixtures.common.db import create_database
from fixtures.vulnerable_app.routes import APP_NAME, router

__all__ = ["APP_NAME", "app", "create_app"]

DESCRIPTION = """
TenantTrace fixture with **manual** tenant scoping and six real isolation holes.

Every route below is also present in the safe fixture with identical request and
response shapes; only the scoping differs.
"""


def create_app(*, cache: Cache | None = None) -> FastAPI:
    """Build a fresh application over a private in-memory database.

    Each call gets its own database and its own cache, so a test can take a
    clean instance without tearing anything down — and so a cache-key leak
    proven in one test cannot bleed into the next.

    Args:
        cache: Cache to use. Defaults to :func:`fixtures.cache.build_cache`,
            which is a dict unless ``REDIS_URL`` is set.

    Returns:
        A configured :class:`~fastapi.FastAPI` application.
    """
    app = FastAPI(
        title="TenantTrace fixture — vulnerable",
        description=DESCRIPTION,
        version="0.1.0",
    )
    # Per-instance state, reached through `request.app.state` in the route
    # dependencies: module-level globals would make two apps share one database.
    app.state.session_factory = create_database()
    app.state.cache = cache if cache is not None else build_cache()
    app.include_router(router)
    return app


app = create_app()
