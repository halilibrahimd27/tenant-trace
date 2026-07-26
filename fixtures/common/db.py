"""Database bootstrap: one private in-memory SQLite database per application.

ADR-0004 rules out Docker for the default test path, so the apps have to be
drivable in-process. Two details make that work:

* ``StaticPool`` — every connection must be *the same* connection. A normal pool
  hands out fresh connections, and each fresh connection to ``:memory:`` gets
  its own empty database, so the tables would vanish between requests.
* ``check_same_thread=False`` — Starlette may run a handler on a worker thread,
  and SQLite otherwise refuses a connection created on a different one.

Each call to :func:`create_database` produces an isolated database, which is how
a test gets a clean fixture app without tearing anything down.
"""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from fixtures.common.models import Base

__all__ = ["create_database", "create_engine_and_schema"]


def create_engine_and_schema() -> Engine:
    """Create an in-memory SQLite engine with the fixture schema applied."""
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    return engine


def create_database() -> sessionmaker[Session]:
    """Create a fresh database and return a session factory bound to it.

    ``expire_on_commit=False`` so a handler can still read a just-committed
    object's attributes while building its response, without a second SELECT.

    Returns:
        A :class:`sessionmaker` over a private in-memory database.
    """
    return sessionmaker(bind=create_engine_and_schema(), expire_on_commit=False, future=True)
