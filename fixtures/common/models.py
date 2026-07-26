"""The schema both fixture apps share.

One set of models, two applications: if the vulnerable and the safe app had
different schemas, a difference in findings could always be blamed on the data
model rather than on the scoping. They differ in exactly one dimension — how
queries are scoped — and nothing else.

Primary keys are UUID strings on purpose (ADR-0003): the oracle treats a
victim-owned id appearing in an attacker's response as evidence, and a bare
integer id collides across tenants often enough to make that evidence worthless.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

__all__ = [
    "SCOPED_MODELS",
    "Base",
    "Customer",
    "Document",
    "Invoice",
    "Tenant",
    "TenantScoped",
    "User",
    "new_id",
]


def new_id() -> str:
    """A fresh UUID4 as a string — the id format every model uses."""
    return str(uuid.uuid4())


def _now() -> datetime:
    """Timezone-aware creation timestamp."""
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Declarative base for the fixture schema."""


class TenantScoped:
    """Declarative mixin marking a model as owned by exactly one tenant.

    This is the hook the safe app's global scoping mechanism attaches to: a
    single ``with_loader_criteria(TenantScoped, ...)`` covers every model
    carrying the mixin, so adding a model does not mean remembering to add a
    filter. The vulnerable app carries the same mixin and simply never installs
    the mechanism, which is what "manual scoping" means in practice.
    """

    tenant_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)


class Tenant(Base):
    """A customer organisation. Not itself tenant-scoped — it *is* the tenant."""

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    label: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class User(TenantScoped, Base):
    """A member of one tenant. Only ever looked up through its JWT claims."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="user")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Invoice(TenantScoped, Base):
    """Tenant-owned money record. ``title`` carries the seeder's canary."""

    __tablename__ = "invoices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    amount: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Document(TenantScoped, Base):
    """Tenant-owned text record. ``body`` carries the seeder's canary."""

    __tablename__ = "documents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    body: Mapped[str] = mapped_column(String(2000), nullable=False, default="")


class Customer(TenantScoped, Base):
    """Tenant-owned contact record. ``name`` carries the seeder's canary."""

    __tablename__ = "customers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False, default="")


# The models a cross-tenant audit cares about. Mirrors `scoped_models` in
# tenanttrace.example.toml; `User` is scoped too but holds no probe-visible data.
SCOPED_MODELS: tuple[str, ...] = ("Invoice", "Document", "Customer")
