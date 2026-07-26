"""Request and response shapes, shared verbatim by both fixture apps.

The prober reads these through ``/openapi.json``, so the field names here are
part of the contract with the dynamic engine. A rename is a breaking change.

Input models keep pydantic's default ``extra="ignore"``: an unexpected
``tenant_id`` in a request body is silently dropped rather than rejected. That
is the *correct* behaviour, and it is what makes ``POST /api/documents`` a
negative control — the vulnerable app's ``POST /api/invoices`` has to opt out of
it explicitly to leak.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

__all__ = [
    "CustomerCreate",
    "CustomerOut",
    "DocumentCreate",
    "DocumentOut",
    "HealthOut",
    "InvoiceCreate",
    "InvoiceOut",
    "SignupIn",
    "SignupOut",
    "StatsOut",
]


class _Out(BaseModel):
    """Base for response models read straight off an ORM object."""

    model_config = ConfigDict(from_attributes=True)


class HealthOut(BaseModel):
    """Liveness response. ``app`` tells the two fixtures apart."""

    status: str
    app: str


class SignupIn(BaseModel):
    """Body of ``POST /api/signup``."""

    company: str
    role: Literal["user", "admin"] = "user"


class SignupOut(BaseModel):
    """Everything a caller needs to act as the tenant it just created."""

    tenant_id: str
    user_id: str
    access_token: str


class InvoiceCreate(BaseModel):
    """Body of ``POST /api/invoices``. Ownership is not an input field."""

    title: str
    amount: int = 0


class InvoiceOut(_Out):
    """An invoice as returned by the API."""

    id: str
    title: str
    amount: int
    tenant_id: str
    created_at: datetime


class DocumentCreate(BaseModel):
    """Body of ``POST /api/documents``. Ownership is not an input field."""

    title: str
    body: str = ""


class DocumentOut(_Out):
    """A document as returned by the API."""

    id: str
    title: str
    body: str
    tenant_id: str


class CustomerCreate(BaseModel):
    """Body of ``POST /api/customers``. Ownership is not an input field."""

    name: str
    email: str = ""


class CustomerOut(_Out):
    """A customer as returned by the API."""

    id: str
    name: str
    email: str
    tenant_id: str


class StatsOut(BaseModel):
    """Aggregates over the caller's own data — that is the whole claim."""

    invoice_count: int
    document_count: int
    customer_count: int
    invoice_total: int
