"""Routes for the safe fixture — global scoping (Mode B), correct.

Same paths, same query parameters, same response shapes as the vulnerable
fixture. The difference is what is *absent*: not one handler below contains a
tenant predicate, because the mechanism in ``scoping.py`` applies it to every
ORM SELECT. A handler that repeated the filter would be harmless but would also
defeat the point — Mode B is a claim about what a developer can no longer forget.

Read this file next to ``fixtures/vulnerable_app/routes.py``. The two are meant
to be diffable.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from fixtures.cache import Cache
from fixtures.common.auth import CurrentPrincipal, Principal, issue_token
from fixtures.common.models import Customer, Document, Invoice, Tenant, User, new_id
from fixtures.common.schemas import (
    CustomerCreate,
    CustomerOut,
    DocumentCreate,
    DocumentOut,
    HealthOut,
    InvoiceCreate,
    InvoiceOut,
    SignupIn,
    SignupOut,
    StatsOut,
)
from fixtures.safe_app.scoping import platform_admin_bypass, tenant_scope

APP_NAME = "safe"

router = APIRouter()


# --------------------------------------------------------------------------- #
# Dependencies
# --------------------------------------------------------------------------- #
async def get_session(request: Request, principal: CurrentPrincipal) -> AsyncIterator[Session]:
    """Yield a session already scoped to the caller's tenant.

    This is the only place the tenant is bound to the query layer. Declared
    ``async`` deliberately: FastAPI runs sync dependencies on a worker thread
    with a *copy* of the context, so a :class:`~contextvars.ContextVar` set
    there would not be visible to the handler.
    """
    factory: sessionmaker[Session] = request.app.state.session_factory
    with factory() as session, tenant_scope(principal.tenant_id):
        yield session


async def get_unscoped_session(request: Request) -> AsyncIterator[Session]:
    """Yield an unscoped session for the one route that runs before a tenant exists.

    Used by ``POST /api/signup`` only. It is not a bypass: there is no tenant to
    scope to yet, and the route creates rows rather than reading them.
    """
    factory: sessionmaker[Session] = request.app.state.session_factory
    with factory() as session:
        yield session


async def get_cache(request: Request) -> Cache:
    """Return this app instance's cache."""
    cache: Cache = request.app.state.cache
    return cache


SessionDep = Annotated[Session, Depends(get_session)]
UnscopedSessionDep = Annotated[Session, Depends(get_unscoped_session)]
CacheDep = Annotated[Cache, Depends(get_cache)]


# --------------------------------------------------------------------------- #
# Public
# --------------------------------------------------------------------------- #
@router.get("/health", response_model=HealthOut, operation_id="health", tags=["public"])
async def health() -> HealthOut:
    """Liveness probe. Names the fixture so a run cannot confuse the two apps."""
    return HealthOut(status="ok", app=APP_NAME)


@router.post(
    "/api/signup",
    response_model=SignupOut,
    status_code=status.HTTP_201_CREATED,
    operation_id="signup",
    tags=["public"],
)
async def signup(payload: SignupIn, session: UnscopedSessionDep) -> SignupOut:
    """Create a tenant plus its first user and return a bearer token."""
    tenant = Tenant(id=new_id(), label=payload.company)
    user = User(id=new_id(), tenant_id=tenant.id, role=payload.role)
    session.add_all([tenant, user])
    session.commit()
    token = issue_token(
        Principal(
            user_id=user.id,
            tenant_id=tenant.id,
            tenant_label=tenant.label,
            role=payload.role,
        )
    )
    return SignupOut(tenant_id=tenant.id, user_id=user.id, access_token=token)


# --------------------------------------------------------------------------- #
# Invoices
# --------------------------------------------------------------------------- #
@router.get(
    "/api/invoices",
    response_model=list[InvoiceOut],
    operation_id="list_invoices",
    tags=["invoices"],
)
async def list_invoices(principal: CurrentPrincipal, session: SessionDep) -> list[Invoice]:
    """List the caller's invoices. The scope, not this line, restricts the rows."""
    return list(session.scalars(select(Invoice).order_by(Invoice.created_at)).all())


@router.post(
    "/api/invoices",
    response_model=InvoiceOut,
    status_code=status.HTTP_201_CREATED,
    operation_id="create_invoice",
    tags=["invoices"],
)
async def create_invoice(
    payload: InvoiceCreate,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> Invoice:
    """Create an invoice owned by the caller.

    ``InvoiceCreate`` has no ``tenant_id`` field and unknown keys are dropped,
    so ownership cannot be supplied by the client. Writes are not covered by the
    read scope, which is precisely why the input schema has to be explicit.
    """
    invoice = Invoice(
        id=new_id(),
        title=payload.title,
        amount=payload.amount,
        tenant_id=principal.tenant_id,
    )
    session.add(invoice)
    session.commit()
    return invoice


@router.get(
    "/api/invoices/{invoice_id}",
    response_model=InvoiceOut,
    operation_id="get_invoice",
    tags=["invoices"],
)
async def get_invoice(invoice_id: str, principal: CurrentPrincipal, session: SessionDep) -> Invoice:
    """Fetch one invoice by id.

    Filtering by id alone is safe here: the scope turns the lookup into
    ``(tenant, id)`` before it reaches the database, so another tenant's id
    resolves to nothing and the response is a 404 rather than a 403.
    """
    invoice = session.scalars(select(Invoice).where(Invoice.id == invoice_id)).one_or_none()
    if invoice is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="invoice not found")
    return invoice


@router.delete(
    "/api/invoices/{invoice_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="delete_invoice",
    tags=["invoices"],
)
async def delete_invoice(
    invoice_id: str, principal: CurrentPrincipal, session: SessionDep
) -> Response:
    """Delete one of the caller's invoices."""
    invoice = session.scalars(select(Invoice).where(Invoice.id == invoice_id)).one_or_none()
    if invoice is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="invoice not found")
    session.delete(invoice)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- #
# Documents
# --------------------------------------------------------------------------- #
@router.get(
    "/api/documents",
    response_model=list[DocumentOut],
    operation_id="list_documents",
    tags=["documents"],
)
async def list_documents(principal: CurrentPrincipal, session: SessionDep) -> list[Document]:
    """List the caller's documents."""
    return list(session.scalars(select(Document)).all())


@router.post(
    "/api/documents",
    response_model=DocumentOut,
    status_code=status.HTTP_201_CREATED,
    operation_id="create_document",
    tags=["documents"],
)
async def create_document(
    payload: DocumentCreate,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> Document:
    """Create a document owned by the caller."""
    document = Document(
        id=new_id(),
        title=payload.title,
        body=payload.body,
        tenant_id=principal.tenant_id,
    )
    session.add(document)
    session.commit()
    return document


@router.get(
    "/api/documents/{document_id}",
    response_model=DocumentOut,
    operation_id="get_document",
    tags=["documents"],
)
async def get_document(
    document_id: str,
    principal: CurrentPrincipal,
    session: SessionDep,
    cache: CacheDep,
) -> dict[str, Any]:
    """Fetch one document by id, through a cache.

    The tenant is part of the cache key. A cache entry is a copy of a query
    result, so it has to be keyed by everything the query was scoped by —
    otherwise the cache quietly re-introduces the bug the scope removed.
    """
    key = f"doc:{principal.tenant_id}:{document_id}"
    cached = cache.get(key)
    if cached is not None:
        body: dict[str, Any] = json.loads(cached)
        return body

    document = session.scalars(select(Document).where(Document.id == document_id)).one_or_none()
    if document is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="document not found")

    payload = DocumentOut.model_validate(document).model_dump()
    cache.set(key, json.dumps(payload), ttl_seconds=300)
    return payload


# --------------------------------------------------------------------------- #
# Customers
# --------------------------------------------------------------------------- #
@router.get(
    "/api/customers",
    response_model=list[CustomerOut],
    operation_id="list_customers",
    tags=["customers"],
)
async def list_customers(
    principal: CurrentPrincipal,
    session: SessionDep,
    tenant_id: Annotated[
        str | None,
        Query(description="Accepted for compatibility and ignored; the credential decides."),
    ] = None,
) -> list[Customer]:
    """List the caller's customers.

    The ``tenant_id`` parameter exists so the two fixtures expose an identical
    API surface, and is deliberately unused: an endpoint that accepts a tenant
    from the client and honours it is hole H4 in the other fixture.
    """
    return list(session.scalars(select(Customer)).all())


@router.post(
    "/api/customers",
    response_model=CustomerOut,
    status_code=status.HTTP_201_CREATED,
    operation_id="create_customer",
    tags=["customers"],
)
async def create_customer(
    payload: CustomerCreate,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> Customer:
    """Create a customer owned by the caller."""
    customer = Customer(
        id=new_id(),
        name=payload.name,
        email=payload.email,
        tenant_id=principal.tenant_id,
    )
    session.add(customer)
    session.commit()
    return customer


# --------------------------------------------------------------------------- #
# Stats
# --------------------------------------------------------------------------- #
@router.get("/api/stats", response_model=StatsOut, operation_id="get_stats", tags=["stats"])
async def get_stats(principal: CurrentPrincipal, session: SessionDep) -> StatsOut:
    """Dashboard counters over the caller's own data.

    Aggregates are ORM SELECTs like any other, so the scope reaches them too —
    which is the answer to the usual objection that global scoping covers
    ``select(Model)`` and forgets ``func.count()``.
    """
    invoice_count = session.scalar(select(func.count(Invoice.id))) or 0
    document_count = session.scalar(select(func.count(Document.id))) or 0
    customer_count = session.scalar(select(func.count(Customer.id))) or 0
    invoice_total = session.scalar(select(func.coalesce(func.sum(Invoice.amount), 0))) or 0
    return StatsOut(
        invoice_count=invoice_count,
        document_count=document_count,
        customer_count=customer_count,
        invoice_total=invoice_total,
    )


# --------------------------------------------------------------------------- #
# Platform admin — the one intentional cross-tenant endpoint
# --------------------------------------------------------------------------- #
@router.get(
    "/api/admin/all-invoices",
    response_model=list[InvoiceOut],
    operation_id="admin_all_invoices",
    tags=["admin"],
)
async def admin_all_invoices(principal: CurrentPrincipal, session: SessionDep) -> list[Invoice]:
    """Every tenant's invoices, for platform administrators.

    This endpoint crosses tenants on purpose. It is here so the audit has
    something correct to *not* report: a tool that flags it is crying wolf, and
    an operator who has to triage a known-good finding on every run stops
    reading the report.

    Two things make it defensible rather than a hole: an authorisation check
    that runs before the bypass, and a bypass that is named, narrow, and scoped
    to a single block. It is listed in ``cross_tenant_allowlist`` in
    ``tenanttrace.toml`` and in ``expect_clean`` in ``labels.yaml``.
    """
    if not principal.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin role required")
    with platform_admin_bypass():
        return list(session.scalars(select(Invoice).order_by(Invoice.created_at)).all())
