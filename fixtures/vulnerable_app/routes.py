"""Routes for the vulnerable fixture — manual scoping (Mode A), done imperfectly.

Every handler is responsible for its own tenant predicate. Most of them
remember. The ones that do not are the labelled holes H1..H6 in
``fixtures/labels.yaml``; the ones that do are the negative controls N1..N3,
which exist so that "the tool reported this endpoint" is information rather than
noise.

Each hole is written the way it actually happens: nobody sets out to write a
cross-tenant read, they write ``session.get(Model, id)`` because that is the
obvious thing to type. Read the ``HOLE`` comments as bug reports, not as
explanations of a demo.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, inspect, select
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
    InvoiceOut,
    SignupIn,
    SignupOut,
    StatsOut,
)

APP_NAME = "vulnerable"

router = APIRouter()


# --------------------------------------------------------------------------- #
# Dependencies
# --------------------------------------------------------------------------- #
async def get_session(request: Request) -> AsyncIterator[Session]:
    """Yield a session from the factory this app instance was built with."""
    factory: sessionmaker[Session] = request.app.state.session_factory
    with factory() as session:
        yield session


async def get_cache(request: Request) -> Cache:
    """Return this app instance's cache."""
    cache: Cache = request.app.state.cache
    return cache


SessionDep = Annotated[Session, Depends(get_session)]
CacheDep = Annotated[Cache, Depends(get_cache)]


class InvoiceCreateLoose(BaseModel):
    """Body of ``POST /api/invoices`` — and hole H6.

    ``extra="allow"`` is the mass-assignment bug in miniature: the schema
    documents ``title`` and ``amount``, but every other key the client sends
    survives validation and reaches the model constructor.
    """

    model_config = ConfigDict(extra="allow")

    title: str
    amount: int = 0


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
async def signup(payload: SignupIn, session: SessionDep) -> SignupOut:
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
    """List the caller's invoices.

    N1 — negative control. Correctly scoped; must never be reported.
    """
    stmt = (
        select(Invoice).where(Invoice.tenant_id == principal.tenant_id).order_by(Invoice.created_at)
    )
    return list(session.scalars(stmt).all())


@router.post(
    "/api/invoices",
    response_model=InvoiceOut,
    status_code=status.HTTP_201_CREATED,
    operation_id="create_invoice",
    tags=["invoices"],
)
async def create_invoice(
    payload: InvoiceCreateLoose,
    principal: CurrentPrincipal,
    session: SessionDep,
) -> Invoice:
    """Create an invoice.

    HOLE H6 (cross_tenant_write, MUTATING) — the handler binds whatever the
    body contained onto the model and only *defaults* ``tenant_id`` to the
    caller's. A client that sends ``tenant_id`` writes into another tenant.
    """
    fields: dict[str, Any] = payload.model_dump()
    # Keeping only real column names is what makes the bug survive contact with
    # a fuzzer instead of 500-ing; it does nothing to stop the cross-tenant write.
    columns = {attr.key for attr in inspect(Invoice).mapper.column_attrs}
    bound = {key: value for key, value in fields.items() if key in columns}
    bound.setdefault("id", new_id())
    bound.setdefault("tenant_id", principal.tenant_id)

    invoice = Invoice(**bound)
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

    HOLE H1 (cross_tenant_read) — ``Session.get`` resolves the primary key and
    nothing else, so identity here is the id alone rather than (tenant, id).
    Any tenant holding a valid id reads the record.
    """
    invoice = session.get(Invoice, invoice_id)
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
    """Delete one of the caller's invoices.

    N3 — negative control. Scoped lookup, 404 for another tenant's id, so the
    response does not even confirm that the id exists.
    """
    stmt = select(Invoice).where(
        Invoice.id == invoice_id,
        Invoice.tenant_id == principal.tenant_id,
    )
    invoice = session.scalars(stmt).one_or_none()
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
    """List documents.

    HOLE H2 (listing_leak) — no tenant predicate, so this returns every
    tenant's rows. A listing leak is worse than an object leak: the caller does
    not even have to guess an id.
    """
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
    """Create a document owned by the caller.

    N2 — negative control. ``DocumentCreate`` has no ``tenant_id`` field and
    ignores unknown keys, so ownership comes from the credential only.
    """
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

    HOLE H5 (cache_key_leak) — the *query* below is correct: it is scoped, and
    it returns 404 for another tenant's document. The leak is entirely in the
    key. ``doc:{id}`` has no tenant component and the cache is consulted before
    the query runs, so whichever tenant warms the entry first serves it to
    everyone who asks for that id afterwards.

    This is the case a code review passes and a load test hides: the leak is
    intermittent and depends on who arrives first.
    """
    key = f"doc:{document_id}"
    cached = cache.get(key)
    if cached is not None:
        body: dict[str, Any] = json.loads(cached)
        return body

    stmt = select(Document).where(
        Document.id == document_id,
        Document.tenant_id == principal.tenant_id,
    )
    document = session.scalars(stmt).one_or_none()
    if document is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="document not found")

    payload = DocumentOut.model_validate(document).model_dump()
    # Only successful lookups are cached — a 404 never poisons the entry.
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
        Query(description="Tenant to list customers for. Defaults to the caller's tenant."),
    ] = None,
) -> list[Customer]:
    """List customers.

    HOLE H4 (param_override) — a query parameter outranks the credential. The
    fallback to ``principal.tenant_id`` is why this looks fine in a
    single-tenant test suite: nothing fails until somebody passes the parameter.
    """
    scope = tenant_id or principal.tenant_id
    stmt = select(Customer).where(Customer.tenant_id == scope)
    return list(session.scalars(stmt).all())


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
    """Create a customer owned by the caller. Ownership is not client input."""
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
    """Dashboard counters.

    HOLE H3 (aggregate_leak) — every aggregate runs over the whole table. No
    row content crosses the boundary, but the counts disclose other tenants'
    volume, and it is the same missing predicate that leaks rows elsewhere.
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
