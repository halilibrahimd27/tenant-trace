"""Everything the two fixture apps share: schema, auth, response shapes, DB.

Only the *scoping* differs between the apps. Keeping the rest identical is what
makes a difference in TenantTrace's output attributable to the scoping and to
nothing else.
"""

from __future__ import annotations

from fixtures.common.auth import CurrentPrincipal, Principal, current_principal, issue_token
from fixtures.common.db import create_database
from fixtures.common.models import (
    SCOPED_MODELS,
    Base,
    Customer,
    Document,
    Invoice,
    Tenant,
    TenantScoped,
    User,
    new_id,
)
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

__all__ = [
    "SCOPED_MODELS",
    "Base",
    "CurrentPrincipal",
    "Customer",
    "CustomerCreate",
    "CustomerOut",
    "Document",
    "DocumentCreate",
    "DocumentOut",
    "HealthOut",
    "Invoice",
    "InvoiceCreate",
    "InvoiceOut",
    "Principal",
    "SignupIn",
    "SignupOut",
    "StatsOut",
    "Tenant",
    "TenantScoped",
    "User",
    "create_database",
    "current_principal",
    "issue_token",
    "new_id",
]
