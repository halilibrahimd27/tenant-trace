"""Global tenant scoping (Mode B) — the mechanism, in one file.

Mode A asks every handler to remember a predicate. Mode B removes the
opportunity to forget: a ``do_orm_execute`` hook attaches
``with_loader_criteria`` to every SELECT touching a model that carries
:class:`~fixtures.common.models.TenantScoped`, using the tenant held in a
:class:`~contextvars.ContextVar` for the current request.

Two consequences matter for a tool auditing this app:

* A handler containing **no** tenant filter is *correct* here, and flagging it
  would be a false positive. That is why the static engine has to know the
  scoping mode before it can say anything — the correct rule is the opposite in
  each mode.
* The mechanism only covers ORM SELECTs. Raw SQL runs outside it, and so does
  anything executed while :func:`platform_admin_bypass` is active. Those are the
  places to look, and they are deliberately few and clearly named.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from sqlalchemy import event
from sqlalchemy.orm import ORMExecuteState, Session, sessionmaker, with_loader_criteria

from fixtures.common.models import TenantScoped

__all__ = [
    "current_tenant",
    "install_tenant_scope",
    "platform_admin_bypass",
    "tenant_scope",
]

# Unset means "no tenant established" — signup and health run that way. The hook
# then adds no criteria at all, rather than defaulting to some tenant: a wrong
# default is worse than no scope, because it looks like it worked.
_current_tenant: ContextVar[str | None] = ContextVar("safe_app_current_tenant", default=None)

# The single, deliberate escape hatch. Named so that grepping for it finds every
# place this application knowingly leaves its own isolation guarantee.
_scope_disabled: ContextVar[bool] = ContextVar("safe_app_scope_disabled", default=False)


def current_tenant() -> str | None:
    """The tenant the current context is scoped to, or ``None`` if unscoped."""
    return _current_tenant.get()


@contextmanager
def tenant_scope(tenant_id: str) -> Iterator[None]:
    """Scope every ORM SELECT in this context to ``tenant_id``.

    Entered by the request dependency, so a handler never has to. Restores the
    previous value on exit, which keeps nesting honest.

    Args:
        tenant_id: The tenant every scoped query is confined to.
    """
    token = _current_tenant.set(tenant_id)
    try:
        yield
    finally:
        _current_tenant.reset(token)


@contextmanager
def platform_admin_bypass() -> Iterator[None]:
    """Run queries outside the tenant scope. Requires an authorisation check.

    The one legitimate cross-tenant path in this application, used by
    ``GET /api/admin/all-invoices``. It is a context manager rather than a flag
    so the bypass cannot outlive the block that asked for it, and it is
    explicitly named so a reviewer — or this tool's static engine — can find
    every occurrence and decide whether each one is intended.
    """
    token = _scope_disabled.set(True)
    try:
        yield
    finally:
        _scope_disabled.reset(token)


def install_tenant_scope(session_factory: sessionmaker[Session]) -> None:
    """Attach the scoping hook to ``session_factory``.

    Registering per factory rather than globally on :class:`~sqlalchemy.orm.Session`
    keeps two application instances independent, which is what lets a test build
    a fresh app without inheriting another app's listeners.

    Args:
        session_factory: The factory whose sessions get scoped.
    """

    @event.listens_for(session_factory, "do_orm_execute")
    def _apply_tenant_criteria(state: ORMExecuteState) -> None:
        # Only SELECTs are filtered. Column and relationship loads are skipped
        # because they refresh an object that has already passed the criteria;
        # re-filtering them breaks lazy loads without adding any protection.
        if not state.is_select or state.is_column_load or state.is_relationship_load:
            return
        if _scope_disabled.get():
            return
        tenant_id = _current_tenant.get()
        if tenant_id is None:
            return

        # `tenant_id` is read *outside* the lambda on purpose. SQLAlchemy caches
        # the lambda and converts its closure variables into bind parameters; a
        # ContextVar lookup written inside the lambda would be evaluated once
        # and then baked into the cached statement for every other tenant.
        state.statement = state.statement.options(
            with_loader_criteria(
                TenantScoped,
                lambda cls: cls.tenant_id == tenant_id,
                include_aliases=True,
            )
        )
