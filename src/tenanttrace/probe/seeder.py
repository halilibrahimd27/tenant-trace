"""The per-application integration point: teaching TenantTrace to plant data.

TenantTrace cannot guess how your application creates a tenant, authenticates
one, or creates an owned record — those are the three things every application
does differently and no specification describes. So you write them once, in
about thirty lines, and everything else is automatic.

That seeding step is also what makes the oracle exact. Because we planted the
canaries, a match is a fact rather than an inference (ADR-0003).

**Trust boundary.** ``[seeder] adapter`` is a dotted path that this module
imports, which is code execution by design: the seeder has to be able to call
your application's own helpers. It is your code, named in your config file, and
TenantTrace makes no attempt to sandbox it — pretending otherwise would be
worse than saying it plainly. Never point this at a module you did not write.
See THREAT_MODEL.md.
"""

from __future__ import annotations

import importlib
from collections.abc import Mapping, Sequence
from typing import Any, Protocol, runtime_checkable

from tenanttrace._importing import ensure_cwd_importable
from tenanttrace.core.models import SeededRecord, TenantContext, TenantLabel
from tenanttrace.probe.oracle import make_canary

__all__ = [
    "SeederAdapter",
    "SeederError",
    "load_seeder",
    "normalize_records",
    "seed_tenant",
]


class SeederError(Exception):
    """Seeding failed. The run cannot continue: there is no ground truth."""


@runtime_checkable
class SeederAdapter(Protocol):
    """What TenantTrace needs from your application.

    Implement these four methods and the rest of the tool works. A worked
    example lives in ``seeders/example_seeder.py``.
    """

    def create_tenant(self, label: str) -> Mapping[str, Any]:
        """Create a fresh tenant and return whatever identifies it downstream.

        The returned mapping is opaque to TenantTrace with one exception: a
        ``tenant_id`` key, if present, is used as the tenant's identity in
        findings and in the parameter-override attack. Include it when your
        application exposes one.
        """
        ...

    def auth_headers(self, tenant: Mapping[str, Any]) -> Mapping[str, str]:
        """Headers that authenticate a request as this tenant."""
        ...

    def seed_records(self, tenant: Mapping[str, Any], canary: str) -> Sequence[Any]:
        """Create records owned by this tenant, each carrying ``canary``.

        The canary must land in a field that comes back in API responses — a
        title, name, or description. A canary stored somewhere the API never
        returns cannot prove anything.

        Return the created objects. Each one should be a mapping with ``kind``
        and ``id`` keys (or a :class:`~tenanttrace.core.models.SeededRecord`);
        anything with an ``id`` is accepted and its kind inferred, because the
        common case is returning your API's own JSON straight back.
        """
        ...

    def cleanup(self, tenant: Mapping[str, Any]) -> None:
        """Remove what this run created. Called even when the run fails."""
        ...


def load_seeder(dotted_path: str, **kwargs: Any) -> SeederAdapter:
    """Import and instantiate ``module.path:ClassName``.

    Constructor arguments are passed by keyword and filtered to the ones the
    class actually accepts, so a seeder that does not care about the HTTP
    client does not have to declare it.
    """
    module_name, _, attr = dotted_path.partition(":")
    if not module_name or not attr:
        msg = (
            f"[seeder] adapter must be 'module.path:ClassName', got {dotted_path!r}. "
            'Example: adapter = "seeders.example_seeder:ExampleSeeder"'
        )
        raise SeederError(msg)

    # An installed console script does not put the working directory on
    # sys.path, so "seeders.my_app:MySeeder" would otherwise never resolve.
    ensure_cwd_importable()

    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        msg = (
            f"could not import seeder module {module_name!r}: {exc}\n"
            "Is it importable from the directory you ran tenanttrace in?"
        )
        raise SeederError(msg) from exc

    factory = getattr(module, attr, None)
    if factory is None:
        msg = f"{module_name!r} has no attribute {attr!r}"
        raise SeederError(msg)

    accepted = _accepted_kwargs(factory)
    try:
        instance = factory(**{k: v for k, v in kwargs.items() if k in accepted})
    except TypeError as exc:
        msg = f"could not construct seeder {dotted_path!r}: {exc}"
        raise SeederError(msg) from exc

    for required in ("create_tenant", "auth_headers", "seed_records", "cleanup"):
        if not callable(getattr(instance, required, None)):
            msg = (
                f"seeder {dotted_path!r} is missing {required}(). A seeder needs all four of "
                "create_tenant, auth_headers, seed_records, cleanup — see "
                "seeders/example_seeder.py."
            )
            raise SeederError(msg)

    return instance  # type: ignore[no-any-return]


def _accepted_kwargs(factory: Any) -> frozenset[str]:
    """Names the callable's signature accepts, or everything if unknowable."""
    import inspect

    try:
        signature = inspect.signature(factory)
    except (TypeError, ValueError):  # pragma: no cover - builtins
        return frozenset()
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in signature.parameters.values()):
        return frozenset({"client", "base_url", "config"})
    return frozenset(signature.parameters)


def normalize_records(
    raw_records: Sequence[Any],
    *,
    owner: TenantLabel,
    canary: str,
    default_kind: str = "record",
) -> tuple[SeededRecord, ...]:
    """Coerce whatever the seeder returned into :class:`SeededRecord` values.

    Deliberately forgiving about shape and strict about content: a record
    without an id is dropped with no id invented for it, because a fabricated
    id would later be searched for in responses and could only produce noise.
    """
    records: list[SeededRecord] = []
    for raw in raw_records:
        if isinstance(raw, SeededRecord):
            records.append(raw)
            continue
        if not isinstance(raw, Mapping):
            continue
        identifier = raw.get("id") or raw.get("uuid") or raw.get("pk")
        if identifier is None:
            continue
        kind = str(raw.get("kind") or raw.get("type") or default_kind)
        record_canary = str(raw.get("canary") or canary)
        fields = {k: v for k, v in raw.items() if k not in {"kind", "type", "canary"}}
        records.append(
            SeededRecord(
                kind=kind,
                id=str(identifier),
                canary=record_canary,
                owner=owner,
                fields=fields,
            )
        )
    return tuple(records)


def seed_tenant(
    seeder: SeederAdapter,
    label: TenantLabel,
    *,
    default_kind: str = "record",
) -> TenantContext:
    """Create one tenant, plant its canary, and return its context.

    Failures are re-raised as :class:`SeederError` with the tenant named. A
    half-seeded run is not a run whose results mean less — it is a run whose
    results mean nothing, so the caller stops here.
    """
    canary = make_canary(label)
    try:
        # Typed as Any deliberately: the Protocol says this returns a mapping,
        # but a seeder is user code that was never type-checked against it, and
        # the resulting error message should name the problem rather than
        # surface three frames later as an AttributeError.
        tenant: Any = seeder.create_tenant(label.value)
    except Exception as exc:  # noqa: BLE001 - user code, any failure is ours to report
        msg = f"seeder.create_tenant({label.value!r}) failed: {type(exc).__name__}: {exc}"
        raise SeederError(msg) from exc

    if not isinstance(tenant, Mapping):
        msg = (
            f"seeder.create_tenant({label.value!r}) must return a mapping, got "
            f"{type(tenant).__name__}"
        )
        raise SeederError(msg)

    try:
        headers = dict(seeder.auth_headers(tenant))
    except Exception as exc:  # noqa: BLE001
        msg = f"seeder.auth_headers for tenant {label.value} failed: {type(exc).__name__}: {exc}"
        raise SeederError(msg) from exc

    try:
        raw_records = seeder.seed_records(tenant, canary)
    except Exception as exc:  # noqa: BLE001
        msg = f"seeder.seed_records for tenant {label.value} failed: {type(exc).__name__}: {exc}"
        raise SeederError(msg) from exc

    records = normalize_records(
        list(raw_records or ()), owner=label, canary=canary, default_kind=default_kind
    )
    if not records:
        msg = (
            f"seeder planted no records for tenant {label.value}. Without seeded data the "
            "oracle has nothing to look for, so every result would be inconclusive."
        )
        raise SeederError(msg)

    return TenantContext(
        label=label,
        tenant_id=str(tenant.get("tenant_id") or tenant.get("id") or label.value),
        canary=canary,
        headers=headers,
        records=records,
        metadata={k: v for k, v in tenant.items() if k not in {"token", "access_token"}},
    )
