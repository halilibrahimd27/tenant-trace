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
import uuid
from collections.abc import Mapping, Sequence
from typing import Any, Protocol, runtime_checkable

import httpx

from tenanttrace._importing import ensure_cwd_importable
from tenanttrace.core.models import SeededRecord, TenantContext, TenantLabel
from tenanttrace.probe.oracle import make_canary

__all__ = [
    "SeederAdapter",
    "SeederClient",
    "SeederError",
    "load_seeder",
    "normalize_records",
    "seed_tenant",
    "unique",
]


class SeederError(Exception):
    """Seeding failed. The run cannot continue: there is no ground truth."""


class SeederClient:
    """A thin, loud HTTP helper for seeders.

    Every one of the six seeders written against real applications hand-rolled
    the same four lines — call, check the status, decode the JSON, fail
    somehow — and three of them wrote their own ``_post`` on top. That is the
    boilerplate this removes.

    The larger win is the failure message. A seeder that raises
    ``KeyError: 'id'`` or a bare ``raise_for_status`` tells whoever is
    debugging it nothing: not which call, not what came back, not what was
    expected. Seeding failures are the most common way a first run dies, and
    they used to be the most expensive to diagnose. Every error here names the
    request, the expected status, the actual one, and what the body said.

    Nothing about it is required — a seeder is ordinary code and may use httpx
    directly, or a vendor SDK, or a database connection.
    """

    def __init__(
        self,
        client: httpx.Client,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self._client = client
        self._headers = dict(headers or {})

    def with_headers(self, **headers: str) -> SeederClient:
        """A copy that sends these headers too — usually a credential."""
        return SeederClient(self._client, headers={**self._headers, **headers})

    def request(
        self,
        method: str,
        path: str,
        *,
        expect: int | tuple[int, ...] = (200, 201, 202, 204),
        json: Any = None,
        data: Any = None,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        """Send a request, insist on the status, return the decoded body.

        Returns ``None`` for an empty body rather than raising: a 204 from a
        delete is a success with nothing to decode.
        """
        wanted = (expect,) if isinstance(expect, int) else tuple(expect)
        try:
            response = self._client.request(
                method.upper(),
                path,
                json=json,
                data=data,
                params=params,
                headers={**self._headers, **dict(headers or {})},
            )
        except httpx.HTTPError as exc:
            msg = f"{method.upper()} {path} could not be sent: {type(exc).__name__}: {exc}"
            raise SeederError(msg) from exc

        if response.status_code not in wanted:
            expected = ", ".join(str(code) for code in wanted)
            msg = (
                f"{method.upper()} {path} returned {response.status_code}, expected "
                f"{expected}. The application said: {_excerpt(response.text)}"
            )
            raise SeederError(msg)

        if not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            msg = (
                f"{method.upper()} {path} returned {response.status_code} but the body is "
                f"not JSON: {_excerpt(response.text)}"
            )
            raise SeederError(msg) from None

    def get(self, path: str, **kwargs: Any) -> Any:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Any:
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> Any:
        return self.request("PUT", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> Any:
        return self.request("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> Any:
        return self.request("DELETE", path, **kwargs)

    def field(self, body: Any, *names: str) -> Any:
        """Read the first present key, or say which ones were looked for.

        ``payload["id"]`` raising ``KeyError: 'id'`` three frames deep is the
        other half of the debugging cost.
        """
        if isinstance(body, Mapping):
            for name in names:
                if name in body:
                    return body[name]
            keys = ", ".join(sorted(str(k) for k in body)[:12]) or "(empty object)"
            msg = (
                f"response has none of {', '.join(names)}. Keys present: {keys}. "
                "Check the shape your application actually returns."
            )
            raise SeederError(msg)
        msg = f"expected a JSON object to read {names[0]!r} from, got {type(body).__name__}"
        raise SeederError(msg)


def unique(prefix: str = "tt") -> str:
    """A short value unique to this run — for names an application must not reuse."""
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _excerpt(text: str, limit: int = 300) -> str:
    body = " ".join(text.split())
    if not body:
        return "(empty body)"
    return body if len(body) <= limit else body[:limit] + "…"


@runtime_checkable
class SeederAdapter(Protocol):
    """What TenantTrace needs from your application.

    Implement these four methods and the rest of the tool works. A worked
    example lives in ``seeders/example_seeder.py``.
    """

    def create_tenant(self, label: str) -> Mapping[str, Any]:
        """Create a fresh tenant and return whatever identifies it downstream.

        The returned mapping is opaque to TenantTrace with one exception:
        **``tenant_id`` must be the tenant's identity as it appears in a URL
        path.** The prober substitutes it into tenant path parameters, so for
        an API shaped ``/api/v1/accounts/{account_id}/…`` it is the account id;
        for ``/api/content/{app}/…`` the app *name*; for
        ``/admin/realms/{realm}/…`` the realm name. Getting it wrong means the
        canonical cross-tenant test is never run.

        Declare a ``canary`` keyword argument to receive the tenant's canary
        here as well — useful when the tenant's own name is the only writable
        free text your application has.
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

        A record may also carry a ``path`` mapping naming the *other* path
        parameters needed to reach it. A nested resource cannot be addressed
        from its own id alone —
        ``/api/database/rows/table/{table_id}/rows/{row_id}`` needs the table —
        so return ``{"kind": "row", "id": "1", "path": {"table_id": "38"}}``
        and the prober fills both slots.

        **``kind`` decides which endpoints an id is tried against**, and it has
        one rule: it must equal the resource segment of the endpoint path,
        lowercase and singular. ``/api/v1/accounts/{account_id}/contacts/{id}``
        wants ``kind="contact"``; ``/admin/realms/{realm}/users/{user-id}``
        wants ``kind="user"``. Get it wrong and nothing errors — the run
        silently degrades to trying a few ids blindly at every endpoint, which
        costs both coverage and confidence. The run warns when no kind matched
        anything.
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
        raw_path = raw.get("path")
        path = (
            {str(k): str(v) for k, v in raw_path.items()} if isinstance(raw_path, Mapping) else {}
        )
        fields = {k: v for k, v in raw.items() if k not in {"kind", "type", "canary", "path"}}
        records.append(
            SeededRecord(
                kind=kind,
                id=str(identifier),
                canary=record_canary,
                owner=owner,
                fields=fields,
                path=path,
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
        # The canary is offered to create_tenant as well, using the same
        # signature filtering as the constructor. Some applications name the
        # tenant itself at creation time and expose nothing else writable —
        # minting the canary only afterwards left those unable to carry one.
        # Typed as Any because the Protocol declares the narrower signature;
        # the keyword is opt-in and discovered from the seeder's own signature.
        create: Any = seeder.create_tenant
        if "canary" in _accepted_kwargs(create):
            tenant: Any = create(label.value, canary=canary)
        else:
            tenant = create(label.value)
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
