"""Turn whatever describes the target's API into an :class:`Endpoint` inventory.

Coverage is bounded by this module: an endpoint nobody told us about does not
get probed, and the report says so rather than implying the surface was
complete.

Loaders are kept behind a small protocol so HAR and Postman importers can be
added later without touching the attacks — they consume ``Endpoint`` and have
no idea where it came from.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Protocol

import httpx
import yaml

from tenanttrace.core.config import Config
from tenanttrace.core.models import Endpoint, HttpMethod

__all__ = [
    "EndpointInventory",
    "SpecError",
    "SpecLoader",
    "load_inventory",
    "parse_openapi",
    "parse_routes",
]

_PATH_PARAM_RE = re.compile(r"\{([^{}/]+)\}")
_MAX_REF_DEPTH = 8


class SpecError(Exception):
    """The API description could not be read. Never silently degrade coverage."""


@dataclass(frozen=True, slots=True)
class EndpointInventory:
    """Everything we know how to talk to, plus what we could not make sense of."""

    endpoints: tuple[Endpoint, ...] = ()
    warnings: tuple[str, ...] = ()
    source: str = ""

    def __len__(self) -> int:
        return len(self.endpoints)

    def __iter__(self) -> Iterator[Endpoint]:
        return iter(self.endpoints)

    def objects(self) -> tuple[Endpoint, ...]:
        """GET endpoints addressing a single object by id — the IDOR surface."""
        return tuple(
            e for e in self.endpoints if e.method is HttpMethod.GET and e.is_object_endpoint
        )

    def collections(self) -> tuple[Endpoint, ...]:
        """GET endpoints returning a collection — the listing surface."""
        return tuple(e for e in self.endpoints if e.is_collection_endpoint)

    def creators(self) -> tuple[Endpoint, ...]:
        """POST endpoints — the mass-assignment surface."""
        return tuple(e for e in self.endpoints if e.method is HttpMethod.POST)

    def filtered(self, config: Config) -> EndpointInventory:
        """Drop excluded paths and cap the surface at ``max_endpoints``.

        The cap exists so that pointing the prober at an application with a
        thousand routes degrades into a slow run rather than an accidental load
        test. Truncation is recorded as a warning — silently testing less than
        the operator asked for is exactly the failure this tool exists to
        avoid.
        """
        excluded = tuple(config.probe.exclude_paths)
        kept = [
            e for e in self.endpoints if not any(fnmatch(e.path, pattern) for pattern in excluded)
        ]
        warnings = list(self.warnings)
        dropped = len(self.endpoints) - len(kept)
        if dropped:
            warnings.append(f"{dropped} endpoint(s) skipped by [probe] exclude_paths")
        if len(kept) > config.probe.max_endpoints:
            warnings.append(
                f"inventory truncated to {config.probe.max_endpoints} of {len(kept)} "
                "endpoints by [probe] max_endpoints — the untested remainder is NOT "
                "evidence of isolation"
            )
            kept = kept[: config.probe.max_endpoints]
        return EndpointInventory(tuple(kept), tuple(warnings), self.source)


class SpecLoader(Protocol):
    """Reads one description format into an inventory."""

    name: str

    def parse(self, document: Any, *, source: str) -> EndpointInventory:
        """Build an inventory from an already-decoded document."""
        ...


# --------------------------------------------------------------------------- #
# OpenAPI
# --------------------------------------------------------------------------- #


def _resolve_ref(document: Mapping[str, Any], ref: str, *, depth: int = 0) -> Any:
    """Resolve a local ``#/components/...`` reference.

    Only local refs: following a remote ``$ref`` would mean fetching a URL that
    the target controls, and a security tool should not be talked into making
    arbitrary outbound requests by the document it is reading.
    """
    if depth > _MAX_REF_DEPTH or not ref.startswith("#/"):
        return None
    node: Any = document
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, Mapping) or part not in node:
            return None
        node = node[part]
    return node


def _deref(document: Mapping[str, Any], node: Any, *, depth: int = 0) -> Any:
    """Follow ``$ref`` chains until a concrete node is reached."""
    seen = 0
    while isinstance(node, Mapping) and "$ref" in node and seen < _MAX_REF_DEPTH:
        node = _resolve_ref(document, str(node["$ref"]), depth=depth + seen)
        seen += 1
    return node


def _body_fields(document: Mapping[str, Any], operation: Mapping[str, Any]) -> tuple[str, ...]:
    """Top-level property names of a JSON request body.

    Only the top level: mass assignment happens on the fields a handler binds
    directly, and walking into nested objects would produce a field list the
    attacks cannot meaningfully use.
    """
    body = _deref(document, operation.get("requestBody"))
    if not isinstance(body, Mapping):
        return ()
    content = body.get("content")
    if not isinstance(content, Mapping):
        return ()
    for media_type, media in content.items():
        if "json" not in str(media_type).lower() or not isinstance(media, Mapping):
            continue
        schema = _deref(document, media.get("schema"))
        if isinstance(schema, Mapping):
            props = schema.get("properties")
            if isinstance(props, Mapping):
                return tuple(str(k) for k in props)
    return ()


def parse_openapi(document: Any, *, source: str = "") -> EndpointInventory:
    """Build an inventory from an OpenAPI 3.x document."""
    if not isinstance(document, Mapping):
        msg = "OpenAPI document must be a JSON/YAML object"
        raise SpecError(msg)
    paths = document.get("paths")
    if not isinstance(paths, Mapping):
        msg = "OpenAPI document has no 'paths' object — nothing to probe"
        raise SpecError(msg)

    endpoints: list[Endpoint] = []
    warnings: list[str] = []

    for raw_path, path_item in paths.items():
        path = str(raw_path)
        if not isinstance(path_item, Mapping):
            warnings.append(f"skipped {path!r}: path item is not an object")
            continue
        if not path.startswith("/"):
            warnings.append(f"skipped {path!r}: path does not start with '/'")
            continue

        shared_params = path_item.get("parameters", [])
        for raw_method, operation in path_item.items():
            method_name = str(raw_method).upper()
            if method_name not in HttpMethod.__members__:
                continue
            if not isinstance(operation, Mapping):
                warnings.append(f"skipped {method_name} {path}: operation is not an object")
                continue

            params: list[Any] = []
            if isinstance(shared_params, Sequence) and not isinstance(shared_params, (str, bytes)):
                params.extend(shared_params)
            op_params = operation.get("parameters", [])
            if isinstance(op_params, Sequence) and not isinstance(op_params, (str, bytes)):
                params.extend(op_params)

            query_params: list[str] = []
            declared_path_params: list[str] = []
            for raw_param in params:
                param = _deref(document, raw_param)
                if not isinstance(param, Mapping):
                    continue
                name = param.get("name")
                if not isinstance(name, str):
                    continue
                where = param.get("in")
                if where == "query":
                    query_params.append(name)
                elif where == "path":
                    declared_path_params.append(name)

            # The path template is the authority on path parameters; the
            # `parameters` list is frequently incomplete in hand-written specs.
            templated = _PATH_PARAM_RE.findall(path)
            path_params = list(dict.fromkeys([*templated, *declared_path_params]))

            tags = operation.get("tags", [])
            endpoints.append(
                Endpoint(
                    method=HttpMethod(method_name),
                    path=path,
                    operation_id=_as_str(operation.get("operationId")),
                    summary=_as_str(operation.get("summary")),
                    path_params=tuple(path_params),
                    query_params=tuple(dict.fromkeys(query_params)),
                    body_fields=_body_fields(document, operation),
                    tags=tuple(str(t) for t in tags) if isinstance(tags, Sequence) else (),
                )
            )

    if not endpoints:
        warnings.append("OpenAPI document declared no usable operations")

    endpoints.sort(key=lambda e: (e.path, e.method.value))
    return EndpointInventory(tuple(endpoints), tuple(warnings), source)


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


# --------------------------------------------------------------------------- #
# routes.yaml — the escape hatch for apps with no machine-readable spec
# --------------------------------------------------------------------------- #


def parse_routes(document: Any, *, source: str = "") -> EndpointInventory:
    """Build an inventory from a hand-written ``routes.yaml``.

    Shape::

        routes:
          - method: GET
            path: /api/invoices/{invoice_id}
            query: [page]
            body: [title, amount]

    This exists because plenty of applications worth auditing have no OpenAPI
    document, and "we could not test it" is a worse outcome than "you listed
    the routes by hand".
    """
    if isinstance(document, Mapping):
        raw_routes = document.get("routes", [])
    elif isinstance(document, Sequence) and not isinstance(document, (str, bytes)):
        raw_routes = document
    else:
        msg = "routes file must be a list, or an object with a 'routes' key"
        raise SpecError(msg)

    endpoints: list[Endpoint] = []
    warnings: list[str] = []
    if not isinstance(raw_routes, Sequence):
        msg = "'routes' must be a list"
        raise SpecError(msg)

    for index, raw in enumerate(raw_routes):
        if not isinstance(raw, Mapping):
            warnings.append(f"skipped routes[{index}]: not an object")
            continue
        method = str(raw.get("method", "GET")).upper()
        path = str(raw.get("path", ""))
        if method not in HttpMethod.__members__ or not path.startswith("/"):
            warnings.append(f"skipped routes[{index}]: bad method or path ({method} {path!r})")
            continue
        query = raw.get("query", []) or []
        body = raw.get("body", []) or []
        endpoints.append(
            Endpoint(
                method=HttpMethod(method),
                path=path,
                operation_id=_as_str(raw.get("operation_id")),
                summary=_as_str(raw.get("summary")),
                path_params=tuple(_PATH_PARAM_RE.findall(path)),
                query_params=tuple(str(q) for q in query),
                body_fields=tuple(str(b) for b in body),
            )
        )

    endpoints.sort(key=lambda e: (e.path, e.method.value))
    return EndpointInventory(tuple(endpoints), tuple(warnings), source)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class _Fetched:
    document: Any
    source: str


def _fetch(spec_path: str, client: httpx.Client | None) -> _Fetched:
    """Read a spec from a URL (through the probe's own client) or from disk."""
    if spec_path.startswith(("http://", "https://")):
        if client is None:
            msg = "an HTTP client is required to fetch a spec over the network"
            raise SpecError(msg)
        try:
            response = client.get(spec_path)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            msg = f"could not fetch the API description from {spec_path}: {exc}"
            raise SpecError(msg) from exc
        try:
            return _Fetched(response.json(), spec_path)
        except ValueError:
            return _Fetched(yaml.safe_load(response.text), spec_path)

    path = Path(spec_path)
    if not path.is_file():
        msg = f"API description not found: {path}"
        raise SpecError(msg)
    text = path.read_text(encoding="utf-8")
    try:
        if path.suffix.lower() in {".yaml", ".yml"}:
            return _Fetched(yaml.safe_load(text), str(path))
        return _Fetched(json.loads(text), str(path))
    except (ValueError, yaml.YAMLError) as exc:
        msg = f"{path} is not valid JSON or YAML: {exc}"
        raise SpecError(msg) from exc


def load_inventory(config: Config, client: httpx.Client | None = None) -> EndpointInventory:
    """Load, parse, and filter the endpoint inventory described by ``config``."""
    spec_path = config.target.spec_path
    if not spec_path:
        if config.target.spec == "openapi":
            spec_path = f"{config.target.base_url}/openapi.json"
        else:
            msg = '[target] spec_path is required unless spec = "openapi"'
            raise SpecError(msg)

    fetched = _fetch(spec_path, client)
    parser = parse_openapi if config.target.spec == "openapi" else parse_routes
    return parser(fetched.document, source=fetched.source).filtered(config)


def substitute_path(path: str, values: Mapping[str, str], *, fallback: str | None = None) -> str:
    """Fill a path template with concrete values.

    Parameters with no supplied value keep their template form unless
    ``fallback`` is given. A request still carrying ``{id}`` is a bug we want
    to see in the artifact rather than a silently mangled URL.
    """

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name in values:
            return str(values[name])
        return fallback if fallback is not None else match.group(0)

    return _PATH_PARAM_RE.sub(replace, path)


def path_param_names(path: str) -> tuple[str, ...]:
    """Names of the ``{placeholders}`` in a path template."""
    return tuple(_PATH_PARAM_RE.findall(path))
