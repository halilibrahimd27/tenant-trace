"""Turn whatever describes the target's API into an :class:`Endpoint` inventory.

Coverage is bounded by this module: an endpoint nobody told us about does not
get probed, and the report says so rather than implying the surface was
complete.

Four formats, because "we could not test it" is a worse answer than "you
exported a HAR":

``openapi``
    The best case. Path templates, parameters, and request schemas are all
    declared, so nothing has to be inferred.
``har``
    A browser or proxy capture. This is how you audit an application whose API
    is real but undocumented — click through it once, save the HAR, point
    TenantTrace at it.
``postman``
    A collection export, which most teams with an undocumented API already
    have lying around.
``routes``
    A hand-written list, for when there is nothing else.

The last three describe *concrete requests*, not templates, so identifiers have
to be inferred back out of the URLs — see :func:`templatize`. Getting that
wrong costs coverage, never correctness: a path that fails to templatise is
probed as a literal, and the oracle judges the response the same way either
way.

Loaders sit behind a small protocol and produce ``Endpoint`` values; the
attacks have no idea where an endpoint came from.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx
import yaml

from tenanttrace.core.config import Config
from tenanttrace.core.models import Endpoint, HttpMethod
from tenanttrace.core.text import count

__all__ = [
    "EndpointInventory",
    "SpecError",
    "SpecLoader",
    "load_inventory",
    "parse_har",
    "parse_openapi",
    "parse_postman",
    "parse_routes",
    "templatize",
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
            warnings.append(f"{count(dropped, 'endpoint')} skipped by [probe] exclude_paths")
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


def _base_path(document: Mapping[str, Any]) -> str:
    """The prefix every path in this document hangs off.

    Swagger 2.0 puts it in ``basePath``; OpenAPI 3 puts it in the path
    component of ``servers[0].url``. Ignoring it is not a cosmetic bug: an API
    served under ``/api/v1`` would be probed at ``/projects`` instead of
    ``/api/v1/projects``, every request would 404, and a run against a real
    application would come back with no coverage at all.
    """
    base = document.get("basePath")
    if isinstance(base, str) and base.startswith("/"):
        return base.rstrip("/")

    servers = document.get("servers")
    if isinstance(servers, Sequence) and not isinstance(servers, (str, bytes)):
        for server in servers:
            url = server.get("url") if isinstance(server, Mapping) else None
            if not isinstance(url, str):
                continue
            # A server URL may be absolute or just a path, and may contain
            # {variable} placeholders we cannot resolve — those are left alone
            # rather than guessed at.
            path = urlsplit(url).path if "://" in url else url
            trimmed = path.rstrip("/")
            if trimmed.startswith("/"):
                return trimmed
    return ""


def parse_openapi(document: Any, *, source: str = "") -> EndpointInventory:
    """Build an inventory from an OpenAPI 3.x or Swagger 2.0 document."""
    if not isinstance(document, Mapping):
        msg = "OpenAPI document must be a JSON/YAML object"
        raise SpecError(msg)
    paths = document.get("paths")
    if not isinstance(paths, Mapping):
        msg = "OpenAPI document has no 'paths' object — nothing to probe"
        raise SpecError(msg)

    base = _base_path(document)

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
                    path=f"{base}{path}" if base else path,
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
# Recorded traffic: HAR and Postman
# --------------------------------------------------------------------------- #

# Segments that look like an identifier rather than a resource name. Kept
# deliberately conservative: mistaking a resource name for an id merges two
# distinct endpoints into one and silently loses coverage, which is worse than
# probing the same endpoint twice.
_ID_SEGMENT_RE = re.compile(
    r"""^(
        \d+                                                   # 42
      | [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}  # uuid
      | [0-7][0-9A-HJKMNP-TV-Z]{25}                           # ulid
      | [0-9a-fA-F]{16,}                                      # long hex
      | [A-Za-z0-9_-]{20,}                                    # opaque token-ish
    )$""",
    re.VERBOSE,
)

# Things a browser capture is full of and an API audit should never touch.
_STATIC_SUFFIXES = (
    ".js",
    ".mjs",
    ".css",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".webm",
)


def templatize(path: str) -> tuple[str, tuple[str, ...]]:
    """Infer a path template from a concrete URL path.

    ``/api/invoices/018f4c1e-…/lines/7`` becomes
    ``/api/invoices/{id}/lines/{id2}`` with parameters ``("id", "id2")``.

    Assumption, and how it can be wrong: a path segment that looks like an
    identifier is one. A resource genuinely named ``/api/2024`` would be
    templatised into ``/api/{id}`` and merged with its siblings. The cost is
    coverage, not a wrong verdict — and the alternative, treating every id as a
    distinct endpoint, turns a hundred-request capture into a hundred
    "endpoints" and buries the report.
    """
    params: list[str] = []
    out: list[str] = []
    for segment in path.split("/"):
        existing = _PATH_PARAM_RE.fullmatch(segment)
        if existing:
            # Already templated — Postman's :param, or a hand-written route.
            # A name the author chose beats one we would have guessed.
            params.append(existing.group(1))
            out.append(segment)
        elif segment and _ID_SEGMENT_RE.match(segment):
            name = "id" if not params else f"id{len(params) + 1}"
            params.append(name)
            out.append("{" + name + "}")
        else:
            out.append(segment)
    return "/".join(out) or "/", tuple(params)


def _is_probe_worthy(path: str) -> bool:
    """Filter out the static assets a browser capture is mostly made of."""
    lowered = path.lower()
    return not lowered.endswith(_STATIC_SUFFIXES)


@dataclass
class _Accumulator:
    """Merges repeated observations of one endpoint into a single Endpoint.

    A capture usually contains the same request many times, sometimes with
    different query parameters. Every observation contributes what it saw.
    """

    method: HttpMethod
    path: str
    path_params: tuple[str, ...]
    query: dict[str, None]
    body: dict[str, None]

    def observe(self, query: Sequence[str], body: Sequence[str]) -> None:
        for name in query:
            self.query.setdefault(name, None)
        for name in body:
            self.body.setdefault(name, None)

    def build(self) -> Endpoint:
        return Endpoint(
            method=self.method,
            path=self.path,
            path_params=self.path_params,
            query_params=tuple(self.query),
            body_fields=tuple(self.body),
        )


def _body_field_names(text: str | None, mime: str) -> tuple[str, ...]:
    """Top-level field names of a recorded request body."""
    if not text:
        return ()
    if "json" in mime.lower():
        try:
            decoded = json.loads(text)
        except ValueError:
            return ()
        return tuple(str(k) for k in decoded) if isinstance(decoded, Mapping) else ()
    if "form" in mime.lower():
        from urllib.parse import parse_qsl

        return tuple(dict.fromkeys(k for k, _ in parse_qsl(text)))
    return ()


def _collect(
    observations: Iterator[tuple[str, str, Sequence[str], Sequence[str]]],
    *,
    host_filter: str | None,
    source: str,
) -> EndpointInventory:
    """Fold concrete observations into a deduplicated inventory."""
    from urllib.parse import parse_qsl, urlsplit

    endpoints: dict[tuple[HttpMethod, str], _Accumulator] = {}
    warnings: list[str] = []
    skipped_host = 0
    skipped_static = 0

    for raw_method, raw_url, extra_query, body_fields in observations:
        method_name = raw_method.upper()
        if method_name not in HttpMethod.__members__:
            continue

        parts = urlsplit(raw_url)
        # A capture contains third-party traffic — CDNs, analytics, fonts.
        # Probing those would send adversarial requests to somebody else's
        # servers, so anything off-target is dropped rather than tested.
        if host_filter and parts.hostname and parts.hostname != host_filter:
            skipped_host += 1
            continue

        path = parts.path or "/"
        if not _is_probe_worthy(path):
            skipped_static += 1
            continue

        template, params = templatize(path)
        query_names = [k for k, _ in parse_qsl(parts.query)] + list(extra_query)

        key = (HttpMethod(method_name), template)
        accumulator = endpoints.get(key)
        if accumulator is None:
            accumulator = _Accumulator(
                method=key[0], path=template, path_params=params, query={}, body={}
            )
            endpoints[key] = accumulator
        accumulator.observe(query_names, body_fields)

    if skipped_host:
        warnings.append(
            f"{count(skipped_host, 'request')} to other hosts were ignored — a capture is not "
            "permission to probe third parties"
        )
    if skipped_static:
        warnings.append(f"{count(skipped_static, 'static asset request')} skipped")
    if not endpoints:
        warnings.append("no probe-worthy requests found in the capture")

    built = sorted((a.build() for a in endpoints.values()), key=lambda e: (e.path, e.method.value))
    return EndpointInventory(tuple(built), tuple(warnings), source)


def parse_har(document: Any, *, source: str = "", host: str | None = None) -> EndpointInventory:
    """Build an inventory from a HAR 1.2 capture.

    ``host`` restricts the import to the target's own hostname. It is not
    optional in practice: a browser HAR is mostly other people's servers.
    """
    if not isinstance(document, Mapping):
        msg = "HAR file must be a JSON object"
        raise SpecError(msg)
    log = document.get("log")
    entries = log.get("entries") if isinstance(log, Mapping) else None
    if not isinstance(entries, Sequence):
        msg = "HAR file has no log.entries array — is it really a HAR?"
        raise SpecError(msg)

    def observations() -> Iterator[tuple[str, str, Sequence[str], Sequence[str]]]:
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            request = entry.get("request")
            if not isinstance(request, Mapping):
                continue
            url = request.get("url")
            method = request.get("method")
            if not isinstance(url, str) or not isinstance(method, str):
                continue
            query = [
                str(q.get("name"))
                for q in request.get("queryString", []) or []
                if isinstance(q, Mapping) and q.get("name")
            ]
            post = request.get("postData")
            body: tuple[str, ...] = ()
            if isinstance(post, Mapping):
                body = _body_field_names(
                    post.get("text") if isinstance(post.get("text"), str) else None,
                    str(post.get("mimeType", "")),
                )
                params = post.get("params")
                if not body and isinstance(params, Sequence):
                    body = tuple(
                        str(p.get("name"))
                        for p in params
                        if isinstance(p, Mapping) and p.get("name")
                    )
            yield method, url, query, body

    return _collect(observations(), host_filter=host, source=source)


def parse_postman(document: Any, *, source: str = "", host: str | None = None) -> EndpointInventory:
    """Build an inventory from a Postman collection (schema v2.x).

    Postman paths often already carry ``:param`` placeholders; those are
    honoured rather than re-inferred, since a name the author chose beats one
    we guessed.
    """
    if not isinstance(document, Mapping) or "item" not in document:
        msg = "Postman collection must be a JSON object with an 'item' array"
        raise SpecError(msg)

    def walk(items: Any) -> Iterator[Mapping[str, Any]]:
        if not isinstance(items, Sequence):
            return
        for item in items:
            if not isinstance(item, Mapping):
                continue
            if "item" in item:  # a folder
                yield from walk(item["item"])
            elif isinstance(item.get("request"), Mapping):
                yield item["request"]

    def observations() -> Iterator[tuple[str, str, Sequence[str], Sequence[str]]]:
        for request in walk(document.get("item")):
            method = request.get("method")
            if not isinstance(method, str):
                continue
            url = request.get("url")
            raw = url.get("raw") if isinstance(url, Mapping) else url
            if not isinstance(raw, str):
                continue
            query: list[str] = []
            if isinstance(url, Mapping):
                query = [
                    str(q.get("key"))
                    for q in url.get("query", []) or []
                    if isinstance(q, Mapping) and q.get("key")
                ]
            body_spec = request.get("body")
            body: tuple[str, ...] = ()
            if isinstance(body_spec, Mapping):
                mode = str(body_spec.get("mode", ""))
                if mode == "raw":
                    body = _body_field_names(body_spec.get("raw"), "json")
                elif mode in {"urlencoded", "formdata"}:
                    entries = body_spec.get(mode, []) or []
                    body = tuple(
                        str(e.get("key"))
                        for e in entries
                        if isinstance(e, Mapping) and e.get("key")
                    )
            # {{baseUrl}}-style variables are not resolvable here and would
            # otherwise become a path segment; strip them to a bare path.
            cleaned = re.sub(r"\{\{[^}]*\}\}", "", raw)
            cleaned = re.sub(r"^https?://[^/]*", "", cleaned)
            if not cleaned.startswith("/"):
                cleaned = "/" + cleaned.lstrip("/")
            # Postman's :param becomes our {param}.
            cleaned = re.sub(r"/:([A-Za-z_][A-Za-z0-9_]*)", r"/{\1}", cleaned)
            yield method, cleaned, query, body

    return _collect(observations(), host_filter=None, source=source)


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
    kind = config.target.spec
    if kind == "openapi":
        inventory = parse_openapi(fetched.document, source=fetched.source)
    elif kind == "har":
        # Scoped to the target's own host: a browser capture is full of
        # third-party traffic, and having a HAR is not permission to probe
        # whoever else appears in it.
        inventory = parse_har(fetched.document, source=fetched.source, host=config.target.host)
    elif kind == "postman":
        inventory = parse_postman(fetched.document, source=fetched.source)
    else:
        inventory = parse_routes(fetched.document, source=fetched.source)
    return inventory.filtered(config)


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
