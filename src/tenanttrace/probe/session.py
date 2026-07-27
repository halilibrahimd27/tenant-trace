"""Authenticated, rate-limited, fully recorded HTTP for one tenant.

Every request the prober sends goes through a :class:`TenantSession`, which
exists to make three guarantees that the attack modules should not have to
think about:

* **Identity is fixed.** A session is one tenant. An attack cannot accidentally
  send tenant A's request with tenant B's credentials, because it never holds
  both.
* **Nothing is unrecorded.** Every exchange lands in the run artifact, whether
  it produced a finding or not. "We tried and it held" is evidence.
* **Nothing runs away.** A shared token bucket caps the whole run at
  ``max_rps`` so an audit does not read as a denial-of-service attempt to
  whoever is watching the target's dashboards.

The transport is injected rather than constructed here, which is what lets the
test suite drive a FastAPI application in-process over ASGI while production
runs go over a socket. The attacks cannot tell the difference (ADR-0004).
"""

from __future__ import annotations

import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any, Self

import httpx

from tenanttrace.core.config import Config
from tenanttrace.core.models import Evidence, HttpMethod, TenantLabel
from tenanttrace.core.redaction import REDACTED, SENSITIVE_HEADERS, is_sensitive_header
from tenanttrace.core.redaction import redact_headers as _redact
from tenanttrace.probe.oracle import ResponseFacts, facts_from_parts

__all__ = [
    "REDACTED",
    "SENSITIVE_HEADERS",
    "Exchange",
    "RateLimiter",
    "TenantSession",
    "build_client",
    "is_sensitive_header",
    "redact_headers",
]


def redact_headers(headers: Mapping[str, str], *, redact: bool = True) -> dict[str, str]:
    """Copy headers with credentials removed. Not optional.

    Redaction happens at the boundary where the exchange is created, not at
    render time, so there is no code path in which a token is written to disk
    and only hidden later.

    ``redact`` is accepted for symmetry with the renderers and deliberately
    does **not** re-enable credentials. ``--full-evidence`` widens what is kept
    of the *target's* responses; it is not a switch for writing our own bearer
    tokens into a file that CI uploads as an artifact.
    """
    del redact  # credentials are never recorded, in any mode
    return _redact(headers)


@dataclass(frozen=True, slots=True)
class Exchange:
    """One request/response pair, in a form the oracle and the report can read."""

    label: TenantLabel
    method: HttpMethod
    url: str
    status: int | None
    request_headers: Mapping[str, str]
    request_body: str | None
    response_text: str
    elapsed_ms: float
    transport_error: str | None = None
    attack: str = ""

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    def facts(self) -> ResponseFacts:
        """The view the oracle judges."""
        return facts_from_parts(
            status=self.status,
            text=self.response_text,
            transport_error=self.transport_error,
            request_url=self.url,
            request_body=self.request_body,
        )

    def evidence(self, *, snippet_chars: int = 2000) -> Evidence:
        """Report-ready evidence. Headers are already redacted."""
        return Evidence(
            request_method=self.method,
            request_url=self.url,
            request_headers=dict(self.request_headers),
            request_body=self.request_body,
            response_status=self.status,
            response_snippet=self.response_text[:snippet_chars],
            elapsed_ms=self.elapsed_ms,
            note=self.transport_error,
        )


@dataclass
class RateLimiter:
    """A token bucket shared by every session in a run.

    Sharing matters: two sessions each politely limited to 10 rps still put 20
    rps on the target, and the operator configured one number.
    """

    max_rps: float
    _last: float = field(default=0.0, init=False)

    def wait(self) -> None:
        """Block just long enough to stay under the configured rate."""
        if self.max_rps <= 0:
            return
        interval = 1.0 / self.max_rps
        now = time.monotonic()
        gap = now - self._last
        if gap < interval:
            time.sleep(interval - gap)
        self._last = time.monotonic()


def build_client(
    config: Config,
    *,
    transport: httpx.BaseTransport | None = None,
) -> httpx.Client:
    """Build the HTTP client every session shares.

    Two defaults here exist to keep traffic where the operator put it.

    **Redirects are not followed.** A redirect can move a request to a host
    outside ``allowed_hosts``, and silently obeying it would route around the
    one safety rail the operator explicitly configured.

    **The environment is not trusted.** httpx honours ``HTTP_PROXY`` and
    ``HTTPS_PROXY`` by default, which would route two tenants' credentials and
    another tenant's leaked data through whatever a shell variable named — on
    a laptop with a debugging proxy left exported, or on a CI runner with an
    egress proxy. ``allowed_hosts`` says where requests may go; an inherited
    proxy quietly makes that untrue.
    """
    return httpx.Client(
        base_url=config.target.base_url,
        timeout=config.target.timeout_seconds,
        follow_redirects=False,
        trust_env=False,
        transport=transport,
        headers={
            "User-Agent": "tenanttrace/0.1 (+https://github.com/halilibrahimd27/tenant-trace)"
        },
    )


class TenantSession:
    """An authenticated client for exactly one tenant."""

    def __init__(
        self,
        *,
        label: TenantLabel,
        client: httpx.Client,
        headers: Mapping[str, str],
        limiter: RateLimiter,
        redact: bool = True,
    ) -> None:
        self.label = label
        self._client = client
        self._headers = dict(headers)
        self._limiter = limiter
        self._redact = redact
        self.exchanges: list[Exchange] = []

    # ------------------------------------------------------------------ #
    @property
    def headers(self) -> Mapping[str, str]:
        """The tenant's auth headers. Never rendered — see :func:`redact_headers`."""
        return dict(self._headers)

    @property
    def authenticated(self) -> bool:
        """False when no credential was ever resolved for this tenant."""
        return bool(self._headers)

    def with_headers(self, extra: Mapping[str, str]) -> TenantSession:
        """A view of this session carrying additional headers.

        Used by the parameter-override attack, which needs to send tenant A's
        credential alongside an ``X-Tenant-ID: B`` header. Exchanges are
        appended to the same list, so nothing escapes the artifact.
        """
        clone = TenantSession(
            label=self.label,
            client=self._client,
            headers={**self._headers, **extra},
            limiter=self._limiter,
            redact=self._redact,
        )
        clone.exchanges = self.exchanges
        return clone

    # ------------------------------------------------------------------ #
    def request(
        self,
        method: HttpMethod | str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Any | None = None,
        attack: str = "",
    ) -> Exchange:
        """Send one request and record it, whatever happens.

        A transport failure is turned into an :class:`Exchange` with an error
        rather than an exception. A prober that dies on the first timeout would
        report the endpoints it reached as the whole story.
        """
        verb = HttpMethod(str(method).upper())
        self._limiter.wait()

        request_body = None
        if json_body is not None:
            request_body = _safe_json(json_body)

        started = time.perf_counter()
        status: int | None = None
        text = ""
        error: str | None = None
        url = path
        try:
            response = self._client.request(
                verb.value,
                path,
                params=dict(params) if params else None,
                json=json_body,
                headers=self._headers,
            )
            status = response.status_code
            text = response.text
            url = str(response.request.url)
        except httpx.HTTPError as exc:
            error = f"{type(exc).__name__}: {exc}"
            url = str(httpx.URL(self._client.base_url).join(path))
        except UnicodeDecodeError as exc:  # pragma: no cover - defensive
            error = f"undecodable response body: {exc}"

        elapsed_ms = (time.perf_counter() - started) * 1000.0
        exchange = Exchange(
            label=self.label,
            method=verb,
            url=url,
            status=status,
            request_headers=redact_headers(self._headers, redact=self._redact),
            request_body=request_body,
            response_text=text,
            elapsed_ms=elapsed_ms,
            transport_error=error,
            attack=attack,
        )
        self.exchanges.append(exchange)
        return exchange

    def get(self, path: str, **kwargs: Any) -> Exchange:
        return self.request(HttpMethod.GET, path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Exchange:
        return self.request(HttpMethod.POST, path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> Exchange:
        return self.request(HttpMethod.DELETE, path, **kwargs)

    # ------------------------------------------------------------------ #
    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None

    def __iter__(self) -> Iterator[Exchange]:
        return iter(self.exchanges)


def _safe_json(value: Any) -> str:
    """Render a request body for the artifact without letting it raise."""
    import json

    try:
        return json.dumps(value, default=str)[:4000]
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return repr(value)[:4000]
