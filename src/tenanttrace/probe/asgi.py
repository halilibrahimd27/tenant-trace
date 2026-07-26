"""Drive an ASGI application in-process, from synchronous code.

``httpx`` ships an ASGI transport, but only an asynchronous one. The prober is
deliberately synchronous — it is sequential and rate-limited by design, so
async would buy nothing and cost a great deal of complexity in every attack
module — which leaves a gap this module fills.

What it buys:

* **A hermetic quality gate.** The fixture applications are audited without a
  server, a port, or a container, so ``make verify`` is fast and deterministic
  on any machine (ADR-0004).
* **A real feature, not just a test seam.** You can point TenantTrace at your
  own FastAPI/Starlette/Django-ASGI application from inside your own pytest
  suite and gate a pull request on tenant isolation without deploying anything.

The event loop lives in one daemon thread for the transport's lifetime rather
than being created per request. That matters for correctness, not speed:
connection pools, caches, and anything created during lifespan startup are
bound to the loop that created them, and tearing the loop down between requests
would quietly break exactly the shared state a caching bug depends on.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
from collections.abc import Callable, MutableMapping
from types import TracebackType
from typing import Any, Self
from urllib.parse import unquote

import httpx

__all__ = ["SyncASGITransport"]

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
ASGIApp = Callable[[Scope, Any, Any], Any]


class SyncASGITransport(httpx.BaseTransport):
    """An ``httpx`` transport that calls an ASGI app directly."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        raise_app_exceptions: bool = True,
        root_path: str = "",
        client: tuple[str, int] = ("127.0.0.1", 50000),
        run_lifespan: bool = True,
    ) -> None:
        self._app = app
        self._raise_app_exceptions = raise_app_exceptions
        self._root_path = root_path
        self._client = client
        self._run_lifespan = run_lifespan

        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._lifespan_queue: asyncio.Queue[Message] | None = None
        self._lifespan_task: asyncio.Future[Any] | None = None
        self._closed = False

    # ------------------------------------------------------------------ #
    # Loop management
    # ------------------------------------------------------------------ #
    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is not None:
            return self._loop

        ready = threading.Event()
        loop_holder: list[asyncio.AbstractEventLoop] = []

        def run() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop_holder.append(loop)
            ready.set()
            loop.run_forever()

        thread = threading.Thread(target=run, name="tenanttrace-asgi", daemon=True)
        thread.start()
        ready.wait(timeout=10)
        if not loop_holder:  # pragma: no cover - defensive
            msg = "could not start the ASGI event loop"
            raise RuntimeError(msg)

        self._loop = loop_holder[0]
        self._thread = thread
        if self._run_lifespan:
            self._start_lifespan()
        return self._loop

    def _submit(self, coro: Any, timeout: float = 60.0) -> Any:
        loop = self._ensure_loop()
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        return future.result(timeout=timeout)

    # ------------------------------------------------------------------ #
    # Lifespan
    # ------------------------------------------------------------------ #
    def _start_lifespan(self) -> None:
        """Run the app's startup handlers, tolerating apps that have none.

        An application that does not implement the lifespan protocol raises
        rather than answering, and that is not an error: plenty of ASGI apps
        are pure request handlers. The failure is swallowed on purpose and the
        transport carries on.
        """
        loop = self._loop
        if loop is None:  # pragma: no cover - defensive
            return

        async def start() -> None:
            queue: asyncio.Queue[Message] = asyncio.Queue()
            self._lifespan_queue = queue
            startup_complete: asyncio.Future[bool] = loop.create_future()

            async def receive() -> Message:
                return await queue.get()

            async def send(message: Message) -> None:
                kind = message.get("type", "")
                if kind == "lifespan.startup.complete" and not startup_complete.done():
                    startup_complete.set_result(True)
                elif kind == "lifespan.startup.failed" and not startup_complete.done():
                    startup_complete.set_result(False)

            scope: Scope = {
                "type": "lifespan",
                "asgi": {"version": "3.0", "spec_version": "2.3"},
            }
            task = asyncio.ensure_future(self._app(scope, receive, send))
            self._lifespan_task = task
            await queue.put({"type": "lifespan.startup"})
            done, _ = await asyncio.wait(
                [startup_complete, task], timeout=15, return_when=asyncio.FIRST_COMPLETED
            )
            if task in done and not startup_complete.done():
                # The app rejected the lifespan protocol entirely.
                task.exception()

        try:
            self._submit(start(), timeout=20)
        except Exception:  # noqa: BLE001 - lifespan is optional by design
            self._lifespan_queue = None

    # ------------------------------------------------------------------ #
    # Request handling
    # ------------------------------------------------------------------ #
    def handle_request(self, request: httpx.Request) -> httpx.Response:
        """Translate an httpx request into one ASGI call and back."""
        if self._closed:  # pragma: no cover - defensive
            msg = "transport is closed"
            raise RuntimeError(msg)

        body = request.read()
        scope: Scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": request.method,
            "headers": [(k.lower(), v) for k, v in request.headers.raw],
            "scheme": request.url.scheme,
            "path": unquote(request.url.path),
            "raw_path": request.url.raw_path.split(b"?")[0],
            "query_string": request.url.query,
            "root_path": self._root_path,
            "server": (request.url.host, request.url.port or _default_port(request.url.scheme)),
            "client": self._client,
        }

        status, headers, content = self._submit(self._call_app(scope, body))
        return httpx.Response(
            status_code=status,
            headers=headers,
            content=content,
            request=request,
        )

    async def _call_app(
        self, scope: Scope, body: bytes
    ) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
        request_sent = False
        status = 500
        headers: list[tuple[bytes, bytes]] = []
        chunks: list[bytes] = []
        response_started = False
        app_exception: BaseException | None = None

        async def receive() -> Message:
            nonlocal request_sent
            if request_sent:
                # The app asked for more body after we sent it all. Answering
                # with a disconnect is what a real server does at that point.
                return {"type": "http.disconnect"}
            request_sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message: Message) -> None:
            nonlocal status, headers, response_started
            kind = message.get("type", "")
            if kind == "http.response.start":
                status = int(message.get("status", 500))
                headers = list(message.get("headers", []))
                response_started = True
            elif kind == "http.response.body":
                chunks.append(bytes(message.get("body", b"")))

        try:
            await self._app(scope, receive, send)
        except BaseException as exc:  # noqa: BLE001 - the app's failure is data to us
            app_exception = exc

        if app_exception is not None:
            if self._raise_app_exceptions:
                raise app_exception
            if not response_started:
                # A crashed handler is reported as a 500 rather than killing the
                # audit. The oracle reads any 5xx as `inconclusive`, which is
                # the honest verdict for an endpoint that fell over.
                return 500, [(b"content-type", b"text/plain")], b"application error"

        return status, headers, b"".join(chunks)

    # ------------------------------------------------------------------ #
    def close(self) -> None:
        """Shut the app down and stop the loop."""
        if self._closed:
            return
        self._closed = True
        loop, queue, task = self._loop, self._lifespan_queue, self._lifespan_task
        if loop is None:
            return

        if queue is not None and task is not None:

            async def shutdown() -> None:
                await queue.put({"type": "lifespan.shutdown"})
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(asyncio.shield(task), timeout=10)

            # Shutdown is best effort: an application that refuses to stop
            # cleanly must not be able to hang the audit that already finished.
            with contextlib.suppress(Exception):
                asyncio.run_coroutine_threadsafe(shutdown(), loop).result(timeout=15)

        loop.call_soon_threadsafe(loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._loop = None
        self._thread = None

    def __enter__(self) -> Self:
        self._ensure_loop()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc: BaseException | None = None,
        tb: TracebackType | None = None,
        /,
    ) -> None:
        self.close()


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80
