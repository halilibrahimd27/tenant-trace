# ADR-0004 — The quality gate audits fixtures in-process, not in containers

- **Status:** accepted
- **Date:** 2026-07-26

## Context

TenantTrace measures its own precision and recall against two bundled fixture
applications. The obvious way to run them is the way a user would: `docker
compose up`, then probe over HTTP.

That makes the project's own quality gate depend on a container runtime, a
Redis server, two free ports, and a health-check race. `make verify` would then
fail on a laptop without Docker, and the metric that is supposed to be the
project's honesty check becomes the flakiest thing in the repository. It also
inverts the dependency the phase plan needs: the gate has to be green before
the fixtures exist in containerised form.

The prober itself has no opinion about transport — it holds an `httpx.Client`
and sends requests. Only the *construction* of that client cares.

## Decision

Inject the transport. `ProbeOptions.transport` is passed straight to
`httpx.Client`, so the gate can drive the fixture applications in-process while
production runs go over a socket. The attacks cannot tell the difference.

`httpx` only ships an *asynchronous* ASGI transport, and the prober is
deliberately synchronous — it is sequential and rate-limited by design, so
making it async would buy nothing and cost complexity in every attack module.
So `probe/asgi.py` implements `SyncASGITransport`: a synchronous
`httpx.BaseTransport` that calls an ASGI application directly, running one
event loop in a daemon thread for the transport's lifetime.

Containers remain the *demo* and the way you audit an application over the
network. `docker compose up -d` still boots both fixtures with real Redis and
audits them over real HTTP. The two paths test different things on purpose: the
in-process path tests the tool, the containerised path tests the integration.

## Consequences

**Good:** `make verify` is hermetic — no Docker, no Redis, no ports, no
network — and the full suite runs in about thirteen seconds. CI needs nothing
beyond Python. The event loop persists across requests, so process-local state
(caches especially) behaves the way it does in production, which matters because
the cache-key attack depends on exactly that state surviving between requests.

**Bad:** the in-process path does not exercise real sockets, so a bug in
connection handling, TLS, or redirect behaviour would not surface there. The
containerised demo covers that, and it runs in CI.

**Neutral:** `SyncASGITransport` turned out to be a user-facing feature rather
than a test seam. You can point TenantTrace at your own FastAPI or Starlette
application from inside your own pytest suite and gate a pull request on tenant
isolation without deploying anything.

## Alternatives considered

- **Boot uvicorn on a random port from the test suite** — real sockets, but
  brings back the port race and a process to reap, and shared state between
  tests becomes hard to reason about.
- **Make the whole prober async** — infects every attack module with `async`
  for no benefit; the prober is rate-limited to single-digit requests per
  second by design.
- **Use `starlette.testclient.TestClient`** — works, but would make the core
  prober depend on Starlette, which is a fixture-only dependency and would be
  absurd in a tool that is supposed to be framework-agnostic.
