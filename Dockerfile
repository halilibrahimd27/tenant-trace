# TenantTrace images.
#
#   runtime  — just the CLI. What gets published to GHCR and what you point at
#              your own application. No fixture dependencies, no FastAPI, no
#              deliberately-vulnerable code anywhere in the layer.
#   demo     — the CLI plus the bundled fixture applications, used by
#              docker-compose.yml so `docker compose up -d` works from a clone.
#
# Build the published image explicitly:  docker build --target runtime -t tenanttrace .

# --------------------------------------------------------------------- base
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Dependency metadata first so a source-only change does not reinstall the world.
# tenanttrace.example.toml is force-included into the wheel (see pyproject.toml)
# so that `tenanttrace init` scaffolds the documented config rather than a bare
# fallback — the build fails without it, which is how this was noticed.
COPY pyproject.toml README.md tenanttrace.example.toml ./
COPY src ./src

# ------------------------------------------------------------------ runtime
FROM base AS runtime

RUN uv pip install --system --no-cache . \
    && useradd --create-home --uid 10001 tenanttrace

# The prober holds two tenants' credentials and writes run artifacts. Running
# it as root inside a container buys nothing and costs the usual things.
USER tenanttrace
WORKDIR /work

ENTRYPOINT ["tenanttrace"]
CMD ["--help"]

# --------------------------------------------------------------------- demo
FROM base AS demo

# `fixtures` brings FastAPI/SQLAlchemy/PyJWT; `redis` makes the fixture cache
# use a real Redis so the cache-key leak is demonstrated over the same
# machinery a production application would use.
RUN uv pip install --system --no-cache ".[fixtures,redis]"

COPY fixtures ./fixtures
COPY docker ./docker

RUN useradd --create-home --uid 10001 tenanttrace \
    && mkdir -p /reports \
    && chown -R tenanttrace:tenanttrace /app /reports

USER tenanttrace
ENV PYTHONPATH=/app

HEALTHCHECK --interval=5s --timeout=3s --retries=12 --start-period=5s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health').status==200 else 1)"

EXPOSE 8000
CMD ["uvicorn", "fixtures.vulnerable_app.main:app", "--host", "0.0.0.0", "--port", "8000"]
