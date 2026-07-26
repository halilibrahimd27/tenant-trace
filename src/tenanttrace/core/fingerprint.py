"""Stable identity for a finding, so a baseline can suppress it across runs.

A fingerprint answers one question: *is this the same finding I already looked
at and accepted?* It therefore has to survive everything that changes about a
finding without changing what it is —

* line numbers moving as code above it is edited,
* endpoints being reordered in the OpenAPI document,
* a path parameter being renamed (``{id}`` → ``{invoice_id}``),
* different seeded canaries and ids on every run,
* the run's timestamps.

...and it has to change when the finding genuinely becomes a different one:
a different endpoint, a different category, a different source symbol.

The deliberate omissions are as important as the inclusions:

``severity``
    Excluded. Re-rating a category in a tool release must not silently
    un-accept every baselined finding of that category.
``line number``
    Excluded — replaced by the enclosing symbol, which is what actually
    identifies the code. This is the single most important choice here: line
    numbers churn constantly and would make a baseline worthless within days.
``canaries, ids, bodies, timestamps``
    Excluded. They differ on every run by construction, and they are exactly
    the values that must never be written to a committed file.

See ADR-0007.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from tenanttrace.core.models import Category, Engine, Finding

__all__ = [
    "FINGERPRINT_VERSION",
    "compute_fingerprint",
    "normalize_path",
    "normalize_source_location",
    "with_fingerprint",
]

# Bumping this deliberately invalidates every existing baseline entry. Do it
# only when the identity rules change in a way that would otherwise silently
# mis-match old findings to new ones.
FINGERPRINT_VERSION = "1"

_PARAM_RE = re.compile(r"\{[^{}/]*\}")
_NUMERIC_SEGMENT_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_ULID_RE = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
_HEXISH_RE = re.compile(r"^[0-9a-fA-F]{16,}$")


def normalize_path(path: str) -> str:
    """Reduce a URL or path to its template form.

    Concrete identifiers become ``{}``, so ``/api/invoices/018f-…`` and
    ``/api/invoices/{invoice_id}`` normalise to the same string. That is what
    lets a fingerprint survive both re-seeding and a parameter rename.

    Absolute URLs are accepted and reduced to their path, because the same
    finding must not fingerprint differently in staging and in CI.

        >>> normalize_path("http://localhost:8000/api/invoices/7/")
        '/api/invoices/{}'
        >>> normalize_path("/api/invoices/{invoice_id}")
        '/api/invoices/{}'
    """
    if "://" in path:
        path = urlsplit(path).path or "/"
    path = path.split("?", 1)[0].split("#", 1)[0]
    if not path.startswith("/"):
        path = "/" + path

    segments: list[str] = []
    for segment in path.split("/"):
        if not segment:
            continue
        if (
            # already a template parameter...
            _PARAM_RE.fullmatch(segment)
            # ...or a concrete identifier that a re-run would change
            or _NUMERIC_SEGMENT_RE.match(segment)
            or _UUID_RE.match(segment)
            or _ULID_RE.match(segment)
            or _HEXISH_RE.match(segment)
        ):
            segments.append("{}")
        else:
            # A segment may embed a parameter: /files/report-{id}.csv
            segments.append(_PARAM_RE.sub("{}", segment).lower())

    return "/" + "/".join(segments) if segments else "/"


def normalize_source_location(location: str) -> str:
    """Reduce ``path/to/file.py:120:fn_name`` to ``path/to/file.py::fn_name``.

    The line number is dropped on purpose — see the module docstring. When no
    symbol is available the file alone is used, which is coarser but still
    stable; two findings of the same category in one file will then share a
    fingerprint, and that is the right trade against a baseline that expires
    every time someone adds an import.
    """
    raw = location.replace("\\", "/").strip()
    parts = raw.split(":")
    file_part = parts[0]
    symbol = ""
    for part in parts[1:]:
        stripped = part.strip()
        if stripped and not stripped.isdigit():
            symbol = stripped
            break

    posix = PurePosixPath(file_part)
    trimmed = _anchor_to_source_root(posix.as_posix().lstrip("/"))
    return f"{trimmed}::{symbol}" if symbol else trimmed


# Directory names that conventionally mark the top of a source tree. Finding
# one lets a fingerprint computed on a laptop match one computed in CI, where
# the checkout lives at a completely different absolute path.
_SOURCE_ROOTS = ("src/", "app/", "lib/")


def _anchor_to_source_root(path: str) -> str:
    """Drop the checkout directory, keeping the path from the source root down.

    The earliest marker wins, and only at a path boundary. Both details matter:
    taking the earliest keeps ``src/app/routes.py`` intact instead of trimming
    it again at ``app/``, and requiring a boundary stops ``myapp/`` from being
    mistaken for the ``app/`` root.
    """
    earliest: int | None = None
    for marker in _SOURCE_ROOTS:
        if path.startswith(marker):
            return path
        idx = path.find("/" + marker)
        if idx >= 0 and (earliest is None or idx + 1 < earliest):
            earliest = idx + 1
    return path[earliest:] if earliest else path


def _canonical_location(engine: Engine, category: Category, location: str) -> str:
    """Location reduced to whatever identifies the finding for this engine."""
    if engine is Engine.STATIC or category in _STATIC_CATEGORIES:
        return normalize_source_location(location)

    # Dynamic locations look like "GET /api/invoices/{id}".
    method, _, path = location.partition(" ")
    if not path:
        return normalize_path(method)
    return f"{method.upper()} {normalize_path(path)}"


_STATIC_CATEGORIES = frozenset(
    {
        Category.MISSING_TENANT_FILTER,
        Category.RAW_SQL_ESCAPE,
        Category.SCOPE_BYPASS_FLAG,
        Category.UNSCOPED_MODEL,
        Category.TENANTLESS_CACHE_KEY,
        Category.TENANTLESS_JOB_PAYLOAD,
    }
)


def compute_fingerprint(finding: Finding) -> str:
    """Deterministic ``sha256:…`` identity for a finding.

    Correlated findings fingerprint as their probe half, so accepting a
    finding while it is probe-only keeps it accepted once the static engine
    also starts reporting it.
    """
    engine = Engine.PROBE if finding.engine is Engine.CORRELATED else finding.engine
    parts = (
        FINGERPRINT_VERSION,
        engine.value,
        finding.category.value,
        _canonical_location(engine, finding.category, finding.location),
    )
    digest = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()
    return f"sha256:{digest[:32]}"


def with_fingerprint(finding: Finding) -> Finding:
    """Return ``finding`` carrying its computed fingerprint."""
    return finding.model_copy(update={"fingerprint": compute_fingerprint(finding)})
