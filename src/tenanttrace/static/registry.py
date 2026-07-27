"""Adapter registry: name to factory, plus ``auto`` detection.

The static core resolves an adapter through this module and never imports one
directly. That is the whole point of the indirection: adding PHP/Laravel should
touch a new package and one line here, not :mod:`tenanttrace.static.engine`.

Sniffing is deliberately shallow — it looks at imports, not at behaviour. A
wrong guess produces a warning and no findings, which is a recoverable outcome;
a clever guess that silently analyses a Django project with SQLAlchemy rules
would produce confident nonsense.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Sequence

from tenanttrace.static.adapters.python_django import (
    ADAPTER_NAME as DJANGO_NAME,
)
from tenanttrace.static.adapters.python_django import (
    PythonDjangoAdapter,
)
from tenanttrace.static.adapters.python_django import (
    _sniff as _sniff_python_django,
)
from tenanttrace.static.adapters.python_sqlalchemy import ADAPTER_NAME, PythonSQLAlchemyAdapter
from tenanttrace.static.base import LanguageAdapter, ParsedFile

__all__ = [
    "AdapterFactory",
    "UnknownAdapterError",
    "available",
    "discovery_globs",
    "get",
    "register",
    "resolve",
]

AdapterFactory = Callable[[], LanguageAdapter]
Sniffer = Callable[[Sequence[ParsedFile]], float]

AUTO = "auto"


class UnknownAdapterError(LookupError):
    """Raised when a configured adapter name has no registration."""


def _sniff_python_sqlalchemy(files: Sequence[ParsedFile]) -> float:
    """Confidence that this tree is a Python + SQLAlchemy application.

    An explicit ``sqlalchemy`` import is near-certain. Plain Python still scores,
    because most of this adapter's rules (raw SQL, cache keys, job payloads) do
    not depend on the ORM at all.
    """
    python_files = 0
    for file in files:
        if not file.rel_path.endswith(".py"):
            continue
        python_files += 1
        for node in ast.walk(file.tree):
            if isinstance(node, ast.Import) and any(
                alias.name.split(".")[0] == "sqlalchemy" for alias in node.names
            ):
                return 1.0
            if (
                isinstance(node, ast.ImportFrom)
                and (node.module or "").split(".")[0] == "sqlalchemy"
            ):
                return 1.0
    return 0.4 if python_files else 0.0


_FACTORIES: dict[str, AdapterFactory] = {
    ADAPTER_NAME: PythonSQLAlchemyAdapter,
    DJANGO_NAME: PythonDjangoAdapter,
}
# Django scores 1.0 on an explicit import and 0.0 otherwise, so a project
# with both loses to whichever it imports — and the SQLAlchemy sniffer
# floors at 0.4 for any Python tree, which is the right tie-break: its
# rules are mostly ORM-independent.
_SNIFFERS: dict[str, Sniffer] = {
    ADAPTER_NAME: _sniff_python_sqlalchemy,
    DJANGO_NAME: _sniff_python_django,
}


def register(name: str, factory: AdapterFactory, sniffer: Sniffer | None = None) -> None:
    """Add or replace an adapter registration.

    Args:
        name: Registry key, matching ``[static] adapter`` in the config file.
        factory: Zero-argument callable returning a fresh adapter.
        sniffer: Optional scorer used when ``adapter = "auto"``. Without one the
            adapter is never chosen automatically, only by name.
    """
    _FACTORIES[name] = factory
    if sniffer is not None:
        _SNIFFERS[name] = sniffer


def available() -> tuple[str, ...]:
    """Registered adapter names, sorted."""
    return tuple(sorted(_FACTORIES))


def discovery_globs() -> tuple[str, ...]:
    """Every glob any adapter can read — what the file walk collects first.

    Discovery has to happen before the adapter is known, so the walk uses the
    union and the chosen adapter filters afterwards.
    """
    globs: set[str] = set()
    for factory in _FACTORIES.values():
        globs.update(factory().file_globs)
    return tuple(sorted(globs))


def get(name: str) -> LanguageAdapter:
    """Instantiate the adapter registered under ``name``.

    Raises:
        UnknownAdapterError: When nothing is registered under that name.
    """
    try:
        factory = _FACTORIES[name]
    except KeyError as exc:
        msg = f"unknown static adapter {name!r}; registered: {', '.join(available()) or '<none>'}"
        raise UnknownAdapterError(msg) from exc
    return factory()


def resolve(name: str, files: Sequence[ParsedFile]) -> LanguageAdapter | None:
    """Pick an adapter by configured name, or by sniffing when ``name`` is auto.

    Args:
        name: ``[static] adapter``. ``"auto"`` sniffs.
        files: Parsed files, used only for sniffing.

    Returns:
        The adapter, or ``None`` when ``auto`` found nothing it recognises —
        the caller reports that as a warning rather than crashing a CI run.

    Raises:
        UnknownAdapterError: When an explicitly named adapter is not registered.
    """
    if name != AUTO:
        return get(name)

    best_name, best_score = "", 0.0
    for candidate, sniffer in _SNIFFERS.items():
        score = sniffer(files)
        if score > best_score:
            best_name, best_score = candidate, score
    return get(best_name) if best_name else None
