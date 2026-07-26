"""A cache small enough that the test suite never needs a server.

The fixture apps need a *real* cache to demonstrate a real cache-key leak: the
bug only exists because a second request can be served from an entry a first
request wrote. That behaviour is identical in Redis and in a dict, so the tests
run against the dict and the Docker Compose setup can run against Redis by
setting ``REDIS_URL``.

Values are opaque strings. The apps store JSON; this module never looks inside.
"""

from __future__ import annotations

import os
import time
from typing import Any, Protocol

__all__ = ["Cache", "MemoryCache", "RedisCache", "build_cache"]


class Cache(Protocol):
    """The four operations the fixture apps need from a cache."""

    def get(self, key: str) -> str | None:
        """Return the cached value, or ``None`` on a miss or an expired entry."""
        ...

    def set(self, key: str, value: str, ttl_seconds: int | None = None) -> None:
        """Store ``value`` under ``key``, optionally expiring after ``ttl_seconds``."""
        ...

    def delete(self, key: str) -> None:
        """Remove ``key``. A missing key is not an error."""
        ...

    def clear(self) -> None:
        """Drop every entry. Used to give each test a clean slate."""
        ...


class MemoryCache:
    """Process-local cache backed by a dict.

    Not thread-safe and deliberately so — adding a lock would say something
    about production readiness that a fixture has no business saying.
    """

    def __init__(self) -> None:
        # key -> (value, monotonic deadline or None for "never expires")
        self._entries: dict[str, tuple[str, float | None]] = {}

    def get(self, key: str) -> str | None:
        """Return the cached value, or ``None`` on a miss or an expired entry."""
        entry = self._entries.get(key)
        if entry is None:
            return None
        value, deadline = entry
        if deadline is not None and time.monotonic() >= deadline:
            del self._entries[key]
            return None
        return value

    def set(self, key: str, value: str, ttl_seconds: int | None = None) -> None:
        """Store ``value`` under ``key``, optionally expiring after ``ttl_seconds``."""
        deadline = None if ttl_seconds is None else time.monotonic() + ttl_seconds
        self._entries[key] = (value, deadline)

    def delete(self, key: str) -> None:
        """Remove ``key``. A missing key is not an error."""
        self._entries.pop(key, None)

    def clear(self) -> None:
        """Drop every entry."""
        self._entries.clear()

    def __len__(self) -> int:
        """Number of entries currently held, expired ones included."""
        return len(self._entries)


class RedisCache:
    """Redis-backed cache, used only when ``REDIS_URL`` is set.

    ``redis`` is an optional extra, so the import happens here rather than at
    module import time: importing this module must never require the package.
    """

    def __init__(self, url: str, *, prefix: str = "tt") -> None:
        # Imported here, not at module scope: `redis` is an optional extra.
        import redis

        self._client: Any = redis.Redis.from_url(url, decode_responses=True)
        self._prefix = prefix

    def _key(self, key: str) -> str:
        return f"{self._prefix}:{key}"

    def get(self, key: str) -> str | None:
        """Return the cached value, or ``None`` on a miss or an expired entry."""
        value = self._client.get(self._key(key))
        # decode_responses=True means str, but a caller could have written bytes
        # through another client; anything that is not text is treated as a miss.
        return value if isinstance(value, str) else None

    def set(self, key: str, value: str, ttl_seconds: int | None = None) -> None:
        """Store ``value`` under ``key``, optionally expiring after ``ttl_seconds``."""
        self._client.set(self._key(key), value, ex=ttl_seconds)

    def delete(self, key: str) -> None:
        """Remove ``key``. A missing key is not an error."""
        self._client.delete(self._key(key))

    def clear(self) -> None:
        """Drop every entry carrying this instance's prefix.

        Scans instead of calling FLUSHDB: a fixture must not wipe a database it
        happens to share with something else.
        """
        for key in self._client.scan_iter(match=f"{self._prefix}:*"):
            self._client.delete(key)


def build_cache(url: str | None = None) -> Cache:
    """Return a :class:`RedisCache` when a URL is configured, else a dict cache.

    Args:
        url: Redis URL. Defaults to the ``REDIS_URL`` environment variable.

    Returns:
        A cache implementing :class:`Cache`.
    """
    resolved = url if url is not None else os.environ.get("REDIS_URL")
    if resolved:
        return RedisCache(resolved)
    return MemoryCache()
