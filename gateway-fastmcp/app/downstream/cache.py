"""A bounded, TTL-evicted in-memory token cache.

Both providers cache minted tokens to avoid an exchange on every call. Left
unbounded the OBO cache would grow one entry per (subject, backend, scope)
forever, so entries are dropped once they reach (expiry − skew) and the least
recently used entry is evicted past ``maxsize``.

Deliberately a drop-in seam for a shared/Redis-backed cache later: get/set is
all the providers depend on.
"""

from __future__ import annotations

import asyncio
import time
import weakref
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Hashable

# Refresh slightly before real expiry so a cached token is never handed out just
# as it becomes unusable at the backend.
DEFAULT_REFRESH_SKEW_S = 60
DEFAULT_MAX_ENTRIES = 2048


class TokenCache:
    """LRU + TTL cache mapping an arbitrary hashable key → access token."""

    def __init__(
        self,
        *,
        maxsize: int = DEFAULT_MAX_ENTRIES,
        refresh_skew_s: int = DEFAULT_REFRESH_SKEW_S,
    ) -> None:
        if maxsize < 1:
            raise ValueError("maxsize must be >= 1")
        self._max = maxsize
        self._skew = refresh_skew_s
        self._data: OrderedDict[Hashable, tuple[str, float]] = OrderedDict()
        self._locks: weakref.WeakValueDictionary[Hashable, asyncio.Lock] = (
            weakref.WeakValueDictionary()
        )

    def _lock_for(self, key: Hashable) -> asyncio.Lock:
        # No await between the get and the set, so two callers for a brand-new
        # key can't both observe a miss under asyncio's cooperative scheduling.
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        return lock

    async def get_or_set(
        self, key: Hashable, fetch: Callable[[], Awaitable[tuple[str, float]]]
    ) -> str:
        """Return a cached token for ``key``, minting one via ``fetch`` on a miss.

        ``fetch`` returns ``(token, expiry_monotonic)``. Concurrent callers for
        the same key serialize on a per-key lock, and the double-check after
        acquiring it means only the first caller for a cold key reaches Entra.
        """
        cached = self.get(key)
        if cached is not None:
            return cached
        async with self._lock_for(key):
            cached = self.get(key)
            if cached is not None:
                return cached
            token, expiry = await fetch()
            self.set(key, token, expiry)
            return token

    def get(self, key: Hashable) -> str | None:
        """Return a still-valid cached token, or None if missing/expiring."""
        item = self._data.get(key)
        if item is None:
            return None
        token, expiry = item
        if expiry - self._skew <= time.monotonic():
            self._data.pop(key, None)
            return None
        self._data.move_to_end(key)
        return token

    def set(self, key: Hashable, token: str, expiry_monotonic: float) -> None:
        """Store ``token`` under ``key`` with an absolute monotonic expiry."""
        self._data[key] = (token, expiry_monotonic)
        self._data.move_to_end(key)
        self._prune()

    def __len__(self) -> int:
        return len(self._data)

    def _prune(self) -> None:
        now = time.monotonic()
        for key in [k for k, (_, expiry) in self._data.items() if expiry <= now]:
            self._data.pop(key, None)
        while len(self._data) > self._max:
            self._data.popitem(last=False)
