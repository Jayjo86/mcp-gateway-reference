"""TokenCache.get_or_set: no thundering herd on a cold key.

A burst of concurrent calls for the same uncached key must fire one Entra token
exchange, not one per caller — each exchange counts against Entra's rate limits.
"""

from __future__ import annotations

import asyncio
import time

from app.downstream.cache import TokenCache


async def test_concurrent_misses_on_the_same_key_fetch_only_once():
    cache = TokenCache()
    calls = 0

    async def fetch() -> tuple[str, float]:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.01)  # simulate a real network round trip
        return "TOKEN", time.monotonic() + 3600

    results = await asyncio.gather(*(cache.get_or_set("k", fetch) for _ in range(10)))

    assert calls == 1
    assert all(r == "TOKEN" for r in results)


async def test_concurrent_misses_on_different_keys_do_not_serialize():
    cache = TokenCache()
    calls: list[str] = []

    def fetcher(key: str):
        async def fetch() -> tuple[str, float]:
            calls.append(key)
            await asyncio.sleep(0.01)
            return f"TOKEN-{key}", time.monotonic() + 3600

        return fetch

    results = await asyncio.gather(
        cache.get_or_set("a", fetcher("a")),
        cache.get_or_set("b", fetcher("b")),
    )

    assert sorted(calls) == ["a", "b"]  # each key's fetch ran exactly once
    assert results == ["TOKEN-a", "TOKEN-b"]


async def test_get_or_set_returns_cached_value_without_calling_fetch():
    cache = TokenCache()
    cache.set("k", "CACHED", time.monotonic() + 3600)

    async def fetch() -> tuple[str, float]:
        raise AssertionError("fetch must not be called on a cache hit")

    assert await cache.get_or_set("k", fetch) == "CACHED"


async def test_fetch_error_propagates_and_does_not_poison_the_cache():
    cache = TokenCache()

    async def failing_fetch() -> tuple[str, float]:
        raise RuntimeError("Entra unreachable")

    async def good_fetch() -> tuple[str, float]:
        return "TOKEN", time.monotonic() + 3600

    try:
        await cache.get_or_set("k", failing_fetch)
        raise AssertionError("expected RuntimeError")
    except RuntimeError:
        pass

    # a subsequent call for the same key must retry, not replay the failure
    assert await cache.get_or_set("k", good_fetch) == "TOKEN"
