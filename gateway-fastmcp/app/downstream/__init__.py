"""Downstream token providers — the exchange at the gateway→backend boundary.

Every provider returns a fresh token scoped to the backend's audience; none ever
forwards the inbound token. The regime is chosen per backend (``BackendServer.
profile``), so one gateway can speak M2M to one upstream and OBO to another.
"""

from __future__ import annotations

from app.config import BackendServer, Settings
from app.downstream.base import DownstreamError, DownstreamTokenProvider
from app.downstream.m2m import M2MTokenProvider
from app.downstream.obo import OboTokenProvider
from app.principal import Principal

# Regime name → provider factory. Add Databricks federation / Vault here.
_PROVIDERS = {
    "m2m": M2MTokenProvider,
    "obo": OboTokenProvider,
}


class DownstreamRouter:
    """Dispatches ``token_for`` to the provider for the backend's regime.

    Providers are built lazily and shared by every backend on the same regime,
    so their token caches are reused.
    """

    def __init__(self, settings: Settings) -> None:
        self._s = settings
        self._providers: dict[str, DownstreamTokenProvider] = {}

    def _provider(self, profile: str) -> DownstreamTokenProvider:
        if profile not in self._providers:
            factory = _PROVIDERS.get(profile)
            if factory is None:
                raise DownstreamError(f"no downstream provider for profile {profile!r}")
            self._providers[profile] = factory(self._s)
        return self._providers[profile]

    async def token_for(
        self, *, principal: Principal, backend: BackendServer, scope: str | None = None
    ) -> str:
        return await self._provider(backend.profile).token_for(
            principal=principal, backend=backend, scope=scope
        )

    async def aclose(self) -> None:
        for provider in self._providers.values():
            await provider.aclose()


def build_router(settings: Settings) -> DownstreamRouter:
    return DownstreamRouter(settings)


__all__ = [
    "DownstreamRouter",
    "DownstreamTokenProvider",
    "M2MTokenProvider",
    "OboTokenProvider",
    "build_router",
]
