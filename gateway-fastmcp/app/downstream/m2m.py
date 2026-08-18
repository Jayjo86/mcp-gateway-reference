"""M2M downstream token via Entra client_credentials.

On an allowed call the gateway mints a token for the target backend using its
own confidential app — a technical identity, not the end user. The token's
``aud`` is the backend's audience; the inbound client token is never forwarded.
Same audience-separation invariant as OBO, different downstream actor.
"""

from __future__ import annotations

import logging
import time

from app.config import BackendServer
from app.downstream.entra import EntraTokenProvider, claims_summary, token_error
from app.principal import Principal

logger = logging.getLogger("gateway.token.m2m")


class M2MTokenProvider(EntraTokenProvider):
    async def token_for(
        self, *, principal: Principal, backend: BackendServer, scope: str | None = None
    ) -> str:
        # M2M is user-independent, and client_credentials cannot request
        # granular delegated scopes — the per-tool `scope` is ignored and the
        # backend's `.default` is used, so the gateway's granted app roles
        # decide what the token can do.
        del principal, scope

        async def fetch() -> tuple[str, float]:
            endpoint = await self._endpoint()
            logger.debug("→ Entra M2M  backend=%s  scope=%s", backend.name, backend.scope)
            resp = await self._http.post(
                endpoint,
                data={
                    "grant_type": "client_credentials",
                    "scope": backend.scope,
                    "client_id": self._s.gateway_client_id,
                    "client_secret": self._s.gateway_client_secret,
                },
            )
            if resp.is_error:
                raise token_error(resp)
            body = resp.json()
            token = body["access_token"]
            logger.debug("← Entra M2M  backend=%s  %s", backend.name, claims_summary(token))
            return token, time.monotonic() + float(body.get("expires_in", 0))

        # One entry per backend: the token doesn't depend on the caller.
        return await self._cache.get_or_set(backend.name, fetch)
