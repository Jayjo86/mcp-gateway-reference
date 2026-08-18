"""Entra On-Behalf-Of downstream token (per-user delegation).

The user's gateway-audience token never reaches a backend. On an allowed call
the gateway exchanges it for a fresh, backend-audience-scoped, short-lived token:

    grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
    assertion={user_token}
    scope={per-tool scope, or the backend default}
    requested_token_use=on_behalf_of
    client_id / client_secret = the gateway app reg

Note the grant type, because the naming trips people up: Entra's OBO is a
JWT-bearer *assertion* grant (RFC 7523 §2.1) with Microsoft's non-standard
``requested_token_use`` parameter on top. It is NOT RFC 8693 token exchange
(``grant_type=urn:ietf:params:oauth:grant-type:token-exchange``), which does the
same job conceptually but is a different grant the Entra v2.0 token endpoint
does not accept. The two are widely conflated, including in write-ups about this
flow.
"""

from __future__ import annotations

import logging
import time

from app.config import BackendServer
from app.downstream.base import DownstreamError
from app.downstream.entra import EntraTokenProvider, claims_summary, token_error
from app.principal import Principal

logger = logging.getLogger("gateway.token.obo")


class OboTokenProvider(EntraTokenProvider):
    async def token_for(
        self, *, principal: Principal, backend: BackendServer, scope: str | None = None
    ) -> str:
        if not principal.raw_token:
            raise DownstreamError("no inbound user token to exchange (OBO requires a user token)")

        # Least privilege: use the per-tool scope the PEP passed, falling back to
        # the backend default only when there isn't one (e.g. list prefetch).
        effective_scope = scope or backend.scope
        # Keyed by scope too, so a narrow read token and a write token for the
        # same user and backend are cached separately.
        key = (principal.actor_sub, backend.name, effective_scope)

        async def fetch() -> tuple[str, float]:
            endpoint = await self._endpoint()
            logger.debug(
                "→ Entra OBO  backend=%s  scope=%s  actor=%s",
                backend.name,
                effective_scope,
                principal.actor_sub,
            )
            resp = await self._http.post(
                endpoint,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": principal.raw_token,
                    "scope": effective_scope,
                    "requested_token_use": "on_behalf_of",
                    "client_id": self._s.gateway_client_id,
                    "client_secret": self._s.gateway_client_secret,
                },
            )
            if resp.is_error:
                raise token_error(resp)
            body = resp.json()
            token = body["access_token"]
            logger.debug("← Entra OBO  backend=%s  %s", backend.name, claims_summary(token))
            return token, time.monotonic() + float(body.get("expires_in", 0))

        return await self._cache.get_or_set(key, fetch)
