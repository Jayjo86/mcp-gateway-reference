"""The downstream-token contract, shared by every regime.

Invariant: ``token_for`` returns a token whose ``aud`` is the backend's
audience, built from the gateway's own credentials (M2M) or by exchanging the
user's token (OBO). The inbound token is never returned or forwarded. On any
failure the provider raises and the PEP turns that into a deny.
"""

from __future__ import annotations

from typing import Protocol

from app.config import BackendServer
from app.principal import Principal


class DownstreamError(RuntimeError):
    """A downstream token could not be obtained — the call must be denied."""


class DownstreamTokenProvider(Protocol):
    async def token_for(
        self, *, principal: Principal, backend: BackendServer, scope: str | None = None
    ) -> str:
        """Return an access token with aud == backend.audience. Raise on failure.

        ``scope`` is the least-privilege, per-tool scope the PEP asks for; when
        None the provider falls back to ``backend.scope``. M2M ignores it —
        client_credentials can only use ``.default``.
        """
        ...

    async def aclose(self) -> None: ...
