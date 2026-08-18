"""Inbound auth — FastMCP's AzureProvider as an OAuth AS broker.

AzureProvider is the authorization server facing MCP clients: it serves the
OAuth metadata documents, handles DCR and CIMD, proxies the PKCE-S256 flow to
Entra, validates the returned Entra token and issues a short-lived FastMCP
session JWT. ``load_access_token`` returns an ``AccessToken`` whose ``.token`` is
the raw Entra JWT and whose ``.claims`` are the decoded Entra payload, so
principal.py and obo.py see the shape they expect.

Entra app reg checklist (gateway):
  - Platform: Web, redirect URI = {GATEWAY_PUBLIC_URL}/auth/callback
  - Expose an API: Application ID URI = GATEWAY_AUDIENCE (api://mcp-gateway)
  - Add a scope named GATEWAY_INBOUND_SCOPE (e.g. access_as_user)
  - Manifest: "requestedAccessTokenVersion": 2
"""

from __future__ import annotations

import logging

from fastmcp.server.auth.providers.azure import AzureProvider
from mcp.server.auth.provider import AccessToken

from app.config import Settings

logger = logging.getLogger("gateway.auth")

# Where we stash the MCP client's identity. Private to this gateway; it never
# appears in a token issued by anyone else. principal.py reads it.
MCP_CLIENT_ID_CLAIM = "mcp_client_id"


class GatewayAzureProvider(AzureProvider):
    """AzureProvider that preserves the MCP client's identity across the token swap.

    Three parties have an identity on every request: the human (Entra `sub` /
    `upn` / `roles`), the MCP client — Claude Code, Cursor, a script — and this
    gateway (Entra `azp`).

    ``OAuthProxy.load_access_token`` deliberately swaps tokens: it verifies the
    session JWT the client presents, uses its ``jti`` to look up the stored
    upstream Entra token, and returns the ``AccessToken`` from validating that.
    Right for the human, wrong for the MCP client — in a broker architecture
    Entra only ever sees one OAuth client (us), so ``azp`` is a constant and an
    allowlist checked against it can never deny.

    The value we need is already in the session JWT: ``JWTIssuer`` writes the
    ``client_id`` this gateway issued at DCR/CIMD registration, and
    ``load_access_token`` reads only ``jti`` and ``upstream_claims`` from it. We
    re-verify the payload and copy ``client_id`` onto the returned claims.

    This depends on two fastmcp internals — the ``jwt_issuer`` property and the
    ``client_id`` payload key. fastmcp is pinned exactly in pyproject.toml and
    tests/test_auth.py asserts the contract against a real JWTIssuer, so an
    upstream rename fails CI instead of silently reverting us to authorizing
    ourselves.
    """

    async def load_access_token(self, token: str) -> AccessToken | None:  # type: ignore[override]
        validated = await super().load_access_token(token)
        if validated is None:
            return None

        try:
            payload = self.jwt_issuer.verify_token(token)
        except Exception:  # noqa: BLE001 — super() already verified it; belt and braces
            logger.warning("session JWT re-verification failed after a successful swap")
            return None

        mcp_client_id = payload.get("client_id")
        if not mcp_client_id:
            # Fail closed: without an agent identity the platform layer has
            # nothing to decide on.
            logger.warning("session JWT carries no client_id — rejecting the session")
            return None

        # Copy before touching .claims — `validated` may be a cached object
        # shared across concurrent requests.
        out = validated.model_copy(deep=True)
        out.claims = {**(out.claims or {}), MCP_CLIENT_ID_CLAIM: mcp_client_id}
        return out


def build_inbound_verifier(settings: Settings) -> AzureProvider:
    return GatewayAzureProvider(
        client_id=settings.gateway_client_id,
        client_secret=settings.gateway_client_secret,
        tenant_id=settings.entra_tenant_id,
        identifier_uri=settings.gateway_audience,
        required_scopes=[settings.gateway_inbound_scope],
        base_url=settings.gateway_public_url,
        jwt_signing_key=settings.gateway_session_signing_key,
        require_authorization_consent=settings.require_consent(),
    )
