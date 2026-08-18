"""Entra token validation for mcp-server-a."""

from __future__ import annotations

import os
from urllib.parse import urlsplit

from fastmcp.server.auth import JWTVerifier, RemoteAuthProvider
from pydantic import AnyHttpUrl


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(
            f"{name} is required. This server validates real Microsoft Entra ID tokens "
            "and refuses to start without it — see README → 'Entra setup'."
        )
    return value


def build_auth() -> RemoteAuthProvider:
    tenant_id = _require_env("ENTRA_TENANT_ID")
    audience = _require_env("MCP_SERVER_A_AUDIENCE")
    app_id = _require_env("MCP_SERVER_A_APP_ID")
    resource_url = _require_env("MCP_RESOURCE_URL")  # public URL of this MCP endpoint

    v2_issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"

    verifier = JWTVerifier(
        jwks_uri=f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys",
        # v2.0 issuer only — a v1.0 (sts.windows.net) token uses a different
        # issuer format and would fail validation anyway.
        issuer=v2_issuer,
        # Two accepted audiences, on purpose. Despite `requestedAccessTokenVersion: 2`
        # on this app's manifest, tokens minted against a `<audience>/.default`
        # scope (M2M, and the gateway's tools/list OBO fallback) come back with
        # `aud` set to the bare Application (client) ID GUID rather than the
        # api:// URI — confirmed against a live tenant.
        #
        # That GUID must be configured explicitly. Deriving it from the audience
        # with urlsplit(...).netloc only works when the URI happens to be written
        # in the guid-qualified form; with the shipped short form
        # (api://mcp-server-a) it yields "mcp-server-a" and every M2M call is
        # rejected.
        audience=[audience, app_id],
        algorithm="RS256",
    )

    parts = urlsplit(resource_url)
    return RemoteAuthProvider(
        token_verifier=verifier,
        authorization_servers=[AnyHttpUrl(v2_issuer)],
        base_url=f"{parts.scheme}://{parts.netloc}",
        resource_name="mcp-server-a (fake CRM)",
    )
