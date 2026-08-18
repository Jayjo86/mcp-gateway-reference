"""The inbound broker: an AzureProvider OAuth AS wired to the gateway's own
Entra app reg, plus the guarantee that the MCP client's client_id survives
OAuthProxy's token swap — the Entra token on the far side of that swap can only
ever name this gateway.
"""

from __future__ import annotations

import pytest
from fastmcp.server.auth.oauth_proxy import OAuthProxy
from fastmcp.server.auth.providers.azure import AzureProvider
from mcp.server.auth.provider import AccessToken

from app.auth import MCP_CLIENT_ID_CLAIM, GatewayAzureProvider, build_inbound_verifier
from app.config import get_settings

# What Entra hands back after the swap: `azp` is ALWAYS the gateway, because in a
# broker architecture Entra never sees the MCP client at all.
GATEWAY_AZP = "11111111-2222-3333-4444-555555555555"
MCP_CLIENT = "https://claude.ai/oauth/claude-code-client-metadata"


def test_broker_is_azure_provider_for_the_gateway_app():
    s = get_settings()
    v = build_inbound_verifier(s)
    assert isinstance(v, AzureProvider)
    assert v._upstream_client_id == s.gateway_client_id
    assert str(v.identifier_uri) == s.gateway_audience
    assert v._tenant_id == s.entra_tenant_id


def _provider() -> GatewayAzureProvider:
    p = build_inbound_verifier(get_settings())
    assert isinstance(p, GatewayAzureProvider)
    # The JWT issuer is created lazily by get_routes(); do it directly so we can
    # mint and verify real session tokens without standing up the HTTP app.
    p.set_mcp_path("/mcp")
    return p


def _entra_access_token() -> AccessToken:
    """The AccessToken OAuthProxy returns today: pure Entra claims."""
    return AccessToken(
        token="upstream.entra.jwt",
        client_id=GATEWAY_AZP,
        scopes=["access_as_user"],
        claims={"sub": "user-1", "azp": GATEWAY_AZP, "roles": ["crm.read"]},
    )


def _session_jwt(provider: GatewayAzureProvider, client_id: str | None) -> str:
    payload_client_id = client_id if client_id is not None else ""
    return provider.jwt_issuer.issue_access_token(
        client_id=payload_client_id,
        scopes=["access_as_user"],
        jti="test-jti",
    )


@pytest.fixture
def swapped_token(monkeypatch):
    """Stub OAuthProxy.load_access_token — the parent our override delegates to."""

    async def fake_load(self, token):
        return _entra_access_token()

    monkeypatch.setattr(OAuthProxy, "load_access_token", fake_load)


async def test_mcp_client_id_survives_the_token_swap(swapped_token):
    # Without the override the only client identity available downstream is the
    # Entra `azp` — this gateway — which makes the allowlist unable to deny.
    provider = _provider()
    token = _session_jwt(provider, MCP_CLIENT)

    out = await provider.load_access_token(token)

    assert out is not None
    assert out.claims[MCP_CLIENT_ID_CLAIM] == MCP_CLIENT
    # the broker's own identity is still there, under its own name
    assert out.claims["azp"] == GATEWAY_AZP
    assert out.claims[MCP_CLIENT_ID_CLAIM] != out.claims["azp"]


async def test_the_upstream_access_token_is_not_mutated(monkeypatch):
    # `validated` may be a cached object shared across concurrent requests;
    # mutating it in place would leak one session's agent id into another's.
    original = _entra_access_token()

    async def fake_load(self, token):
        return original

    monkeypatch.setattr(OAuthProxy, "load_access_token", fake_load)
    provider = _provider()

    out = await provider.load_access_token(_session_jwt(provider, MCP_CLIENT))

    assert out is not original
    assert MCP_CLIENT_ID_CLAIM not in (original.claims or {})


async def test_session_without_client_id_is_rejected(swapped_token):
    # Fail closed: a request we cannot attribute to an agent must not run.
    provider = _provider()
    assert await provider.load_access_token(_session_jwt(provider, None)) is None


async def test_failed_swap_stays_failed(monkeypatch):
    async def fake_load(self, token):
        return None

    monkeypatch.setattr(OAuthProxy, "load_access_token", fake_load)
    provider = _provider()
    assert await provider.load_access_token(_session_jwt(provider, MCP_CLIENT)) is None


def test_fastmcp_session_jwt_still_carries_client_id():
    """Pin the upstream contract GatewayAzureProvider rests on: if a future
    fastmcp renames or drops the session JWT's `client_id`, the override would
    quietly stop finding an agent identity."""
    provider = _provider()
    payload = provider.jwt_issuer.verify_token(_session_jwt(provider, MCP_CLIENT))
    assert payload["client_id"] == MCP_CLIENT
