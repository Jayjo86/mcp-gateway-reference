"""Per-server authorization regime: each backend declares its own profile and
the router dispatches to the matching provider."""

from __future__ import annotations

import pytest

from app.config import BackendServer, Settings
from app.downstream import (
    DownstreamRouter,
    M2MTokenProvider,
    OboTokenProvider,
    build_router,
)
from app.downstream.base import DownstreamError


def _backend(name: str, profile: str) -> BackendServer:
    return BackendServer(
        name=name,
        namespace=name.replace("-", "_"),
        url=f"http://{name}:9000/mcp",
        audience=f"api://{name}",
        scope=f"api://{name}/.default",
        profile=profile,
    )


def test_per_server_profile_overrides_default():
    s = Settings(
        entra_tenant_id="t",
        gateway_client_id="c",
        gateway_client_secret="x",
        downstream_profile="m2m",
        mcp_server_b_profile="obo",
    )
    backends = s.backends()
    assert backends["mcp-server-a"].profile == "m2m"  # inherits default
    assert backends["mcp-server-b"].profile == "obo"  # per-server override


def test_router_dispatches_to_provider_per_regime():
    s = Settings(
        entra_tenant_id="t",
        gateway_client_id="c",
        gateway_client_secret="x",
    )
    router = build_router(s)
    assert isinstance(router, DownstreamRouter)
    assert isinstance(router._provider("m2m"), M2MTokenProvider)
    assert isinstance(router._provider("obo"), OboTokenProvider)
    # same regime → shared instance (caches are reused)
    assert router._provider("m2m") is router._provider("m2m")


async def test_unknown_profile_is_fail_closed():
    s = Settings(
        entra_tenant_id="t",
        gateway_client_id="c",
        gateway_client_secret="x",
    )
    router = build_router(s)
    with pytest.raises(DownstreamError):
        await router.token_for(principal=None, backend=_backend("x", "vault"))
    await router.aclose()


class _FakeResp:
    is_error = False

    def json(self):
        return {"access_token": "TOKEN", "expires_in": 3600}


class _FakeHttp:
    def __init__(self):
        self.posts = []

    async def post(self, url, data=None):
        self.posts.append(data)
        return _FakeResp()

    async def aclose(self): ...


async def test_obo_requests_per_tool_scope_with_fallback():
    from app.downstream.obo import OboTokenProvider
    from app.principal import Principal

    http = _FakeHttp()
    s = Settings(
        entra_tenant_id="t",
        gateway_client_id="c",
        gateway_client_secret="x",
    )
    prov = OboTokenProvider(s, http=http)
    prov._token_endpoint = "http://token"  # skip OIDC discovery
    principal = Principal(
        actor_sub="u1",
        actor_upn=None,
        agent_client_id="https://claude.ai/oauth/claude-code-client-metadata",  # the MCP client
        agent_kind="cimd",
        broker_client_id="gateway-app-guid",  # this gateway — a different thing
        scopes=[],
        roles=[],
        groups=[],
        raw_token="header.payload.sig",
    )
    backend = _backend("mcp-server-b", "obo")

    # per-tool least-privilege scope is used verbatim
    await prov.token_for(
        principal=principal, backend=backend, scope="api://mcp-server-b/Ledger.Write"
    )
    assert http.posts[-1]["scope"] == "api://mcp-server-b/Ledger.Write"

    # no per-tool scope → fall back to the backend default
    await prov.token_for(principal=principal, backend=backend, scope=None)
    assert http.posts[-1]["scope"] == backend.scope
