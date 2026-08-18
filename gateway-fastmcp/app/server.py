"""Assemble the FastMCP gateway.

FastMCP is the substrate: it brokers inbound OAuth (app/auth.py), aggregates the
upstream MCP servers via mount + per-backend proxy, and runs the middleware
pipeline. We supply the OPA PEP, the downstream token router and the audit
writer.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.auth import build_inbound_verifier
from app.config import Settings
from app.downstream import build_router
from app.middleware.audit import AuditWriter
from app.middleware.opa_client import OpaClient
from app.middleware.opa_pep import OpaPep
from app.upstreams import build_proxy


def build_gateway(settings: Settings) -> FastMCP:
    settings.require_entra()

    opa = OpaClient(settings)
    downstream = build_router(settings)
    audit = AuditWriter(settings)

    @asynccontextmanager
    async def lifespan(_: FastMCP):
        await audit.open()
        try:
            yield
        finally:
            await audit.aclose()
            await opa.aclose()
            await downstream.aclose()

    gateway = FastMCP(
        "mcp-gateway",
        auth=build_inbound_verifier(settings),
        lifespan=lifespan,
    )
    gateway.add_middleware(OpaPep(settings=settings, opa=opa, downstream=downstream, audit=audit))

    # RFC 9728 bare-path alias. AzureProvider serves protected-resource metadata
    # only at the resource-scoped path (/.well-known/oauth-protected-resource/mcp),
    # but some MCP clients probe the bare path — serve an equivalent document
    # there so discovery doesn't 404.
    public_url = settings.gateway_public_url.rstrip("/")

    @gateway.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
    async def protected_resource_metadata(_: Request) -> JSONResponse:
        return JSONResponse(
            {
                "resource": f"{public_url}/mcp",
                "authorization_servers": [f"{public_url}/"],
                "scopes_supported": [settings.gateway_inbound_scope],
                "bearer_methods_supported": ["header"],
            }
        )

    # Aggregate upstreams; each backend's tools are namespaced (server_a_*, ...).
    for backend in settings.backends().values():
        gateway.mount(build_proxy(backend), namespace=backend.namespace)

    return gateway
