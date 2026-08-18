"""Upstream aggregation without token passthrough.

FastMCP's convenience ``ProxyClient`` / ``as_proxy()`` default to
``forward_incoming_headers=True``, which forwards the inbound ``Authorization``
header straight to the upstream — exactly the token passthrough the MCP
authorization spec forbids and the bug this gateway exists to prevent.

So the proxy is built from a plain ``fastmcp.Client``, which forwards nothing:
the only credential it sends is the backend-audience token the PEP minted for
this request. During unauthenticated discovery there is no token yet and the
upstream's own verifier rejects the call.
"""

from __future__ import annotations

from fastmcp import Client
from fastmcp.client.auth import BearerAuth
from fastmcp.server.providers.proxy import FastMCPProxy

from app.config import BackendServer
from app.context import downstream_tokens


def build_proxy(backend: BackendServer) -> FastMCPProxy:
    def client_factory() -> Client:
        token = downstream_tokens.get({}).get(backend.name)
        auth = BearerAuth(token) if token else None
        return Client(backend.url, auth=auth)

    return FastMCPProxy(client_factory=client_factory, name=backend.name)
