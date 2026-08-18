"""The no-passthrough invariant: a backend only ever sees the gateway-minted,
backend-audience token — never the inbound client token."""

from __future__ import annotations

from fastmcp.client.auth import BearerAuth
from fastmcp.client.transports.http import StreamableHttpTransport

from app.config import BackendServer
from app.context import downstream_tokens
from app.upstreams import build_proxy

BACKEND = BackendServer(
    name="mcp-server-a",
    namespace="server_a",
    url="http://mcp-server-a:9000/mcp",
    audience="api://mcp-server-a",
    scope="api://mcp-server-a/.default",
)


def _client_factory(proxy):
    # FastMCPProxy stores the factory we passed in.
    return proxy.client_factory


def test_proxy_client_does_not_forward_incoming_headers():
    proxy = build_proxy(BACKEND)
    downstream_tokens.set({"mcp-server-a": "DOWNSTREAM_TOKEN"})
    client = _client_factory(proxy)()

    # The crux: a plain Client must NOT enable header forwarding (that flag is
    # what would leak the inbound Authorization header to the backend).
    transport = client.transport
    assert isinstance(transport, StreamableHttpTransport)
    # hasattr first: a bare getattr(..., False) can't tell "the flag is off"
    # from "FastMCP renamed the flag", and would pass silently either way.
    assert hasattr(transport, "forward_incoming_headers")
    assert transport.forward_incoming_headers is False


def test_proxy_client_carries_the_downstream_token():
    proxy = build_proxy(BACKEND)
    downstream_tokens.set({"mcp-server-a": "DOWNSTREAM_TOKEN"})
    client = _client_factory(proxy)()
    assert isinstance(client.transport.auth, BearerAuth)


def test_no_token_means_no_auth():
    proxy = build_proxy(BACKEND)
    downstream_tokens.set({})  # discovery / no allow decision yet
    client = _client_factory(proxy)()
    assert client.transport.auth is None
