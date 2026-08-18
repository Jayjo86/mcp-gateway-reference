"""Fake CRM MCP server (backend "A").

Deliberately boring — it exists to make the audience-separation invariant
visible. Auth is FastMCP's ``RemoteAuthProvider``: it serves RFC 9728
protected-resource metadata and answers an unauthenticated request with 401 +
``WWW-Authenticate: Bearer resource_metadata="..."``. The wrapped JWTVerifier
accepts only tokens signed by this tenant's Entra and carrying
``aud=$MCP_SERVER_A_AUDIENCE``, so a token minted for mcp-server-b can't call
this server.
"""

from __future__ import annotations

import os

from fastmcp import FastMCP

from .auth import build_auth

mcp = FastMCP("mcp-server-a (fake CRM)", auth=build_auth())

_CUSTOMERS = [
    {"id": "C-001", "name": "Acme GmbH", "tier": "enterprise"},
    {"id": "C-002", "name": "Globex AG", "tier": "smb"},
    {"id": "C-003", "name": "Initech KG", "tier": "smb"},
]


@mcp.tool
def crm_list_customers() -> list[dict]:
    """List CRM customers (read-only)."""
    return _CUSTOMERS


@mcp.tool
def crm_update_customer(customer_id: str, tier: str) -> dict:
    """Update a CRM customer's tier. Elevated — see the gateway tool registry."""
    for customer in _CUSTOMERS:
        if customer["id"] == customer_id:
            customer["tier"] = tier
            return customer
    raise ValueError(f"no such customer: {customer_id}")


def main() -> None:
    mcp.run(transport="http", host="0.0.0.0", port=int(os.environ.get("PORT", "9000")))


if __name__ == "__main__":
    main()
