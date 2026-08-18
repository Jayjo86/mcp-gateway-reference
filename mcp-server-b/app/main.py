"""Fake ledger MCP server (backend "B").

Deliberately boring — it exists to make the audience-separation invariant
visible. Tools return canned data; ``app.auth.build_auth`` puts a JWTVerifier in
the request path so every call must present a token with
``aud=$MCP_SERVER_B_AUDIENCE``.
"""

from __future__ import annotations

import os

from fastmcp import FastMCP

from .auth import build_auth

mcp = FastMCP("mcp-server-b (fake ledger)", auth=build_auth())

_BALANCES = {
    "ACC-1000": {"account": "ACC-1000", "currency": "EUR", "balance": 152340.55},
    "ACC-2000": {"account": "ACC-2000", "currency": "EUR", "balance": -4210.00},
}
_ENTRIES: list[dict] = []


@mcp.tool
def ledger_get_balance(account: str) -> dict:
    """Get an account balance (read-only)."""
    if account not in _BALANCES:
        raise ValueError(f"no such account: {account}")
    return _BALANCES[account]


@mcp.tool
def ledger_post_entry(account: str, amount: float, memo: str) -> dict:
    """Post a ledger entry. Elevated — see the gateway tool registry."""
    if account not in _BALANCES:
        raise ValueError(f"no such account: {account}")
    _BALANCES[account]["balance"] = round(_BALANCES[account]["balance"] + amount, 2)
    entry = {"account": account, "amount": amount, "memo": memo}
    _ENTRIES.append(entry)
    return {"posted": entry, "new_balance": _BALANCES[account]["balance"]}


def main() -> None:
    mcp.run(transport="http", host="0.0.0.0", port=int(os.environ.get("PORT", "9000")))


if __name__ == "__main__":
    main()
