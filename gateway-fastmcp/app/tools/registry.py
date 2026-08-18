"""Tool registry and per-tool regulatory metadata.

The tags here are inherited by the audit row for every call and are also
available to OPA policy. Keys are the bare backend tool names — tools reach the
gateway namespaced by mount, and the PEP strips the namespace before looking one
up here.

A static table for the PoC. In a real deployment it would be discovered from the
backends via tools/list, with the tags living alongside the tool definitions.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolMeta:
    name: str
    server: str
    description: str
    # Regulatory tags inherited by the audit row.
    nis2_significant: bool = False
    dora_major: bool = False
    aiact_highrisk: bool = False
    # App role on the GATEWAY app registration a principal must hold to call
    # this tool. It arrives in the `roles` claim of the gateway-audience token
    # we already validated
    required_role: str | None = None
    # Least-privilege delegated scope suffix requested for the downstream OBO
    # token when this tool is called, e.g. "Ledger.Write". Combined with the
    # backend's audience at call time (BackendServer.scope_for)
    downstream_scope: str | None = None
    # Argument names this tool's policy is allowed to see. Everything else is
    # withheld from the PDP — only the hash of the full argument set is audited,
    # and the raw values never leave the gateway. Default empty: a tool sends no
    # arguments at all unless it declares them.
    policy_args: tuple[str, ...] = ()


REGISTRY: dict[str, ToolMeta] = {
    # mcp-server-a — fake CRM
    "crm_list_customers": ToolMeta(
        name="crm_list_customers",
        server="mcp-server-a",
        description="List CRM customers (read-only).",
        downstream_scope="Customers.Read",
    ),
    "crm_update_customer": ToolMeta(
        name="crm_update_customer",
        server="mcp-server-a",
        description="Update a CRM customer record.",
        aiact_highrisk=True,
        required_role="Crm-Customers.Write",
        downstream_scope="Customers.Write",
        policy_args=("tier",),  # tool.rego constrains tier to allowed_tiers
    ),
    # mcp-server-b — fake ledger
    "ledger_get_balance": ToolMeta(
        name="ledger_get_balance",
        server="mcp-server-b",
        description="Get an account balance (read-only).",
        downstream_scope="Ledger.Read",
    ),
    "ledger_post_entry": ToolMeta(
        name="ledger_post_entry",
        server="mcp-server-b",
        description="Post a ledger entry.",
        nis2_significant=True,
        dora_major=True,
        aiact_highrisk=True,
        required_role="Ledger.Write",
        downstream_scope="Ledger.Write",
        policy_args=("amount",),  # tool.rego caps amount at max_amount
    ),
}


def lookup(tool_name: str) -> ToolMeta | None:
    return REGISTRY.get(tool_name)
