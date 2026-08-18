# Layer 1 — platform team.
#
# Owns the single decision the gateway queries (`data.mcp.allow`) and the global
# guardrails that apply to every MCP server and tool. A request is allowed only
# if all three layers agree: platform (here) ∧ domain ∧ tool.
#
# Owned by the platform team via CODEOWNERS; domain teams must not edit it.
package mcp

# The decision the gateway POSTs for. Default deny.
default allow := false

allow if {
	platform_allow
	domain_allow
	tool_allow
}

# Human-readable explanation, surfaced to the user and written to the audit row.
default reason := "denied"

reason := "allowed: all policy layers agree" if allow

reason := sprintf("denied by platform layer: %s", [platform_deny_reason]) if not platform_allow

reason := "denied by domain layer" if {
	platform_allow
	not domain_allow
}

reason := sprintf("denied by tool layer: missing app role (need %v)", [required_role]) if {
	platform_allow
	domain_allow
	not tool_allow
	required_role != ""
}

# An empty `required_role` here means the role check passed, so the failure is
# the args-level constraint — name it instead of falling through to "denied".
reason := sprintf("denied by tool layer: %s", [args_deny_reason]) if {
	platform_allow
	domain_allow
	not tool_allow
	required_role == ""
	args_deny_reason != ""
}

# ── platform guardrails ─────────────────────────────────────────────────────

default platform_allow := false

platform_allow if {
	# the tool must be one the platform knows about
	data.tools[input.tool]
	agent_ok
}

# ── the agent: which MCP client is calling ──────────────────────────────────
#
# `input.agent` is the MCP client — Claude Code, Cursor, a script. It is NOT this
# gateway: the gateway's own Entra client id arrives separately as `input.broker`
# and is the same value on every request ever made, so it can never be an
# authorization input.
#
# Read this before tightening the enforcement mode. Authorization in this gateway
# is the USER's: domain.rego and tool.rego both decide on `input.actor.roles`,
# which Entra signed after a real human authenticated under whatever conditional
# access the tenant enforces. That is the load-bearing control and it is complete
# without this layer.
#
# The agent identity is attribution — "which client software did this?" on every
# audit row, a reporting obligation rather than an authorization one. Gating on it
# is an optional and coarse supply-chain control: the session token is a bearer
# token, so an allowlist controls who was ISSUED one, never who is using it. The
# confused-deputy control that fires at the right moment is the OAuth consent
# interstitial, not this rule. Hence the default is record, don't gate.

# Absent key → "audit". An unrecognised value matches neither mode and denies
# everything with an explicit reason, so a typo fails loudly rather than silently
# disabling the control you thought you had turned on.
_enforcement := object.get(data.platform, "agent_enforcement", "audit")

# "audit" — the agent id reaches the PDP and the audit row and gates nothing.
agent_ok if _enforcement == "audit"

# "allowlist" — opt in to the supply-chain control.
agent_ok if {
	_enforcement == "allowlist"
	agent_trusted
}

# CIMD — the client id is an HTTPS URL whose metadata document FastMCP fetched and
# required to name itself. Verified, and stable across every installation of that
# client software. This is the entry that scales.
agent_trusted if {
	input.agent.kind == "cimd"
	input.agent.id in data.platform.allowed_agents
}

# DCR — the client id is a UUID this gateway minted for whoever POSTed to
# /register. It identifies an installation, not a product, and `client_name` is
# self-asserted. Pinning them works for a known set of machines and doesn't
# survive a re-registration, so this list is for local dev and single-tenant
# deployments. If you find yourself maintaining it, you want "audit" or
# CIMD-only clients instead.
agent_trusted if {
	input.agent.kind == "dcr"
	input.agent.id in data.platform.allowed_dynamic_client_ids
}

# ── deny reasons ────────────────────────────────────────────────────────────

default platform_deny_reason := "no platform rule matched"

platform_deny_reason := sprintf("unknown tool %q", [input.tool]) if not data.tools[input.tool]

platform_deny_reason := sprintf(
	"platform.agent_enforcement is %q — expected \"audit\" or \"allowlist\"",
	[_enforcement],
) if {
	data.tools[input.tool]
	not _enforcement in {"audit", "allowlist"}
}

# Name the exact value and its kind, so the operator can see what to allowlist
# without turning on debug logging.
platform_deny_reason := sprintf(
	"agent %q (%v) is not on the platform allowlist",
	[input.agent.id, input.agent.kind],
) if {
	data.tools[input.tool]
	_enforcement == "allowlist"
	not agent_trusted
	input.agent.id != ""
}

platform_deny_reason := "no agent identity on the request" if {
	data.tools[input.tool]
	_enforcement == "allowlist"
	input.agent.id == ""
}
