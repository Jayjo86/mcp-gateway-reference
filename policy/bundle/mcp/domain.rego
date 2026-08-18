# Layer 2 — domain teams.
#
# Each domain team owns the slice of this layer for the MCP server(s) they run:
# which backends are enabled, which app roles may reach a given server,
# environment gates, change-freeze windows.
#
# Server access is authorized on Entra APP ROLES (`input.actor.roles`), not raw
# directory groups. App roles are never subject to the Entra `groups`-claim
# overage cap (>~200 groups drops the claim in favour of a Graph pointer), which
# would otherwise silently deny heavily-grouped users. Assign a directory group
# to an app role in Entra if you want group-based administration — the token then
# carries only the small role value.
#
# Per-server sections owned by the respective domain team via CODEOWNERS.
package mcp

default domain_allow := false

# The tool's server must be enabled and the principal must hold an app role
# permitted to use it. Role → server mapping lives in data.json.
domain_allow if {
	server := data.tools[input.tool].server
	server in data.domain.enabled_servers
	some r in input.actor.roles
	r in data.domain.server_roles[server]
}

# ── server-level access (list/enumerate) ────────────────────────────────────
#
# `tools/list` decides whether to mint a downstream credential for a BACKEND
# before any specific tool is known, so it can't route through `domain_allow`
# above (which looks the server up via `data.tools[input.tool]`). Same role →
# server mapping, `input.server` supplied directly.
#
# It also folds in the platform-layer agent check: a list prefetch is exactly the
# kind of credential mint the allowlist exists to gate, and skipping it would let
# an unapproved client mint tokens the tool-call path would have denied it.

default list_allow := false

list_allow if {
	_server_enabled
	_has_role_for_server
	agent_ok
}

_server_enabled if input.server in data.domain.enabled_servers

_has_role_for_server if {
	some r in input.actor.roles
	r in data.domain.server_roles[input.server]
}

default list_reason := "denied"

list_reason := "allowed: domain layer agrees" if list_allow

list_reason := sprintf("server %q is not enabled", [input.server]) if not _server_enabled

# These `not agent_ok` branches mirror `platform_deny_reason` rather than calling
# it: that rule is guarded on `data.tools[input.tool]`, which a list request never
# has, so its guards would never fire for this input shape.
list_reason := sprintf("agent %q (%v) is not on the platform allowlist", [input.agent.id, input.agent.kind]) if {
	_server_enabled
	_enforcement == "allowlist"
	not agent_trusted
	input.agent.id != ""
}

list_reason := "no agent identity on the request" if {
	_server_enabled
	_enforcement == "allowlist"
	not agent_trusted
	input.agent.id == ""
}

list_reason := sprintf(
	"platform.agent_enforcement is %q — expected \"audit\" or \"allowlist\"",
	[_enforcement],
) if {
	_server_enabled
	not _enforcement in {"audit", "allowlist"}
}

list_reason := sprintf("no app role permits access to %q", [input.server]) if {
	_server_enabled
	agent_ok
	not _has_role_for_server
}
