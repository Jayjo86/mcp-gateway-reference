# Policy tests — kept OUT of policy/bundle/ so they never load into the
# serving OPA instance (docker-compose.yml only points --server at
# policy/bundle). Run with: opa test policy/bundle policy/tests
package mcp_test

import data.mcp

# Shared test data mirroring policy/data.json. Worth loading the real file here
# instead of duplicating it.
_data := {
	"platform": {
		# as shipped: the agent id is recorded, not gated on
		"agent_enforcement": "audit",
		"allowed_agents": ["https://claude.ai/oauth/claude-code-client-metadata"],
		"allowed_dynamic_client_ids": ["9f2c1a4e-0000-0000-0000-000000000000"],
	},
	"domain": {
		"enabled_servers": ["mcp-server-a", "mcp-server-b"],
		"server_roles": {
			"mcp-server-a": ["crm.read"],
			"mcp-server-b": ["ledger.read"],
		},
	},
	"tools": {
		"crm_list_customers": {"server": "mcp-server-a"},
		"crm_update_customer": {
			"server": "mcp-server-a",
			"required_role": "Crm-Customers.Write",
			"allowed_tiers": ["smb", "enterprise"],
		},
		"ledger_post_entry": {
			"server": "mcp-server-b",
			"required_role": "Ledger.Write",
			"max_amount": 1000000,
		},
	},
}

test_allow_read_for_member if {
	mcp.allow with data.platform as _data.platform
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "cimd"},
			"tool": "crm_list_customers",
			"actor": {"sub": "u1", "roles": ["crm.read"]},
		}
}

test_deny_missing_role if {
	not mcp.allow with data.platform as _data.platform
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "cimd"},
			"tool": "crm_update_customer",
			"actor": {"sub": "u1", "roles": ["crm.read"]},
		}

	mcp.required_role == "Crm-Customers.Write" with data.tools as _data.tools
		with input as {"tool": "crm_update_customer"}
}

# ── the agent: WHICH MCP CLIENT is calling ───────────────────────────────────
#
# `input.agent` is the MCP client (Claude Code, Cursor, a script), never this
# gateway — the gateway arrives as `input.broker` and is constant on every
# request. Authorization is the USER's (see the domain/tool tests above); these
# tests cover the optional supply-chain control layered on top.

# The same platform data with the opt-in control switched on.
_enforcing := object.union(_data.platform, {"agent_enforcement": "allowlist"})

# ── default posture: "audit" ─────────────────────────────────────────────────

# As shipped, an unknown agent is NOT denied. The identity is recorded (it
# reaches the PDP and the audit row); it does not gate. A self-registering DCR
# client therefore works with no setup — which is the point of DCR.
test_audit_mode_does_not_gate_on_the_agent if {
	mcp.allow with data.platform as _data.platform
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "deadbeef-0000-0000-0000-000000000000", "kind": "dcr"},
			"tool": "crm_list_customers",
			"actor": {"sub": "u1", "roles": ["crm.read"]},
		}
}

# ...but it never weakens the USER's authorization. Audit mode relaxes exactly
# one check; the domain and tool layers are untouched.
test_audit_mode_still_requires_the_user_role if {
	not mcp.allow with data.platform as _data.platform
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "cimd"},
			"tool": "crm_update_customer",
			"args": {"tier": "smb"},
			"actor": {"sub": "u1", "roles": ["crm.read"]},
		}
}

# An absent key means "audit": a data.json written before this knob existed
# keeps working rather than denying every request.
test_absent_enforcement_key_means_audit if {
	_legacy := {"allowed_agents": [], "allowed_dynamic_client_ids": []}

	mcp.allow with data.platform as _legacy
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "deadbeef-0000-0000-0000-000000000000", "kind": "dcr"},
			"tool": "crm_list_customers",
			"actor": {"sub": "u1", "roles": ["crm.read"]},
		}
}

# A TYPO, however, must not silently disable the control you meant to enable.
# Neither mode matches, so everything denies with a reason naming the bad value.
test_misspelled_enforcement_fails_closed if {
	_typo := object.union(_data.platform, {"agent_enforcement": "allowlst"})

	not mcp.allow with data.platform as _typo
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "cimd"},
			"tool": "crm_list_customers",
			"actor": {"sub": "u1", "roles": ["crm.read"]},
		}

	reason := mcp.platform_deny_reason with data.platform as _typo
		with data.tools as _data.tools
		with input as {"tool": "crm_list_customers", "agent": {"id": "x", "kind": "cimd"}}

	contains(reason, "agent_enforcement")
	contains(reason, "allowlst")
}

# ── opt-in posture: "allowlist" ──────────────────────────────────────────────

test_allowlist_admits_a_listed_cimd_agent if {
	mcp.allow with data.platform as _enforcing
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "cimd"},
			"tool": "crm_list_customers",
			"actor": {"sub": "u1", "roles": ["crm.read"]},
		}
}

test_allowlist_denies_an_unlisted_cimd_agent if {
	not mcp.allow with data.platform as _enforcing
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "https://evil.example/cimd.json", "kind": "cimd"},
			"tool": "crm_list_customers",
			"actor": {"sub": "u1", "roles": ["crm.read"]},
		}
}

test_allowlist_admits_a_pinned_dcr_installation if {
	mcp.allow with data.platform as _enforcing
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "9f2c1a4e-0000-0000-0000-000000000000", "kind": "dcr"},
			"tool": "crm_list_customers",
			"actor": {"sub": "u1", "roles": ["crm.read"]},
		}
}

test_allowlist_denies_an_unpinned_dcr_installation if {
	not mcp.allow with data.platform as _enforcing
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "deadbeef-0000-0000-0000-000000000000", "kind": "dcr"},
			"tool": "crm_list_customers",
			"actor": {"sub": "u1", "roles": ["crm.read"]},
		}
}

# `kind` is load-bearing, not decoration: a self-registered client that names
# itself after an allowlisted CIMD URL must not inherit that URL's trust. Only a
# client whose ID FastMCP actually resolved and verified is classified "cimd".
test_allowlist_denies_a_dcr_agent_spoofing_a_cimd_url if {
	not mcp.allow with data.platform as _enforcing
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "dcr"},
			"tool": "crm_list_customers",
			"actor": {"sub": "u1", "roles": ["crm.read"]},
		}
}

# THE REGRESSION TEST. This gateway's own Entra client ID must never authorize
# anything: it is the broker, it arrives on `input.broker`, it is the same value
# on every request — and for a while it was what `input.agent` contained, which
# made this layer a check that could not fail. If this passes as an agent, the
# token swap in app/auth.py:GatewayAzureProvider has stopped preserving the
# client identity.
test_allowlist_denies_the_gateway_as_agent if {
	not mcp.allow with data.platform as _enforcing
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "11111111-2222-3333-4444-555555555555", "kind": "dcr"},
			"broker": "11111111-2222-3333-4444-555555555555",
			"tool": "crm_list_customers",
			"actor": {"sub": "u1", "roles": ["crm.read"]},
		}
}

test_allowlist_denies_a_request_with_no_agent_identity if {
	not mcp.allow with data.platform as _enforcing
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "", "kind": "unknown"},
			"tool": "crm_list_customers",
			"actor": {"sub": "u1", "roles": ["crm.read"]},
		}

	mcp.platform_deny_reason == "no agent identity on the request" with data.platform as _enforcing
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "", "kind": "unknown"},
			"tool": "crm_list_customers",
		}
}

# The deny names the exact value to allowlist, so turning the control on is
# self-service: read the error, paste the string into data.json.
test_deny_reason_names_the_agent if {
	mcp.platform_deny_reason == `agent "deadbeef-0000-0000-0000-000000000000" (dcr) is not on the platform allowlist` with data.platform as _enforcing
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "deadbeef-0000-0000-0000-000000000000", "kind": "dcr"},
			"tool": "crm_list_customers",
		}
}

# ── argument-level (content-based) constraints ───────────────────────────────

test_deny_ledger_over_cap if {
	not mcp.allow with data.platform as _data.platform
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "cimd"},
			"tool": "ledger_post_entry",
			"args": {"amount": 5000000},
			"actor": {
				"sub": "u1",
				"roles": ["ledger.read", "Ledger.Write"],
			},
		}
}

test_allow_ledger_within_cap if {
	mcp.allow with data.platform as _data.platform
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "cimd"},
			"tool": "ledger_post_entry",
			"args": {"amount": 500},
			"actor": {
				"sub": "u1",
				"roles": ["ledger.read", "Ledger.Write"],
			},
		}
}

test_deny_crm_bad_tier if {
	not mcp.allow with data.platform as _data.platform
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "cimd"},
			"tool": "crm_update_customer",
			"args": {"tier": "platinum"},
			"actor": {
				"sub": "u1",
				"roles": ["crm.read", "Crm-Customers.Write"],
			},
		}
}

test_allow_crm_update_with_role if {
	mcp.allow with data.platform as _data.platform
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "cimd"},
			"tool": "crm_update_customer",
			"args": {"tier": "smb"},
			"actor": {
				"sub": "u1",
				"roles": ["crm.read", "Crm-Customers.Write"],
			},
		}
}

# Domain layer is authorized on app roles, not directory groups (overage-immune).
# A principal holding the tool role but NOT the server-access role is denied at
# the domain layer.
test_ledger_negative_amount_over_cap_is_denied if {
	not mcp.allow with data.platform as _data.platform
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "cimd"},
			"tool": "ledger_post_entry",
			"args": {"amount": -5000000},
			"actor": {"sub": "u1", "roles": ["ledger.read", "Ledger.Write"]},
		}
}

test_ledger_missing_amount_is_denied_not_ignored if {
	not mcp.allow with data.platform as _data.platform
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "cimd"},
			"tool": "ledger_post_entry",
			"args": {},
			"actor": {"sub": "u1", "roles": ["ledger.read", "Ledger.Write"]},
		}
}

test_crm_missing_tier_is_denied_not_ignored if {
	not mcp.allow with data.platform as _data.platform
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "cimd"},
			"tool": "crm_update_customer",
			"args": {},
			"actor": {"sub": "u1", "roles": ["crm.read", "Crm-Customers.Write"]},
		}
}

# THE REGRESSION TEST for the required_role/reason mix-up: the caller already
# holds Ledger.Write, so the deny must not claim a missing role — that would
# send an admin to grant a role the caller already has for an amount problem.
test_ledger_over_cap_reason_names_the_amount_not_the_role if {
	input_ := {
		"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "cimd"},
		"tool": "ledger_post_entry",
		"args": {"amount": 5000000},
		"actor": {"sub": "u1", "roles": ["ledger.read", "Ledger.Write"]},
	}

	mcp.required_role == "" with data.platform as _data.platform
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as input_

	reason := mcp.reason with data.platform as _data.platform
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as input_

	contains(reason, "cap")
	not contains(reason, "app role")
}

test_crm_bad_tier_reason_names_the_tier_not_the_role if {
	input_ := {
		"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "cimd"},
		"tool": "crm_update_customer",
		"args": {"tier": "platinum"},
		"actor": {"sub": "u1", "roles": ["crm.read", "Crm-Customers.Write"]},
	}

	mcp.required_role == "" with data.platform as _data.platform
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as input_

	reason := mcp.reason with data.platform as _data.platform
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as input_

	contains(reason, "tier")
	not contains(reason, "app role")
}

test_deny_without_server_role if {
	not mcp.allow with data.platform as _data.platform
		with data.domain as _data.domain
		with data.tools as _data.tools
		with input as {
			"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "cimd"},
			"tool": "crm_update_customer",
			"args": {"tier": "smb"},
			"actor": {"sub": "u1", "roles": ["Crm-Customers.Write"]},
		}
}

# ── server-level access (tools/list downstream-token prefetch) ──────────────
#
# `list_allow` gates minting a downstream credential for a whole backend, before
# any specific tool is known. The tools/list prefetch goes through it so that
# operation is OPA-gated and audited like a real call, not a free pass.

test_list_allow_for_member_with_server_role if {
	mcp.list_allow with data.platform as _data.platform
		with data.domain as _data.domain
		with input as {
			"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "cimd"},
			"server": "mcp-server-a",
			"actor": {"sub": "u1", "roles": ["crm.read"]},
		}
}

test_list_deny_without_server_role if {
	input_ := {
		"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "cimd"},
		"server": "mcp-server-a",
		"actor": {"sub": "u1", "roles": ["ledger.read"]},
	}

	not mcp.list_allow with data.platform as _data.platform
		with data.domain as _data.domain
		with input as input_

	reason := mcp.list_reason with data.platform as _data.platform
		with data.domain as _data.domain
		with input as input_

	contains(reason, "no app role")
}

test_list_deny_for_disabled_server if {
	input_ := {
		"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "cimd"},
		"server": "mcp-server-zzz",
		"actor": {"sub": "u1", "roles": ["crm.read"]},
	}

	not mcp.list_allow with data.platform as _data.platform
		with data.domain as _data.domain
		with input as input_

	reason := mcp.list_reason with data.platform as _data.platform
		with data.domain as _data.domain
		with input as input_

	contains(reason, "is not enabled")
}

# THE REGRESSION TEST for this fix: a DCR client not on the allowlist must not
# be able to mint a downstream credential via tools/list just because the
# tool-call path (platform_allow) isn't involved for a list operation.
test_list_deny_for_unlisted_agent_under_allowlist if {
	input_ := {
		"agent": {"id": "deadbeef-0000-0000-0000-000000000000", "kind": "dcr"},
		"server": "mcp-server-a",
		"actor": {"sub": "u1", "roles": ["crm.read"]},
	}

	not mcp.list_allow with data.platform as _enforcing
		with data.domain as _data.domain
		with input as input_

	reason := mcp.list_reason with data.platform as _enforcing
		with data.domain as _data.domain
		with input as input_

	contains(reason, "is not on the platform allowlist")
}

test_list_allow_for_pinned_dcr_agent_under_allowlist if {
	mcp.list_allow with data.platform as _enforcing
		with data.domain as _data.domain
		with input as {
			"agent": {"id": "9f2c1a4e-0000-0000-0000-000000000000", "kind": "dcr"},
			"server": "mcp-server-a",
			"actor": {"sub": "u1", "roles": ["crm.read"]},
		}
}

test_list_deny_reason_for_bad_enforcement_value if {
	input_ := {
		"agent": {"id": "https://claude.ai/oauth/claude-code-client-metadata", "kind": "cimd"},
		"server": "mcp-server-a",
		"actor": {"sub": "u1", "roles": ["crm.read"]},
	}
	_typo := object.union(_data.platform, {"agent_enforcement": "allowlst"})

	not mcp.list_allow with data.platform as _typo
		with data.domain as _data.domain
		with input as input_

	reason := mcp.list_reason with data.platform as _typo
		with data.domain as _data.domain
		with input as input_

	contains(reason, "agent_enforcement")
}
