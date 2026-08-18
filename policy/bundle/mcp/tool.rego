# Layer 3 — tool teams.
#
# Owns per-tool constraints: the elevated app role a tool needs, if any, and any
# tool-specific argument constraints. When a tool needs a role the user doesn't
# hold, `tool_allow` is false and `required_role` is set — the gateway turns that
# into a hard deny naming the role to request. App roles are admin-assigned in
# Entra, so there is no runtime step-up.
#
# Per-tool sections owned by the owning tool team via CODEOWNERS.
package mcp

# The app role configured for a tool, "" if none. Internal — `role_ok` reads this
# directly, and the exported `required_role` below is a separate rule so it can
# be conditioned on `role_ok` without creating a cycle.
default _configured_role := ""

_configured_role := data.tools[input.tool].required_role if {
	data.tools[input.tool].required_role
}

default tool_allow := false

tool_allow if {
	role_ok
	args_ok
}

# ── app-role requirement ────────────────────────────────────────────────────

role_ok if _configured_role == ""

role_ok if {
	_configured_role != ""
	_configured_role in input.actor.roles
}

# Exported only when the role check is what actually failed. platform.rego turns
# a non-empty `required_role` into MissingEntitlement — if this fired whenever a
# tool merely *has* a configured role, an args-only denial would tell an admin to
# grant a role the caller already holds.
default required_role := ""

required_role := _configured_role if not role_ok

# ── per-tool argument constraints (content-based authorization) ─────────────
#
# These read the actual arguments from `input.args`, sent by the gateway PEP and
# never persisted. Default allow; specific tools tighten it below.
#
# Check presence via `object.keys` before checking the value, so a missing or
# wrong-typed argument fails CLOSED. Two traps otherwise:
#
#   1. `input.args.amount` on an absent key is undefined, so a naive
#      `> max_amount` comparison never fires and `default args_ok := true` wins.
#   2. `not is_number(input.args.amount)` looks like the fix but isn't: with the
#      key absent, the builtin call has no result to negate, so `not <that>` is
#      also undefined rather than true and the constraint still never fires.
#
# Membership over a concrete key set is always defined, present or not.

default args_ok := true

_ledger_amount_present if "amount" in object.keys(input.args)

# ledger_post_entry: amount must be present, numeric, and within the cap in
# either direction — a large negative posting is as significant as a positive one.
args_ok := false if {
	input.tool == "ledger_post_entry"
	not _ledger_amount_present
}

args_ok := false if {
	input.tool == "ledger_post_entry"
	_ledger_amount_present
	not is_number(input.args.amount)
}

args_ok := false if {
	input.tool == "ledger_post_entry"
	_ledger_amount_present
	is_number(input.args.amount)
	abs(input.args.amount) > data.tools.ledger_post_entry.max_amount
}

_crm_tier_present if "tier" in object.keys(input.args)

# crm_update_customer: tier must be present and one of the allowed values.
args_ok := false if {
	input.tool == "crm_update_customer"
	not _crm_tier_present
}

args_ok := false if {
	input.tool == "crm_update_customer"
	_crm_tier_present
	not is_string(input.args.tier)
}

args_ok := false if {
	input.tool == "crm_update_customer"
	_crm_tier_present
	is_string(input.args.tier)
	allowed := data.tools.crm_update_customer.allowed_tiers
	not input.args.tier in allowed
}

# ── argument-level deny reason ──────────────────────────────────────────────
#
# Lets platform.rego name the args failure instead of falling through to the
# generic "denied" when no role is at issue.

default args_deny_reason := ""

args_deny_reason := "amount is required" if {
	input.tool == "ledger_post_entry"
	not _ledger_amount_present
}

args_deny_reason := "amount must be a number" if {
	input.tool == "ledger_post_entry"
	_ledger_amount_present
	not is_number(input.args.amount)
}

args_deny_reason := sprintf("amount exceeds the %v cap", [data.tools.ledger_post_entry.max_amount]) if {
	input.tool == "ledger_post_entry"
	_ledger_amount_present
	is_number(input.args.amount)
	abs(input.args.amount) > data.tools.ledger_post_entry.max_amount
}

args_deny_reason := "tier is required" if {
	input.tool == "crm_update_customer"
	not _crm_tier_present
}

args_deny_reason := "tier must be a string" if {
	input.tool == "crm_update_customer"
	_crm_tier_present
	not is_string(input.args.tier)
}

args_deny_reason := sprintf("tier must be one of %v", [data.tools.crm_update_customer.allowed_tiers]) if {
	input.tool == "crm_update_customer"
	_crm_tier_present
	is_string(input.args.tier)
	allowed := data.tools.crm_update_customer.allowed_tiers
	not input.args.tier in allowed
}
