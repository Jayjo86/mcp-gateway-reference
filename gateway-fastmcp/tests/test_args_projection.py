"""Only the arguments a tool declares may reach the PDP.

Content-based policy needs real values, but sending every argument means tool
payloads — customer names, memos, amounts — cross a process boundary on every
call. Each tool declares the fields its policy actually reads; the rest are
dropped at `build_input`, which is the only place an argument can get out.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.middleware.opa_client import build_input, project_args
from app.principal import Principal
from app.tools import registry

TOOL_REGO = Path(__file__).resolve().parents[2] / "policy" / "bundle" / "mcp" / "tool.rego"

PRINCIPAL = Principal(
    actor_sub="u1",
    actor_upn=None,
    agent_client_id="https://claude.ai/oauth/claude-code-client-metadata",
    agent_kind="cimd",
    broker_client_id="gateway-app-guid",
    scopes=[],
    roles=[],
    groups=[],
    raw_token="header.payload.sig",
)


@pytest.mark.parametrize(
    ("arguments", "declared", "expected"),
    [
        ({"amount": 5, "memo": "secret"}, ("amount",), {"amount": 5}),
        ({"amount": 5}, (), {}),  # nothing declared → nothing sent
        (None, ("amount",), {}),  # no arguments at all
        ({"memo": "secret"}, ("amount",), {}),  # declared but absent → absent
        ({"amount": 0, "tier": "smb"}, ("amount", "tier"), {"amount": 0, "tier": "smb"}),
    ],
)
def test_project_args(arguments, declared, expected):
    assert project_args(arguments, declared) == expected


def test_projection_is_an_allowlist_not_a_denylist():
    # Adding an argument to a tool must not silently start leaking it.
    assert project_args({"amount": 5, "newly_added_pii": "x"}, ("amount",)) == {"amount": 5}


def test_build_input_projects_and_defaults_to_sending_nothing():
    sent = build_input(
        PRINCIPAL,
        tool="ledger_post_entry",
        server="mcp-server-b",
        args_hash="deadbeef",
        args={"account": "ACC-1000", "amount": 5, "memo": "secret"},
    )
    # policy_args omitted → fail closed, send nothing
    assert sent["args"] == {}
    assert sent["args_hash"] == "deadbeef"  # the hash is unaffected either way


def test_build_input_sends_exactly_the_declared_fields():
    sent = build_input(
        PRINCIPAL,
        tool="ledger_post_entry",
        server="mcp-server-b",
        args_hash="deadbeef",
        args={"account": "ACC-1000", "amount": 5, "memo": "secret"},
        policy_args=("amount",),
    )
    assert sent["args"] == {"amount": 5}


def _rego_arg_references() -> dict[str, set[str]]:
    """Which `input.args.X` each tool's rules read, parsed out of tool.rego.

    Crude on purpose — a block-level scan, not a Rego parser. It only has to
    catch the case that matters: a rule constrains an argument the registry
    never declared, so the gateway withholds it and the constraint silently
    stops applying to the value it was written for.
    """
    text = TOOL_REGO.read_text(encoding="utf-8")
    refs: dict[str, set[str]] = {}
    for block in text.split("\n\n"):
        tools = set(re.findall(r'input\.tool == "([a-z_]+)"', block))
        args = set(re.findall(r"input\.args\.([a-z_]+)", block))
        for tool in tools:
            refs.setdefault(tool, set()).update(args)
    return {t: a for t, a in refs.items() if a}


def test_rego_reads_no_argument_the_registry_withholds():
    referenced = _rego_arg_references()
    assert referenced, "parsed no input.args references — the scan or tool.rego moved"

    problems = []
    for tool, args in referenced.items():
        meta = registry.lookup(tool)
        if meta is None:
            problems.append(f"tool.rego constrains {tool!r}, which is not in the registry")
            continue
        undeclared = args - set(meta.policy_args)
        if undeclared:
            problems.append(
                f"{tool}: tool.rego reads input.args.{{{', '.join(sorted(undeclared))}}} "
                f"but registry policy_args={meta.policy_args} — the gateway would withhold "
                "them and the constraint would never fire on a real value"
            )
    assert not problems, "\n".join(problems)


def test_no_tool_declares_an_argument_no_policy_reads():
    # The other direction: a declared field nobody constrains is data sent to the
    # PDP for no reason. Not a security hole, but it is the thing to delete.
    referenced = _rego_arg_references()
    unused = {
        name: set(meta.policy_args) - referenced.get(name, set())
        for name, meta in registry.REGISTRY.items()
        if set(meta.policy_args) - referenced.get(name, set())
    }
    assert not unused, f"policy_args declared but never read by tool.rego: {unused}"
