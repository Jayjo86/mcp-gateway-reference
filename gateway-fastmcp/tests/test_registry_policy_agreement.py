"""Registry <-> policy/data.json agreement.

`app/tools/registry.py` and `policy/data.json` are two hand-maintained copies of
the same fact — which server a tool lives on, which role it needs. Drift between
them doesn't surface until that specific tool/role combination is exercised.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.tools import registry

DATA_JSON = Path(__file__).resolve().parents[2] / "policy" / "data.json"


def _policy_tools() -> dict:
    return json.loads(DATA_JSON.read_text())["tools"]


def test_every_registry_tool_is_declared_in_policy_data():
    policy_tools = _policy_tools()
    missing = set(registry.REGISTRY) - set(policy_tools)
    assert not missing, f"tools in registry.py but missing from data.json: {missing}"


def test_every_policy_tool_is_in_the_registry():
    policy_tools = _policy_tools()
    extra = set(policy_tools) - set(registry.REGISTRY)
    assert not extra, f"tools in data.json but missing from registry.py: {extra}"


def test_server_and_required_role_agree():
    policy_tools = _policy_tools()
    mismatches = []
    for name, meta in registry.REGISTRY.items():
        entry = policy_tools.get(name)
        if entry is None:
            continue  # already reported by test_every_registry_tool_is_declared_in_policy_data
        if entry.get("server") != meta.server:
            mismatches.append(
                f"{name}: registry.server={meta.server!r} != data.json.server={entry.get('server')!r}"
            )
        # Absent key in data.json == None, same as the registry's default.
        policy_role = entry.get("required_role")
        if policy_role != meta.required_role:
            mismatches.append(
                f"{name}: registry.required_role={meta.required_role!r} != "
                f"data.json.required_role={policy_role!r}"
            )
    assert not mismatches, "\n".join(mismatches)
