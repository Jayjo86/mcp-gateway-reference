"""The three identities on a request must stay three: the actor (the human), the
agent (the MCP client program) and the broker (this gateway).

Collapsing the last two makes platform.rego's allowlist a check that cannot fail,
and puts the wrong middle link in the audit log's delegation chain.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mcp.server.auth.provider import AccessToken

from app.auth import MCP_CLIENT_ID_CLAIM
from app.config import get_settings
from app.principal import (
    AGENT_KIND_CIMD,
    AGENT_KIND_DCR,
    AGENT_KIND_UNKNOWN,
    classify_agent,
    from_access_token,
)

GATEWAY_AZP = "11111111-2222-3333-4444-555555555555"
DCR_CLIENT = "9f2c1a4e-1111-2222-3333-444455556666"
CIMD_CLIENT = "https://claude.ai/oauth/claude-code-client-metadata"


def _token(**claims) -> AccessToken:
    base = {"sub": "user-1", "azp": GATEWAY_AZP, "scp": "access_as_user", "roles": ["crm.read"]}
    return AccessToken(
        token="raw.jwt.here",
        client_id=GATEWAY_AZP,  # JWTVerifier derives this from the Entra token
        scopes=[],
        claims={**base, **claims},
    )


def test_agent_is_the_mcp_client_not_the_gateway():
    p = from_access_token(_token(**{MCP_CLIENT_ID_CLAIM: CIMD_CLIENT}))
    assert p.agent_client_id == CIMD_CLIENT
    assert p.broker_client_id == GATEWAY_AZP
    assert p.agent_client_id != p.broker_client_id


def test_agent_never_falls_back_to_the_broker():
    """When the agent claim is absent the answer is "no agent identity", not
    "the gateway": a fallback to azp/appid/client_id looks harmless and quietly
    restores a tautological allowlist. The empty string denies, as intended."""
    p = from_access_token(_token())
    assert p.agent_client_id == ""
    assert p.agent_kind == AGENT_KIND_UNKNOWN
    assert p.broker_client_id == GATEWAY_AZP


def test_actor_identity_is_unaffected():
    p = from_access_token(_token(upn="igor@example.com", **{MCP_CLIENT_ID_CLAIM: CIMD_CLIENT}))
    assert p.actor_sub == "user-1"
    assert p.actor_upn == "igor@example.com"
    assert p.roles == ["crm.read"]
    assert p.scopes == ["access_as_user"]


@pytest.mark.parametrize(
    ("client_id", "expected"),
    [
        (CIMD_CLIENT, AGENT_KIND_CIMD),
        ("https://cursor.com/.well-known/oauth-client", AGENT_KIND_CIMD),
        (DCR_CLIENT, AGENT_KIND_DCR),
        # http, bare host, and root-path URLs are NOT CIMD — mirrors
        # CIMDClientManager.is_cimd_client_id, which requires https + host + path.
        ("http://claude.ai/cimd.json", AGENT_KIND_DCR),
        ("https://claude.ai", AGENT_KIND_DCR),
        ("https://claude.ai/", AGENT_KIND_DCR),
        ("", AGENT_KIND_UNKNOWN),
    ],
)
def test_agent_kind_classification(client_id, expected):
    assert classify_agent(client_id) == expected


def test_gateway_client_id_is_not_in_the_platform_allowlist():
    """The gateway's own client id must never be allowlisted as an "agent" —
    that is what turns the allowlist into a tautology."""
    platform = json.loads((Path(__file__).parents[2] / "policy" / "data.json").read_text())[
        "platform"
    ]
    allowed = platform["allowed_agents"]
    assert get_settings().gateway_client_id not in allowed
    assert GATEWAY_AZP not in allowed
    assert GATEWAY_AZP not in platform["allowed_dynamic_client_ids"]
    # CIMD entries are the only kind that can ever match a verified agent id.
    for entry in allowed:
        assert classify_agent(entry) == AGENT_KIND_CIMD, (
            f"{entry!r} in allowed_agents is not a CIMD URL, so it can never match; "
            "DCR client ids belong in allowed_dynamic_client_ids"
        )


def test_agent_enforcement_is_a_recognised_mode():
    """platform.rego treats an unrecognised mode as deny-everything, so a typo
    in data.json is an outage. Catch it in CI instead."""
    platform = json.loads((Path(__file__).parents[2] / "policy" / "data.json").read_text())[
        "platform"
    ]
    assert platform.get("agent_enforcement", "audit") in {"audit", "allowlist"}


def test_shipped_enforcement_mode_is_the_one_the_docs_promise():
    """`data.json` is documented in five places as shipping "audit"; pin it.

    This is a value a maintainer flips locally to exercise the allowlist and
    then forgets to flip back — which is exactly what happened once. The cost is
    silent: every document still says agent gating is opt-in and off, while a
    fresh clone denies any client that isn't on the CIMD allowlist. The
    recognised-mode check above does not catch it, because "allowlist" is a
    perfectly valid mode.

    So this pins the shipped VALUE rather than its validity. If you genuinely
    mean to change the default, these change with it:

      * README.md — "Which agents may call" (the `"audit"` (shipped default) bullet)
      * README.md — "Known limitations" (`platform.agent_enforcement` ships as ...)
      * policy/bundle/mcp/platform.rego — "Hence the default is record, don't gate"
      * policy/tests/mcp/policy_test.rego — "as shipped: the agent id is recorded"
      * the three-layer article's data.json snippet and the paragraph under it
    """
    platform = json.loads((Path(__file__).parents[2] / "policy" / "data.json").read_text())[
        "platform"
    ]
    assert platform.get("agent_enforcement", "audit") == "audit", (
        "policy/data.json ships an agent_enforcement value the documentation "
        "contradicts — see this test's docstring for what must change together"
    )
