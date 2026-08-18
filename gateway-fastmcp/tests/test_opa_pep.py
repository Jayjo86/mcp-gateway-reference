"""PEP ordering: an OPA deny blocks the call before any downstream token is
minted, and a downstream exchange failure is itself a deny."""

from __future__ import annotations

import mcp.types as mt
import pytest
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import AccessToken
from fastmcp.server.middleware import MiddlewareContext

import app.middleware.opa_pep as pep_mod
from app.config import get_settings
from app.downstream.base import DownstreamError
from app.middleware.opa_client import Decision, ListDecision
from app.middleware.opa_pep import MissingEntitlement, OpaPep


class FakeOpa:
    def __init__(self, decision: Decision, list_decision: ListDecision | None = None) -> None:
        self.decision = decision
        # Defaults to allow so existing on_list_tools tests, which don't care
        # about the list-access gate, don't all need updating for it.
        self.list_decision = list_decision or ListDecision(allow=True, reason="ok")
        self.last_input = None
        self.last_list_inputs = []

    async def evaluate(self, opa_input):
        self.last_input = opa_input
        return self.decision

    async def evaluate_list_access(self, opa_input):
        self.last_list_inputs.append(opa_input)
        return self.list_decision


class SpyDownstream:
    def __init__(self, *, fail: bool = False) -> None:
        self.calls = 0
        self.fail = fail
        self.last_scope = "__unset__"

    async def token_for(self, *, principal, backend, scope=None):
        self.calls += 1
        self.last_scope = scope
        if self.fail:
            raise DownstreamError("exchange failed")
        return "DOWNSTREAM"

    async def aclose(self): ...


class SpyAudit:
    def __init__(self) -> None:
        self.records = []

    async def write(self, record):
        self.records.append(record)


def _ctx(tool="server_a_crm_list_customers", arguments=None):
    msg = mt.CallToolRequestParams(
        name=tool, arguments={"a": 1} if arguments is None else arguments
    )
    return MiddlewareContext(message=msg, method="tools/call")


# The agent (the MCP client) and the broker (this gateway) are different values,
# so the fixtures below must not use the same string for both.
MCP_CLIENT = "https://claude.ai/oauth/claude-code-client-metadata"
GATEWAY_AZP = "11111111-2222-3333-4444-555555555555"


def _token():
    return AccessToken(
        token="header.payload.sig",
        client_id=GATEWAY_AZP,  # JWTVerifier derives this from the Entra token
        scopes=[],
        subject="user-1",
        claims={
            "sub": "user-1",
            "azp": GATEWAY_AZP,
            "scp": "",
            "mcp_client_id": MCP_CLIENT,
        },
    )


def _pep(opa, downstream, audit):
    return OpaPep(settings=get_settings(), opa=opa, downstream=downstream, audit=audit)


async def _call_next(_ctx):
    return "UPSTREAM_RESULT"


@pytest.fixture(autouse=True)
def patch_token(monkeypatch):
    monkeypatch.setattr(pep_mod, "get_access_token", _token)
    monkeypatch.setattr(pep_mod, "get_http_headers", lambda **k: {})


async def test_deny_blocks_before_token_mint():
    downstream = SpyDownstream()
    audit = SpyAudit()
    pep = _pep(FakeOpa(Decision(allow=False, reason="nope")), downstream, audit)

    with pytest.raises(ToolError):
        await pep.on_call_tool(_ctx(), _call_next)

    assert downstream.calls == 0  # no token ever minted on a deny
    assert audit.records[-1].opa_decision is False


async def test_missing_role_raises_missing_entitlement():
    pep = _pep(
        FakeOpa(Decision(allow=False, reason="missing role", required_role="Ledger.Write")),
        SpyDownstream(),
        SpyAudit(),
    )
    with pytest.raises(MissingEntitlement) as ei:
        await pep.on_call_tool(_ctx(), _call_next)
    assert ei.value.role == "Ledger.Write"


async def test_allow_mints_then_calls_next():
    downstream = SpyDownstream()
    audit = SpyAudit()
    pep = _pep(FakeOpa(Decision(allow=True, reason="ok")), downstream, audit)

    result = await pep.on_call_tool(_ctx(), _call_next)

    assert result == "UPSTREAM_RESULT"
    assert downstream.calls == 1
    assert audit.records[-1].opa_decision is True
    assert audit.records[-1].downstream_token_aud == "api://mcp-server-a"
    assert audit.records[-1].status == "ok"
    # the PEP requests the tool's least-privilege downstream scope, not `.default`
    assert downstream.last_scope == "api://mcp-server-a/Customers.Read"


async def test_audit_trace_id_is_server_generated_and_non_null():
    # even when the client sends NO traceparent, the audit row still gets a
    # non-null, server-generated trace id (the audit identity is never optional).
    audit = SpyAudit()
    pep = _pep(FakeOpa(Decision(allow=True, reason="ok")), SpyDownstream(), audit)

    await pep.on_call_tool(_ctx(), _call_next)

    rec = audit.records[-1]
    assert rec.trace_id is not None
    assert len(rec.trace_id) == 32 and int(rec.trace_id, 16) != 0
    assert rec.client_trace_id is None  # no incoming traceparent to correlate


async def test_client_traceparent_is_never_the_audit_identity(monkeypatch):
    # a client-supplied traceparent must NOT become the audit trace_id; it is
    # only recorded separately (client_trace_id) for correlation.
    client_tid = "a" * 32
    monkeypatch.setattr(
        pep_mod,
        "get_http_headers",
        lambda **k: {"traceparent": f"00-{client_tid}-bbbbbbbbbbbbbbbb-01"},
    )
    audit = SpyAudit()
    pep = _pep(FakeOpa(Decision(allow=True, reason="ok")), SpyDownstream(), audit)

    await pep.on_call_tool(_ctx(), _call_next)

    rec = audit.records[-1]
    assert rec.trace_id is not None and rec.trace_id != client_tid
    assert rec.client_trace_id == client_tid  # kept only for correlation


async def test_downstream_failure_denies():
    downstream = SpyDownstream(fail=True)
    audit = SpyAudit()
    pep = _pep(FakeOpa(Decision(allow=True, reason="ok")), downstream, audit)

    with pytest.raises(ToolError):
        await pep.on_call_tool(_ctx(), _call_next)

    assert audit.records[-1].status == "error"


async def test_opa_sees_the_mcp_client_as_the_agent():
    # The PDP must be able to tell one MCP client from another. If `agent.id`
    # were the gateway's own id, platform.rego's allowlist could never deny.
    opa = FakeOpa(Decision(allow=True, reason="ok"))
    await _pep(opa, SpyDownstream(), SpyAudit()).on_call_tool(_ctx(), _call_next)

    assert opa.last_input["agent"] == {"id": MCP_CLIENT, "kind": "cimd"}
    assert opa.last_input["broker"] == GATEWAY_AZP


async def test_audit_row_records_both_hops_of_the_delegation_chain():
    audit = SpyAudit()
    await _pep(FakeOpa(Decision(allow=True, reason="ok")), SpyDownstream(), audit).on_call_tool(
        _ctx(), _call_next
    )

    rec = audit.records[-1]
    assert rec.agent_client_id == MCP_CLIENT  # who called
    assert rec.agent_kind == "cimd"  # and how much that is worth
    assert rec.broker_client_id == GATEWAY_AZP  # via which broker
    assert rec.actor_sub == "user-1"  # on whose behalf


async def test_only_declared_arguments_reach_the_pdp():
    # crm_list_customers declares no policy_args, so nothing is sent — the PDP
    # gets the hash and the identity, not the payload.
    opa = FakeOpa(Decision(allow=True, reason="ok"))
    await _pep(opa, SpyDownstream(), SpyAudit()).on_call_tool(_ctx(), _call_next)
    assert opa.last_input["args"] == {}
    assert "args_hash" in opa.last_input


async def test_declared_arguments_reach_the_pdp_and_others_do_not():
    # ledger_post_entry declares policy_args=("amount",) because tool.rego caps
    # it. `memo` is not policy-relevant and must not cross to the PDP.
    opa = FakeOpa(Decision(allow=True, reason="ok"))
    ctx = _ctx("server_b_ledger_post_entry", {"account": "ACC-1000", "amount": 5, "memo": "secret"})
    await _pep(opa, SpyDownstream(), SpyAudit()).on_call_tool(ctx, _call_next)
    assert opa.last_input["args"] == {"amount": 5}


async def test_args_hash_covers_the_full_argument_set():
    # The hash is the audit correlator: it must identify the call that ran, not
    # the projection sent to the PDP.
    opa = FakeOpa(Decision(allow=True, reason="ok"))
    audit = SpyAudit()
    args = {"account": "ACC-1000", "amount": 5, "memo": "secret"}
    ctx = _ctx("server_b_ledger_post_entry", args)
    await _pep(opa, SpyDownstream(), audit).on_call_tool(ctx, _call_next)

    assert audit.records[-1].tool_args_hash == pep_mod._args_hash(args)
    assert audit.records[-1].tool_args_hash != pep_mod._args_hash({"amount": 5})


async def test_audit_failure_does_not_mask_result():
    class FailingAudit:
        async def write(self, record):
            raise RuntimeError("db down")

    pep = _pep(FakeOpa(Decision(allow=True, reason="ok")), SpyDownstream(), FailingAudit())
    # the tool result must still come back even though the audit write blew up
    result = await pep.on_call_tool(_ctx(), _call_next)
    assert result == "UPSTREAM_RESULT"


async def test_read_resource_is_fail_closed():
    audit = SpyAudit()
    pep = _pep(FakeOpa(Decision(allow=True, reason="ok")), SpyDownstream(), audit)
    msg = mt.ReadResourceRequestParams(uri="resource://server_a/secret")
    ctx = MiddlewareContext(message=msg, method="resources/read")
    with pytest.raises(ToolError):
        await pep.on_read_resource(ctx, _call_next)
    assert audit.records[-1].opa_decision is False


async def test_get_prompt_is_fail_closed():
    audit = SpyAudit()
    pep = _pep(FakeOpa(Decision(allow=True, reason="ok")), SpyDownstream(), audit)
    msg = mt.GetPromptRequestParams(name="server_a_some_prompt")
    ctx = MiddlewareContext(message=msg, method="prompts/get")
    with pytest.raises(ToolError):
        await pep.on_get_prompt(ctx, _call_next)
    assert audit.records[-1].opa_decision is False


async def test_resolve_is_exact_match_not_prefix():
    # Prefix matching would let a `server_a` namespace swallow names from a
    # `server_ab` one, so resolution goes through the exact registered set.
    pep = _pep(FakeOpa(Decision(allow=True, reason="ok")), SpyDownstream(), SpyAudit())
    bare, backend = pep._resolve("server_a_crm_list_customers")
    assert bare == "crm_list_customers" and backend.name == "mcp-server-a"
    # a name that merely shares the prefix but isn't registered stays unresolved
    bare, backend = pep._resolve("server_ab_widget")
    assert backend is None


async def test_list_tools_denies_a_backend_without_the_domain_role():
    # A principal OPA won't clear for a backend gets no credential minted for
    # it — a list is not a free pass.
    opa = FakeOpa(
        Decision(allow=True, reason="ok"),
        list_decision=ListDecision(allow=False, reason="no app role permits access to X"),
    )
    downstream = SpyDownstream()
    audit = SpyAudit()
    pep = _pep(opa, downstream, audit)

    async def _list_next(_ctx):
        return []

    ctx = MiddlewareContext(message=object(), method="tools/list")
    await pep.on_list_tools(ctx, _list_next)

    assert downstream.calls == 0  # no policy decision → no credential minted
    rows = [r for r in audit.records if r.tool_name == "tools/list"]
    assert len(rows) == 2  # one audit row per backend, both denied
    assert all(r.opa_decision is False and r.status == "denied" for r in rows)


async def test_list_tools_mints_only_for_backends_opa_clears_and_audits_each():
    opa = FakeOpa(Decision(allow=True, reason="ok"))  # list_decision defaults to allow
    downstream = SpyDownstream()
    audit = SpyAudit()
    pep = _pep(opa, downstream, audit)

    async def _list_next(_ctx):
        return []

    ctx = MiddlewareContext(message=object(), method="tools/list")
    await pep.on_list_tools(ctx, _list_next)

    assert downstream.calls == 2  # one mint per backend, both cleared
    rows = [r for r in audit.records if r.tool_name == "tools/list"]
    assert len(rows) == 2
    assert all(r.opa_decision is True and r.status == "ok" for r in rows)


async def test_list_tools_asks_opa_per_backend_with_no_specific_tool():
    opa = FakeOpa(Decision(allow=True, reason="ok"))
    pep = _pep(opa, SpyDownstream(), SpyAudit())

    async def _list_next(_ctx):
        return []

    ctx = MiddlewareContext(message=object(), method="tools/list")
    await pep.on_list_tools(ctx, _list_next)

    assert len(opa.last_list_inputs) == 2  # mcp-server-a, mcp-server-b
    for inp in opa.last_list_inputs:
        assert inp["agent"] == {"id": MCP_CLIENT, "kind": "cimd"}
        assert "tool" not in inp  # a list decision precedes any specific tool


async def test_list_tools_logs_partial_on_prefetch_failure(caplog):
    import logging

    pep = _pep(
        FakeOpa(Decision(allow=True, reason="ok")),
        SpyDownstream(fail=True),  # every backend token mint fails
        SpyAudit(),
    )

    async def _list_next(_ctx):
        return []

    ctx = MiddlewareContext(message=object(), method="tools/list")
    with caplog.at_level(logging.WARNING, logger="gateway.pep"):
        await pep.on_list_tools(ctx, _list_next)
    # per-backend failures are logged, and the partial state is surfaced as a
    # WARNING rather than a silently short list.
    assert any("token mint failed" in r.message for r in caplog.records)
    assert any("PARTIAL" in r.message for r in caplog.records)


class _ListedTool:
    """Minimal stand-in for what call_next returns from the mounted proxies."""

    def __init__(self, name: str) -> None:
        self.name = name


def _listing(*names):
    async def _list_next(_ctx):
        return [_ListedTool(n) for n in names]

    return _list_next


def _list_ctx():
    return MiddlewareContext(message=object(), method="tools/list")


async def test_governed_tools_are_listed():
    pep = _pep(FakeOpa(Decision(allow=True, reason="ok")), SpyDownstream(), SpyAudit())
    tools = await pep.on_list_tools(
        _list_ctx(), _listing("server_a_crm_list_customers", "server_b_ledger_get_balance")
    )
    assert [t.name for t in tools] == [
        "server_a_crm_list_customers",
        "server_b_ledger_get_balance",
    ]


async def test_ungoverned_tool_is_hidden_and_reported(caplog):
    # A tool a backend serves but registry.py / data.json don't know about would
    # be denied as unknown if called. Listing it advertises a tool that can never
    # work, so it is dropped — and said out loud, once.
    import logging

    pep = _pep(FakeOpa(Decision(allow=True, reason="ok")), SpyDownstream(), SpyAudit())
    with caplog.at_level(logging.WARNING, logger="gateway.pep"):
        tools = await pep.on_list_tools(
            _list_ctx(), _listing("server_a_crm_list_customers", "server_a_undeclared_thing")
        )

    assert [t.name for t in tools] == ["server_a_crm_list_customers"]
    warnings = [r.getMessage() for r in caplog.records if "no entry" in r.getMessage()]
    assert len(warnings) == 1
    assert "server_a_undeclared_thing" in warnings[0]


async def test_ungoverned_warning_is_not_repeated_per_session(caplog):
    import logging

    pep = _pep(FakeOpa(Decision(allow=True, reason="ok")), SpyDownstream(), SpyAudit())
    with caplog.at_level(logging.WARNING, logger="gateway.pep"):
        for _ in range(3):  # an agent reconnecting and re-listing
            await pep.on_list_tools(_list_ctx(), _listing("server_a_undeclared_thing"))

    assert sum("no entry" in r.getMessage() for r in caplog.records) == 1


async def test_calling_an_ungoverned_tool_is_still_denied_and_audited():
    audit = SpyAudit()
    downstream = SpyDownstream()
    pep = _pep(FakeOpa(Decision(allow=True, reason="ok")), downstream, audit)

    with pytest.raises(ToolError):
        await pep.on_call_tool(_ctx("server_a_undeclared_thing"), _call_next)

    assert downstream.calls == 0
    assert audit.records[-1].opa_decision is False
    assert audit.records[-1].status == "denied"


# ── every hook audits, on every path ────────────────────────────────────────
#
# The reason OpaPep funnels through a single _authorize/_write: a new MCP hook
# must not be able to ship without an audit row. This is the test that fails if
# one does.


async def _drive(pep, hook_name):
    """Invoke one hook with a plausible context; swallow the deny it may raise."""
    hooks = {
        "on_call_tool": (_ctx(), _call_next),
        "on_call_tool_unknown": (_ctx("server_a_nope"), _call_next),
        "on_list_tools": (_list_ctx(), _listing()),
        "on_list_resources": (
            MiddlewareContext(message=object(), method="resources/list"),
            _call_next,
        ),
        "on_list_prompts": (MiddlewareContext(message=object(), method="prompts/list"), _call_next),
        "on_read_resource": (
            MiddlewareContext(
                message=mt.ReadResourceRequestParams(uri="resource://server_a/secret"),
                method="resources/read",
            ),
            _call_next,
        ),
        "on_get_prompt": (
            MiddlewareContext(
                message=mt.GetPromptRequestParams(name="server_a_some_prompt"),
                method="prompts/get",
            ),
            _call_next,
        ),
    }
    ctx, nxt = hooks[hook_name]
    method = getattr(pep, hook_name.removesuffix("_unknown"))
    try:
        await method(ctx, nxt)
    except ToolError:
        pass


@pytest.mark.parametrize(
    "hook",
    [
        "on_call_tool",
        "on_call_tool_unknown",
        "on_list_tools",
        "on_list_resources",
        "on_list_prompts",
        "on_read_resource",
        "on_get_prompt",
    ],
)
async def test_every_hook_writes_an_audit_row(hook):
    audit = SpyAudit()
    await _drive(_pep(FakeOpa(Decision(allow=True, reason="ok")), SpyDownstream(), audit), hook)
    assert audit.records, f"{hook} completed without writing an audit row"
    for rec in audit.records:
        assert rec.trace_id and len(rec.trace_id) == 32
        assert rec.status in {"ok", "denied", "error", "upstream_error"}
