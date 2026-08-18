"""The PDP call: ask the OPA sidecar for an allow/deny decision.

OPA is the decision point, this middleware is the enforcement point. We POST the
request context and read back ``data.mcp.allow`` / ``reason`` /
``required_role``. The input shape matches the three-layer bundle in
policy/bundle/mcp/. Any error talking to OPA is a deny.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx2

from app.config import Settings
from app.principal import Principal

logger = logging.getLogger("gateway.opa_client")


@dataclass
class Decision:
    allow: bool
    reason: str = ""
    required_role: str | None = None  # the gateway app role the principal lacks


@dataclass
class ListDecision:
    """Whether a principal may enumerate a backend's tools. No specific tool is
    known yet, so this comes from `list_allow` / `list_reason`, not `allow`."""

    allow: bool
    reason: str = ""


def project_args(arguments: dict | None, policy_args: tuple[str, ...]) -> dict:
    """Narrow tool arguments to the fields the tool declares its policy needs.

    Allowlist, not denylist: a field nobody declared is withheld, so adding an
    argument to a tool cannot silently start leaking it to the PDP.
    """
    if not policy_args:
        return {}
    return {k: v for k, v in (arguments or {}).items() if k in policy_args}


def build_input(
    principal: Principal,
    *,
    tool: str,
    server: str,
    args_hash: str,
    args: dict | None = None,
    policy_args: tuple[str, ...] = (),
) -> dict:
    """Shape the OPA input document for a tool call.

    Takes the *raw* ``args`` and the tool's declared ``policy_args``, and does
    the projection here rather than trusting callers to pre-filter — this is the
    only place a tool argument can reach the PDP, so it is the only place the
    rule has to hold. ``args_hash`` is over the full set and is what the audit
    log stores.
    """
    return {
        "tool": tool,
        "server": server,
        # The agent is the MCP client; `kind` tells policy whether that id was
        # verified (cimd) or merely self-registered (dcr). The broker is this
        # gateway — constant by design, passed for symmetry, never an
        # authorization input.
        "agent": {"id": principal.agent_client_id, "kind": principal.agent_kind},
        "broker": principal.broker_client_id,
        "args_hash": args_hash,
        "args": project_args(args, policy_args),
        "actor": {
            "sub": principal.actor_sub,
            "upn": principal.actor_upn,
            "scopes": principal.scopes,
            "roles": principal.roles,
            "groups": principal.groups,
        },
    }


def build_list_input(principal: Principal, *, server: str) -> dict:
    """Shape the OPA input for a list decision.

    Deliberately carries no `tool` or `args`: a list precedes any specific tool
    being known, so it is evaluated against `list_allow` / `list_reason`.
    """
    return {
        "server": server,
        "agent": {"id": principal.agent_client_id, "kind": principal.agent_kind},
        "broker": principal.broker_client_id,
        "actor": {
            "sub": principal.actor_sub,
            "upn": principal.actor_upn,
            "scopes": principal.scopes,
            "roles": principal.roles,
            "groups": principal.groups,
        },
    }


class OpaClient:
    def __init__(self, settings: Settings, *, http: httpx2.AsyncClient | None = None) -> None:
        self._url = f"{settings.opa_url.rstrip('/')}/{settings.opa_decision_path.strip('/')}"
        self._http = http or httpx2.AsyncClient(timeout=5.0)
        self._owns_http = http is None

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def _query(self, opa_input: dict) -> dict | None:
        """POST the input and return the `data.mcp` result document, or None if
        the PDP is unreachable or the response is malformed."""
        try:
            resp = await self._http.post(self._url, json={"input": opa_input})
            resp.raise_for_status()
            return resp.json().get("result", {})
        except (httpx2.HTTPError, ValueError) as exc:
            # The detail goes to the log, not the audit `reason` — that field is
            # a stable operator-facing string, not a place for transport errors.
            logger.warning("OPA request failed, denying by default: %s", exc)
            return None

    async def evaluate(self, opa_input: dict) -> Decision:
        result = await self._query(opa_input)
        if result is None:
            return Decision(allow=False, reason="OPA unavailable, denied")

        return Decision(
            allow=bool(result.get("allow", False)),
            reason=result.get("reason", "denied"),
            required_role=result.get("required_role") or None,
        )

    async def evaluate_list_access(self, opa_input: dict) -> ListDecision:
        result = await self._query(opa_input)
        if result is None:
            return ListDecision(allow=False, reason="OPA unavailable, denied")

        return ListDecision(
            allow=bool(result.get("list_allow", False)),
            reason=result.get("list_reason", "denied"),
        )
