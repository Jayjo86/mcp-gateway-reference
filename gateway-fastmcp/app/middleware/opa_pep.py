"""The Policy Enforcement Point — OPA on every call and every list.

Order is the whole point: OPA decides first, and only on an allow does a
downstream token come into existence. A denied call never causes a backend token
to exist and never reaches a backend, and a downstream exchange failure is a
deny. The inbound token is never put on the wire; the token the PEP stashes per
backend is the only credential the proxy client uses.

That applies to list operations too, per backend (``data.mcp.list_allow``), not
just ``on_call_tool``.

Every hook describes what it wants as an ``Operation`` and hands it to
``_authorize``, which owns decide → mint → audit. There is exactly one call to
``_write`` in this module, so a new MCP operation cannot accidentally ship
without an audit row.

Tools arrive namespaced by mount (``server_a_crm_list_customers``); we split the
namespace off to recover the bare name for the registry, OPA and the backend.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass

import jwt
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_access_token, get_http_headers
from fastmcp.server.middleware import Middleware, MiddlewareContext

from app.config import BackendServer, Settings
from app.context import downstream_tokens
from app.downstream.base import DownstreamError, DownstreamTokenProvider
from app.middleware.audit import AuditRecord, AuditWriter
from app.middleware.opa_client import OpaClient, build_input, build_list_input
from app.principal import AGENT_KIND_UNKNOWN, Principal, from_access_token
from app.tools import registry

logger = logging.getLogger("gateway.pep")

_ANONYMOUS = Principal("", None, "", AGENT_KIND_UNKNOWN, "", [], [], [], "")


class MissingEntitlement(ToolError):
    """OPA denied because the principal lacks the required gateway app role.

    App roles are admin-assigned in Entra, so there is no runtime consent or
    step-up: this is a hard deny that names the role to request.
    """

    def __init__(self, role: str) -> None:
        super().__init__(f'missing_entitlement: requires app role "{role}"')
        self.role = role


@dataclass(frozen=True)
class Trace:
    """The audit identity for one operation, plus the caller's trace to join on."""

    trace_id: str
    client_trace_id: str | None

    @classmethod
    def new(cls) -> Trace:
        return cls(_new_trace_id(), _client_trace_id())


@dataclass(frozen=True)
class Operation:
    """What the PEP is being asked to authorize.

    One shape for every MCP operation, so ``_authorize`` can own the decision and
    the audit row instead of each hook re-deriving them.
    """

    method: str  # the MCP method, e.g. "tools/call" — audited as the row's tool_name for lists
    target: str  # bare tool name, resource uri, or the method name for lists
    backend: BackendServer | None = None
    meta: registry.ToolMeta | None = None
    args: dict | None = None
    # False → this operation is not covered by the policy model, so it is denied
    # before OPA is consulted rather than passed through unauthorized.
    modeled: bool = True

    @property
    def server(self) -> str:
        return self.backend.name if self.backend is not None else "unknown"

    @property
    def audience(self) -> str | None:
        return self.backend.audience if self.backend is not None else None


class OpaPep(Middleware):
    def __init__(
        self,
        *,
        settings: Settings,
        opa: OpaClient,
        downstream: DownstreamTokenProvider,
        audit: AuditWriter,
    ) -> None:
        self._s = settings
        self._opa = opa
        self._downstream = downstream
        self._audit = audit
        backends = settings.backends()
        self._namespaces = {b.namespace: b for b in backends.values()}
        # Names already reported by _warn_ungoverned, so a reconnecting agent
        # doesn't repeat the warning on every session.
        self._warned_ungoverned: set[str] = set()
        # Exact resolution table: mounted name (``<namespace>_<tool>``) → (bare
        # tool name, backend). Built from the registry so resolution is
        # unambiguous — a prefix match on ``server_a_`` would also swallow a
        # ``server_ab`` namespace, and splitting on the first ``_`` breaks
        # because namespaces contain underscores themselves. A collision is a
        # configuration error and fails fast here.
        self._by_namespaced: dict[str, tuple[str, BackendServer]] = {}
        for bare, meta in registry.REGISTRY.items():
            backend = backends.get(meta.server)
            if backend is None:
                continue
            full = f"{backend.namespace}_{bare}"
            existing = self._by_namespaced.get(full)
            if existing is not None and existing[1] is not backend:
                raise RuntimeError(
                    f"ambiguous mounted tool name {full!r}: maps to both "
                    f"{existing[1].name!r} and {backend.name!r}"
                )
            self._by_namespaced[full] = (bare, backend)

    def _resolve(self, namespaced: str) -> tuple[str, BackendServer | None]:
        """(bare tool name, backend) for a mounted tool name; backend is None if
        the name isn't one we registered."""
        return self._by_namespaced.get(namespaced, (namespaced, None))

    # ── the chokepoint ──────────────────────────────────────────────────────

    async def _authorize(
        self,
        op: Operation,
        principal: Principal,
        context: MiddlewareContext,
        call_next,
    ):
        """Decide, mint on allow, proceed, audit. Every path writes one row.

        Nothing else in this class talks to OPA, the downstream provider or the
        audit writer for a single-target operation. A new MCP hook gets the
        ordering guarantee by delegating here rather than by re-implementing it.
        """
        trace = Trace.new()

        refusal = self._pre_check(op)
        if refusal is not None:
            await self._write(op, principal, trace, allow=False, reason=refusal, status="denied")
            raise ToolError(self._refusal_message(op))

        logger.debug(
            "%s  target=%s  backend=%s  principal=%s  scopes=%s",
            op.method,
            op.target,
            op.server,
            principal.actor_sub,
            principal.scopes,
        )
        # INFO on purpose: this is the line that tells an operator which MCP
        # client is actually calling, and that value is what goes into
        # policy/data.json's allowlist. A DCR client id can't be guessed — this
        # gateway mints it at registration time.
        logger.info(
            "agent=%s kind=%s broker=%s tool=%s",
            principal.agent_client_id or "<none>",
            principal.agent_kind,
            principal.broker_client_id,
            op.target,
        )

        # Only the arguments this tool's policy declares it needs reach the PDP;
        # the audit row keeps the hash of the full set. See opa_client.build_input.
        decision = await self._opa.evaluate(
            build_input(
                principal,
                tool=op.target,
                server=op.server,
                args_hash=_args_hash(op.args),
                args=op.args,
                policy_args=op.meta.policy_args if op.meta else (),
            )
        )
        logger.debug("OPA decision  allow=%s  reason=%s", decision.allow, decision.reason)
        if not decision.allow:
            await self._write(
                op, principal, trace, allow=False, reason=decision.reason, status="denied"
            )
            if decision.required_role:
                raise MissingEntitlement(decision.required_role)
            raise ToolError(f"authorization denied: {decision.reason}")

        # Allowed — only now does a downstream token come into existence, scoped
        # to the tool's least-privilege scope under OBO. The registry holds only
        # the suffix ("Ledger.Write"); the backend's audience supplies the
        # Application ID URI prefix. M2M ignores it and uses `.default`.
        assert op.backend is not None and op.meta is not None  # guaranteed by _pre_check
        scope = op.backend.scope_for(op.meta.downstream_scope) if op.meta.downstream_scope else None
        try:
            ds_token = await self._downstream.token_for(
                principal=principal, backend=op.backend, scope=scope
            )
        except DownstreamError as exc:
            await self._write(
                op, principal, trace, allow=True, reason=decision.reason, status="error"
            )
            raise ToolError(f"downstream authorization failed: {exc}") from exc

        downstream_tokens.set({**downstream_tokens.get({}), op.backend.name: ds_token})
        started = time.monotonic()
        status = "ok"
        try:
            return await call_next(context)
        except Exception:
            status = "upstream_error"
            raise
        finally:
            await self._write(
                op,
                principal,
                trace,
                allow=True,
                reason=decision.reason,
                status=status,
                jti=_jti(ds_token),
                latency_ms=int((time.monotonic() - started) * 1000),
            )

    def _pre_check(self, op: Operation) -> str | None:
        """The audit reason to deny on before OPA is consulted, or None."""
        if not op.modeled:
            return f"{op.method} not authorized: not modeled by gateway policy"
        if op.backend is None or op.meta is None:
            return "unknown tool or server"
        return None

    def _refusal_message(self, op: Operation) -> str:
        if not op.modeled:
            return f"{op.method} denied: not authorized by this gateway"
        return f"unknown tool: {op.target}"

    # ── hooks ───────────────────────────────────────────────────────────────

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        token = get_access_token()
        if token is None:
            raise ToolError("unauthorized")  # FastMCP should already enforce this
        tool_name, backend = self._resolve(context.message.name)
        op = Operation(
            method="tools/call",
            target=tool_name,
            backend=backend,
            meta=registry.lookup(tool_name),
            args=context.message.arguments,
        )
        return await self._authorize(op, from_access_token(token), context, call_next)

    async def on_read_resource(self, context: MiddlewareContext, call_next):
        """Fail closed: resources aren't modeled by this gateway's policy.

        The OPA bundle and tool registry are tool-centric. Rather than let a read
        through unauthorized and unaudited, deny it and write a deny row. To lift
        this, model resources in data.json plus a `resource_allow` rule and drop
        ``modeled=False`` — the decision and audit path is already shared.
        """
        return await self._unmodeled(context, call_next, method="resources/read")

    async def on_get_prompt(self, context: MiddlewareContext, call_next):
        """Fail closed: prompts aren't modeled by policy either. See above."""
        return await self._unmodeled(context, call_next, method="prompts/get")

    async def _unmodeled(self, context: MiddlewareContext, call_next, *, method: str):
        token = get_access_token()
        principal = from_access_token(token) if token is not None else _ANONYMOUS
        target = getattr(context.message, "uri", None) or getattr(context.message, "name", method)
        op = Operation(method=method, target=str(target), modeled=False)
        return await self._authorize(op, principal, context, call_next)

    async def on_list_tools(self, context: MiddlewareContext, call_next):
        token = get_access_token()
        principal = from_access_token(token) if token is not None else None
        if principal is not None:
            failed = await self._prefetch_downstream_tokens(principal, method="tools/list")
            if failed:
                logger.warning(
                    "tools/list is PARTIAL — tools from these backends are missing: %s",
                    ", ".join(failed),
                )
        tools = await call_next(context)
        if principal is None:
            return tools
        return [t for t in tools if self._visible(t, principal)]

    async def on_list_resources(self, context: MiddlewareContext, call_next):
        token = get_access_token()
        if token is not None:
            await self._prefetch_downstream_tokens(
                from_access_token(token), method="resources/list"
            )
        return await call_next(context)

    async def on_list_prompts(self, context: MiddlewareContext, call_next):
        token = get_access_token()
        if token is not None:
            await self._prefetch_downstream_tokens(from_access_token(token), method="prompts/list")
        return await call_next(context)

    # ── the list path ───────────────────────────────────────────────────────

    async def _prefetch_downstream_tokens(self, principal: Principal, *, method: str) -> list[str]:
        """Mint downstream tokens so a list call can authenticate — but only for
        the backends OPA clears this principal for, with an audit row either way.

        A separate path from ``_authorize`` on purpose: this is N decisions over
        N backends where partial success is the correct outcome, not one decision
        about one target. It shares the same "no token without a decision" rule
        and the same ``_write``. Returns the backends whose exchange failed.

        A single unreachable backend must not fail the whole list, so an exchange
        failure is caught per backend and logged at WARNING; a policy deny is the
        expected common case (most principals don't hold every role) and only
        reaches DEBUG.
        """
        tokens: dict[str, str] = {}
        failed: list[str] = []
        trace = Trace.new()
        for backend in self._namespaces.values():
            op = Operation(method=method, target=method, backend=backend)
            decision = await self._opa.evaluate_list_access(
                build_list_input(principal, server=backend.name)
            )
            if not decision.allow:
                logger.debug(
                    "%s: backend=%s not listed for principal=%s: %s",
                    method,
                    backend.name,
                    principal.actor_sub,
                    decision.reason,
                )
                await self._write(
                    op, principal, trace, allow=False, reason=decision.reason, status="denied"
                )
                continue
            try:
                ds_token = await self._downstream.token_for(principal=principal, backend=backend)
            except DownstreamError as exc:
                failed.append(backend.name)
                logger.warning(
                    "downstream token mint failed for backend=%s during %s; "
                    "its tools will be missing from the (partial) list: %s",
                    backend.name,
                    method,
                    exc,
                )
                await self._write(
                    op, principal, trace, allow=True, reason=decision.reason, status="error"
                )
                continue
            tokens[backend.name] = ds_token
            await self._write(
                op,
                principal,
                trace,
                allow=True,
                reason=decision.reason,
                status="ok",
                jti=_jti(ds_token),
            )
        if tokens:
            downstream_tokens.set({**downstream_tokens.get({}), **tokens})
        return failed

    def _visible(self, tool, principal: Principal) -> bool:
        """Filter the aggregated tool list before it reaches the agent.

        Two different jobs, only one of which is about the principal:

        * **Ungoverned tools are hidden.** A tool a backend serves but the
          registry and policy don't know about resolves to no backend, and
          ``_authorize`` would deny it as unknown. Listing it would advertise a
          tool that can never be called, so drop it and say so once.
        * **Elevated per-tool roles are best-effort UX, not enforcement.** The
          per-backend gate already happened in ``_prefetch_downstream_tokens``,
          and Rego checks ``required_role`` again at call time regardless — so
          this half can drift without weakening enforcement, only UX.
        """
        name = getattr(tool, "name", "")
        bare, backend = self._resolve(name)
        if backend is None:
            self._warn_ungoverned(name)
            return False
        meta = registry.lookup(bare)
        if meta is None or not meta.required_role:
            return True
        return meta.required_role in principal.roles

    def _warn_ungoverned(self, name: str) -> None:
        """Report a served-but-ungoverned tool once per process.

        This is the line an operator sees the day a backend team ships a tool
        without a governance entry. Deduplicated because every reconnecting agent
        re-lists, and a warning that repeats hourly stops being read.
        """
        if name in self._warned_ungoverned:
            return
        self._warned_ungoverned.add(name)
        logger.warning(
            "tool %r is served by a backend but has no entry in app/tools/registry.py "
            "and policy/data.json — hidden from tools/list, and denied if called",
            name,
        )

    # ── the only audit write ────────────────────────────────────────────────

    async def _write(
        self,
        op: Operation,
        principal: Principal,
        trace: Trace,
        *,
        allow: bool,
        reason: str,
        status: str,
        jti: str | None = None,
        latency_ms: int = 0,
    ) -> None:
        """Write the audit row. The only call site for the audit writer.

        A write failure is logged loudly but never masks the tool result or the
        original exception — the side effect may already have happened on the
        backend, so raising here would lose the client's result and still not
        produce a record. The log is the last-resort trail.
        """
        meta = op.meta
        record = AuditRecord(
            actor_sub=principal.actor_sub,
            actor_upn=principal.actor_upn,
            agent_client_id=principal.agent_client_id,
            agent_kind=principal.agent_kind,
            broker_client_id=principal.broker_client_id,
            mcp_server=op.server,
            tool_name=op.target,
            tool_args_hash=_args_hash(op.args),
            opa_decision=allow,
            opa_reason=reason,
            downstream_token_jti=jti,
            downstream_token_aud=op.audience,
            latency_ms=latency_ms,
            status=status,
            trace_id=trace.trace_id,
            client_trace_id=trace.client_trace_id,
            nis2_significant=bool(meta and meta.nis2_significant),
            dora_major=bool(meta and meta.dora_major),
            aiact_highrisk=bool(meta and meta.aiact_highrisk),
        )
        try:
            await self._audit.write(record)
        except Exception:  # audit must never break the call path
            logger.exception("AUDIT WRITE FAILED — record not persisted: %s", record)


def _args_hash(arguments) -> str:
    """Hash of the FULL argument set — the audit correlator.

    Deliberately not the projected subset sent to the PDP: the hash has to
    identify the call that actually ran.
    """
    blob = json.dumps(arguments or {}, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()


def _jti(token: str) -> str | None:
    try:
        return jwt.decode(token, options={"verify_signature": False}).get("jti")
    except jwt.PyJWTError:
        return None


def _new_trace_id() -> str:
    """A fresh W3C trace-id (16 random bytes).

    This is the authoritative audit identity: minted here on every call, so it
    can never be forged, omitted or influenced by the client.
    """
    return secrets.token_hex(16)


def _client_trace_id() -> str | None:
    """The caller's incoming W3C traceparent trace-id, if any.

    Kept only to correlate this row with the caller's upstream trace. It is
    untrusted input and must never be used as the audit identity, so validate
    the shape rather than storing garbage.
    """
    tp = get_http_headers(include={"traceparent"}).get("traceparent")
    if tp and tp.count("-") >= 3:
        cand = tp.split("-")[1]
        if len(cand) == 32 and all(c in "0123456789abcdef" for c in cand) and int(cand, 16) != 0:
            return cand
    return None
