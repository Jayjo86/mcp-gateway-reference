"""Audit writer — one Postgres row per tool call, allowed or denied.

Written by the PEP after the downstream response returns, or immediately on a
policy denial. The regulatory tags come from the tool registry so the NIS2 /
DORA / GDPR reporting clocks are queryable rather than searched for in a panic.
The trace id is server-generated and never null; the client's incoming
traceparent is stored separately for correlation only.

Plain Postgres on purpose for v1 — tamper-evidence is future hardening. With no
audit DB configured the writer degrades to a log line rather than dropping the
record.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import asyncpg

from app.config import Settings

logger = logging.getLogger("gateway.audit")

_INSERT = """
INSERT INTO audit_log (
    actor_sub, actor_upn, agent_client_id, agent_kind, broker_client_id,
    mcp_server, tool_name, tool_args_hash,
    opa_decision, opa_reason, downstream_token_jti, downstream_token_aud,
    latency_ms, status, trace_id, client_trace_id,
    nis2_significant, dora_major, aiact_highrisk
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19
)
"""


@dataclass
class AuditRecord:
    actor_sub: str
    actor_upn: str | None
    agent_client_id: str
    agent_kind: str  # cimd | dcr | unknown
    broker_client_id: str
    mcp_server: str
    tool_name: str
    tool_args_hash: str
    opa_decision: bool
    opa_reason: str
    downstream_token_jti: str | None
    downstream_token_aud: str | None
    latency_ms: int
    status: str  # ok | denied | error | upstream_error
    trace_id: str  # server-generated; the audit identity, never null
    client_trace_id: str | None = None  # caller's traceparent, correlation only
    nis2_significant: bool = False
    dora_major: bool = False
    aiact_highrisk: bool = False


class AuditWriter:
    def __init__(self, settings: Settings) -> None:
        self._dsn = settings.audit_database_url
        self._pool: asyncpg.Pool | None = None

    async def open(self) -> None:
        if self._dsn:
            self._pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=4)

    async def aclose(self) -> None:
        if self._pool is not None:
            await self._pool.close()

    async def write(self, r: AuditRecord) -> None:
        if self._pool is None:
            logger.info("audit (no DB): %s", r)
            return
        await self._pool.execute(
            _INSERT,
            r.actor_sub,
            r.actor_upn,
            r.agent_client_id,
            r.agent_kind,
            r.broker_client_id,
            r.mcp_server,
            r.tool_name,
            r.tool_args_hash,
            r.opa_decision,
            r.opa_reason,
            r.downstream_token_jti,
            r.downstream_token_aud,
            r.latency_ms,
            r.status,
            r.trace_id,
            r.client_trace_id,
            r.nis2_significant,
            r.dora_major,
            r.aiact_highrisk,
        )
