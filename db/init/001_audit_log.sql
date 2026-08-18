-- Audit log shaped for NIS2 / DORA / EU AI Act / GDPR reporting.
--
-- One row per tool call, written by the gateway after the downstream response
-- returns. The boolean tags are inherited from per-tool metadata so the 24h
-- (NIS2) / 4h (DORA) / 72h (GDPR) reporting clocks are queryable rather than
-- searched for in a panic.
--
-- Plain Postgres on purpose; tamper-evident storage (signed receipts, hash
-- chains, append-only) is future hardening — see "Known limitations" in the
-- README.

CREATE TABLE IF NOT EXISTS audit_log (
    id                     BIGSERIAL PRIMARY KEY,
    ts                     TIMESTAMPTZ  NOT NULL DEFAULT now(),

    -- Delegation chain: human → agent → gateway → backend. The middle two are
    -- distinct identities and must never be conflated — see app/auth.py.
    actor_sub              TEXT         NOT NULL,           -- human user (`sub`)
    actor_upn              TEXT,                            -- user principal name, if present
    -- the MCP client that called, as the client_id this gateway's OAuth server
    -- issued at registration; read from the session JWT, not the Entra token
    agent_client_id        TEXT         NOT NULL,
    -- 'cimd' = an HTTPS URL FastMCP fetched and verified, stable across
    -- installs; 'dcr' = a UUID minted at /register, an installation rather than
    -- a product; 'unknown' = no agent identity present
    agent_kind             TEXT         NOT NULL DEFAULT 'unknown',
    -- this gateway's own Entra app (`azp`) — constant by design
    broker_client_id       TEXT,

    -- what was called
    mcp_server             TEXT         NOT NULL,           -- e.g. mcp-server-a
    tool_name              TEXT         NOT NULL,
    tool_args_hash         TEXT         NOT NULL,           -- hash of args, not the args themselves

    -- the authorization decision
    opa_decision           BOOLEAN      NOT NULL,
    opa_reason             TEXT         NOT NULL DEFAULT '',

    -- the downstream (OBO) token actually used — for correlation with Entra logs
    downstream_token_jti   TEXT,
    downstream_token_aud   TEXT,

    -- outcome
    latency_ms             INTEGER      NOT NULL,
    status                 TEXT         NOT NULL,           -- ok | denied | error | upstream_error
    -- server-generated W3C trace-id, never derived from client input: the
    -- audit identity, so it cannot be forged or omitted
    trace_id               TEXT         NOT NULL,           -- joins to SIEM/OTel
    -- the caller's incoming traceparent trace-id, for correlation only
    client_trace_id        TEXT,

    -- regulatory tags inherited from the tool's metadata
    nis2_significant       BOOLEAN      NOT NULL DEFAULT FALSE,
    dora_major             BOOLEAN      NOT NULL DEFAULT FALSE,
    aiact_highrisk         BOOLEAN      NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS audit_log_ts_idx           ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS audit_log_actor_idx        ON audit_log (actor_sub);
CREATE INDEX IF NOT EXISTS audit_log_server_tool_idx  ON audit_log (mcp_server, tool_name);
-- partial indexes so the regulatory-reporting queries are cheap
CREATE INDEX IF NOT EXISTS audit_log_nis2_idx  ON audit_log (ts DESC) WHERE nis2_significant;
CREATE INDEX IF NOT EXISTS audit_log_dora_idx  ON audit_log (ts DESC) WHERE dora_major;
CREATE INDEX IF NOT EXISTS audit_log_aiact_idx ON audit_log (ts DESC) WHERE aiact_highrisk;

-- Column comments for the delegation chain. The `--` comments above document the
-- table for whoever reads this file; these document it for whoever is sitting at a
-- psql prompt six months from now with no checkout, which is when it matters.
-- Visible via \d+ audit_log.
COMMENT ON COLUMN audit_log.agent_client_id  IS
    'The MCP client that called (Claude Code, Cursor, ...): the client_id this gateway''s '
    'OAuth server issued at DCR/CIMD registration, read from the FastMCP session JWT.';
COMMENT ON COLUMN audit_log.agent_kind       IS
    'cimd = verified HTTPS client-metadata URL, stable across installs; '
    'dcr = UUID minted at /register, identifies an installation not a product; '
    'unknown = no agent identity present.';
COMMENT ON COLUMN audit_log.broker_client_id IS
    'This gateway''s own Entra app registration (`azp`) — the broker hop. Constant by design.';

-- Retention: AI Act Art. 19 / Art. 26(6) require ≥ 6 months. Enforce with a
-- scheduled job (pg_cron or external) in a real deployment — out of scope for v1.
