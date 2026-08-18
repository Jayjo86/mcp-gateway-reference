"""Map a validated token into the principal the OPA input and audit row need.

``get_access_token()`` returns the token FastMCP already validated (signature,
audience, issuer, expiry). We only read its claims here; the raw token is used
as the OBO assertion and is never forwarded to a backend.

Three identities travel on every request:

  * the actor — the human, from the Entra claims
  * the agent — the MCP client program the human is driving. Its identity is the
    client id this gateway's OAuth server issued at registration, recovered by
    ``GatewayAzureProvider`` onto the ``mcp_client_id`` claim.
  * the broker — this gateway, Entra's `azp`. Constant by design.

Keeping the last two apart is the point: reading the agent from `azp` yields the
broker on every request, which turns the platform allowlist into a tautology.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from fastmcp.server.dependencies import AccessToken

from app.auth import MCP_CLIENT_ID_CLAIM

# How much an agent id is worth, which decides what policy may conclude from it.
AGENT_KIND_CIMD = "cimd"  # an HTTPS URL FastMCP fetched and matched: verified
AGENT_KIND_DCR = "dcr"  # a UUID we minted at /register: unverified
AGENT_KIND_UNKNOWN = "unknown"  # no agent identity at all


@dataclass(frozen=True)
class Principal:
    actor_sub: str  # human user (`sub`) or, for M2M, the app object id
    actor_upn: str | None  # user principal name, if present; None for M2M
    agent_client_id: str  # the MCP client — session JWT `client_id`
    agent_kind: str  # cimd | dcr | unknown
    broker_client_id: str  # this gateway's Entra app (`azp`)
    scopes: list[str]  # delegated scopes (`scp`)
    roles: list[str]  # app roles (`roles`)
    groups: list[str]  # `groups`
    raw_token: str  # held only for the OBO exchange — never forwarded


def classify_agent(client_id: str) -> str:
    """Which registration path produced this client id, and so how much it means.

    Mirrors ``CIMDClientManager.is_cimd_client_id``: a CIMD client id is an
    HTTPS URL with a host and a non-root path. FastMCP fetches that URL and
    requires the document to name itself, so the id is verified and stable
    across every installation of that client software.

    Anything else is a DCR registration — a UUID minted for whoever POSTed to
    /register. It identifies an installation, not a product: useful as audit
    evidence, weak as an authorization input. platform.rego treats the two
    differently.
    """
    if not client_id:
        return AGENT_KIND_UNKNOWN
    try:
        parsed = urlparse(client_id)
    except (ValueError, AttributeError):
        return AGENT_KIND_DCR
    if parsed.scheme == "https" and parsed.netloc and parsed.path not in ("", "/"):
        return AGENT_KIND_CIMD
    return AGENT_KIND_DCR


def from_access_token(token: AccessToken) -> Principal:
    claims = token.claims or {}
    scp = claims.get("scp", "")
    scopes = scp.split() if isinstance(scp, str) else list(scp or [])
    # No fallback to `azp`/`appid`/`token.client_id`, deliberately: all three are
    # the broker's identity, so a fallback would silently restore the tautology
    # this field exists to avoid. An empty agent id matches no allowlist entry
    # and is denied by the platform layer, which is the outcome we want.
    agent_client_id = claims.get(MCP_CLIENT_ID_CLAIM) or ""
    return Principal(
        actor_sub=claims.get("sub") or claims.get("oid", ""),
        actor_upn=claims.get("upn") or claims.get("preferred_username"),
        agent_client_id=agent_client_id,
        agent_kind=classify_agent(agent_client_id),
        broker_client_id=claims.get("azp") or claims.get("appid") or "",
        scopes=scopes,
        roles=list(claims.get("roles", []) or []),
        groups=list(claims.get("groups", []) or []),
        raw_token=token.token,
    )
