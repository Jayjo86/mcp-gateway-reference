"""Environment-driven configuration. Entra values are required — there is no mock IdP.

The gateway runs FastMCP's ``AzureProvider`` as a full OAuth 2.1 authorization
server in front of Microsoft Entra ID: MCP clients authenticate against the
gateway (DCR / CIMD / PKCE-S256) and the gateway is a confidential OAuth client
to Entra behind the scenes. Clients never present Entra tokens to us directly,
which is what the broker settings below (public URL, session signing key,
consent) are for.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict

# Downstream authorization regimes a backend may declare. See app/downstream/.
VALID_PROFILES = frozenset({"m2m", "obo"})


class BackendServer(BaseModel):
    """One backend MCP server the gateway can route to."""

    name: str
    url: str
    audience: str
    scope: str
    # Mount namespace this backend's tools appear under on the gateway.
    namespace: str
    # Downstream regime for the gateway→backend hop: "m2m" (client_credentials,
    # the gateway's own service principal) or "obo" (Entra On-Behalf-Of, per-user
    # delegation — an RFC 7523 jwt-bearer assertion grant, not RFC 8693 token
    # exchange; see app/downstream/obo.py).
    profile: str = "m2m"

    def scope_for(self, suffix: str) -> str:
        """Qualify a scope suffix with this backend's audience, e.g.
        "Ledger.Write" -> "api://<tenant-guid>/mcp-server-b/Ledger.Write".
        Keeps the tool registry free of any Application ID URI assumptions.
        """
        return f"{self.audience}/{suffix}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Entra
    entra_tenant_id: str = ""

    gateway_client_id: str = ""
    gateway_client_secret: str = ""
    gateway_audience: str = "api://mcp-gateway"
    # Scope defined under "Expose an API" on the gateway app reg. Passed to
    # AzureProvider unprefixed; it prefixes gateway_audience itself.
    gateway_inbound_scope: str = "access_as_user"
    # Public URL advertised in OAuth metadata. Must be reachable by MCP clients.
    gateway_public_url: str = "http://localhost:8443"
    gateway_session_signing_key: str = "change-me-dev-only"
    # Consent screen for dynamically-registered / CIMD clients (confused-deputy
    # protection). Forced on when gateway_env == "prod" — see require_consent().
    gateway_require_consent: bool = False
    gateway_env: str = "dev"

    mcp_server_a_audience: str = "api://mcp-server-a"
    mcp_server_b_audience: str = "api://mcp-server-b"
    # Backend default scope: used by M2M (client_credentials only accepts
    # `.default`) and as the OBO fallback for calls with no per-tool scope, such
    # as the tools/list prefetch. OBO tool calls use the least-privilege scope
    # from app/tools/registry.py instead.
    mcp_server_a_scope: str = "api://mcp-server-a/.default"
    mcp_server_b_scope: str = "api://mcp-server-b/.default"
    mcp_server_a_url: str = "http://mcp-server-a:9000/mcp"
    mcp_server_b_url: str = "http://mcp-server-b:9000/mcp"

    # Live entries per in-memory downstream token cache. Bounds memory and
    # stale-secret retention until the cache moves to a shared store.
    downstream_token_cache_max: int = 2048

    # Downstream regime for any backend that doesn't set its own. Kept equal to
    # the value .env.example ships, so the documented configuration and the
    # fallback can't disagree about what an unconfigured backend does.
    downstream_profile: str = "obo"
    mcp_server_a_profile: str = ""
    mcp_server_b_profile: str = ""

    # Gateway
    gateway_host: str = "0.0.0.0"
    gateway_port: int = 8000
    gateway_tls_cert: str = ""
    gateway_tls_key: str = ""

    # OPA
    opa_url: str = "http://opa:8181"
    opa_decision_path: str = "v1/data/mcp"

    # Audit
    audit_database_url: str = ""

    # Dev only: request/response logging plus DEBUG token-exchange logs.
    log_traffic: bool = False

    def backends(self) -> dict[str, BackendServer]:
        return {
            "mcp-server-a": BackendServer(
                name="mcp-server-a",
                namespace="server_a",
                url=self.mcp_server_a_url,
                audience=self.mcp_server_a_audience,
                scope=self.mcp_server_a_scope,
                profile=self.mcp_server_a_profile or self.downstream_profile,
            ),
            "mcp-server-b": BackendServer(
                name="mcp-server-b",
                namespace="server_b",
                url=self.mcp_server_b_url,
                audience=self.mcp_server_b_audience,
                scope=self.mcp_server_b_scope,
                profile=self.mcp_server_b_profile or self.downstream_profile,
            ),
        }

    @property
    def entra_oidc_config(self) -> str:
        """Entra's OIDC discovery URL, derived from the tenant id rather than
        configured separately.

        It used to be its own `ENTRA_OIDC_CONFIG=.../${ENTRA_TENANT_ID}/...`
        entry in `.env`. python-dotenv expands `${...}`, but Compose's
        `env_file:` injects the line verbatim, so the gateway could receive the
        literal placeholder depending on how it was loaded.
        """
        return f"https://login.microsoftonline.com/{self.entra_tenant_id}/v2.0/.well-known/openid-configuration"

    def require_consent(self) -> bool:
        """Effective consent setting: always on in prod, else the flag."""
        return self.gateway_require_consent or self.gateway_env.lower() == "prod"

    def require_entra(self) -> None:
        """Fail fast if Entra is not configured."""
        missing = [
            k
            for k in (
                "entra_tenant_id",
                "gateway_client_id",
                "gateway_client_secret",
            )
            if not getattr(self, k)
        ]
        if missing:
            raise RuntimeError(
                f"Missing required Entra configuration: {', '.join(missing)}. "
                "Copy .env.example to .env and fill it in — see README 'Entra setup'."
            )
        bad = {
            b.name: b.profile for b in self.backends().values() if b.profile not in VALID_PROFILES
        }
        if bad:
            raise RuntimeError(
                f"Unknown downstream profile(s): {bad}. Valid values are {sorted(VALID_PROFILES)}."
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
