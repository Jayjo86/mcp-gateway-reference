"""Entra plumbing shared by the M2M and OBO token providers.

Both regimes need the same HTTP client, the same one-off token-endpoint
discovery and the same bounded token cache; only the grant differs.
"""

from __future__ import annotations

import httpx2
import jwt

from app.config import Settings
from app.downstream.base import DownstreamError
from app.downstream.cache import TokenCache


class EntraTokenProvider:
    """Base for the per-regime providers: HTTP client, discovery, token cache."""

    def __init__(self, settings: Settings, *, http: httpx2.AsyncClient | None = None) -> None:
        self._s = settings
        self._http = http or httpx2.AsyncClient(timeout=10.0)
        self._owns_http = http is None
        self._token_endpoint: str | None = None
        self._cache = TokenCache(maxsize=settings.downstream_token_cache_max)

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def _endpoint(self) -> str:
        """The tenant's token endpoint, discovered once and remembered."""
        if self._token_endpoint is None:
            try:
                resp = await self._http.get(self._s.entra_oidc_config)
                resp.raise_for_status()
                self._token_endpoint = resp.json()["token_endpoint"]
            except (httpx2.HTTPError, KeyError, ValueError) as exc:
                raise DownstreamError(
                    f"failed to fetch Entra OIDC config from {self._s.entra_oidc_config}: {exc}"
                ) from exc
        return self._token_endpoint


def claims_summary(token: str) -> str:
    """A short, non-secret digest of a minted token for DEBUG logging."""
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return "(undecodable)"
    subject = claims.get("sub") or claims.get("oid", "?")
    return f"aud={claims.get('aud')!r}  sub={subject}  exp={claims.get('exp')}"


def token_error(resp: httpx2.Response) -> DownstreamError:
    """Turn a failed Entra token response into the error the PEP denies on."""
    try:
        body = resp.json()
        detail = body.get("error_description") or body.get("error") or resp.text
    except ValueError:
        detail = resp.text
    return DownstreamError(f"Entra token request failed ({resp.status_code}): {detail}")
