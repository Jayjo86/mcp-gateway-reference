"""Audience validation on mcp-server-a.

The foundational invariant: a token issued for api://mcp-server-b is
rejected by mcp-server-a's JWTVerifier, and vice versa. Uses a locally
generated RSA key pair, so no Entra tenant is needed to run these.
"""

from __future__ import annotations

import pytest
from fastmcp.server.auth import JWTVerifier
from fastmcp.server.auth.providers.jwt import RSAKeyPair

AUD_A = "api://mcp-server-a"
AUD_B = "api://mcp-server-b"
ISSUER = "https://test.example.invalid"


@pytest.fixture(scope="module")
def key() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture(scope="module")
def verifier(key: RSAKeyPair) -> JWTVerifier:
    return JWTVerifier(
        public_key=key.public_key,
        issuer=ISSUER,
        audience=AUD_A,
        algorithm="RS256",
    )


@pytest.mark.asyncio
async def test_correct_audience_accepted(key: RSAKeyPair, verifier: JWTVerifier) -> None:
    token = key.create_token(subject="u1", issuer=ISSUER, audience=AUD_A)
    assert await verifier.load_access_token(token) is not None


@pytest.mark.asyncio
async def test_server_b_token_rejected(key: RSAKeyPair, verifier: JWTVerifier) -> None:
    """The core invariant: a token for server-b cannot authenticate to server-a."""
    token = key.create_token(subject="u1", issuer=ISSUER, audience=AUD_B)
    assert await verifier.load_access_token(token) is None


@pytest.mark.asyncio
async def test_expired_token_rejected(key: RSAKeyPair, verifier: JWTVerifier) -> None:
    token = key.create_token(subject="u1", issuer=ISSUER, audience=AUD_A, expires_in_seconds=-1)
    assert await verifier.load_access_token(token) is None


@pytest.mark.asyncio
async def test_wrong_issuer_rejected(key: RSAKeyPair, verifier: JWTVerifier) -> None:
    token = key.create_token(subject="u1", issuer="https://evil.example.invalid", audience=AUD_A)
    assert await verifier.load_access_token(token) is None


@pytest.mark.asyncio
async def test_v1_sts_issuer_rejected(key: RSAKeyPair) -> None:
    """A v1.0 (sts.windows.net) token is rejected: we validate the v2.0 issuer only."""
    tenant = "contoso-tenant-id"
    v2_verifier = JWTVerifier(
        public_key=key.public_key,
        issuer=f"https://login.microsoftonline.com/{tenant}/v2.0",
        audience=AUD_A,
        algorithm="RS256",
    )
    v1_token = key.create_token(
        subject="u1", issuer=f"https://sts.windows.net/{tenant}/", audience=AUD_A
    )
    assert await v2_verifier.load_access_token(v1_token) is None
