"""build_auth() must accept both the audience URI and the app's GUID.

The GUID comes from an explicit env var rather than being guessed from the
audience URI: `urlsplit("api://mcp-server-a").netloc` is "mcp-server-a", not
a GUID, so under the shipped short-form default a derived value would accept
the wrong string and reject every real M2M / list-prefetch token.
"""

from __future__ import annotations

import pytest

from app.auth import build_auth

REQUIRED_ENV = {
    "ENTRA_TENANT_ID": "contoso-tenant-id",
    "MCP_SERVER_A_AUDIENCE": "api://mcp-server-a",
    "MCP_SERVER_A_APP_ID": "aaaaaaaa-2222-3333-4444-555555555555",
    "MCP_RESOURCE_URL": "http://localhost:9001/mcp",
}


def _set_env(monkeypatch: pytest.MonkeyPatch, **overrides: str) -> None:
    env = {**REQUIRED_ENV, **overrides}
    for key, value in env.items():
        monkeypatch.setenv(key, value)


def test_verifier_accepts_both_the_audience_uri_and_the_app_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_env(monkeypatch)
    provider = build_auth()
    assert provider.token_verifier.audience == [
        REQUIRED_ENV["MCP_SERVER_A_AUDIENCE"],
        REQUIRED_ENV["MCP_SERVER_A_APP_ID"],
    ]


def test_app_id_is_not_guessed_from_the_short_form_audience(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A short-form audience makes urlsplit(...).netloc == "mcp-server-a".
    That string is not a GUID and must never appear as an accepted audience —
    only the explicit MCP_SERVER_A_APP_ID may.
    """
    _set_env(monkeypatch)
    provider = build_auth()
    assert "mcp-server-a" not in provider.token_verifier.audience
    assert REQUIRED_ENV["MCP_SERVER_A_APP_ID"] in provider.token_verifier.audience


def test_missing_app_id_fails_fast(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_env(monkeypatch, MCP_SERVER_A_APP_ID="")
    with pytest.raises(RuntimeError, match="MCP_SERVER_A_APP_ID"):
        build_auth()
