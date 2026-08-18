"""The OAuth 2.1 AS surface the gateway exposes to MCP clients.

AzureProvider implements the endpoints; these tests check the spec-required
content: RFC 8414 metadata advertising PKCE-S256 and CIMD, RFC 9728
protected-resource metadata at both the resource-scoped path and the bare-path
alias, a 401 whose WWW-Authenticate points at a URL that actually resolves, and
DCR issuing a client_id.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from app.config import Settings
from app.server import build_gateway


def _settings(**over) -> Settings:
    base = {
        "entra_tenant_id": "00000000-0000-0000-0000-000000000000",
        "gateway_client_id": "test-client",
        "gateway_client_secret": "test-secret",
    }
    return Settings(**{**base, **over})


@pytest.fixture
def client() -> TestClient:
    return TestClient(build_gateway(_settings()).http_app(transport="http"))


def test_as_metadata_advertises_pkce_s256_and_cimd(client: TestClient):
    r = client.get("/.well-known/oauth-authorization-server")
    assert r.status_code == 200
    body = r.json()
    assert body["code_challenge_methods_supported"] == ["S256"]
    assert body["client_id_metadata_document_supported"] is True
    # endpoints live under the gateway's advertised public URL
    assert body["authorization_endpoint"].startswith("http://localhost:8443")
    assert body["token_endpoint"].startswith("http://localhost:8443")
    assert body["registration_endpoint"].startswith("http://localhost:8443")


def test_protected_resource_metadata_scoped_and_bare_agree(client: TestClient):
    scoped = client.get("/.well-known/oauth-protected-resource/mcp")
    bare = client.get("/.well-known/oauth-protected-resource")
    assert scoped.status_code == 200
    assert bare.status_code == 200  # the alias — no 404 for clients probing the bare path
    for key in ("resource", "authorization_servers"):
        assert bare.json()[key] == scoped.json()[key]
    assert scoped.json()["resource"] == "http://localhost:8443/mcp"


def test_unauthenticated_mcp_is_401_with_resolvable_resource_metadata(client: TestClient):
    r = client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream"},
    )
    assert r.status_code == 401
    www = r.headers.get("www-authenticate", "")
    assert "Bearer" in www
    assert "resource_metadata=" in www
    # the advertised metadata URL must actually resolve (regression guard for the
    # path-prefix quirk)
    url = www.split('resource_metadata="', 1)[1].split('"', 1)[0]
    path = url.replace("http://localhost:8443", "")
    assert client.get(path).status_code == 200


def test_dcr_register_issues_a_client_id(client: TestClient):
    r = client.post(
        "/register",
        json={
            "client_name": "test-mcp-client",
            "redirect_uris": ["http://localhost:3118/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "none",
        },
    )
    assert r.status_code in (200, 201)
    assert r.json().get("client_id")


def test_prod_env_forces_consent():
    assert _settings(gateway_env="prod").require_consent() is True
    assert _settings(gateway_require_consent=True).require_consent() is True
    assert _settings().require_consent() is False
