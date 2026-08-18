# Connecting Claude Code to the Gateway

The gateway uses **FastMCP's `AzureProvider`** as an OAuth 2.1 AS broker. MCP clients
never touch Entra directly; they do a PKCE-S256 flow against the gateway, which proxies
to Entra and issues a short-lived FastMCP session JWT. This document explains how to
complete that flow with the Claude Code CLI.

## Prerequisites

### 1. Entra app registration (gateway)

In Azure Portal → App registrations → your gateway app:

| Setting | Value |
|---|---|
| Platform | Web |
| Redirect URI | `{GATEWAY_PUBLIC_URL}/auth/callback` |
| Expose an API → Application ID URI | `api://mcp-gateway` |
| Expose an API → Scope | `access_as_user` |
| Manifest → `requestedAccessTokenVersion` | `2` |

**The redirect URI must exactly match `GATEWAY_PUBLIC_URL`.** `.env.example` ships the
plain-HTTP default (`GATEWAY_PUBLIC_URL=http://localhost:8443`), so register
`http://localhost:8443/auth/callback`. If you instead run with TLS (generate certs
with `./scripts/gen-local-certs.sh` — see ["HTTP vs HTTPS mismatch"](#http-vs-https-mismatch)
below), set `GATEWAY_PUBLIC_URL=https://localhost:8443` and add the `https://` variant.
Both can coexist.

### 2. `.env`

```bash
GATEWAY_PUBLIC_URL=http://localhost:8443  # .env.example default (plain HTTP); use https://... for TLS — see "HTTP vs HTTPS mismatch" below
GATEWAY_CLIENT_ID=<gateway app client id>
GATEWAY_CLIENT_SECRET=<gateway app client secret>
ENTRA_TENANT_ID=<your tenant id>
GATEWAY_AUDIENCE=api://mcp-gateway
GATEWAY_INBOUND_SCOPE=access_as_user
GATEWAY_SESSION_SIGNING_KEY=change-me-dev-only   # rotate in prod
GATEWAY_ENV=dev                                  # "prod" forces the consent screen on
GATEWAY_REQUIRE_CONSENT=false                    # true (or GATEWAY_ENV=prod) in shared deployments
# Leave blank for plain-HTTP local dev; fill in for TLS:
GATEWAY_TLS_CERT=
GATEWAY_TLS_KEY=
```

> **Consent screen.** For local dev the confused-deputy consent screen is off, so
> `claude mcp login` completes without an extra approval step. In any shared or
> production deployment set `GATEWAY_ENV=prod` (or `GATEWAY_REQUIRE_CONSENT=true`):
> dynamically-registered / CIMD clients must then approve a consent screen before
> the gateway issues a session token — this is the MCP-spec confused-deputy
> protection for DCR clients.

### 3. Stack running

```bash
docker compose up
```

Gateway serves on `http://0.0.0.0:8000` inside the container, exposed as host port 8443.

## Register the gateway with Claude Code

```bash
claude mcp add --transport http mcp-gateway http://localhost:8443/mcp
```

## Authenticate (one-time per gateway start)

Claude Code's auto-redirect is **disabled during normal sessions** — you must authenticate
explicitly before starting a session:

```bash
claude mcp login mcp-gateway
```

This will:
1. Start a local callback server on `localhost:3118`
2. Open your browser to `http://localhost:8443/authorize`
3. Gateway proxies to Entra login
4. After you sign in, the browser redirects back and Claude Code stores a session token

Once `mcp-login` succeeds, start a regular session:

```bash
claude
```

The `mcp-gateway` tools will be available.

## Known limitation: re-login required after the gateway is recreated

`AzureProvider` does *not* keep its OAuth session state (JTI → Entra-token mapping,
refresh tokens) in memory — `app/auth.py` doesn't pass a `client_storage`, so
`AzureProvider` falls back to its own default: an **encrypted on-disk file store**
(`FileTreeStore` + Fernet, keyed off `GATEWAY_SESSION_SIGNING_KEY`) under
`~/.local/share/fastmcp/oauth-proxy/<key-fingerprint>/` inside the container
(`/home/appuser/.local/share/fastmcp`, since the gateway runs as the non-root
`appuser`). It's not backed by a Docker volume, so it lives in the container's
writable layer.

Two things actually invalidate it:

- **The container is recreated** — `docker compose down` + `up`, or
  `docker compose up --build` — which discards the writable layer along with the
  store. A plain `docker compose restart gateway` (or `docker restart <container>`)
  keeps the same container filesystem and does **not** wipe it — no re-login needed
  in that case.
- **`GATEWAY_SESSION_SIGNING_KEY` changes.** The storage directory's name is a
  fingerprint derived from that key, so rotating it (as recommended above for prod)
  points the gateway at a fresh, empty directory — orphaning every existing session,
  with no restart required.

Either way, Claude Code's stored refresh token becomes unknown to the gateway, which
rejects it with `invalid_grant` and logs:

```
Refresh token not found for client=... it was already rotated, expired, or revoked.
Rejecting with invalid_grant, which forces the client to re-authenticate.
```

**Workaround (local dev):** treat `claude mcp login` as a per-recreate step, not a
one-time step:

```bash
claude mcp logout mcp-gateway
claude mcp login mcp-gateway
```

**Production fix:** pass a persistent `client_storage` to `AzureProvider` in
`app/auth.py`. This is closer than it sounds — `AzureProvider` already accepts a
`client_storage: AsyncKeyValue` constructor argument, and a Redis-backed
implementation (`key_value.aio.stores.redis.store`) is already an installed
dependency, so this is a one-call-site change, not new infrastructure design. (A
Docker volume mounted over the file-store directory is a cheaper stopgap if you'd
rather avoid a Redis dependency for now.) Out of scope for v1, but the right next
step before any shared or long-running deployment.

## Removing stored credentials

```bash
claude mcp logout mcp-gateway
```

## Troubleshooting

### `AADSTS50011` — redirect URI mismatch

Entra rejected the redirect because the URI the gateway sent doesn't match what's
registered in the portal. Check that `GATEWAY_PUBLIC_URL` in `.env` is correct (http vs
https) and that `{GATEWAY_PUBLIC_URL}/auth/callback` is listed under the gateway app's
redirect URIs in the Azure Portal.

### Stuck on "Skipping connection (cached needs-auth)"

A failed or interrupted auth attempt leaves partial state in two files. Clear it:

```bash
claude mcp logout mcp-gateway
```

If `logout` alone doesn't clear it (e.g. the state is corrupted), manually remove just
the `mcp-gateway` entries. Note `credentials.json` keys its `mcpOAuth` entries as
`<server-name>|<config-hash>`, not the bare server name — match on the `mcp-gateway|`
prefix so other authenticated MCP servers aren't logged out along with it:

```powershell
# PowerShell
$f = "$env:USERPROFILE\.claude\.credentials.json"
$c = Get-Content $f | ConvertFrom-Json
$c.mcpOAuth.PSObject.Properties |
    Where-Object { $_.Name -eq 'mcp-gateway' -or $_.Name -like 'mcp-gateway|*' } |
    ForEach-Object { $c.mcpOAuth.PSObject.Properties.Remove($_.Name) }
$c | ConvertTo-Json -Depth 10 | Set-Content $f

# Then remove from the needs-auth cache (keyed by bare server name here)
$f2 = "$env:USERPROFILE\.claude\mcp-needs-auth-cache.json"
$c2 = Get-Content $f2 | ConvertFrom-Json
$c2.PSObject.Properties.Remove('mcp-gateway')
$c2 | ConvertTo-Json -Depth 10 | Set-Content $f2
```

After clearing, run `claude mcp login mcp-gateway` again — do **not** start a `claude`
session first, as that will immediately re-populate the partial state.

### HTTP vs HTTPS mismatch

If you change `GATEWAY_PUBLIC_URL` between `http://` and `https://`, you must:
1. Update the redirect URI in the Entra portal to match
2. Run `claude mcp logout mcp-gateway` to clear the stale discovery state
3. Rebuild and restart the gateway (`docker compose up --build gateway`)
4. Run `claude mcp login mcp-gateway` again
