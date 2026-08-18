"""Dev-only ASGI middleware: logs inbound HTTP traffic for the auth/MCP flows.

Enable with LOG_TRAFFIC=true. Redacts secrets (code_verifier, client_secret,
assertion) and truncates opaque values (code, state) to keep logs readable.
Safe for SSE/streaming: only buffers the body on the small auth endpoints.
"""

from __future__ import annotations

import logging
from urllib.parse import parse_qs

from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger("gateway.traffic")

_BUFFER_PATHS = frozenset({"/token"})
_REDACT = frozenset({"code_verifier", "client_secret", "assertion"})
_TRUNCATE = frozenset({"code", "state", "code_challenge", "session_state"})


class RequestLogMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method: str = scope["method"]
        path: str = scope["path"]
        qs: str = scope.get("query_string", b"").decode()
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}

        auth = headers.get("authorization", "")
        logger.info("→ %s %s%s  [%s]", method, path, "?..." if qs else "", _fmt_bearer(auth))

        if qs and path in {"/authorize", "/auth/callback"}:
            _log_params(parse_qs(qs))

        if method == "POST" and path in _BUFFER_PATHS:
            receive = _buffering_receive(receive, path)

        async def logging_send(message):
            if message.get("type") == "http.response.start":
                logger.info("← %s  %s", message["status"], path)
            await send(message)

        await self.app(scope, receive, logging_send)


def _fmt_bearer(auth: str) -> str:
    if not auth:
        return "no auth"
    if auth.lower().startswith("bearer "):
        t = auth[7:]
        return f"Bearer {t[:12]}…" if len(t) > 12 else f"Bearer {t}"
    return auth[:30]


def _log_params(params: dict[str, list[str]]) -> None:
    for k, vals in params.items():
        v = vals[0] if vals else ""
        if k in _REDACT:
            display = "(redacted)"
        elif k in _TRUNCATE and len(v) > 24:
            display = v[:24] + "…"
        else:
            display = v
        logger.info("    %-28s %s", k + "=", display)


def _buffering_receive(receive: Receive, path: str) -> Receive:
    """Buffer the full request body, log it, then replay it to the app."""
    _state: dict = {"done": False, "body": b""}

    async def _inner():
        if not _state["done"]:
            chunks: list[bytes] = []
            while True:
                msg = await receive()
                chunks.append(msg.get("body", b""))
                if not msg.get("more_body", False):
                    break
            body = b"".join(chunks)
            _state["done"] = True
            _state["body"] = body
            logger.info("  POST %s body:", path)
            try:
                _log_params(parse_qs(body.decode()))
            except Exception:  # noqa: BLE001 — a dev logger must never break a request
                logger.info("  (raw body: %r)", body[:200])
        return {"type": "http.request", "body": _state["body"], "more_body": False}

    return _inner
