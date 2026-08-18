"""Gateway entrypoint — Streamable HTTP on the FastMCP substrate."""

from __future__ import annotations

import logging

import uvicorn
from starlette.middleware import Middleware

from app.config import get_settings
from app.server import build_gateway

# Chatty per-request loggers, kept at WARNING unless LOG_TRAFFIC is on.
_VERBOSE_LOGGERS = ("gateway.traffic", "gateway.token.m2m", "gateway.token.obo", "gateway.pep")


def _configure_logging(log_traffic: bool) -> None:
    # Root stays at INFO even with LOG_TRAFFIC on. DEBUG on the root logger also
    # turns on httpx, fastmcp and asyncpg, which bury the token-exchange lines
    # this flag exists to surface. A child logger set to DEBUG still reaches
    # root's handler, so scoping the raise to `gateway` loses none of ours.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(name)-28s %(levelname)-8s %(message)s",
    )
    logging.getLogger("gateway").setLevel(logging.DEBUG if log_traffic else logging.INFO)
    if not log_traffic:
        for name in _VERBOSE_LOGGERS:
            logging.getLogger(name).setLevel(logging.WARNING)


def main() -> None:
    settings = get_settings()
    _configure_logging(settings.log_traffic)

    gateway = build_gateway(settings)

    middleware = None
    if settings.log_traffic:
        from app.middleware.request_log import RequestLogMiddleware

        middleware = [Middleware(RequestLogMiddleware)]

    app = gateway.http_app(middleware=middleware, transport="http")

    uvicorn.run(
        app,
        host=settings.gateway_host,
        port=settings.gateway_port,
        ssl_certfile=settings.gateway_tls_cert or None,
        ssl_keyfile=settings.gateway_tls_key or None,
    )


if __name__ == "__main__":
    main()
