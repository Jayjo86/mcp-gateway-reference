"""Per-request state shared between the OPA PEP and the upstream proxy factory.

FastMCP's ``client_factory`` is synchronous, so the downstream token mint can't
happen inside it. The PEP runs first in the middleware chain, awaits the mint and
stashes the result here keyed by backend name; the factory then reads its token
synchronously when FastMCP builds the upstream client.

This is what makes the no-passthrough invariant explicit: a backend only ever
sees the token minted for its own audience.
"""

from __future__ import annotations

from contextvars import ContextVar

# backend.name -> backend-audience-scoped access token, set by the PEP. No
# default value: unset means unauthenticated discovery, and every reader passes
# its own empty fallback rather than sharing one mutable map across requests.
downstream_tokens: ContextVar[dict[str, str]] = ContextVar("downstream_tokens")
