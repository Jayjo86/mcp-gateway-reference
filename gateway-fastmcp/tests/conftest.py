import os

# Minimal Entra config so Settings/build_gateway don't fail fast in unit tests.
# entra_oidc_config is derived from ENTRA_TENANT_ID (app/config.py), not its
# own env var — nothing to set here for it.
os.environ.setdefault("ENTRA_TENANT_ID", "00000000-0000-0000-0000-000000000000")
os.environ.setdefault("GATEWAY_CLIENT_ID", "test-client")
os.environ.setdefault("GATEWAY_CLIENT_SECRET", "test-secret")
