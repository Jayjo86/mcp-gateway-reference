"""No value from a developer's local `.env` may appear in a committed file.

This repo is meant to be published. `.env` is gitignored, but that only protects
the file — it does nothing about a real tenant GUID pasted into a test fixture,
which is exactly how identifiers leak out of an otherwise careful repo. Real
Entra Application IDs did sit in these tests until this guard was added.

Skipped when there is no local `.env` (CI, or a fresh clone), so it costs
nothing there and fails loudly on the machine that actually has the secrets.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
ENV = REPO / ".env"

GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
SECRET_KEY = re.compile(r"SECRET|PASSWORD|_KEY$|SIGNING", re.IGNORECASE)

# Directories git never sees, plus the dev-only files that are allowed to hold
# real values because they are gitignored.
SKIP_DIRS = {
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "certs",
    ".git",
    ".claude",
}
SKIP_FILES = {".env", ".env.local"}
# Placeholders that ship identically in .env and .env.example on purpose.
PLACEHOLDERS = {"change-me-dev-only", "mcp-dev-only"}


def _identifying_env_values() -> dict[str, str]:
    """The `.env` values worth guarding: real GUIDs and anything secret-shaped.

    Deliberately narrow. Guarding every value would flag the shared defaults
    (`http://opa:8181`, `access_as_user`) that are *supposed* to appear in both
    `.env` and `.env.example`, and a check that cries wolf gets deleted.
    """
    values: dict[str, str] = {}
    for line in ENV.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, raw = line.partition("=")
        key, value = key.strip(), raw.strip().strip("\"'")
        if not value or value in PLACEHOLDERS:
            continue
        if GUID.match(value) or (SECRET_KEY.search(key) and len(value) >= 12):
            values[key] = value
    return values


def _committed_files() -> list[Path]:
    return [
        p
        for p in REPO.rglob("*")
        if p.is_file()
        and not SKIP_DIRS.intersection(p.parts)
        and p.name not in SKIP_FILES
        and p.suffix not in {".pyc", ".lock"}
    ]


@pytest.mark.skipif(not ENV.exists(), reason="no local .env to leak")
def test_no_local_env_value_appears_in_a_committed_file():
    guarded = _identifying_env_values()
    if not guarded:
        pytest.skip(".env holds no GUIDs or secrets to guard")

    leaks = []
    for path in _committed_files():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for key, value in guarded.items():
            if value in text:
                leaks.append(f"{path.relative_to(REPO)} contains the value of {key}")

    assert not leaks, (
        "Local .env values found in files that would be committed:\n  "
        + "\n  ".join(sorted(leaks))
        + "\n\nReplace them with obviously-synthetic values."
    )
