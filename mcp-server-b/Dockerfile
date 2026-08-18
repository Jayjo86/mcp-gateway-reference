FROM python:3.12-slim

# Pinned for the same reason the compose images are: an unpinned build tool is
# a dependency that changes without a commit.
COPY --from=ghcr.io/astral-sh/uv:0.8.8 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

COPY pyproject.toml uv.lock ./
# --frozen: fail the build if uv.lock is out of sync with pyproject.toml,
# rather than silently re-resolving a different dependency set.
RUN uv sync --frozen --no-dev

COPY app ./app

# Non-root: a compromised process shouldn't run as root inside its own
# container by default.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /opt/venv /app
USER appuser

EXPOSE 9000
CMD ["python", "-m", "app.main"]
