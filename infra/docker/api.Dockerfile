# syntax=docker/dockerfile:1.7

ARG UV_VERSION=0.11.28
FROM ghcr.io/astral-sh/uv:${UV_VERSION}@sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa AS uv

FROM python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b AS development

COPY --from=uv /uv /uvx /bin/

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /workspace

COPY . .
RUN uv sync --all-groups --locked

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b AS production

COPY --from=uv /uv /uvx /bin/

ENV PATH="/opt/venv/bin:${PATH}" \
    AQT_ENVIRONMENT=paper \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_DEV=1 \
    UV_NO_SYNC=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /workspace

# The build context is secret-filtered by .dockerignore. A full source copy is
# intentional until a narrower wheel/image manifest is content-addressed:
# Alembic revisions and the verified no-exposure artifact are runtime inputs.
COPY . .
RUN uv sync --no-dev --locked \
    && groupadd --system --gid 10001 autoquant \
    && useradd --system --uid 10001 --gid autoquant --home-dir /nonexistent autoquant

USER 10001:10001

# This is a fail-closed one-shot admission command today. It exits nonzero in a
# paper environment until ADR 0088's external smoke sources are bound. A later
# reviewed runtime composition must replace --once before creating the worker.
CMD ["autoquant-trader", "--once"]
