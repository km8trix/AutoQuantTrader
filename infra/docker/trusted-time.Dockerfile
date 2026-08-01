# syntax=docker/dockerfile:1.7

ARG ALPINE_IMAGE=alpine:3.23.5@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b
ARG UV_VERSION=0.11.28

FROM ghcr.io/astral-sh/uv:${UV_VERSION}@sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa AS uv

# Build one static, exact-version monitoring client for the Python supervisor.
# The daemon is never controlled through Docker or UDP; this binary talks only
# to the shared Unix command socket.
FROM ${ALPINE_IMAGE} AS chronyc-build
ARG CHRONY_VERSION=4.8
RUN apk add --no-cache build-base
ADD --checksum=sha256:33ea8eb2a4daeaa506e8fcafd5d6d89027ed6f2f0609645c6f149b560d301706 \
    https://chrony-project.org/releases/chrony-4.8.tar.gz \
    /tmp/chrony.tar.gz
WORKDIR /tmp/chrony
RUN tar --extract --gzip --strip-components=1 --file /tmp/chrony.tar.gz \
    && LDFLAGS=-static ./configure \
        --prefix=/usr/local \
        --disable-readline \
        --disable-sechash \
        --disable-nts \
        --disable-refclock \
        --disable-phc \
        --disable-pps \
        --disable-rtc \
        --disable-privdrop \
        --without-libcap \
        --without-seccomp \
        --disable-timestamping \
    && make -j2 chronyc \
    && cp chronyc /usr/local/bin/chronyc \
    && /usr/local/bin/chronyc -v | grep -F "version ${CHRONY_VERSION}"

# The source observes but cannot adjust the shared container/host clock.  It
# has no listening NTP or UDP monitoring port and runs as the same fixed
# unprivileged identity as the evidence supervisor.
FROM ${ALPINE_IMAGE} AS chrony-source
RUN apk add --no-cache \
        "ca-certificates=20260611-r0" \
        "chrony=4.8-r2" \
    && addgroup -S -g 10001 autoquant \
    && adduser -S -D -H -u 10001 -G autoquant autoquant \
    && mkdir -p /etc/autoquant/trusted-time /run/chrony /var/lib/chrony/nts \
    && chown -R 10001:10001 /run/chrony /var/lib/chrony \
    && chmod 0750 /run/chrony \
    && chronyd -v | grep -F "version 4.8"
COPY --chown=0:0 --chmod=0444 infra/trusted-time/chrony.conf \
    /etc/autoquant/trusted-time/chrony.conf
RUN echo "5b59d843624fa3b1a923804e44df96a7fbce3848380bf0d5a4b888072310fa23  /etc/autoquant/trusted-time/chrony.conf" \
    | sha256sum -c -

USER 10001:10001
ENTRYPOINT ["/usr/sbin/chronyd"]
CMD ["-x", "-d", "-U", "-f", "/etc/autoquant/trusted-time/chrony.conf"]

# Keep the persistence process on the already reviewed Python production base.
# The database and Phase 6D anchor inputs plus the Chrony socket are mounted at runtime.
FROM ${PYTHON_IMAGE} AS trusted-time-supervisor
COPY --from=uv /uv /uvx /bin/

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_DEV=1 \
    UV_NO_SYNC=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /workspace
COPY pyproject.toml uv.lock ./
COPY apps/__init__.py ./apps/__init__.py
COPY apps/trusted_time_supervisor ./apps/trusted_time_supervisor
COPY packages ./packages
COPY infra/trusted-time ./infra/trusted-time
RUN uv sync --no-dev --locked \
    && groupadd --system --gid 10001 autoquant \
    && useradd --system --uid 10001 --gid autoquant --home-dir /nonexistent autoquant \
    && mkdir -p /etc/autoquant/trusted-time \
    && install -o root -g root -m 0444 infra/trusted-time/chrony.conf \
        /etc/autoquant/trusted-time/chrony.conf \
    && install -o root -g root -m 0444 infra/trusted-time/source-authority.json \
        /etc/autoquant/trusted-time/source-authority.json \
    && install -o root -g root -m 0444 \
        packages/persistence/certs/supabase-prod-ca-2021.crt \
        /etc/autoquant/trusted-time/supabase-prod-ca-2021.crt
COPY --from=chronyc-build --chown=0:0 --chmod=0555 /usr/local/bin/chronyc \
    /usr/local/bin/chronyc
RUN /usr/local/bin/chronyc -v | grep -F "version 4.8" \
    && echo "5b59d843624fa3b1a923804e44df96a7fbce3848380bf0d5a4b888072310fa23  /etc/autoquant/trusted-time/chrony.conf" \
        | sha256sum -c - \
    && echo "700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7  /etc/autoquant/trusted-time/supabase-prod-ca-2021.crt" \
        | sha256sum -c -

USER 10001:10001
CMD ["autoquant-trusted-time-supervisor"]
