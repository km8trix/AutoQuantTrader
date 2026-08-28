# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG ALPINE_IMAGE=alpine:3.23.5@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
ARG PYTHON_BUILDER_IMAGE=python:3.12.13-bookworm@sha256:3cd9086bdb30f7c9bc08a3fa621d9842e0d3f6f9291aeb4677e0547817c10b12
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

# Compile the CPython-minor/platform wheel in an isolated stage.  The compiler,
# headers, source, and build backend never enter the production rootfs.
FROM ${PYTHON_BUILDER_IMAGE} AS trusted-time-supervisor-build
COPY --from=uv /uv /uvx /bin/

ENV PATH="/opt/autoquant/trusted-time/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SOURCE_DATE_EPOCH=0 \
    UV_COMPILE_BYTECODE=0 \
    UV_BUILD_CONSTRAINT=/workspace/build_support/native_build_constraints.txt \
    UV_LINK_MODE=copy \
    UV_NO_DEV=1 \
    UV_PROJECT_ENVIRONMENT=/opt/autoquant/trusted-time

WORKDIR /workspace
RUN python -I -B -c \
        'import platform, sys; assert sys.version_info[:3] == (3, 12, 13); assert platform.machine() in ("aarch64", "x86_64")' \
    && case "$(uname -m)" in \
        aarch64) \
            gcc_sha256=dc53dbc5a583d03ae8ed6272ca9afc0f58873f9f9b86dd7d448b17fb3f88a8d0; \
            readelf_sha256=4f2b46707a337a09271ec70ddbbbb648b5ede5ed82f4e055b5133c9818647e32 ;; \
        x86_64) \
            gcc_sha256=75e997ec62297a6484f491bae28ab0ccb489daba23e398fd10fe68e9e6f0def8; \
            readelf_sha256=afa25ff2dc25a71b79e853b9e3a9abb7b4e8c83efac17c0a637cbbb687442a4f ;; \
        *) exit 1 ;; \
    esac \
    && echo "${gcc_sha256}  /usr/bin/gcc" | sha256sum -c - \
    && echo "${readelf_sha256}  /usr/bin/readelf" | sha256sum -c - \
    && echo "729ef157f6026e6e1b3104593f87dddc597c3b83b60c7c2965878c62a56c6f7d  /usr/local/include/python3.12/Python.h" \
        | sha256sum -c -
COPY pyproject.toml uv.lock ./
COPY build_support/build_trusted_time_v2_candidates.py \
    build_support/build_trusted_time_v2_linked_role_test.py \
    build_support/exercise_trusted_time_v2_exact_candidates.py \
    build_support/native_build_constraints.txt \
    build_support/native_image_manifest.py \
    build_support/native_owned_file_descriptor_hook.py \
    build_support/qualify_trusted_time_v2_candidates.py \
    build_support/smoke_trusted_time_v2_sdist.py \
    build_support/trusted_time_v2_candidate_execution.Dockerfile \
    build_support/trusted_time_v2_seccomp_manifests.py \
    ./build_support/
COPY build_support/trusted_time_v2_candidate_import_roots/host/autoquant_trusted_time_v2_host_entry.py \
    ./build_support/trusted_time_v2_candidate_import_roots/host/autoquant_trusted_time_v2_host_entry.py
COPY build_support/trusted_time_v2_candidate_import_roots/recovery/autoquant_trusted_time_v2_recovery_entry.py \
    ./build_support/trusted_time_v2_candidate_import_roots/recovery/autoquant_trusted_time_v2_recovery_entry.py
COPY build_support/trusted_time_v2_candidate_import_roots/supervisor/autoquant_trusted_time_v2_supervisor_entry.py \
    ./build_support/trusted_time_v2_candidate_import_roots/supervisor/autoquant_trusted_time_v2_supervisor_entry.py
COPY infra/trusted-time/graceful-stop-v2/seccomp/host.json \
    infra/trusted-time/graceful-stop-v2/seccomp/provisioner.json \
    infra/trusted-time/graceful-stop-v2/seccomp/recovery.json \
    infra/trusted-time/graceful-stop-v2/seccomp/supervisor.json \
    ./infra/trusted-time/graceful-stop-v2/seccomp/
COPY native/bounded_process.c \
    native/owned_file_descriptor.c \
    native/trusted_time_graceful_stop_v2_endpoint.c \
    native/trusted_time_graceful_stop_v2_endpoint.h \
    native/trusted_time_graceful_stop_v2_resources.c \
    native/trusted_time_graceful_stop_v2_resources.h \
    native/trusted_time_graceful_stop_v2_signer.c \
    native/trusted_time_graceful_stop_v2_signer.h \
    native/trusted_time_python_launcher.c \
    native/trusted_time_v2_authority.c \
    native/trusted_time_v2_authority.h \
    native/trusted_time_v2_descriptor_baseline.c \
    native/trusted_time_v2_descriptor_baseline.h \
    native/trusted_time_v2_fork_guard.c \
    native/trusted_time_v2_fork_guard.h \
    native/trusted_time_v2_provisioner.c \
    native/trusted_time_v2_provisioner.h \
    native/trusted_time_v2_role_launcher.c \
    native/trusted_time_v2_role_launcher.h \
    native/trusted_time_v2_seccomp.c \
    native/trusted_time_v2_seccomp.h \
    native/trusted_time_v2_secret_mount_admission.c \
    native/trusted_time_v2_secret_mount_admission.h \
    ./native/
COPY third_party/monocypher/4.0.3/LICENCE.md \
    third_party/monocypher/4.0.3/VENDORING.json \
    ./third_party/monocypher/4.0.3/
COPY third_party/monocypher/4.0.3/src/monocypher.c \
    third_party/monocypher/4.0.3/src/monocypher.h \
    ./third_party/monocypher/4.0.3/src/
COPY third_party/monocypher/4.0.3/src/optional/monocypher-ed25519.c \
    third_party/monocypher/4.0.3/src/optional/monocypher-ed25519.h \
    ./third_party/monocypher/4.0.3/src/optional/
COPY tests/native/trusted_time_v2_seccomp_manifest_harness.c \
    ./tests/native/trusted_time_v2_seccomp_manifest_harness.c
COPY tests/fixtures/native/trusted-time-v2/import-roots/host/autoquant_trusted_time_v2_host_entry.py \
    ./tests/fixtures/native/trusted-time-v2/import-roots/host/autoquant_trusted_time_v2_host_entry.py
COPY tests/fixtures/native/trusted-time-v2/import-roots/recovery/autoquant_trusted_time_v2_recovery_entry.py \
    ./tests/fixtures/native/trusted-time-v2/import-roots/recovery/autoquant_trusted_time_v2_recovery_entry.py
COPY tests/fixtures/native/trusted-time-v2/import-roots/supervisor/autoquant_trusted_time_v2_supervisor_entry.py \
    ./tests/fixtures/native/trusted-time-v2/import-roots/supervisor/autoquant_trusted_time_v2_supervisor_entry.py
COPY apps/__init__.py ./apps/__init__.py
COPY apps/trusted_time_supervisor ./apps/trusted_time_supervisor
COPY packages ./packages
RUN uv build --sdist --no-sources \
        --build-constraints /workspace/build_support/native_build_constraints.txt \
        --require-hashes \
        --out-dir /tmp/autoquant-native-dist/sdist \
        /workspace \
    && uv build --wheel --no-sources \
        --build-constraints /workspace/build_support/native_build_constraints.txt \
        --require-hashes \
        --out-dir /tmp/autoquant-native-dist/wheel \
        /tmp/autoquant-native-dist/sdist/autoquant_trader-0.1.0.tar.gz \
    && uv sync --no-dev --locked --no-install-project --no-build \
    && set -- /tmp/autoquant-native-dist/wheel/*.whl \
    && [ "$#" -eq 1 ] \
    && uv pip install \
        --python /opt/autoquant/trusted-time/bin/python \
        --no-deps \
        "$1"

# Keep the persistence process on the already reviewed Python production base.
# The database and Phase 6D anchor inputs plus the Chrony socket are mounted at runtime.
FROM ${PYTHON_IMAGE} AS trusted-time-supervisor

ENV PATH="/opt/autoquant/trusted-time/bin:${PATH}" \
    LD_LIBRARY_PATH="" \
    LD_PRELOAD="" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=0 \
    UV_NO_DEV=1 \
    UV_NO_SYNC=1 \
    UV_PROJECT_ENVIRONMENT=/opt/autoquant/trusted-time

WORKDIR /
COPY --from=trusted-time-supervisor-build --chown=0:0 \
    /opt/autoquant/trusted-time \
    /opt/autoquant/trusted-time
COPY --chown=0:0 --chmod=0444 infra/trusted-time/chrony.conf \
    /etc/autoquant/trusted-time/chrony.conf
COPY --chown=0:0 --chmod=0444 infra/trusted-time/source-authority.json \
    /etc/autoquant/trusted-time/source-authority.json
COPY --chown=0:0 --chmod=0444 packages/persistence/certs/supabase-prod-ca-2021.crt \
    /etc/autoquant/trusted-time/supabase-prod-ca-2021.crt
RUN groupadd --system --gid 10001 autoquant \
    && useradd --system --uid 10001 --gid autoquant --home-dir /nonexistent autoquant \
    && test "$(id -u autoquant)" = 10001 \
    && test "$(id -g autoquant)" = 10001
COPY --from=chronyc-build --chown=0:0 --chmod=0555 /usr/local/bin/chronyc \
    /usr/local/bin/chronyc
COPY --chown=0:0 --chmod=0444 build_support/native_image_manifest.py \
    /usr/local/lib/autoquant-native-image-manifest.py
RUN echo "5b59d843624fa3b1a923804e44df96a7fbce3848380bf0d5a4b888072310fa23  /etc/autoquant/trusted-time/chrony.conf" \
        | sha256sum -c - \
    && echo "700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7  /etc/autoquant/trusted-time/supabase-prod-ca-2021.crt" \
        | sha256sum -c - \
    && chown -R 0:0 /opt/autoquant/trusted-time /etc/autoquant \
    && find /opt/autoquant/trusted-time /etc/autoquant -type d -exec chmod 0555 {} + \
    && find /opt/autoquant/trusted-time /etc/autoquant -type f -exec chmod a-w {} + \
    && chmod 0550 /var/cache/apt/archives/partial \
    && /usr/local/bin/python -I -B -S -c \
        'import os, platform, sys; assert sys.version_info[:3] == (3, 12, 13); assert platform.machine() in ("aarch64", "x86_64"); prefix = "/opt/autoquant/trusted-time"; launcher = prefix + "/bin/autoquant-trusted-time-python"; directory = prefix + "/share/autoquant-trader/native"; attestation = directory + "/native_owned_file_descriptor_launcher.json"; assert sorted(os.listdir(directory)) == [os.path.basename(attestation)]; startup_hook = prefix + "/lib/python3.12/site-packages/_virtualenv.pth"; assert open(startup_hook, "rb").read() == b"import _virtualenv"; os.unlink(startup_hook); os.chmod(launcher, 0o555); os.chmod(attestation, 0o444); assert os.stat(launcher, follow_symlinks=False).st_mode & 0o777 == 0o555; assert os.stat(attestation, follow_symlinks=False).st_mode & 0o777 == 0o444' \
    && mkdir -p /etc/autoquant/native \
    && chmod 0555 /etc/autoquant/native \
    && test -z "${LD_LIBRARY_PATH}" \
    && test -z "${LD_PRELOAD}" \
    && /usr/local/bin/python -I -B -S \
        /usr/local/lib/autoquant-native-image-manifest.py \
        write / /etc/autoquant/native/executable-import-manifest.jsonl \
    && /usr/local/bin/python -I -B -S \
        /usr/local/lib/autoquant-native-image-manifest.py \
        verify / /etc/autoquant/native/executable-import-manifest.jsonl \
    && /usr/local/bin/chronyc -v | grep -F "version 4.8"

USER 10001:10001
CMD ["/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python", "supervisor"]
