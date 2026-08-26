"""Build and qualify the two Phase 6D trusted-time images by immutable ID."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import io
import json
import os
import re
import secrets
import stat
import sys
import tarfile
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Never, cast


def _require_isolated_cli_source_runtime(
    *,
    expected_relative_path: Path,
    module_file: str = __file__,
) -> Path:
    """Fail closed unless this CLI is executing canonical source in an isolated runtime."""

    try:
        repository_root = Path.cwd()
        expected_source = repository_root / expected_relative_path
        actual_source = Path(os.path.abspath(module_file))
        source_metadata = expected_source.lstat()
        canonical_root = repository_root.resolve(strict=True)
        canonical_source = expected_source.resolve(strict=True)
        runtime_prefix = Path(sys.prefix).resolve(strict=True)
        base_prefix = Path(sys.base_prefix).resolve(strict=True)
        reusable_repository_venv = (canonical_root / ".venv").resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        raise RuntimeError("trusted-time CLI runtime attestation failed") from None
    if (
        repository_root != canonical_root
        or expected_source != canonical_source
        or actual_source != expected_source
        or not stat.S_ISREG(source_metadata.st_mode)
        or source_metadata.st_nlink != 1
        or sys.flags.isolated != 1
        or sys.flags.dont_write_bytecode != 1
        or sys.pycache_prefix != "/dev/null"
        or runtime_prefix in (base_prefix, reusable_repository_venv)
        or runtime_prefix.is_relative_to(reusable_repository_venv)
    ):
        raise RuntimeError("trusted-time CLI runtime attestation failed")
    for raw_path in sys.path:
        if not raw_path:
            continue
        try:
            candidate = Path(raw_path).resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            raise RuntimeError("trusted-time CLI runtime attestation failed") from None
        if candidate == reusable_repository_venv or candidate.is_relative_to(
            reusable_repository_venv
        ):
            raise RuntimeError("trusted-time CLI runtime attestation failed")
    sys.path.insert(0, os.fspath(canonical_root))
    return canonical_root


def _require_repository_first_party_sources(repository_root: Path) -> None:
    """Require every loaded first-party module to originate at its exact source path."""

    for module_name, module in tuple(sys.modules.items()):
        if module_name.split(".", 1)[0] not in {"apps", "packages", "scripts"}:
            continue
        origin = getattr(module, "__file__", None)
        if type(origin) is not str:
            raise RuntimeError("trusted-time first-party source attestation failed")
        module_path = repository_root.joinpath(*module_name.split("."))
        expected_sources = {
            module_path.with_suffix(".py"),
            module_path / "__init__.py",
        }
        try:
            lexical_origin = Path(os.path.abspath(origin))
            canonical_origin = lexical_origin.resolve(strict=True)
            source_metadata = lexical_origin.lstat()
        except (OSError, RuntimeError, ValueError):
            raise RuntimeError("trusted-time first-party source attestation failed") from None
        if (
            lexical_origin != canonical_origin
            or lexical_origin not in expected_sources
            or lexical_origin.suffix != ".py"
            or "__pycache__" in lexical_origin.parts
            or not stat.S_ISREG(source_metadata.st_mode)
            or source_metadata.st_nlink != 1
        ):
            raise RuntimeError("trusted-time first-party source attestation failed")


_CLI_REPOSITORY_ROOT = (
    _require_isolated_cli_source_runtime(
        expected_relative_path=Path("scripts/verify_trusted_time_images.py")
    )
    if __name__ == "__main__"
    else None
)

from packages.adapters.trusted_time._bounded_process import (  # noqa: E402
    _run_bounded_process,
)
from packages.adapters.trusted_time._owned_file_descriptor import (  # noqa: E402
    _fstat as _native_fstat,
)
from packages.adapters.trusted_time._owned_file_descriptor import (  # noqa: E402
    _list_snapshot as _native_list_snapshot,
)
from packages.adapters.trusted_time._owned_file_descriptor import (  # noqa: E402
    _open_child_directory as _native_open_child_directory,
)
from packages.adapters.trusted_time._owned_file_descriptor import (  # noqa: E402
    _open_child_regular as _native_open_child_regular,
)
from packages.adapters.trusted_time._owned_file_descriptor import (  # noqa: E402
    _open_root_directory as _native_open_root_directory,
)
from packages.adapters.trusted_time._owned_file_descriptor import (  # noqa: E402
    _OwnedFileDescriptor as _NativeOwnedFileDescriptor,
)
from packages.adapters.trusted_time._owned_file_descriptor import (  # noqa: E402
    _read_snapshot as _native_read_snapshot,
)
from packages.adapters.trusted_time._owned_file_descriptor import (  # noqa: E402
    _statat as _native_statat,
)
from scripts.bounded_subprocess import (  # noqa: E402
    BoundedSubprocessError,
    BoundedSubprocessResult,
    run_bounded_subprocess,
)

ROOT = _CLI_REPOSITORY_ROOT or Path(__file__).resolve().parents[1]
if _CLI_REPOSITORY_ROOT is not None:
    _require_repository_first_party_sources(ROOT)
CONFIG_SHA256 = hashlib.sha256(
    (ROOT / "infra" / "trusted-time" / "chrony.conf").read_bytes()
).hexdigest()
AUTHORITY_SHA256 = hashlib.sha256(
    (ROOT / "infra" / "trusted-time" / "source-authority.json").read_bytes()
).hexdigest()
DATABASE_CA_SHA256 = hashlib.sha256(
    (ROOT / "packages" / "persistence" / "certs" / "supabase-prod-ca-2021.crt").read_bytes()
).hexdigest()
COMPOSE_PATH = ROOT / "infra" / "compose" / "trusted-time.compose.yaml"
DEFAULTS_PATH = ROOT / "infra" / "compose" / "trusted-time.defaults.env"
SOURCE_IMAGE = "autoquanttrader-trusted-time-source:phase6d-v1"
SUPERVISOR_IMAGE = "autoquanttrader-trusted-time-supervisor:phase6d-v1"
SOURCE_IMAGE_ENVIRONMENT = "AQT_TRUSTED_TIME_SOURCE_IMAGE"
SUPERVISOR_IMAGE_ENVIRONMENT = "AQT_TRUSTED_TIME_SUPERVISOR_IMAGE"
DATABASE_SECRET_FILE_ENVIRONMENT = "AQT_TRUSTED_TIME_DATABASE_SECRET_SOURCE_FILE"
_SECRETLESS_SUPERVISOR_INPUT_DIGEST = "0" * 64
_SECRETLESS_SUPERVISOR_DOCKER_ENVIRONMENT_ARGUMENTS = (
    "--env",
    "AQT_TRUSTED_TIME_EXPECTED_DATABASE_URL_SHA256=" + _SECRETLESS_SUPERVISOR_INPUT_DIGEST,
    "--env",
    "AQT_TRUSTED_TIME_EXPECTED_HEAD_ANCHOR_AUTHORITY_SHA256=" + _SECRETLESS_SUPERVISOR_INPUT_DIGEST,
    "--env",
    "AQT_TRUSTED_TIME_EXPECTED_HEAD_ANCHOR_AUTH_SECRET_SHA256="
    + _SECRETLESS_SUPERVISOR_INPUT_DIGEST,
    "--env",
    "AQT_TRUSTED_TIME_EXPECTED_HEAD_ANCHOR_SIGNING_KEY_SHA256="
    + _SECRETLESS_SUPERVISOR_INPUT_DIGEST,
)
IGNORED_ARTIFACT_ROOT = ROOT / "artifacts"
DEFAULT_IMAGE_ADMISSION_ARTIFACT = IGNORED_ARTIFACT_ROOT / "trusted-time" / "image-admission.json"
IMAGE_ADMISSION_CONTRACT_VERSION = "phase6d-trusted-time-image-admission-v3"
IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS = 900
MAXIMUM_IMAGE_ADMISSION_BYTES = 65_536
SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_PATH = (
    "/etc/autoquant/native/executable-import-manifest.jsonl"
)
SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_HELPER = "/usr/local/lib/autoquant-native-image-manifest.py"
SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SCHEMA = "autoquant-native-executable-image-manifest-v2"
_MAXIMUM_EXECUTABLE_IMPORT_MANIFEST_BYTES = 128 * 1_024 * 1_024
_MAXIMUM_GIT_REVISION_STDOUT_BYTES = 64
_MAXIMUM_GIT_STATUS_STDOUT_BYTES = 65_536
_MAXIMUM_GIT_TREE_STDOUT_BYTES = 8 * 1_024 * 1_024
_MAXIMUM_GIT_BATCH_STDOUT_BYTES = 64 * 1_024 * 1_024
_MAXIMUM_GIT_BATCH_STDIN_BYTES = 1 * 1_024 * 1_024
_MAXIMUM_GIT_STDERR_BYTES = 16_384
_MAXIMUM_OPERATOR_AUTHORITY_GIT_BYTES = 4_096
_MAXIMUM_OPERATOR_AUTHORITY_GIT_TREE_BYTES = 1_024
_POST_ENROLLMENT_OPERATOR_AUTHORITY_RELATIVE_PATH = (
    "infra/trusted-time/post-enrollment-operator-attestation-authority.json"
)
_MAXIMUM_DOCKER_BUILD_STDOUT_BYTES = 128
_MAXIMUM_DOCKER_CONTROL_STDOUT_BYTES = 1 * 1_024 * 1_024
_MAXIMUM_DOCKER_INSPECTION_STDOUT_BYTES = 4 * 1_024 * 1_024
_MAXIMUM_DOCKER_STDERR_BYTES = 1 * 1_024 * 1_024
_MAXIMUM_DOCKER_BUILD_CONTEXT_BYTES = 72 * 1_024 * 1_024
_MAXIMUM_REVIEWED_INPUT_BYTES = 4 * 1_024 * 1_024
MIGRATION_PATH = ROOT / "migrations" / "versions" / "0036_phase6_trusted_time_head_anchors.py"
_TRUSTED_TIME_DOCKERFILE_RELATIVE_PATH = "infra/docker/trusted-time.Dockerfile"
_TRUSTED_TIME_DOCKERFILE_FRONTEND = (
    b"# syntax=docker/dockerfile:1.7@sha256:"
    b"a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e\n"
)
_REVIEWED_FIXED_RELATIVE_PATHS = (
    ".dockerignore",
    "Makefile",
    "apps/__init__.py",
    "build_support/native_build_constraints.txt",
    "build_support/native_image_manifest.py",
    "build_support/native_owned_file_descriptor_hook.py",
    "infra/compose/trusted-time.compose.yaml",
    "infra/compose/trusted-time.defaults.env",
    _TRUSTED_TIME_DOCKERFILE_RELATIVE_PATH,
    "infra/docker/trusted-time.Dockerfile.dockerignore",
    "infra/trusted-time/chrony.conf",
    "infra/trusted-time/source-authority.json",
    "migrations/versions/0036_phase6_trusted_time_head_anchors.py",
    "native/bounded_process.c",
    "native/owned_file_descriptor.c",
    "native/trusted_time_python_launcher.c",
    "packages/persistence/certs/supabase-prod-ca-2021.crt",
    "pyproject.toml",
    "scripts/bounded_subprocess.py",
    "scripts/credential_env.py",
    "scripts/enroll_trusted_time_head_anchor.py",
    "scripts/inspect_trusted_time_qualification.py",
    "scripts/start_trusted_time_supervisor.py",
    "scripts/trusted_time_post_enrollment_action_topology_fence.py",
    "scripts/trusted_time_post_enrollment_active_controller.py",
    "scripts/trusted_time_post_enrollment_active_controller_admission.py",
    "scripts/trusted_time_post_enrollment_claimed_fence.py",
    "scripts/trusted_time_post_enrollment_clean_stop_terminal_reauthentication.py",
    "scripts/trusted_time_post_enrollment_controller_outcome.py",
    "scripts/trusted_time_post_enrollment_evidence.py",
    "scripts/trusted_time_post_enrollment_execution_admission.py",
    "scripts/trusted_time_post_enrollment_graceful_stop.py",
    "scripts/trusted_time_post_enrollment_graceful_stop_lifecycle.py",
    "scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py",
    "scripts/trusted_time_post_enrollment_host_orchestrator.py",
    "scripts/trusted_time_post_enrollment_outcome.py",
    "scripts/trusted_time_post_enrollment_persistent_topology.py",
    "scripts/trusted_time_post_enrollment_shutdown_locator.py",
    "scripts/trusted_time_post_enrollment_sequence_one_reauthentication.py",
    "scripts/trusted_time_post_enrollment_sequence_two_verifier.py",
    "scripts/trusted_time_post_enrollment_staged_topology.py",
    "scripts/trusted_time_post_enrollment_staging.py",
    "scripts/trusted_time_post_enrollment_start.py",
    "scripts/trusted_time_post_enrollment_topology.py",
    "scripts/trusted_time_post_enrollment_topology_fence.py",
    "scripts/trusted_time_post_enrollment_topology_reader.py",
    "scripts/verify_trusted_time_compose.py",
    "scripts/verify_trusted_time_images.py",
    "uv.lock",
)
_REVIEWED_DIRECTORY_RELATIVE_PATHS = (
    "apps/trusted_time_supervisor",
    "infra/trusted-time",
    "packages",
)
_TRUSTED_TIME_DOCKERIGNORE_BYTES = b"""\
**
!pyproject.toml
!uv.lock
!build_support/
!build_support/native_image_manifest.py
!build_support/native_build_constraints.txt
!build_support/native_owned_file_descriptor_hook.py
!native/
!native/bounded_process.c
!native/owned_file_descriptor.c
!native/trusted_time_python_launcher.c
!apps/
!apps/__init__.py
!apps/trusted_time_supervisor/
!apps/trusted_time_supervisor/**/
!apps/trusted_time_supervisor/**/*.py
!packages/
!packages/**/
!packages/**/*.py
!packages/persistence/certs/supabase-prod-ca-2021.crt
!infra/
!infra/trusted-time/
!infra/trusted-time/chrony.conf
!infra/trusted-time/source-authority.json
**/__pycache__
**/__pycache__/**
**/.hypothesis
**/.hypothesis/**
**/.mypy_cache
**/.mypy_cache/**
**/.pytest_cache
**/.pytest_cache/**
**/.ruff_cache
**/.ruff_cache/**
**/.venv
**/.venv/**
**/node_modules
**/node_modules/**
"""
_BUILD_CONTEXT_FIXED_RELATIVE_PATHS = frozenset(
    {
        "apps/__init__.py",
        "build_support/native_build_constraints.txt",
        "build_support/native_image_manifest.py",
        "build_support/native_owned_file_descriptor_hook.py",
        _TRUSTED_TIME_DOCKERFILE_RELATIVE_PATH,
        "infra/docker/trusted-time.Dockerfile.dockerignore",
        "infra/trusted-time/chrony.conf",
        "infra/trusted-time/source-authority.json",
        "native/bounded_process.c",
        "native/owned_file_descriptor.c",
        "native/trusted_time_python_launcher.c",
        "packages/persistence/certs/supabase-prod-ca-2021.crt",
        "pyproject.toml",
        "uv.lock",
    }
)
EXPECTED_SCHEMA_REVISION = "0036_phase6_time_anchors"
EXPECTED_CATALOG_RELATIONS = (
    "phase6_trusted_time_head_anchor_intents",
    "phase6_trusted_time_head_anchor_receipts",
)
SUPERVISOR_SCHEMA_CONTRACT_COMMAND = (
    "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
    "image-schema-contract",
)
SUPERVISOR_BASE_PYTHON = "/usr/local/bin/python"
SOCKET_VOLUME_DRIVER_OPTIONS = {
    "type": "tmpfs",
    "device": "tmpfs",
    "o": "rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0750",
}
_SOCKET_MOUNTINFO_RECEIPT = "tmpfs:rw:noexec:nosuid:nodev\n"
_SOCKET_MOUNTINFO_CHECK = r"""
set -f
seen=0
while IFS= read -r line; do
    field=0
    mount_point=
    mount_options=
    separator=0
    filesystem_type=
    super_options=
    for value in $line; do
        field=$((field + 1))
        if [ "$field" -eq 5 ]; then mount_point=$value; fi
        if [ "$field" -eq 6 ]; then mount_options=$value; fi
        if [ "$separator" -eq 1 ]; then
            filesystem_type=$value
            separator=2
        elif [ "$separator" -eq 2 ]; then
            separator=3
        elif [ "$separator" -eq 3 ]; then
            super_options=$value
            separator=4
        elif [ "$value" = - ]; then
            separator=1
        fi
    done
    if [ "$mount_point" != /run/chrony ]; then continue; fi
    seen=$((seen + 1))
    if [ "$filesystem_type" != tmpfs ]; then exit 41; fi
    options=,$mount_options,
    case "$options" in *,rw,*) ;; *) exit 42 ;; esac
    case "$options" in *,noexec,*) ;; *) exit 43 ;; esac
    case "$options" in *,nosuid,*) ;; *) exit 44 ;; esac
    case "$options" in *,nodev,*) ;; *) exit 45 ;; esac
    case "$options" in *,ro,*|*,exec,*|*,suid,*|*,dev,*) exit 47 ;; esac
done < /proc/self/mountinfo
if [ "$seen" -ne 1 ]; then exit 46; fi
printf 'tmpfs:rw:noexec:nosuid:nodev\n'
""".strip()
_IMAGE_INSPECTION_FORMAT = (
    '{"cmd":{{json (index .Config "Cmd")}},'
    '"entrypoint":{{json (index .Config "Entrypoint")}},'
    '"env":{{json (index .Config "Env")}},'
    '"exposed_ports":{{json (index .Config "ExposedPorts")}},'
    '"healthcheck":{{json (index .Config "Healthcheck")}},"id":{{json .Id}},'
    '"shell":{{json (index .Config "Shell")}},'
    '"user":{{json (index .Config "User")}},'
    '"volumes":{{json (index .Config "Volumes")}},'
    '"working_dir":{{json (index .Config "WorkingDir")}}}'
)
_IMAGE_ID_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_GIT_REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")
_GIT_OBJECT_ID_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_BOOT_SESSION_UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
_BOOT_SESSION_ID_PATTERN = re.compile(
    r"(?:darwin|linux):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}"
)
_LINUX_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
_DARWIN_BOOT_SESSION_COMMAND = (
    "/usr/sbin/sysctl",
    "-n",
    "kern.bootsessionuuid",
)
_CREATED_AT_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{6}Z"
)
_CHRONYD_VERSION_PATTERN = re.compile(
    r"chronyd \(chrony\) version 4\.8 \((?P<features>[+-][A-Z0-9_]+"
    r"(?: [+-][A-Z0-9_]+)*)\)\n?"
)
_CHRONYC_VERSION_PATTERN = re.compile(
    r"chronyc \(chrony\) version 4\.8 \([+-][A-Z0-9_]+"
    r"(?: [+-][A-Z0-9_]+)*\)\n?"
)
_PASSTHROUGH_ENVIRONMENT = frozenset(
    {
        "DOCKER_CERT_PATH",
        "DOCKER_CONFIG",
        "DOCKER_CONTEXT",
        "DOCKER_HOST",
        "DOCKER_TLS_VERIFY",
        "HOME",
        "LANG",
        "LC_ALL",
        "NO_COLOR",
        "PATH",
        "TERM",
        "TMPDIR",
        "XDG_CONFIG_HOME",
    }
)
_STATIC_ELF_CHECK = """\
import struct
import sys

path = "/usr/local/bin/chronyc"
try:
    payload = open(path, "rb").read()
    if len(payload) < 64 or payload[:4] != b"\\x7fELF" or payload[4] != 2:
        raise ValueError
    byte_order = "<" if payload[5] == 1 else ">" if payload[5] == 2 else None
    if byte_order is None:
        raise ValueError
    program_offset = struct.unpack_from(byte_order + "Q", payload, 32)[0]
    entry_size = struct.unpack_from(byte_order + "H", payload, 54)[0]
    entry_count = struct.unpack_from(byte_order + "H", payload, 56)[0]
    if entry_size < 56 or program_offset + entry_size * entry_count > len(payload):
        raise ValueError
    for index in range(entry_count):
        offset = program_offset + index * entry_size
        if struct.unpack_from(byte_order + "I", payload, offset)[0] == 3:
            raise ValueError
except (OSError, struct.error, ValueError):
    sys.exit(1)
"""
_CA_STORE_CHECK = """\
import os
import sys

path = "/etc/ssl/certs/ca-certificates.crt"
try:
    metadata = os.stat(path, follow_symlinks=True)
except OSError:
    sys.exit(1)
sys.exit(0 if metadata.st_size > 0 else 1)
"""


class TrustedTimeImageVerificationError(RuntimeError):
    """A built image differs from the reviewed evidence-only contract."""


class _OwnedFileDescriptor(ctypes.c_int):
    """Own one libc-opened descriptor before the Python CALL can return."""

    def fileno(self) -> int:
        descriptor = self.value
        if descriptor < 0:
            raise OSError
        return descriptor

    def __index__(self) -> int:
        return self.fileno()

    @property
    def closed(self) -> bool:
        return self.value < 0

    def close(self) -> None:
        descriptor = self.value
        if descriptor < 0:
            return
        try:
            self.value = -1
            os.close(descriptor)
        except OSError:
            raise
        except BaseException:
            with suppress(OSError):
                os.close(descriptor)
            raise

    def __del__(self) -> None:
        with suppress(BaseException):
            self.close()


def _preferred_cleanup_exception(
    primary: BaseException | None,
    cleanup: BaseException | None,
) -> BaseException | None:
    if primary is not None and not isinstance(primary, Exception):
        return primary
    if cleanup is not None and not isinstance(cleanup, Exception):
        return cleanup
    return primary if primary is not None else cleanup


def _preferred_cleanup_exceptions(
    *errors: BaseException | None,
) -> BaseException | None:
    preferred: BaseException | None = None
    for error in errors:
        preferred = _preferred_cleanup_exception(preferred, error)
    return preferred


def _cleanup_owned_descriptors(
    owners: tuple[_OwnedFileDescriptor | None, ...],
) -> BaseException | None:
    first_error: BaseException | None = None
    for owner in owners:
        if owner is None or owner.closed:
            continue
        try:
            owner.close()
        except BaseException as error:
            first_error = _preferred_cleanup_exception(first_error, error)
    return first_error


def _cleanup_native_owned_descriptors(
    owners: tuple[_NativeOwnedFileDescriptor | None, ...],
) -> BaseException | None:
    """Close every native owner and preserve asynchronous-exception priority."""

    first_error: BaseException | None = None
    for owner in owners:
        if owner is None:
            continue
        for _ in range(2):
            try:
                if owner.closed:
                    break
                owner.close()
            except BaseException as error:
                first_error = _preferred_cleanup_exception(first_error, error)
        try:
            if not owner.closed:
                first_error = _preferred_cleanup_exception(
                    first_error,
                    RuntimeError("native owned file descriptor could not be closed"),
                )
        except BaseException as error:
            first_error = _preferred_cleanup_exception(first_error, error)
    return first_error


_LIBC = ctypes.CDLL(None, use_errno=True)
_OWNED_OPEN = _LIBC.open
_OWNED_OPEN.argtypes = (ctypes.c_char_p, ctypes.c_int)
_OWNED_OPEN.restype = _OwnedFileDescriptor
_OWNED_OPENAT = _LIBC.openat
_OWNED_OPENAT.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
_OWNED_OPENAT.restype = _OwnedFileDescriptor


def _open_owned_descriptor(
    path: str | Path,
    *,
    flags: int,
    mode: int = 0,
    dir_fd: int | None = None,
) -> _OwnedFileDescriptor:
    """Open directly into a VM-owned descriptor object or raise exact errno."""

    ctypes.set_errno(0)
    if dir_fd is None:
        owner = cast(
            _OwnedFileDescriptor,
            _OWNED_OPEN(os.fsencode(path), flags, ctypes.c_int(mode)),
        )
    else:
        owner = cast(
            _OwnedFileDescriptor,
            _OWNED_OPENAT(dir_fd, os.fsencode(path), flags, ctypes.c_int(mode)),
        )
    if owner.value >= 0:
        return owner
    error_number = ctypes.get_errno() or errno.EIO
    if error_number == errno.EEXIST:
        raise FileExistsError(error_number, os.strerror(error_number), os.fspath(path))
    if error_number == errno.ENOENT:
        raise FileNotFoundError(error_number, os.strerror(error_number), os.fspath(path))
    raise OSError(error_number, os.strerror(error_number), os.fspath(path))


def _open_owned_file(
    path: str | Path,
    *,
    dir_fd: int | None = None,
    exclusive: bool = False,
) -> _OwnedFileDescriptor:
    """Return an already-owning descriptor directly from libc open/openat."""

    flags = (
        ((os.O_RDWR | os.O_CREAT | os.O_EXCL) if exclusive else os.O_RDONLY)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    if not exclusive:
        flags |= getattr(os, "O_NONBLOCK", 0)
    return _open_owned_descriptor(
        path,
        flags=flags,
        mode=0o600,
        dir_fd=dir_fd,
    )


class _DarwinMachTimebaseInfo(ctypes.Structure):
    _fields_ = (("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32))


def _build_suspend_aware_monotonic_clock(
    *,
    platform_name: object,
    clock_gettime_ns: object,
    clock_boottime: object,
    darwin_library_loader: object,
) -> Callable[[], int]:
    """Seal one native clock whose elapsed time includes system suspend."""

    maximum_observation = (1 << 63) - 1

    def unavailable() -> Never:
        raise TrustedTimeImageVerificationError(
            "trusted-time suspend-aware monotonic clock is unavailable"
        ) from None

    def validate(observed: object) -> int:
        if type(observed) is not int or observed < 0 or observed > maximum_observation:
            unavailable()
        return observed

    if platform_name == "linux" and callable(clock_gettime_ns) and type(clock_boottime) is int:
        captured_clock_gettime_ns = clock_gettime_ns
        captured_clock_boottime = clock_boottime

        def linux_clock() -> int:
            try:
                observed = captured_clock_gettime_ns(captured_clock_boottime)
            except BaseException:
                unavailable()
            return validate(observed)

        return linux_clock

    if platform_name == "darwin" and callable(darwin_library_loader):
        try:
            library = darwin_library_loader(None)
            continuous_time = library.mach_continuous_time
            continuous_time.argtypes = []
            continuous_time.restype = ctypes.c_uint64
            timebase_info = library.mach_timebase_info
            timebase_info.argtypes = [ctypes.POINTER(_DarwinMachTimebaseInfo)]
            timebase_info.restype = ctypes.c_int
            timebase = _DarwinMachTimebaseInfo()
            if timebase_info(ctypes.byref(timebase)) != 0:
                raise ValueError
            numerator = int(timebase.numer)
            denominator = int(timebase.denom)
            if numerator <= 0 or denominator <= 0:
                raise ValueError
        except BaseException:
            return unavailable

        def darwin_clock() -> int:
            try:
                ticks = continuous_time()
                if type(ticks) is not int:
                    unavailable()
                observed = ticks * numerator // denominator
            except TrustedTimeImageVerificationError:
                raise
            except BaseException:
                unavailable()
            return validate(observed)

        return darwin_clock

    return unavailable


_suspend_aware_monotonic_ns = _build_suspend_aware_monotonic_clock(
    platform_name=sys.platform,
    clock_gettime_ns=getattr(time, "clock_gettime_ns", None),
    clock_boottime=getattr(time, "CLOCK_BOOTTIME", None),
    darwin_library_loader=ctypes.CDLL,
)


def _canonical_boot_session_id(platform_name: str, encoded_uuid: bytes) -> str:
    if type(encoded_uuid) is not bytes:
        raise TrustedTimeImageVerificationError("trusted-time boot session identity is unavailable")
    if encoded_uuid.endswith(b"\n"):
        encoded_uuid = encoded_uuid[:-1]
    try:
        boot_uuid = encoded_uuid.decode("ascii").lower()
    except UnicodeDecodeError:
        raise TrustedTimeImageVerificationError(
            "trusted-time boot session identity is unavailable"
        ) from None
    if (
        platform_name not in {"darwin", "linux"}
        or _BOOT_SESSION_UUID_PATTERN.fullmatch(boot_uuid) is None
        or boot_uuid.replace("-", "") == "0" * 32
    ):
        raise TrustedTimeImageVerificationError("trusted-time boot session identity is unavailable")
    return f"{platform_name}:{boot_uuid}"


def _linux_boot_session_id() -> str:
    boot_id_path = _LINUX_BOOT_ID_PATH
    directory_owner: _NativeOwnedFileDescriptor | None = None
    next_directory_owner: _NativeOwnedFileDescriptor | None = None
    file_owner: _NativeOwnedFileDescriptor | None = None
    encoded_uuid: bytes | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            path = os.fspath(boot_id_path)
            if (
                type(boot_id_path) is not type(Path())
                or type(path) is not str
                or not os.path.isabs(path)
                or os.path.abspath(path) != path
                or os.path.normpath(path) != path
                or "\x00" in path
            ):
                raise OSError
            components = tuple(path.split(os.sep))[1:]
            if not components or any(
                not component
                or component in {".", ".."}
                or os.sep in component
                or "\x00" in component
                or len(os.fsencode(component)) > 255
                for component in components
            ):
                raise OSError
            directory_owner = _native_open_root_directory()
            for component in components[:-1]:
                next_directory_owner = _native_open_child_directory(
                    directory_owner,
                    component,
                )
                if not stat.S_ISDIR(_native_fstat(next_directory_owner)[2]):
                    raise OSError
                intermediate_error = _cleanup_native_owned_descriptors((directory_owner,))
                if intermediate_error is not None:
                    raise intermediate_error
                directory_owner = next_directory_owner
                next_directory_owner = None
            directory_before = _native_fstat(directory_owner)
            file_name = components[-1]
            file_owner = _native_open_child_regular(directory_owner, file_name)
            before = _native_fstat(file_owner)
            named_before = _native_statat(directory_owner, file_name)
            if before != named_before or not stat.S_ISREG(before[2]):
                raise OSError
            encoded, read_before, read_after = _native_read_snapshot(file_owner, 37)
            final = _native_fstat(file_owner)
            named_final = _native_statat(directory_owner, file_name)
            directory_final = _native_fstat(directory_owner)
            if (
                read_before != before
                or read_after != before
                or final != before
                or named_final != before
                or directory_final != directory_before
                or _LINUX_BOOT_ID_PATH is not boot_id_path
                or os.fspath(boot_id_path) != path
            ):
                raise OSError
            encoded_uuid = encoded
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup_native_owned_descriptors(
                (file_owner, next_directory_owner, directory_owner)
            )
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup_native_owned_descriptors(
            (file_owner, next_directory_owner, directory_owner)
        )
    terminal = _preferred_cleanup_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        if not isinstance(terminal, Exception):
            raise terminal
        raise TrustedTimeImageVerificationError(
            "trusted-time boot session identity is unavailable"
        ) from None
    if encoded_uuid is None:
        raise TrustedTimeImageVerificationError("trusted-time boot session identity is unavailable")
    return _canonical_boot_session_id("linux", encoded_uuid)


def _darwin_boot_session_id() -> str:
    try:
        completed = run_bounded_subprocess(
            _DARWIN_BOOT_SESSION_COMMAND,
            cwd=ROOT,
            environment={"LC_ALL": "C", "PATH": os.defpath},
            timeout_seconds=5,
            maximum_stdout_bytes=64,
            maximum_stderr_bytes=256,
        )
    except BoundedSubprocessError:
        raise TrustedTimeImageVerificationError(
            "trusted-time boot session identity is unavailable"
        ) from None
    if _bytes_process_returncode(completed) != 0 or _bytes_process_stderr(completed) != b"":
        raise TrustedTimeImageVerificationError("trusted-time boot session identity is unavailable")
    return _canonical_boot_session_id("darwin", _bytes_process_stdout(completed))


def _current_boot_session_id() -> str:
    """Return one strict, nonsecret identity for the current kernel boot."""

    if sys.platform == "linux":
        return _linux_boot_session_id()
    if sys.platform == "darwin":
        return _darwin_boot_session_id()
    raise TrustedTimeImageVerificationError("trusted-time boot session identity is unavailable")


@dataclass(frozen=True, slots=True)
class TrustedTimeImageIdentities:
    """Immutable Docker image IDs admitted as one source/supervisor pair."""

    source_id: str
    supervisor_id: str

    def __post_init__(self) -> None:
        if (
            _IMAGE_ID_PATTERN.fullmatch(self.source_id) is None
            or _IMAGE_ID_PATTERN.fullmatch(self.supervisor_id) is None
            or self.source_id == self.supervisor_id
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time immutable image identities are malformed"
            )


type _ResolvedTrustedTimeImageIds = tuple[str, str, str]

type _VerifiedTrustedTimeImages = tuple[str, str, str, str]

type _ImageInspectionProjection = tuple[
    str,
    str,
    str,
    tuple[str, ...] | None,
    tuple[str, ...] | None,
    tuple[str, ...] | None,
    str,
]


def _make_resolved_image_ids(source_id: str, supervisor_id: str) -> _ResolvedTrustedTimeImageIds:
    return ("resolved-trusted-time-image-ids-v1", source_id, supervisor_id)


def _require_resolved_image_ids(value: object) -> _ResolvedTrustedTimeImageIds:
    if type(value) is not tuple or len(value) != 3:
        raise TrustedTimeImageVerificationError(
            "trusted-time immutable image identities are malformed"
        )
    tag = tuple.__getitem__(value, 0)
    source_id = tuple.__getitem__(value, 1)
    supervisor_id = tuple.__getitem__(value, 2)
    if (
        type(tag) is not str
        or tag != "resolved-trusted-time-image-ids-v1"
        or type(source_id) is not str
        or type(supervisor_id) is not str
        or _IMAGE_ID_PATTERN.fullmatch(source_id) is None
        or _IMAGE_ID_PATTERN.fullmatch(supervisor_id) is None
        or source_id == supervisor_id
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time immutable image identities are malformed"
        )
    return cast(_ResolvedTrustedTimeImageIds, value)


def _make_verified_images(
    source_id: str,
    supervisor_id: str,
    supervisor_manifest_sha256: str,
) -> _VerifiedTrustedTimeImages:
    return (
        "verified-trusted-time-images-v1",
        source_id,
        supervisor_id,
        supervisor_manifest_sha256,
    )


def _require_verified_images(value: object) -> _VerifiedTrustedTimeImages:
    if type(value) is not tuple or len(value) != 4:
        raise TrustedTimeImageVerificationError(
            "trusted-time immutable image identities are malformed"
        )
    tag = tuple.__getitem__(value, 0)
    source_id = tuple.__getitem__(value, 1)
    supervisor_id = tuple.__getitem__(value, 2)
    manifest_sha256 = tuple.__getitem__(
        value,
        3,
    )
    if (
        type(tag) is not str
        or tag != "verified-trusted-time-images-v1"
        or type(source_id) is not str
        or type(supervisor_id) is not str
        or type(manifest_sha256) is not str
        or _IMAGE_ID_PATTERN.fullmatch(source_id) is None
        or _IMAGE_ID_PATTERN.fullmatch(supervisor_id) is None
        or source_id == supervisor_id
        or _SHA256_PATTERN.fullmatch(manifest_sha256) is None
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time immutable image identities are malformed"
        )
    return cast(_VerifiedTrustedTimeImages, value)


def _verified_image_source_id(value: object) -> str:
    return tuple.__getitem__(_require_verified_images(value), 1)


def _verified_image_supervisor_id(value: object) -> str:
    return tuple.__getitem__(
        _require_verified_images(value),
        2,
    )


def _verified_image_manifest_sha256(value: object) -> str:
    return tuple.__getitem__(
        _require_verified_images(value),
        3,
    )


def _make_image_inspection_projection(
    *,
    image_id: str,
    user: str,
    entrypoint: tuple[str, ...] | None,
    command: tuple[str, ...] | None,
    environment: tuple[str, ...] | None,
    working_directory: str,
) -> _ImageInspectionProjection:
    return (
        "trusted-time-image-inspection-projection-v1",
        image_id,
        user,
        entrypoint,
        command,
        environment,
        working_directory,
    )


def _require_image_inspection_projection(value: object) -> _ImageInspectionProjection:
    if type(value) is not tuple or len(value) != 7:
        raise TrustedTimeImageVerificationError("Docker image inspection is malformed")
    tag = tuple.__getitem__(value, 0)
    image_id = tuple.__getitem__(value, 1)
    user = tuple.__getitem__(value, 2)
    entrypoint = tuple.__getitem__(value, 3)
    command = tuple.__getitem__(value, 4)
    environment = tuple.__getitem__(value, 5)
    working_directory = tuple.__getitem__(value, 6)
    if (
        type(tag) is not str
        or tag != "trusted-time-image-inspection-projection-v1"
        or type(image_id) is not str
        or type(user) is not str
        or (
            entrypoint is not None
            and (type(entrypoint) is not tuple or any(type(item) is not str for item in entrypoint))
        )
        or (
            command is not None
            and (type(command) is not tuple or any(type(item) is not str for item in command))
        )
        or (
            environment is not None
            and (
                type(environment) is not tuple or any(type(item) is not str for item in environment)
            )
        )
        or type(working_directory) is not str
    ):
        raise TrustedTimeImageVerificationError("Docker image inspection is malformed")
    return cast(_ImageInspectionProjection, value)


def _image_inspection_value(value: object, index: int) -> object:
    return tuple.__getitem__(_require_image_inspection_projection(value), index)


@dataclass(frozen=True, slots=True)
class TrustedTimeImageAdmission:
    """One canonical owner-only admission bound to reviewed source bytes."""

    path: Path
    identities: TrustedTimeImageIdentities
    boot_session_id: str
    git_revision: str
    source_revision_sha256: str
    artifact_sha256: str
    created_at_utc: str
    created_monotonic_ns: int

    def __post_init__(self) -> None:
        if (
            not self.path.is_absolute()
            or type(self.boot_session_id) is not str
            or _BOOT_SESSION_ID_PATTERN.fullmatch(self.boot_session_id) is None
            or self.boot_session_id.partition(":")[2].replace("-", "") == "0" * 32
            or _GIT_REVISION_PATTERN.fullmatch(self.git_revision) is None
            or _SHA256_PATTERN.fullmatch(self.source_revision_sha256) is None
            or _SHA256_PATTERN.fullmatch(self.artifact_sha256) is None
            or _CREATED_AT_PATTERN.fullmatch(self.created_at_utc) is None
            or type(self.created_monotonic_ns) is not int
            or self.created_monotonic_ns < 0
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time image admission artifact is malformed"
            )


@dataclass(frozen=True, slots=True)
class TrustedTimeImageAdmissionProvenance:
    """Exact owner-only archive bytes, authenticated without freshness authority."""

    path: Path
    identities: TrustedTimeImageIdentities
    boot_session_id: str
    git_revision: str
    source_revision_sha256: str
    artifact_sha256: str
    created_at_utc: str
    created_monotonic_ns: int
    encoded: bytes
    file_identity: tuple[int, ...]

    def __post_init__(self) -> None:
        try:
            admission = TrustedTimeImageAdmission(
                path=self.path,
                identities=self.identities,
                boot_session_id=self.boot_session_id,
                git_revision=self.git_revision,
                source_revision_sha256=self.source_revision_sha256,
                artifact_sha256=self.artifact_sha256,
                created_at_utc=self.created_at_utc,
                created_monotonic_ns=self.created_monotonic_ns,
            )
            admission.__post_init__()
        except Exception:
            raise TrustedTimeImageVerificationError(
                "trusted-time image admission provenance is malformed"
            ) from None
        if (
            type(self.path) is not type(Path())
            or self.path.name != f"image-admission-{self.artifact_sha256}.json"
            or type(self.encoded) is not bytes
            or not self.encoded
            or len(self.encoded) > MAXIMUM_IMAGE_ADMISSION_BYTES
            or hashlib.sha256(self.encoded).hexdigest() != self.artifact_sha256
            or type(self.file_identity) is not tuple
            or len(self.file_identity) != 9
            or any(type(item) is not int for item in self.file_identity)
            or not stat.S_ISREG(self.file_identity[2])
            or stat.S_IMODE(self.file_identity[2]) != 0o600
            or self.file_identity[3] != os.geteuid()
            or self.file_identity[5] != 1
            or self.file_identity[6] != len(self.encoded)
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time image admission provenance is malformed"
            )

    def admission(self) -> TrustedTimeImageAdmission:
        """Return the non-authorizing decoded admission projection."""

        return TrustedTimeImageAdmission(
            path=self.path,
            identities=self.identities,
            boot_session_id=self.boot_session_id,
            git_revision=self.git_revision,
            source_revision_sha256=self.source_revision_sha256,
            artifact_sha256=self.artifact_sha256,
            created_at_utc=self.created_at_utc,
            created_monotonic_ns=self.created_monotonic_ns,
        )


type _ReviewedInputBindings = tuple[
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    tuple[str, ...],
    str,
    str,
]


def _make_reviewed_input_bindings(
    *,
    authority_sha256: str,
    chrony_config_sha256: str,
    compose_sha256: str,
    database_ca_sha256: str,
    dockerfile_sha256: str,
    migration_sha256: str,
    schema_revision: str,
    catalog_relations: tuple[str, ...],
    source_revision_sha256: str,
    uv_lock_sha256: str,
) -> _ReviewedInputBindings:
    return (
        "trusted-time-reviewed-input-bindings-v1",
        authority_sha256,
        chrony_config_sha256,
        compose_sha256,
        database_ca_sha256,
        dockerfile_sha256,
        migration_sha256,
        schema_revision,
        catalog_relations,
        source_revision_sha256,
        uv_lock_sha256,
    )


def _require_reviewed_input_bindings(value: object) -> _ReviewedInputBindings:
    if type(value) is not tuple or len(value) != 11:
        raise TrustedTimeImageVerificationError("trusted-time reviewed inputs are malformed")
    tag = tuple.__getitem__(value, 0)
    scalar_values = tuple(
        tuple.__getitem__(value, index)
        for index in (
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            9,
            10,
        )
    )
    catalog_relations = tuple.__getitem__(value, 8)
    if (
        type(tag) is not str
        or tag != "trusted-time-reviewed-input-bindings-v1"
        or any(type(item) is not str for item in scalar_values)
        or type(catalog_relations) is not tuple
        or any(type(item) is not str for item in catalog_relations)
    ):
        raise TrustedTimeImageVerificationError("trusted-time reviewed inputs are malformed")
    return cast(_ReviewedInputBindings, value)


def _reviewed_input_value(value: object, index: int) -> object:
    return tuple.__getitem__(_require_reviewed_input_bindings(value), index)


def _reviewed_input_payload(bindings: object) -> dict[str, object]:
    exact = _require_reviewed_input_bindings(bindings)
    return {
        "authority_sha256": _reviewed_input_value(exact, 1),
        "chrony_config_sha256": _reviewed_input_value(exact, 2),
        "compose_sha256": _reviewed_input_value(exact, 3),
        "database_ca_sha256": _reviewed_input_value(exact, 4),
        "dockerfile_sha256": _reviewed_input_value(exact, 5),
        "migration_sha256": _reviewed_input_value(exact, 6),
        "schema_revision": _reviewed_input_value(exact, 7),
        "catalog_relations": list(
            cast(
                tuple[str, ...],
                _reviewed_input_value(exact, 8),
            )
        ),
        "source_revision_sha256": _reviewed_input_value(exact, 9),
        "uv_lock_sha256": _reviewed_input_value(exact, 10),
    }


def _immutable_reviewed_input_payload(bindings: _ReviewedInputBindings) -> tuple[object, ...]:
    exact = _require_reviewed_input_bindings(bindings)
    return _immutable_json_object(
        (
            ("authority_sha256", _reviewed_input_value(exact, 1)),
            (
                "catalog_relations",
                _immutable_json_array(
                    cast(
                        tuple[str, ...],
                        _reviewed_input_value(exact, 8),
                    )
                ),
            ),
            (
                "chrony_config_sha256",
                _reviewed_input_value(exact, 2),
            ),
            ("compose_sha256", _reviewed_input_value(exact, 3)),
            (
                "database_ca_sha256",
                _reviewed_input_value(exact, 4),
            ),
            (
                "dockerfile_sha256",
                _reviewed_input_value(exact, 5),
            ),
            (
                "migration_sha256",
                _reviewed_input_value(exact, 6),
            ),
            ("schema_revision", _reviewed_input_value(exact, 7)),
            (
                "source_revision_sha256",
                _reviewed_input_value(exact, 9),
            ),
            ("uv_lock_sha256", _reviewed_input_value(exact, 10)),
        )
    )


def _mapping(value: object, field_name: str) -> Mapping[str, object]:
    if type(value) is not dict:
        raise TrustedTimeImageVerificationError(f"{field_name} must be an object")
    return value


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        ) from None


def _immutable_json_object(items: tuple[tuple[str, object], ...]) -> tuple[object, ...]:
    return (0, items)


def _immutable_json_array(items: tuple[object, ...]) -> tuple[object, ...]:
    return (1, items)


_MAXIMUM_IMMUTABLE_JSON_DEPTH = 64
_MAXIMUM_IMMUTABLE_JSON_NODES = 100_000
_JSON_HEXADECIMAL_DIGITS = frozenset("0123456789abcdefABCDEF")


def _decode_immutable_json_text(
    encoded: object,
    *,
    maximum_characters: int,
    maximum_nodes: int,
    label: str,
) -> object:
    """Decode bounded JSON directly into recursively immutable primitive nodes."""

    if (
        type(encoded) is not str
        or type(maximum_characters) is not int
        or maximum_characters <= 0
        or type(maximum_nodes) is not int
        or not 0 < maximum_nodes <= _MAXIMUM_IMMUTABLE_JSON_NODES
        or not encoded
        or len(encoded) > maximum_characters
        or type(label) is not str
        or not label
    ):
        raise TrustedTimeImageVerificationError(f"{label} returned malformed JSON")
    text = encoded
    length = len(text)

    def fail() -> Never:
        raise TrustedTimeImageVerificationError(f"{label} returned malformed JSON")

    def skip_whitespace(index: int) -> int:
        while index < length and text[index] in " \t\r\n":
            index += 1
        return index

    def hexadecimal_value(index: int) -> int:
        end = index + 4
        token = text[index:end]
        if len(token) != 4 or any(item not in _JSON_HEXADECIMAL_DIGITS for item in token):
            fail()
        return int(token, 16)

    def parse_string(index: int) -> tuple[str, int]:
        if index >= length or text[index] != '"':
            fail()
        index += 1
        result = ""
        segment_start = index
        while index < length:
            character = text[index]
            ordinal = ord(character)
            if character == '"':
                segment = text[segment_start:index]
                if any(0xD800 <= ord(item) <= 0xDFFF for item in segment):
                    fail()
                return result + segment, index + 1
            if ordinal < 0x20:
                fail()
            if character != "\\":
                if 0xD800 <= ordinal <= 0xDFFF:
                    fail()
                index += 1
                continue
            result += text[segment_start:index]
            index += 1
            if index >= length:
                fail()
            escaped = text[index]
            escape_names = ('"', "/", "\\", "b", "f", "n", "r", "t")
            escape_values = ('"', "/", "\\", "\b", "\f", "\n", "\r", "\t")
            if escaped in escape_names:
                result += escape_values[escape_names.index(escaped)]
                index += 1
                segment_start = index
                continue
            if escaped != "u":
                fail()
            code_point = hexadecimal_value(index + 1)
            index += 5
            if 0xD800 <= code_point <= 0xDBFF:
                if index + 6 > length or text[index : index + 2] != "\\u":
                    fail()
                low_surrogate = hexadecimal_value(index + 2)
                if not 0xDC00 <= low_surrogate <= 0xDFFF:
                    fail()
                code_point = 0x10000 + ((code_point - 0xD800) << 10) + (low_surrogate - 0xDC00)
                index += 6
            elif 0xDC00 <= code_point <= 0xDFFF:
                fail()
            result += chr(code_point)
            segment_start = index
        fail()

    def parse_value(
        index: int,
        *,
        depth: int,
        remaining_nodes: int,
    ) -> tuple[object, int, int]:
        if depth > _MAXIMUM_IMMUTABLE_JSON_DEPTH or remaining_nodes <= 0:
            fail()
        index = skip_whitespace(index)
        if index >= length:
            fail()
        character = text[index]
        if character == '"':
            value, final_index = parse_string(index)
            return value, final_index, 1
        if text.startswith("true", index):
            return True, index + 4, 1
        if text.startswith("false", index):
            return False, index + 5, 1
        if text.startswith("null", index):
            return None, index + 4, 1
        if character == "[":
            array_items: tuple[object, ...] = ()
            used_nodes = 1
            index = skip_whitespace(index + 1)
            if index < length and text[index] == "]":
                return _immutable_json_array(array_items), index + 1, used_nodes
            while True:
                item, index, child_nodes = parse_value(
                    index,
                    depth=depth + 1,
                    remaining_nodes=remaining_nodes - used_nodes,
                )
                array_items += (item,)
                used_nodes += child_nodes
                index = skip_whitespace(index)
                if index >= length:
                    fail()
                if text[index] == "]":
                    return _immutable_json_array(array_items), index + 1, used_nodes
                if text[index] != ",":
                    fail()
                index = skip_whitespace(index + 1)
        if character == "{":
            object_items: tuple[tuple[str, object], ...] = ()
            used_nodes = 1
            index = skip_whitespace(index + 1)
            if index < length and text[index] == "}":
                return _immutable_json_object(object_items), index + 1, used_nodes
            while True:
                key, index = parse_string(index)
                if any(existing == key for existing, _ in object_items):
                    fail()
                used_nodes += 1
                if used_nodes >= remaining_nodes:
                    fail()
                index = skip_whitespace(index)
                if index >= length or text[index] != ":":
                    fail()
                parsed_value, index, child_nodes = parse_value(
                    index + 1,
                    depth=depth + 1,
                    remaining_nodes=remaining_nodes - used_nodes,
                )
                object_items += ((key, parsed_value),)
                used_nodes += child_nodes
                index = skip_whitespace(index)
                if index >= length:
                    fail()
                if text[index] == "}":
                    return _immutable_json_object(object_items), index + 1, used_nodes
                if text[index] != ",":
                    fail()
                index = skip_whitespace(index + 1)
        number_start = index
        if character == "-":
            index += 1
            if index >= length:
                fail()
        if index < length and text[index] == "0":
            index += 1
            if index < length and text[index].isdigit():
                fail()
        elif index < length and "1" <= text[index] <= "9":
            index += 1
            while index < length and text[index].isdigit():
                index += 1
        else:
            fail()
        if index < length and text[index] in ".eE":
            fail()
        token = text[number_start:index]
        if len(token) > 20:
            fail()
        integer_value = int(token)
        if not -(2**63) <= integer_value <= 2**63 - 1:
            fail()
        return integer_value, index, 1

    value, final_index, used_nodes = parse_value(
        0,
        depth=0,
        remaining_nodes=maximum_nodes,
    )
    if used_nodes > maximum_nodes or skip_whitespace(final_index) != length:
        fail()
    return value


def _immutable_json_object_items(value: object, *, label: str) -> tuple[tuple[str, object], ...]:
    tag = tuple.__getitem__(value, 0) if type(value) is tuple and len(value) == 2 else None
    if (
        type(value) is not tuple
        or len(value) != 2
        or type(tag) is not int
        or tag != 0
        or type(tuple.__getitem__(value, 1)) is not tuple
    ):
        raise TrustedTimeImageVerificationError(f"{label} must be an object")
    items = cast(tuple[tuple[str, object], ...], tuple.__getitem__(value, 1))
    if type(items) is not tuple or any(type(item) is not tuple or len(item) != 2 for item in items):
        raise TrustedTimeImageVerificationError(f"{label} must be an object")
    keys = tuple(tuple.__getitem__(item, 0) for item in items)
    if any(type(key) is not str for key in keys) or len(frozenset(keys)) != len(keys):
        raise TrustedTimeImageVerificationError(f"{label} must be an object")
    return items


def _immutable_json_object_keys(value: object, *, label: str) -> frozenset[str]:
    return frozenset(key for key, _ in _immutable_json_object_items(value, label=label))


def _immutable_json_object_value(value: object, key: str, *, label: str) -> object:
    items = _immutable_json_object_items(value, label=label)
    matches = tuple(item for item_key, item in items if item_key == key)
    if len(matches) != 1:
        raise TrustedTimeImageVerificationError(f"{label} lacks exact field {key}")
    return matches[0]


def _immutable_json_array_items(value: object, *, label: str) -> tuple[object, ...]:
    tag = tuple.__getitem__(value, 0) if type(value) is tuple and len(value) == 2 else None
    if (
        type(value) is not tuple
        or len(value) != 2
        or type(tag) is not int
        or tag != 1
        or type(tuple.__getitem__(value, 1)) is not tuple
    ):
        raise TrustedTimeImageVerificationError(f"{label} must be an array")
    return cast(tuple[object, ...], tuple.__getitem__(value, 1))


def _canonical_immutable_json_bytes(value: object) -> bytes:
    if value is None:
        return b"null"
    if type(value) is bool:
        return b"true" if value else b"false"
    if type(value) is int:
        return str(value).encode("ascii")
    if type(value) is str:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    if (
        type(value) is tuple
        and len(value) == 2
        and type(tuple.__getitem__(value, 0)) is int
        and tuple.__getitem__(value, 0) == 1
        and type(tuple.__getitem__(value, 1)) is tuple
    ):
        encoded = b"["
        separator = b""
        for item in cast(tuple[object, ...], tuple.__getitem__(value, 1)):
            encoded += separator + _canonical_immutable_json_bytes(item)
            separator = b","
        return encoded + b"]"
    if (
        type(value) is tuple
        and len(value) == 2
        and type(tuple.__getitem__(value, 0)) is int
        and tuple.__getitem__(value, 0) == 0
        and type(tuple.__getitem__(value, 1)) is tuple
    ):
        items = _immutable_json_object_items(
            value,
            label="trusted-time image admission artifact",
        )
        keys = tuple(cast(str, tuple.__getitem__(item, 0)) for item in items)
        if any(keys[index] >= keys[index + 1] for index in range(len(keys) - 1)) or any(
            type(key) is not str for key in keys
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time image admission artifact is malformed"
            )
        encoded = b"{"
        separator = b""
        for pair in items:
            key = cast(str, tuple.__getitem__(pair, 0))
            item = tuple.__getitem__(pair, 1)
            encoded += (
                separator
                + _canonical_immutable_json_bytes(key)
                + b":"
                + _canonical_immutable_json_bytes(item)
            )
            separator = b","
        return encoded + b"}"
    raise TrustedTimeImageVerificationError("trusted-time image admission artifact is malformed")


def _exact_relative_components(relative_path: str) -> tuple[str, ...]:
    if (
        type(relative_path) is not str
        or not relative_path
        or relative_path.startswith("/")
        or os.path.normpath(relative_path) != relative_path
        or "\x00" in relative_path
    ):
        raise TrustedTimeImageVerificationError("trusted-time reviewed input is unavailable")
    components = tuple(relative_path.split("/"))
    if any(
        not component
        or component in {".", ".."}
        or "/" in component
        or "\x00" in component
        or len(os.fsencode(component)) > 255
        for component in components
    ):
        raise TrustedTimeImageVerificationError("trusted-time reviewed input is unavailable")
    return components


def _exact_repository_root_components() -> tuple[str, tuple[str, ...]]:
    if type(ROOT) is not type(Path()):
        raise TrustedTimeImageVerificationError("trusted-time reviewed input is unavailable")
    root = os.fspath(ROOT)
    if (
        type(root) is not str
        or not os.path.isabs(root)
        or os.path.abspath(root) != root
        or os.path.normpath(root) != root
        or "\x00" in root
    ):
        raise TrustedTimeImageVerificationError("trusted-time reviewed input is unavailable")
    components = tuple(root.split(os.sep))[1:]
    if not components or any(
        not component
        or component in {".", ".."}
        or os.sep in component
        or "\x00" in component
        or len(os.fsencode(component)) > 255
        for component in components
    ):
        raise TrustedTimeImageVerificationError("trusted-time reviewed input is unavailable")
    return root, components


def _native_reviewed_file_bytes(
    relative_path: str,
    *,
    required_mode: int | None = None,
) -> bytes:
    """Read one reviewed file as exact bytes without exposing its native owner."""

    root, root_components = _exact_repository_root_components()
    relative_components = _exact_relative_components(relative_path)
    directory_components = (*root_components, *relative_components[:-1])
    directory_owner: _NativeOwnedFileDescriptor | None = None
    next_directory_owner: _NativeOwnedFileDescriptor | None = None
    file_owner: _NativeOwnedFileDescriptor | None = None
    result: bytes | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            directory_owner = _native_open_root_directory()
            for component in directory_components:
                next_directory_owner = _native_open_child_directory(
                    directory_owner,
                    component,
                )
                metadata = _native_fstat(next_directory_owner)
                if not stat.S_ISDIR(metadata[2]):
                    raise OSError
                intermediate_error = _cleanup_native_owned_descriptors((directory_owner,))
                if intermediate_error is not None:
                    raise intermediate_error
                directory_owner = next_directory_owner
                next_directory_owner = None
            directory_before = _native_fstat(directory_owner)
            file_name = relative_components[-1]
            file_owner = _native_open_child_regular(directory_owner, file_name)
            before = _native_fstat(file_owner)
            named_before = _native_statat(directory_owner, file_name)
            if (
                before != named_before
                or not stat.S_ISREG(before[2])
                or before[5] != 1
                or before[6] < 0
                or before[6] > _MAXIMUM_REVIEWED_INPUT_BYTES
                or (required_mode is not None and stat.S_IMODE(before[2]) != required_mode)
            ):
                raise OSError
            encoded, read_before, read_after = _native_read_snapshot(
                file_owner,
                _MAXIMUM_REVIEWED_INPUT_BYTES,
            )
            final = _native_fstat(file_owner)
            named_final = _native_statat(directory_owner, file_name)
            directory_final = _native_fstat(directory_owner)
            if (
                read_before != before
                or read_after != before
                or final != before
                or named_final != before
                or directory_final != directory_before
                or len(encoded) != before[6]
                or os.fspath(ROOT) != root
            ):
                raise OSError
            result = encoded
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup_native_owned_descriptors(
                (file_owner, next_directory_owner, directory_owner)
            )
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup_native_owned_descriptors(
            (file_owner, next_directory_owner, directory_owner)
        )
    terminal = _preferred_cleanup_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        if not isinstance(terminal, Exception):
            raise terminal
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed inputs are unavailable"
        ) from None
    if result is None:
        raise TrustedTimeImageVerificationError("trusted-time reviewed input is unavailable")
    return result


def _stable_file_sha256(path: Path) -> str:
    if type(path) is not type(Path()):
        raise TrustedTimeImageVerificationError("trusted-time reviewed input is unavailable")
    root, _ = _exact_repository_root_components()
    raw = os.fspath(path)
    root_boundary = root if root.endswith(os.sep) else root + os.sep
    if type(raw) is not str or not raw.startswith(root_boundary):
        raise TrustedTimeImageVerificationError("trusted-time reviewed input is unavailable")
    relative = raw[len(root_boundary) :]
    return hashlib.sha256(_native_reviewed_file_bytes(relative)).hexdigest()


_IGNORED_REVIEWED_DIRECTORY_NAMES = frozenset(
    {
        ".hypothesis",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "node_modules",
    }
)


def _ignore_reviewed_file_name(name: str) -> bool:
    return (
        name.endswith(".pyc")
        or name == ".DS_Store"
        or name == ".env"
        or (name.startswith(".env.") and name != ".env.example")
    )


def _native_reviewed_directory_inventory(
    directory_owner: _NativeOwnedFileDescriptor,
    *,
    relative_directory: str,
    depth: int,
) -> tuple[str, ...]:
    if type(depth) is not int or depth < 0 or depth > 64:
        raise TrustedTimeImageVerificationError("trusted-time reviewed input is unavailable")
    names, directory_before, directory_after = _native_list_snapshot(directory_owner)
    if (
        directory_before != directory_after
        or directory_before != _native_fstat(directory_owner)
        or not stat.S_ISDIR(directory_before[2])
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed during admission"
        )
    result: tuple[str, ...] = ()
    for name in names:
        relative = f"{relative_directory}/{name}"
        named_before = _native_statat(directory_owner, name)
        if stat.S_ISDIR(named_before[2]):
            if name in _IGNORED_REVIEWED_DIRECTORY_NAMES:
                continue
            child_owner: _NativeOwnedFileDescriptor | None = None
            body_error: BaseException | None = None
            transition_error: BaseException | None = None
            cleanup_error: BaseException | None = None
            retry_error: BaseException | None = None
            nested: tuple[str, ...] | None = None
            try:
                try:
                    child_owner = _native_open_child_directory(directory_owner, name)
                    if _native_fstat(child_owner) != named_before:
                        raise OSError
                    nested = _native_reviewed_directory_inventory(
                        child_owner,
                        relative_directory=relative,
                        depth=depth + 1,
                    )
                    if (
                        _native_fstat(child_owner) != named_before
                        or _native_statat(directory_owner, name) != named_before
                    ):
                        raise OSError
                except BaseException as error:
                    body_error = error
                finally:
                    cleanup_error = _cleanup_native_owned_descriptors((child_owner,))
            except BaseException as error:
                transition_error = error
            finally:
                retry_error = _cleanup_native_owned_descriptors((child_owner,))
            terminal = _preferred_cleanup_exceptions(
                body_error,
                transition_error,
                cleanup_error,
                retry_error,
            )
            if terminal is not None:
                if not isinstance(terminal, Exception):
                    raise terminal
                raise TrustedTimeImageVerificationError(
                    "trusted-time reviewed input is unavailable"
                ) from None
            if nested is None:
                raise TrustedTimeImageVerificationError(
                    "trusted-time reviewed input is unavailable"
                )
            result += nested
        elif stat.S_ISREG(named_before[2]):
            if not _ignore_reviewed_file_name(name):
                result += (relative,)
        else:
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed input cannot contain a symlink"
            )
    final_names, final_before, final_after = _native_list_snapshot(directory_owner)
    if (
        final_names != names
        or final_before != directory_before
        or final_after != directory_before
        or _native_fstat(directory_owner) != directory_before
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed during admission"
        )
    return result


def _native_reviewed_inventory(relative_directory: str) -> tuple[str, ...]:
    _, root_components = _exact_repository_root_components()
    relative_components = _exact_relative_components(relative_directory)
    directory_owner: _NativeOwnedFileDescriptor | None = None
    next_directory_owner: _NativeOwnedFileDescriptor | None = None
    result: tuple[str, ...] | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            directory_owner = _native_open_root_directory()
            for component in (*root_components, *relative_components):
                next_directory_owner = _native_open_child_directory(
                    directory_owner,
                    component,
                )
                if not stat.S_ISDIR(_native_fstat(next_directory_owner)[2]):
                    raise OSError
                intermediate_error = _cleanup_native_owned_descriptors((directory_owner,))
                if intermediate_error is not None:
                    raise intermediate_error
                directory_owner = next_directory_owner
                next_directory_owner = None
            result = _native_reviewed_directory_inventory(
                directory_owner,
                relative_directory=relative_directory,
                depth=0,
            )
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup_native_owned_descriptors(
                (next_directory_owner, directory_owner)
            )
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup_native_owned_descriptors((next_directory_owner, directory_owner))
    terminal = _preferred_cleanup_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        if not isinstance(terminal, Exception):
            raise terminal
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input is unavailable"
        ) from None
    if result is None:
        raise TrustedTimeImageVerificationError("trusted-time reviewed input is unavailable")
    return result


def _reviewed_input_relative_paths() -> tuple[str, ...]:
    observed = tuple(_REVIEWED_FIXED_RELATIVE_PATHS)
    for relative in observed:
        _exact_relative_components(relative)
    for relative_directory in _REVIEWED_DIRECTORY_RELATIVE_PATHS:
        _exact_relative_components(relative_directory)
        observed += _native_reviewed_inventory(relative_directory)
    exact = tuple(sorted(frozenset(observed)))
    if not exact:
        raise TrustedTimeImageVerificationError("trusted-time reviewed input is unavailable")
    return exact


def _reviewed_input_paths() -> tuple[Path, ...]:
    """Return non-authoritative display paths for tests and Git comparison."""

    return tuple(ROOT / relative for relative in _reviewed_input_relative_paths())


def reviewed_input_bindings() -> _ReviewedInputBindings:
    """Hash every reviewed input that can affect this admission boundary."""

    entries: list[dict[str, str]] = []
    hashes: dict[str, str] = {}
    for relative in _reviewed_input_relative_paths():
        digest = hashlib.sha256(_native_reviewed_file_bytes(relative)).hexdigest()
        hashes[relative] = digest
        entries.append(
            {
                "path": relative,
                "sha256": digest,
            }
        )
    source_revision_sha256 = hashlib.sha256(
        _canonical_json_bytes(
            {
                "algorithm": "sha256-canonical-reviewed-path-manifest-v1",
                "files": entries,
            }
        )
    ).hexdigest()
    return _make_reviewed_input_bindings(
        authority_sha256=hashes["infra/trusted-time/source-authority.json"],
        chrony_config_sha256=hashes["infra/trusted-time/chrony.conf"],
        compose_sha256=hashes["infra/compose/trusted-time.compose.yaml"],
        database_ca_sha256=hashes["packages/persistence/certs/supabase-prod-ca-2021.crt"],
        dockerfile_sha256=hashes["infra/docker/trusted-time.Dockerfile"],
        migration_sha256=hashes["migrations/versions/0036_phase6_trusted_time_head_anchors.py"],
        schema_revision=EXPECTED_SCHEMA_REVISION,
        catalog_relations=EXPECTED_CATALOG_RELATIONS,
        source_revision_sha256=source_revision_sha256,
        uv_lock_sha256=hashes["uv.lock"],
    )


def _absolute_artifact_path(path: Path, *, ignored_root: Path) -> tuple[Path, Path]:
    if not isinstance(path, Path) or not isinstance(ignored_root, Path):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact path is invalid"
        )
    absolute = Path(os.path.abspath(path))
    root = Path(os.path.abspath(ignored_root))
    if (
        not path.is_absolute()
        or absolute != path
        or not ignored_root.is_absolute()
        or root != ignored_root
        or absolute == root
        or not absolute.is_relative_to(root)
        or absolute.name in {"", ".", ".."}
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact path is invalid"
        )
    return absolute, root


def _absolute_artifact_path_strings(
    path: object,
    *,
    ignored_root: object,
) -> tuple[str, str]:
    """Return exact primitive artifact/root paths for private authority seams."""

    if type(path) is not type(Path()) or type(ignored_root) is not type(Path()):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact path is invalid"
        )
    try:
        raw_path = os.fspath(path)
        raw_root = os.fspath(ignored_root)
        absolute = os.path.abspath(raw_path)
        root = os.path.abspath(raw_root)
    except (OSError, TypeError, ValueError):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact path is invalid"
        ) from None
    root_boundary = root if root.endswith(os.sep) else root + os.sep
    if (
        type(raw_path) is not str
        or type(raw_root) is not str
        or not os.path.isabs(raw_path)
        or absolute != raw_path
        or os.path.normpath(raw_path) != raw_path
        or not os.path.isabs(raw_root)
        or root != raw_root
        or os.path.normpath(raw_root) != raw_root
        or raw_path == raw_root
        or not raw_path.startswith(root_boundary)
        or os.path.basename(raw_path) in {"", ".", ".."}
        or "\x00" in raw_path
        or "\x00" in raw_root
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact path is invalid"
        )
    return raw_path, raw_root


def _open_owner_only_artifact_directory(
    path: Path,
    *,
    ignored_root: Path,
    create: bool,
) -> _OwnedFileDescriptor:
    absolute = Path(os.path.abspath(path))
    root = Path(os.path.abspath(ignored_root))
    if absolute != path or (absolute != root and not absolute.is_relative_to(root)):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact directory is invalid"
        )
    directory_owner: _OwnedFileDescriptor | None = None
    current = Path(absolute.anchor)
    try:
        directory_owner = _open_owned_descriptor(
            absolute.anchor,
            flags=(
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            ),
        )
        for part in absolute.parts[1:]:
            current /= part
            protected = current == root or current.is_relative_to(root)
            if protected and create:
                try:
                    os.mkdir(part, 0o700, dir_fd=directory_owner.fileno())
                    created = True
                except FileExistsError:
                    created = False
            else:
                created = False
            next_owner = _open_owned_descriptor(
                part,
                flags=(
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                ),
                dir_fd=directory_owner.fileno(),
            )
            try:
                metadata = os.fstat(next_owner.fileno())
                if created:
                    os.fchmod(next_owner.fileno(), 0o700)
                    metadata = os.fstat(next_owner.fileno())
                if protected and (
                    metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                    or not stat.S_ISDIR(metadata.st_mode)
                ):
                    raise TrustedTimeImageVerificationError(
                        "trusted-time image admission artifact directory is invalid"
                    )
                if created:
                    os.fsync(next_owner.fileno())
                    os.fsync(directory_owner.fileno())
            except BaseException:
                next_owner.close()
                raise
            directory_owner.close()
            directory_owner = next_owner
        return directory_owner
    except BaseException as error:
        if directory_owner is not None:
            directory_owner.close()
        if isinstance(error, (OSError, TrustedTimeImageVerificationError)):
            raise TrustedTimeImageVerificationError(
                "trusted-time image admission artifact directory is invalid"
            ) from None
        raise


def _read_existing_owner_only_artifact(
    directory_descriptor: int,
    file_name: str,
    *,
    label: str,
) -> bytes | None:
    file_owner: _OwnedFileDescriptor | None = None
    try:
        file_owner = _open_owned_file(file_name, dir_fd=directory_descriptor)
        descriptor = file_owner.fileno()
    except FileNotFoundError:
        return None
    except OSError:
        raise TrustedTimeImageVerificationError(
            f"trusted-time image admission {label} is invalid"
        ) from None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAXIMUM_IMAGE_ADMISSION_BYTES
        ):
            raise TrustedTimeImageVerificationError(
                f"trusted-time image admission {label} is invalid"
            )
        chunks: list[bytes] = []
        remaining = MAXIMUM_IMAGE_ADMISSION_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        encoded = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(encoded) != before.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_mode != after.st_mode
            or before.st_uid != after.st_uid
            or before.st_nlink != after.st_nlink
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise TrustedTimeImageVerificationError(
                f"trusted-time image admission {label} is invalid"
            )
        return encoded
    finally:
        if file_owner is not None:
            file_owner.close()


def _confirm_exact_existing_owner_only_artifact_durable(
    directory_descriptor: int,
    file_name: str,
    *,
    expected_encoded: bytes,
    label: str,
) -> None:
    """Fsync and read back one exact held owner-only artifact and its name."""

    file_owner: _OwnedFileDescriptor | None = None

    def readback(descriptor: int) -> bytes:
        os.lseek(descriptor, 0, os.SEEK_SET)
        retained = bytearray()
        while len(retained) <= MAXIMUM_IMAGE_ADMISSION_BYTES:
            chunk = os.read(
                descriptor,
                min(65_536, MAXIMUM_IMAGE_ADMISSION_BYTES + 1 - len(retained)),
            )
            if not chunk:
                break
            retained.extend(chunk)
        return bytes(retained)

    try:
        directory_before = os.fstat(directory_descriptor)
        file_owner = _open_owned_file(file_name, dir_fd=directory_descriptor)
        descriptor = file_owner.fileno()
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size != len(expected_encoded)
            or before.st_size <= 0
            or before.st_size > MAXIMUM_IMAGE_ADMISSION_BYTES
        ):
            raise OSError
        encoded = readback(descriptor)
        after_read = os.fstat(descriptor)
        named_before = os.stat(
            file_name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            encoded != expected_encoded
            or _stable_image_admission_file_identity(before)
            != _stable_image_admission_file_identity(after_read)
            or _stable_image_admission_file_identity(after_read)
            != _stable_image_admission_file_identity(named_before)
        ):
            raise OSError
        os.fsync(descriptor)
        os.fsync(directory_descriptor)
        final_encoded = readback(descriptor)
        final = os.fstat(descriptor)
        named_final = os.stat(
            file_name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        directory_final = os.fstat(directory_descriptor)
        if (
            final_encoded != expected_encoded
            or _stable_image_admission_file_identity(before)
            != _stable_image_admission_file_identity(final)
            or _stable_image_admission_file_identity(final)
            != _stable_image_admission_file_identity(named_final)
            or _stable_image_admission_file_identity(directory_before)
            != _stable_image_admission_file_identity(directory_final)
        ):
            raise OSError
    except OSError:
        raise TrustedTimeImageVerificationError(
            f"trusted-time image admission {label} is invalid"
        ) from None
    finally:
        if file_owner is not None:
            with suppress(OSError):
                file_owner.close()


class _OwnedTemporaryImageAdmissionArtifact:
    """Own one random O_EXCL temporary name across every CALL/STORE edge."""

    __slots__ = (
        "_creation_call_started",
        "_directory_descriptor",
        "_file_identity",
        "_file_name",
        "_file_owner",
        "_name_retirement_started",
    )

    def __init__(self, directory_descriptor: int, file_name: str) -> None:
        self._creation_call_started = False
        self._directory_descriptor = directory_descriptor
        self._file_identity: tuple[int, int] | None = None
        self._file_name = file_name
        self._file_owner: _OwnedFileDescriptor | None = None
        self._name_retirement_started = False

    def create(self) -> _OwnedFileDescriptor:
        if self._creation_call_started or self._file_owner is not None:
            raise TrustedTimeImageVerificationError(
                "trusted-time image admission temporary artifact is invalid"
            )

        self._creation_call_started = True
        try:
            self._file_owner = _open_owned_file(
                self._file_name,
                dir_fd=self._directory_descriptor,
                exclusive=True,
            )
        except FileExistsError:
            self._creation_call_started = False
            raise
        metadata = os.fstat(self._file_owner.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != 0
        ):
            raise OSError
        self._file_identity = (metadata.st_dev, metadata.st_ino)
        return self._file_owner

    def close_file(self) -> None:
        owner = self._file_owner
        if owner is not None:
            owner.close()
            self._file_owner = None

    def _validate_named_identity(self) -> None:
        if self._file_identity is None:
            return
        named = os.stat(
            self._file_name,
            dir_fd=self._directory_descriptor,
            follow_symlinks=False,
        )
        if (named.st_dev, named.st_ino) != self._file_identity:
            raise OSError

    def unlink_name(self) -> None:
        self.close_file()
        self._validate_named_identity()
        self._name_retirement_started = True
        os.unlink(self._file_name, dir_fd=self._directory_descriptor)
        self._creation_call_started = False

    def replace_name(self, target_name: str) -> None:
        self.close_file()
        self._validate_named_identity()
        self._name_retirement_started = True
        os.replace(
            self._file_name,
            target_name,
            src_dir_fd=self._directory_descriptor,
            dst_dir_fd=self._directory_descriptor,
        )
        self._creation_call_started = False

    def cleanup(self) -> None:
        """Close and durably unlink only the exact temporary name this owner created."""

        try:
            self.close_file()
            if self._creation_call_started:
                try:
                    self._validate_named_identity()
                    os.unlink(self._file_name, dir_fd=self._directory_descriptor)
                except FileNotFoundError:
                    if not self._name_retirement_started:
                        raise
                os.fsync(self._directory_descriptor)
                self._creation_call_started = False
        except OSError:
            raise TrustedTimeImageVerificationError(
                "trusted-time image admission temporary artifact cleanup failed"
            ) from None


def _retain_content_addressed_image_admission(
    canonical_path: Path,
    encoded: bytes,
    *,
    ignored_root: Path,
) -> Path:
    """Create an immutable owner-only copy named by the exact artifact bytes."""

    artifact_sha256 = hashlib.sha256(encoded).hexdigest()
    archive = canonical_path.with_name(f"image-admission-{artifact_sha256}.json")
    directory_owner: _OwnedFileDescriptor | None = None
    temporary_owner: _OwnedTemporaryImageAdmissionArtifact | None = None
    temporary_name = f".{archive.name}.{os.getpid()}.{secrets.token_hex(16)}.tmp"
    try:
        directory_owner = _open_owner_only_artifact_directory(
            archive.parent,
            ignored_root=ignored_root,
            create=True,
        )
        directory_descriptor = directory_owner.fileno()
        existing = _read_existing_owner_only_artifact(
            directory_descriptor,
            archive.name,
            label="archive",
        )
        if existing is not None:
            if existing != encoded:
                raise TrustedTimeImageVerificationError(
                    "trusted-time image admission archive is invalid"
                )
            _confirm_exact_existing_owner_only_artifact_durable(
                directory_descriptor,
                archive.name,
                expected_encoded=encoded,
                label="archive",
            )
            return archive

        temporary_owner = _OwnedTemporaryImageAdmissionArtifact(
            directory_descriptor,
            temporary_name,
        )
        file_owner = temporary_owner.create()
        file_descriptor = file_owner.fileno()
        view = memoryview(encoded)
        while view:
            written = os.write(file_descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fchmod(file_descriptor, 0o600)
        os.fsync(file_descriptor)
        temporary_owner.close_file()
        os.link(
            temporary_name,
            archive.name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        temporary_owner.unlink_name()
        os.fsync(directory_descriptor)
        _confirm_exact_existing_owner_only_artifact_durable(
            directory_descriptor,
            archive.name,
            expected_encoded=encoded,
            label="archive",
        )
        return archive
    except TrustedTimeImageVerificationError:
        raise
    except (OSError, ValueError):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission archive write failed"
        ) from None
    finally:
        if temporary_owner is not None:
            temporary_owner.cleanup()
        if directory_owner is not None:
            directory_owner.close()


def _validate_content_addressed_image_admission(
    canonical_path: Path,
    encoded: bytes,
    *,
    ignored_root: Path,
) -> None:
    artifact_sha256 = hashlib.sha256(encoded).hexdigest()
    archive = canonical_path.with_name(f"image-admission-{artifact_sha256}.json")
    directory_owner: _OwnedFileDescriptor | None = None
    try:
        directory_owner = _open_owner_only_artifact_directory(
            archive.parent,
            ignored_root=ignored_root,
            create=False,
        )
        directory_descriptor = directory_owner.fileno()
        existing = _read_existing_owner_only_artifact(
            directory_descriptor,
            archive.name,
            label="archive",
        )
        if existing != encoded:
            raise TrustedTimeImageVerificationError(
                "trusted-time image admission archive is invalid"
            )
    finally:
        if directory_owner is not None:
            directory_owner.close()


def _admission_payload(
    identities: TrustedTimeImageIdentities,
    bindings: _ReviewedInputBindings,
    *,
    supervisor_executable_import_manifest_sha256: str,
    boot_session_id: str,
    git_revision: str,
    created_at_utc: str,
    created_monotonic_ns: int,
) -> dict[str, object]:
    return {
        "authority_granted": False,
        "boot_session_id": boot_session_id,
        "contract_version": IMAGE_ADMISSION_CONTRACT_VERSION,
        "created_at_utc": created_at_utc,
        "created_monotonic_ns": created_monotonic_ns,
        "fresh_for_seconds": IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS,
        "git_revision": git_revision,
        "images": {
            "source_id": identities.source_id,
            "supervisor_id": identities.supervisor_id,
            "supervisor_executable_import_manifest_sha256": (
                supervisor_executable_import_manifest_sha256
            ),
        },
        "inputs": _reviewed_input_payload(bindings),
        "new_exposure_authorized": False,
        "service": "trusted-time-image-admission",
        "status": "admitted",
    }


def write_image_admission_artifact(
    path: Path,
    identities: TrustedTimeImageIdentities,
    *,
    git_revision: str,
    supervisor_executable_import_manifest_sha256: str,
    bindings: _ReviewedInputBindings | None = None,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
    utc_now: datetime | None = None,
    monotonic_ns: int | None = None,
) -> TrustedTimeImageAdmission:
    """Atomically replace the canonical owner-only image admission artifact."""

    if type(identities) is not TrustedTimeImageIdentities:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission identities are invalid"
        )
    if type(git_revision) is not str or _GIT_REVISION_PATTERN.fullmatch(git_revision) is None:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission Git revision is invalid"
        )
    if (
        type(supervisor_executable_import_manifest_sha256) is not str
        or _SHA256_PATTERN.fullmatch(supervisor_executable_import_manifest_sha256) is None
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time supervisor executable/import manifest identity is invalid"
        )
    absolute, _ = _absolute_artifact_path(path, ignored_root=ignored_root)
    reviewed = reviewed_input_bindings() if bindings is None else bindings
    try:
        reviewed = _require_reviewed_input_bindings(reviewed)
    except TrustedTimeImageVerificationError:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission inputs are invalid"
        ) from None
    observed_boot_session = _current_boot_session_id()
    observed_utc = datetime.now(UTC) if utc_now is None else utc_now
    observed_monotonic = _suspend_aware_monotonic_ns() if monotonic_ns is None else monotonic_ns
    if (
        type(observed_utc) is not datetime
        or observed_utc.tzinfo is None
        or observed_utc.utcoffset() != UTC.utcoffset(observed_utc)
        or type(observed_monotonic) is not int
        or observed_monotonic < 0
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission creation clock is invalid"
        )
    created_at = (
        observed_utc.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )
    encoded = _canonical_json_bytes(
        _admission_payload(
            identities,
            reviewed,
            supervisor_executable_import_manifest_sha256=(
                supervisor_executable_import_manifest_sha256
            ),
            boot_session_id=observed_boot_session,
            git_revision=git_revision,
            created_at_utc=created_at,
            created_monotonic_ns=observed_monotonic,
        )
    )
    if not encoded or len(encoded) > MAXIMUM_IMAGE_ADMISSION_BYTES:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        )

    prior_directory_owner: _OwnedFileDescriptor | None = None
    try:
        prior_directory_owner = _open_owner_only_artifact_directory(
            absolute.parent,
            ignored_root=ignored_root,
            create=True,
        )
        prior_encoded = _read_existing_owner_only_artifact(
            prior_directory_owner.fileno(),
            absolute.name,
            label="artifact target",
        )
    finally:
        if prior_directory_owner is not None:
            prior_directory_owner.close()
    if prior_encoded is not None:
        _retain_content_addressed_image_admission(
            absolute,
            prior_encoded,
            ignored_root=ignored_root,
        )
    _retain_content_addressed_image_admission(
        absolute,
        encoded,
        ignored_root=ignored_root,
    )

    directory_owner: _OwnedFileDescriptor | None = None
    temporary_owner: _OwnedTemporaryImageAdmissionArtifact | None = None
    temporary_name = f".{absolute.name}.{os.getpid()}.{secrets.token_hex(16)}.tmp"
    try:
        directory_owner = _open_owner_only_artifact_directory(
            absolute.parent,
            ignored_root=ignored_root,
            create=True,
        )
        directory_descriptor = directory_owner.fileno()
        if (
            _read_existing_owner_only_artifact(
                directory_descriptor,
                absolute.name,
                label="artifact target",
            )
            != prior_encoded
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time image admission artifact target is invalid"
            )
        temporary_owner = _OwnedTemporaryImageAdmissionArtifact(
            directory_descriptor,
            temporary_name,
        )
        file_owner = temporary_owner.create()
        file_descriptor = file_owner.fileno()
        view = memoryview(encoded)
        while view:
            written = os.write(file_descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fchmod(file_descriptor, 0o600)
        os.fsync(file_descriptor)
        temporary_owner.replace_name(
            absolute.name,
        )
        os.fsync(directory_descriptor)
    except TrustedTimeImageVerificationError:
        raise
    except (OSError, ValueError):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact write failed"
        ) from None
    finally:
        if temporary_owner is not None:
            temporary_owner.cleanup()
        if directory_owner is not None:
            directory_owner.close()

    if reviewed_input_bindings() != reviewed:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed during admission"
        )
    admission, admission_snapshot = _load_current_image_admission_with_snapshot(
        absolute,
        ignored_root=ignored_root,
        monotonic_ns=observed_monotonic,
    )
    admission_snapshot = _require_current_admission_snapshot(admission_snapshot)
    if (
        _current_admission_snapshot_value(admission_snapshot, 4) != identities.source_id
        or _current_admission_snapshot_value(admission_snapshot, 5) != identities.supervisor_id
        or _current_admission_snapshot_value(admission_snapshot, 6) != observed_boot_session
        or _current_admission_snapshot_value(admission_snapshot, 7) != git_revision
        or _current_admission_snapshot_value(admission_snapshot, 8)
        != _reviewed_input_value(reviewed, 9)
        or _current_admission_snapshot_value(
            admission_snapshot,
            9,
        )
        != supervisor_executable_import_manifest_sha256
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact changed during creation"
        )
    return admission


def _decode_structural_admission_payload(
    payload: object,
    *,
    path: Path,
    artifact_sha256: str,
) -> TrustedTimeImageAdmission:
    root = _mapping(payload, "trusted-time image admission")
    if set(root) != {
        "authority_granted",
        "boot_session_id",
        "contract_version",
        "created_at_utc",
        "created_monotonic_ns",
        "fresh_for_seconds",
        "git_revision",
        "images",
        "inputs",
        "new_exposure_authorized",
        "service",
        "status",
    }:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        )
    images = _mapping(root.get("images"), "trusted-time image admission images")
    inputs = _mapping(root.get("inputs"), "trusted-time image admission inputs")
    expected_inputs = reviewed_input_bindings()
    expected_inputs_payload = _reviewed_input_payload(expected_inputs)
    if (
        root.get("authority_granted") is not False
        or root.get("contract_version") != IMAGE_ADMISSION_CONTRACT_VERSION
        or root.get("fresh_for_seconds") != IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS
        or root.get("new_exposure_authorized") is not False
        or root.get("service") != "trusted-time-image-admission"
        or root.get("status") != "admitted"
        or set(images)
        != {
            "source_id",
            "supervisor_executable_import_manifest_sha256",
            "supervisor_id",
        }
        or set(inputs) != set(expected_inputs_payload)
        or inputs != expected_inputs_payload
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        )
    created_at = root.get("created_at_utc")
    created_monotonic = root.get("created_monotonic_ns")
    artifact_boot_session = root.get("boot_session_id")
    git_revision = root.get("git_revision")
    supervisor_manifest_sha256 = images.get("supervisor_executable_import_manifest_sha256")
    if (
        type(created_at) is not str
        or _CREATED_AT_PATTERN.fullmatch(created_at) is None
        or type(created_monotonic) is not int
        or type(artifact_boot_session) is not str
        or _BOOT_SESSION_ID_PATTERN.fullmatch(artifact_boot_session) is None
        or artifact_boot_session.partition(":")[2].replace("-", "") == "0" * 32
        or type(git_revision) is not str
        or _GIT_REVISION_PATTERN.fullmatch(git_revision) is None
        or type(supervisor_manifest_sha256) is not str
        or _SHA256_PATTERN.fullmatch(supervisor_manifest_sha256) is None
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        )
    if created_monotonic < 0:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        )
    try:
        parsed_created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        ) from None
    if (
        parsed_created_at.tzinfo is None
        or parsed_created_at.utcoffset() != UTC.utcoffset(parsed_created_at)
        or parsed_created_at.isoformat(timespec="microseconds").replace("+00:00", "Z") != created_at
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        )
    return TrustedTimeImageAdmission(
        path=path,
        identities=TrustedTimeImageIdentities(
            source_id=images.get("source_id"),  # type: ignore[arg-type]
            supervisor_id=images.get("supervisor_id"),  # type: ignore[arg-type]
        ),
        boot_session_id=artifact_boot_session,
        git_revision=git_revision,
        source_revision_sha256=cast(
            str,
            _reviewed_input_value(
                expected_inputs,
                9,
            ),
        ),
        artifact_sha256=artifact_sha256,
        created_at_utc=created_at,
        created_monotonic_ns=created_monotonic,
    )


def _decode_admission_payload(
    payload: object,
    *,
    path: Path,
    artifact_sha256: str,
    boot_session_id: str,
    monotonic_ns: int,
) -> TrustedTimeImageAdmission:
    if (
        type(boot_session_id) is not str
        or _BOOT_SESSION_ID_PATTERN.fullmatch(boot_session_id) is None
        or boot_session_id.partition(":")[2].replace("-", "") == "0" * 32
    ):
        raise TrustedTimeImageVerificationError("trusted-time boot session identity is unavailable")
    admission = _decode_structural_admission_payload(
        payload,
        path=path,
        artifact_sha256=artifact_sha256,
    )
    if admission.boot_session_id != boot_session_id:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact belongs to a different boot session"
        )
    if (
        type(monotonic_ns) is not int
        or monotonic_ns < admission.created_monotonic_ns
        or monotonic_ns - admission.created_monotonic_ns
        > IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS * 1_000_000_000
    ):
        raise TrustedTimeImageVerificationError("trusted-time image admission artifact is stale")
    return admission


def _stable_image_admission_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_exact_image_admission_archive(
    path: str,
    *,
    ignored_root: str,
) -> tuple[bytes, tuple[int, ...], tuple[int, ...]]:
    if (
        type(path) is not str
        or type(ignored_root) is not str
        or not os.path.isabs(path)
        or os.path.abspath(path) != path
        or os.path.normpath(path) != path
        or not os.path.isabs(ignored_root)
        or os.path.abspath(ignored_root) != ignored_root
        or os.path.normpath(ignored_root) != ignored_root
        or not path.startswith(
            ignored_root if ignored_root.endswith(os.sep) else ignored_root + os.sep
        )
        or os.path.basename(path) in {"", ".", ".."}
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission provenance is unavailable"
        )
    parent = os.path.dirname(path)
    parent_components = tuple(parent.split(os.sep))[1:]
    ignored_root_components = tuple(ignored_root.split(os.sep))[1:]
    if parent_components[: len(ignored_root_components)] != ignored_root_components or any(
        not component
        or component in {".", ".."}
        or os.sep in component
        or "\x00" in component
        or len(os.fsencode(component)) > 255
        for component in parent_components
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission provenance is unavailable"
        )
    directory_owner: _NativeOwnedFileDescriptor | None = None
    next_directory_owner: _NativeOwnedFileDescriptor | None = None
    file_owner: _NativeOwnedFileDescriptor | None = None
    result: tuple[bytes, tuple[int, ...], tuple[int, ...]] | None = None
    body_error: BaseException | None = None
    transition_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    retry_error: BaseException | None = None
    try:
        try:
            directory_owner = _native_open_root_directory()
            for index, component in enumerate(parent_components, start=1):
                next_directory_owner = _native_open_child_directory(
                    directory_owner,
                    component,
                )
                component_metadata = _native_fstat(next_directory_owner)
                if index >= len(ignored_root_components) and (
                    not stat.S_ISDIR(component_metadata[2])
                    or component_metadata[3] != os.geteuid()
                    or stat.S_IMODE(component_metadata[2]) != 0o700
                ):
                    raise OSError
                intermediate_error = _cleanup_native_owned_descriptors((directory_owner,))
                if intermediate_error is not None:
                    raise intermediate_error
                directory_owner = next_directory_owner
                next_directory_owner = None
            directory_before = _native_fstat(directory_owner)
            file_name = os.path.basename(path)
            file_owner = _native_open_child_regular(directory_owner, file_name)
            before = _native_fstat(file_owner)
            named_before = _native_statat(directory_owner, file_name)
            if (
                before != named_before
                or not stat.S_ISREG(before[2])
                or before[3] != os.geteuid()
                or stat.S_IMODE(before[2]) != 0o600
                or before[5] != 1
                or before[6] <= 0
                or before[6] > MAXIMUM_IMAGE_ADMISSION_BYTES
            ):
                raise OSError
            encoded, read_before, read_after = _native_read_snapshot(
                file_owner,
                MAXIMUM_IMAGE_ADMISSION_BYTES,
            )
            final = _native_fstat(file_owner)
            named_final = _native_statat(directory_owner, file_name)
            directory_final = _native_fstat(directory_owner)
            if (
                read_before != before
                or read_after != before
                or final != before
                or named_final != before
                or directory_final != directory_before
                or len(encoded) != before[6]
            ):
                raise OSError
            result = (encoded, directory_final, final)
        except BaseException as error:
            body_error = error
        finally:
            cleanup_error = _cleanup_native_owned_descriptors(
                (file_owner, next_directory_owner, directory_owner)
            )
    except BaseException as error:
        transition_error = error
    finally:
        retry_error = _cleanup_native_owned_descriptors(
            (file_owner, next_directory_owner, directory_owner)
        )
    terminal = _preferred_cleanup_exceptions(
        body_error,
        transition_error,
        cleanup_error,
        retry_error,
    )
    if terminal is not None:
        if not isinstance(terminal, Exception):
            raise terminal
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission provenance is unavailable"
        ) from None
    if result is None:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission provenance is unavailable"
        )
    return result


type _TrustedTimeImageAdmissionProvenanceSnapshot = tuple[
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    int,
    bytes,
    tuple[int, ...],
    tuple[int, ...],
]
type _CurrentTrustedTimeImageAdmissionSnapshot = tuple[
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    str,
    int,
    bytes,
    tuple[int, ...],
    tuple[int, ...],
    tuple[int, ...],
    tuple[int, ...],
]


def _make_provenance_snapshot(
    *,
    path: str,
    source_id: str,
    supervisor_id: str,
    boot_session_id: str,
    git_revision: str,
    source_revision_sha256: str,
    supervisor_executable_import_manifest_sha256: str,
    artifact_sha256: str,
    created_at_utc: str,
    created_monotonic_ns: int,
    encoded: bytes,
    directory_identity: tuple[int, ...],
    file_identity: tuple[int, ...],
) -> _TrustedTimeImageAdmissionProvenanceSnapshot:
    return (
        "trusted-time-image-admission-provenance-snapshot-v1",
        path,
        source_id,
        supervisor_id,
        boot_session_id,
        git_revision,
        source_revision_sha256,
        supervisor_executable_import_manifest_sha256,
        artifact_sha256,
        created_at_utc,
        created_monotonic_ns,
        encoded,
        directory_identity,
        file_identity,
    )


def _make_current_admission_snapshot(
    *,
    path: str,
    ignored_root: str,
    archive_path: str,
    source_id: str,
    supervisor_id: str,
    boot_session_id: str,
    git_revision: str,
    source_revision_sha256: str,
    supervisor_executable_import_manifest_sha256: str,
    artifact_sha256: str,
    created_at_utc: str,
    created_monotonic_ns: int,
    encoded: bytes,
    directory_identity: tuple[int, ...],
    file_identity: tuple[int, ...],
    archive_directory_identity: tuple[int, ...],
    archive_file_identity: tuple[int, ...],
) -> _CurrentTrustedTimeImageAdmissionSnapshot:
    return (
        "current-trusted-time-image-admission-snapshot-v1",
        path,
        ignored_root,
        archive_path,
        source_id,
        supervisor_id,
        boot_session_id,
        git_revision,
        source_revision_sha256,
        supervisor_executable_import_manifest_sha256,
        artifact_sha256,
        created_at_utc,
        created_monotonic_ns,
        encoded,
        directory_identity,
        file_identity,
        archive_directory_identity,
        archive_file_identity,
    )


def _require_primitive_identity(value: object) -> tuple[int, ...]:
    if type(value) is not tuple or len(value) != 9 or any(type(item) is not int for item in value):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission snapshot is malformed"
        )
    return cast(tuple[int, ...], value)


def _require_provenance_snapshot(
    value: object,
) -> _TrustedTimeImageAdmissionProvenanceSnapshot:
    if type(value) is not tuple or len(value) != 14:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission provenance is malformed"
        )
    tag = tuple.__getitem__(value, 0)
    path = tuple.__getitem__(value, 1)
    source_id = tuple.__getitem__(value, 2)
    supervisor_id = tuple.__getitem__(value, 3)
    boot_session_id = tuple.__getitem__(value, 4)
    git_revision = tuple.__getitem__(value, 5)
    source_revision_sha256 = tuple.__getitem__(value, 6)
    manifest_sha256 = tuple.__getitem__(value, 7)
    artifact_sha256 = tuple.__getitem__(value, 8)
    created_at_utc = tuple.__getitem__(value, 9)
    created_monotonic_ns = tuple.__getitem__(value, 10)
    encoded = tuple.__getitem__(value, 11)
    directory_identity = tuple.__getitem__(value, 12)
    file_identity = tuple.__getitem__(value, 13)
    if (
        type(tag) is not str
        or tag != "trusted-time-image-admission-provenance-snapshot-v1"
        or type(path) is not str
        or type(source_id) is not str
        or type(supervisor_id) is not str
        or type(boot_session_id) is not str
        or type(git_revision) is not str
        or type(source_revision_sha256) is not str
        or type(manifest_sha256) is not str
        or type(artifact_sha256) is not str
        or type(created_at_utc) is not str
        or type(created_monotonic_ns) is not int
        or type(encoded) is not bytes
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission provenance is malformed"
        )
    _require_primitive_identity(directory_identity)
    _require_primitive_identity(file_identity)
    return cast(_TrustedTimeImageAdmissionProvenanceSnapshot, value)


def _require_current_admission_snapshot(
    value: object,
) -> _CurrentTrustedTimeImageAdmissionSnapshot:
    if type(value) is not tuple or len(value) != 18:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission snapshot is malformed"
        )
    tag = tuple.__getitem__(value, 0)
    string_indexes = (
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
    )
    if (
        type(tag) is not str
        or tag != "current-trusted-time-image-admission-snapshot-v1"
        or any(type(tuple.__getitem__(value, index)) is not str for index in string_indexes)
        or type(tuple.__getitem__(value, 12)) is not int
        or type(tuple.__getitem__(value, 13)) is not bytes
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission snapshot is malformed"
        )
    for index in (
        14,
        15,
        16,
        17,
    ):
        _require_primitive_identity(tuple.__getitem__(value, index))
    return cast(_CurrentTrustedTimeImageAdmissionSnapshot, value)


def _provenance_snapshot_value(value: object, index: int) -> object:
    return tuple.__getitem__(_require_provenance_snapshot(value), index)


def _current_admission_snapshot_value(value: object, index: int) -> object:
    return tuple.__getitem__(_require_current_admission_snapshot(value), index)


def _load_image_admission_provenance_artifact_with_snapshot(
    path: Path,
    *,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> tuple[
    TrustedTimeImageAdmissionProvenance,
    _TrustedTimeImageAdmissionProvenanceSnapshot,
]:
    """Authenticate one exact content-addressed archive without freshness authority."""

    absolute, exact_ignored_root = _absolute_artifact_path_strings(
        path,
        ignored_root=ignored_root,
    )
    artifact_name = os.path.basename(absolute)
    prefix = "image-admission-"
    suffix = ".json"
    if (
        not artifact_name.startswith(prefix)
        or not artifact_name.endswith(suffix)
        or len(artifact_name) != len(prefix) + 64 + len(suffix)
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission provenance binding is invalid"
        )
    expected_sha256 = artifact_name[len(prefix) : -len(suffix)]
    if _SHA256_PATTERN.fullmatch(expected_sha256) is None:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission provenance binding is invalid"
        )
    encoded, directory_identity, file_identity = _read_exact_image_admission_archive(
        absolute,
        ignored_root=exact_ignored_root,
    )
    if hashlib.sha256(encoded).hexdigest() != expected_sha256:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission provenance binding is invalid"
        )
    reviewed_inputs = reviewed_input_bindings()
    reviewed_inputs_tree = _immutable_reviewed_input_payload(reviewed_inputs)
    reviewed_inputs_encoded = _canonical_immutable_json_bytes(reviewed_inputs_tree)
    try:
        encoded_text = encoded.decode("utf-8", errors="strict")
        payload_tree = _decode_immutable_json_text(
            encoded_text,
            maximum_characters=MAXIMUM_IMAGE_ADMISSION_BYTES,
            maximum_nodes=128,
            label="trusted-time image admission artifact",
        )
    except UnicodeDecodeError:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        ) from None
    if _canonical_immutable_json_bytes(payload_tree) != encoded:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is not canonical"
        )
    root_label = "trusted-time image admission"
    images = _immutable_json_object_value(payload_tree, "images", label=root_label)
    inputs = _immutable_json_object_value(payload_tree, "inputs", label=root_label)
    image_label = "trusted-time image admission images"
    input_label = "trusted-time image admission inputs"
    source_id = _immutable_json_object_value(images, "source_id", label=image_label)
    supervisor_id = _immutable_json_object_value(images, "supervisor_id", label=image_label)
    supervisor_manifest_sha256 = _immutable_json_object_value(
        images,
        "supervisor_executable_import_manifest_sha256",
        label=image_label,
    )
    boot_session_id = _immutable_json_object_value(
        payload_tree,
        "boot_session_id",
        label=root_label,
    )
    git_revision = _immutable_json_object_value(
        payload_tree,
        "git_revision",
        label=root_label,
    )
    source_revision_sha256 = _immutable_json_object_value(
        inputs,
        "source_revision_sha256",
        label=input_label,
    )
    created_at_utc = _immutable_json_object_value(
        payload_tree,
        "created_at_utc",
        label=root_label,
    )
    created_monotonic_ns = _immutable_json_object_value(
        payload_tree,
        "created_monotonic_ns",
        label=root_label,
    )
    if (
        type(source_id) is not str
        or type(supervisor_id) is not str
        or type(supervisor_manifest_sha256) is not str
        or type(boot_session_id) is not str
        or type(git_revision) is not str
        or type(source_revision_sha256) is not str
        or type(created_at_utc) is not str
        or type(created_monotonic_ns) is not int
        or _canonical_immutable_json_bytes(inputs) != reviewed_inputs_encoded
        or _reviewed_input_value(
            reviewed_inputs,
            9,
        )
        != source_revision_sha256
        or _IMAGE_ID_PATTERN.fullmatch(source_id) is None
        or _IMAGE_ID_PATTERN.fullmatch(supervisor_id) is None
        or _SHA256_PATTERN.fullmatch(supervisor_manifest_sha256) is None
        or source_id == supervisor_id
        or _BOOT_SESSION_ID_PATTERN.fullmatch(boot_session_id) is None
        or boot_session_id.partition(":")[2].replace("-", "") == "0" * 32
        or _GIT_REVISION_PATTERN.fullmatch(git_revision) is None
        or _SHA256_PATTERN.fullmatch(source_revision_sha256) is None
        or _CREATED_AT_PATTERN.fullmatch(created_at_utc) is None
        or created_monotonic_ns < 0
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        )
    try:
        parsed_created_at = datetime.fromisoformat(created_at_utc.replace("Z", "+00:00"))
    except ValueError:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        ) from None
    if (
        parsed_created_at.tzinfo is None
        or parsed_created_at.utcoffset() != UTC.utcoffset(parsed_created_at)
        or parsed_created_at.isoformat(timespec="microseconds").replace("+00:00", "Z")
        != created_at_utc
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        )

    expected_admission_tree = _immutable_json_object(
        (
            ("authority_granted", False),
            ("boot_session_id", boot_session_id),
            ("contract_version", IMAGE_ADMISSION_CONTRACT_VERSION),
            ("created_at_utc", created_at_utc),
            ("created_monotonic_ns", created_monotonic_ns),
            ("fresh_for_seconds", IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS),
            ("git_revision", git_revision),
            (
                "images",
                _immutable_json_object(
                    (
                        ("source_id", source_id),
                        (
                            "supervisor_executable_import_manifest_sha256",
                            supervisor_manifest_sha256,
                        ),
                        ("supervisor_id", supervisor_id),
                    )
                ),
            ),
            ("inputs", reviewed_inputs_tree),
            ("new_exposure_authorized", False),
            ("service", "trusted-time-image-admission"),
            ("status", "admitted"),
        )
    )
    expected_admission_encoded = _canonical_immutable_json_bytes(expected_admission_tree)
    if expected_admission_encoded != encoded:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        )
    try:
        secondary_payload: Any = json.loads(expected_admission_encoded)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        ) from None
    admission = _decode_structural_admission_payload(
        secondary_payload,
        path=Path(absolute),
        artifact_sha256=expected_sha256,
    )
    if (
        expected_admission_encoded != encoded
        or _canonical_immutable_json_bytes(
            _immutable_reviewed_input_payload(reviewed_input_bindings())
        )
        != reviewed_inputs_encoded
        or os.fspath(admission.path) != absolute
        or admission.identities.source_id != source_id
        or admission.identities.supervisor_id != supervisor_id
        or admission.boot_session_id != boot_session_id
        or admission.git_revision != git_revision
        or admission.source_revision_sha256 != source_revision_sha256
        or admission.artifact_sha256 != expected_sha256
        or admission.created_at_utc != created_at_utc
        or admission.created_monotonic_ns != created_monotonic_ns
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is malformed"
        )
    provenance = TrustedTimeImageAdmissionProvenance(
        path=Path(absolute),
        identities=TrustedTimeImageIdentities(
            source_id=source_id,
            supervisor_id=supervisor_id,
        ),
        boot_session_id=boot_session_id,
        git_revision=git_revision,
        source_revision_sha256=source_revision_sha256,
        artifact_sha256=expected_sha256,
        created_at_utc=created_at_utc,
        created_monotonic_ns=created_monotonic_ns,
        encoded=encoded,
        file_identity=file_identity,
    )
    provenance.__post_init__()
    final_encoded, final_directory_identity, final_file_identity = (
        _read_exact_image_admission_archive(
            absolute,
            ignored_root=exact_ignored_root,
        )
    )
    if (
        (final_encoded, final_directory_identity, final_file_identity)
        != (encoded, directory_identity, file_identity)
        or expected_admission_encoded != encoded
        or _canonical_immutable_json_bytes(
            _immutable_reviewed_input_payload(reviewed_input_bindings())
        )
        != reviewed_inputs_encoded
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission provenance is malformed"
        )
    snapshot = _require_provenance_snapshot(
        _make_provenance_snapshot(
            path=absolute,
            source_id=source_id,
            supervisor_id=supervisor_id,
            boot_session_id=boot_session_id,
            git_revision=git_revision,
            source_revision_sha256=source_revision_sha256,
            supervisor_executable_import_manifest_sha256=supervisor_manifest_sha256,
            artifact_sha256=expected_sha256,
            created_at_utc=created_at_utc,
            created_monotonic_ns=created_monotonic_ns,
            encoded=encoded,
            directory_identity=directory_identity,
            file_identity=file_identity,
        )
    )
    if (
        os.fspath(provenance.path) != absolute
        or provenance.identities.source_id != source_id
        or provenance.identities.supervisor_id != supervisor_id
        or provenance.boot_session_id != boot_session_id
        or provenance.git_revision != git_revision
        or provenance.source_revision_sha256 != source_revision_sha256
        or provenance.artifact_sha256 != expected_sha256
        or provenance.created_at_utc != created_at_utc
        or provenance.created_monotonic_ns != created_monotonic_ns
        or provenance.encoded != encoded
        or provenance.file_identity != file_identity
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission provenance is malformed"
        )
    return provenance, snapshot


def load_image_admission_provenance_artifact(
    path: Path,
    *,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> TrustedTimeImageAdmissionProvenance:
    """Authenticate one exact content-addressed archive without freshness authority."""

    provenance, _ = _load_image_admission_provenance_artifact_with_snapshot(
        path,
        ignored_root=ignored_root,
    )
    return provenance


def _load_current_image_admission_with_snapshot(
    path: Path = DEFAULT_IMAGE_ADMISSION_ARTIFACT,
    *,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
    monotonic_ns: int | None = None,
) -> tuple[TrustedTimeImageAdmission, _CurrentTrustedTimeImageAdmissionSnapshot]:
    """Read one current admission and its exact primitive immutable snapshot."""

    absolute, exact_ignored_root = _absolute_artifact_path_strings(
        path,
        ignored_root=ignored_root,
    )
    observed_boot_session = _current_boot_session_id()
    encoded, directory_identity, file_identity = _read_exact_image_admission_archive(
        absolute,
        ignored_root=exact_ignored_root,
    )
    artifact_sha256 = hashlib.sha256(encoded).hexdigest()
    archive_path = os.path.join(
        os.path.dirname(absolute),
        f"image-admission-{artifact_sha256}.json",
    )
    _, snapshot = _load_image_admission_provenance_artifact_with_snapshot(
        Path(archive_path),
        ignored_root=Path(exact_ignored_root),
    )
    snapshot = _require_provenance_snapshot(snapshot)
    snapshot_source_id = cast(str, _provenance_snapshot_value(snapshot, 2))
    snapshot_supervisor_id = cast(str, _provenance_snapshot_value(snapshot, 3))
    snapshot_boot_session_id = cast(str, _provenance_snapshot_value(snapshot, 4))
    snapshot_git_revision = cast(str, _provenance_snapshot_value(snapshot, 5))
    snapshot_source_revision_sha256 = cast(
        str,
        _provenance_snapshot_value(snapshot, 6),
    )
    snapshot_manifest_sha256 = cast(
        str,
        _provenance_snapshot_value(snapshot, 7),
    )
    snapshot_artifact_sha256 = cast(str, _provenance_snapshot_value(snapshot, 8))
    snapshot_created_at_utc = cast(str, _provenance_snapshot_value(snapshot, 9))
    snapshot_created_monotonic_ns = cast(int, _provenance_snapshot_value(snapshot, 10))
    snapshot_encoded = cast(bytes, _provenance_snapshot_value(snapshot, 11))
    snapshot_directory_identity = cast(
        tuple[int, ...],
        _provenance_snapshot_value(snapshot, 12),
    )
    snapshot_file_identity = cast(
        tuple[int, ...],
        _provenance_snapshot_value(snapshot, 13),
    )
    observed_monotonic_ns = _suspend_aware_monotonic_ns() if monotonic_ns is None else monotonic_ns
    candidate = TrustedTimeImageAdmission(
        path=Path(absolute),
        identities=TrustedTimeImageIdentities(
            source_id=snapshot_source_id,
            supervisor_id=snapshot_supervisor_id,
        ),
        boot_session_id=snapshot_boot_session_id,
        git_revision=snapshot_git_revision,
        source_revision_sha256=snapshot_source_revision_sha256,
        artifact_sha256=snapshot_artifact_sha256,
        created_at_utc=snapshot_created_at_utc,
        created_monotonic_ns=snapshot_created_monotonic_ns,
    )
    candidate.__post_init__()
    if snapshot_boot_session_id != observed_boot_session:
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact belongs to a different boot session"
        )
    if (
        type(observed_monotonic_ns) is not int
        or observed_monotonic_ns < snapshot_created_monotonic_ns
        or observed_monotonic_ns - snapshot_created_monotonic_ns
        > IMAGE_ADMISSION_MAXIMUM_AGE_SECONDS * 1_000_000_000
    ):
        raise TrustedTimeImageVerificationError("trusted-time image admission artifact is stale")
    if (
        _provenance_snapshot_value(snapshot, 1) != archive_path
        or snapshot_encoded != encoded
        or snapshot_artifact_sha256 != artifact_sha256
        or snapshot_directory_identity != directory_identity
        or (absolute == archive_path and snapshot_file_identity != file_identity)
        or candidate.path != Path(absolute)
        or candidate.identities.source_id != snapshot_source_id
        or candidate.identities.supervisor_id != snapshot_supervisor_id
        or candidate.boot_session_id != snapshot_boot_session_id
        or candidate.git_revision != snapshot_git_revision
        or candidate.source_revision_sha256 != snapshot_source_revision_sha256
        or candidate.artifact_sha256 != snapshot_artifact_sha256
        or candidate.created_at_utc != snapshot_created_at_utc
        or candidate.created_monotonic_ns != snapshot_created_monotonic_ns
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact is unavailable"
        )
    final_encoded, final_directory_identity, final_file_identity = (
        _read_exact_image_admission_archive(
            absolute,
            ignored_root=exact_ignored_root,
        )
    )
    _, final_snapshot = _load_image_admission_provenance_artifact_with_snapshot(
        Path(archive_path),
        ignored_root=Path(exact_ignored_root),
    )
    candidate.__post_init__()
    if (
        (final_encoded, final_directory_identity, final_file_identity)
        != (encoded, directory_identity, file_identity)
        or _require_provenance_snapshot(final_snapshot) != snapshot
        or candidate.path != Path(absolute)
        or candidate.identities.source_id != snapshot_source_id
        or candidate.identities.supervisor_id != snapshot_supervisor_id
        or candidate.boot_session_id != snapshot_boot_session_id
        or candidate.git_revision != snapshot_git_revision
        or candidate.source_revision_sha256 != snapshot_source_revision_sha256
        or candidate.artifact_sha256 != snapshot_artifact_sha256
        or candidate.created_at_utc != snapshot_created_at_utc
        or candidate.created_monotonic_ns != snapshot_created_monotonic_ns
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact changed during authentication"
        )
    current_snapshot = _require_current_admission_snapshot(
        _make_current_admission_snapshot(
            path=absolute,
            ignored_root=exact_ignored_root,
            archive_path=archive_path,
            source_id=snapshot_source_id,
            supervisor_id=snapshot_supervisor_id,
            boot_session_id=snapshot_boot_session_id,
            git_revision=snapshot_git_revision,
            source_revision_sha256=snapshot_source_revision_sha256,
            supervisor_executable_import_manifest_sha256=snapshot_manifest_sha256,
            artifact_sha256=snapshot_artifact_sha256,
            created_at_utc=snapshot_created_at_utc,
            created_monotonic_ns=snapshot_created_monotonic_ns,
            encoded=encoded,
            directory_identity=directory_identity,
            file_identity=file_identity,
            archive_directory_identity=snapshot_directory_identity,
            archive_file_identity=snapshot_file_identity,
        )
    )
    admission = TrustedTimeImageAdmission(
        path=Path(absolute),
        identities=TrustedTimeImageIdentities(
            source_id=snapshot_source_id,
            supervisor_id=snapshot_supervisor_id,
        ),
        boot_session_id=snapshot_boot_session_id,
        git_revision=snapshot_git_revision,
        source_revision_sha256=snapshot_source_revision_sha256,
        artifact_sha256=snapshot_artifact_sha256,
        created_at_utc=snapshot_created_at_utc,
        created_monotonic_ns=snapshot_created_monotonic_ns,
    )
    admission.__post_init__()
    if (
        admission.path != Path(absolute)
        or admission.identities.source_id != snapshot_source_id
        or admission.identities.supervisor_id != snapshot_supervisor_id
        or admission.boot_session_id != snapshot_boot_session_id
        or admission.git_revision != snapshot_git_revision
        or admission.source_revision_sha256 != snapshot_source_revision_sha256
        or admission.artifact_sha256 != snapshot_artifact_sha256
        or admission.created_at_utc != snapshot_created_at_utc
        or admission.created_monotonic_ns != snapshot_created_monotonic_ns
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image admission artifact changed during authentication"
        )
    return admission, current_snapshot


def _load_current_image_admission_snapshot(
    path: Path = DEFAULT_IMAGE_ADMISSION_ARTIFACT,
    *,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
    monotonic_ns: int | None = None,
) -> _CurrentTrustedTimeImageAdmissionSnapshot:
    """Return only the primitive current-admission authority snapshot."""

    _, snapshot = _load_current_image_admission_with_snapshot(
        path,
        ignored_root=ignored_root,
        monotonic_ns=monotonic_ns,
    )
    return _require_current_admission_snapshot(snapshot)


def load_image_admission_artifact(
    path: Path = DEFAULT_IMAGE_ADMISSION_ARTIFACT,
    *,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
    monotonic_ns: int | None = None,
) -> TrustedTimeImageAdmission:
    """Read one secondary public view of the current immutable admission."""

    admission, _ = _load_current_image_admission_with_snapshot(
        path,
        ignored_root=ignored_root,
        monotonic_ns=monotonic_ns,
    )
    return admission


def _immutable_json_string_array_or_none(value: object, *, label: str) -> tuple[str, ...] | None:
    if value is None:
        return None
    items = _immutable_json_array_items(value, label=label)
    if any(type(item) is not str for item in items):
        raise TrustedTimeImageVerificationError(f"{label} must be a string array or null")
    return cast(tuple[str, ...], items)


def _image_inspection_projection(
    payload: object,
    *,
    expected_image_id: str,
) -> _ImageInspectionProjection:
    label = "Docker image inspection"
    expected_keys = frozenset(
        {
            "cmd",
            "entrypoint",
            "env",
            "exposed_ports",
            "healthcheck",
            "id",
            "shell",
            "user",
            "volumes",
            "working_dir",
        }
    )
    if _immutable_json_object_keys(payload, label=label) != expected_keys:
        raise TrustedTimeImageVerificationError("Docker image inspection is malformed")
    image_id = _immutable_json_object_value(payload, "id", label=label)
    user = _immutable_json_object_value(payload, "user", label=label)
    working_directory = _immutable_json_object_value(payload, "working_dir", label=label)
    if (
        type(image_id) is not str
        or image_id != expected_image_id
        or _IMAGE_ID_PATTERN.fullmatch(image_id) is None
        or type(user) is not str
        or type(working_directory) is not str
        or _immutable_json_object_value(payload, "exposed_ports", label=label) is not None
        or _immutable_json_object_value(payload, "healthcheck", label=label) is not None
        or _immutable_json_object_value(payload, "volumes", label=label) is not None
        or _immutable_json_object_value(payload, "shell", label=label) is not None
    ):
        raise TrustedTimeImageVerificationError("Docker image inspection is malformed")
    projection = _make_image_inspection_projection(
        image_id=image_id,
        user=user,
        entrypoint=_immutable_json_string_array_or_none(
            _immutable_json_object_value(payload, "entrypoint", label=label),
            label="Docker image entrypoint",
        ),
        command=_immutable_json_string_array_or_none(
            _immutable_json_object_value(payload, "cmd", label=label),
            label="Docker image command",
        ),
        environment=_immutable_json_string_array_or_none(
            _immutable_json_object_value(payload, "env", label=label),
            label="Docker image environment",
        ),
        working_directory=working_directory,
    )
    return _require_image_inspection_projection(projection)


def validate_source_inspection(inspection: object) -> None:
    exact = _require_image_inspection_projection(inspection)
    if (
        _image_inspection_value(exact, 2) != "10001:10001"
        or _image_inspection_value(exact, 3) != ("/usr/sbin/chronyd",)
        or _image_inspection_value(exact, 4)
        != (
            "-x",
            "-d",
            "-U",
            "-f",
            "/etc/autoquant/trusted-time/chrony.conf",
        )
        or _image_inspection_value(exact, 5)
        != ("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",)
        or _image_inspection_value(exact, 6) != "/"
    ):
        raise TrustedTimeImageVerificationError("Chrony image configuration drifted")


def validate_supervisor_inspection(inspection: object) -> None:
    exact = _require_image_inspection_projection(inspection)
    if (
        _image_inspection_value(exact, 2) != "10001:10001"
        or _image_inspection_value(exact, 3) is not None
        or _image_inspection_value(exact, 4)
        != (
            "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
            "supervisor",
        )
        or _image_inspection_value(exact, 5)
        != (
            "PATH=/opt/autoquant/trusted-time/bin:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG=C.UTF-8",
            "GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305",
            "PYTHON_VERSION=3.12.13",
            "PYTHON_SHA256=c08bc65a81971c1dd5783182826503369466c7e67374d1646519adf05207b684",
            "LD_LIBRARY_PATH=",
            "LD_PRELOAD=",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONUNBUFFERED=1",
            "UV_COMPILE_BYTECODE=0",
            "UV_NO_DEV=1",
            "UV_NO_SYNC=1",
            "UV_PROJECT_ENVIRONMENT=/opt/autoquant/trusted-time",
        )
        or _image_inspection_value(exact, 6) != "/"
    ):
        raise TrustedTimeImageVerificationError("supervisor image configuration drifted")


def validate_chronyd_version(returncode: int, stdout: str, stderr: str) -> None:
    output = stdout + stderr
    match = _CHRONYD_VERSION_PATTERN.fullmatch(output)
    if returncode != 0 or match is None or "+NTS" not in match.group("features").split():
        raise TrustedTimeImageVerificationError(
            "Chrony source image lacks exact NTS-enabled version 4.8"
        )


def validate_chronyc_version(returncode: int, stdout: str, stderr: str) -> None:
    output = stdout + stderr
    if returncode != 0 or _CHRONYC_VERSION_PATTERN.fullmatch(output) is None:
        raise TrustedTimeImageVerificationError(
            "supervisor image lacks exact Chrony client version 4.8"
        )


def validate_static_chronyc(returncode: int, stdout: str, stderr: str) -> None:
    if returncode != 0 or stdout or stderr:
        raise TrustedTimeImageVerificationError(
            "supervisor Chrony client has a dynamic ELF interpreter"
        )


def validate_ca_trust_store(returncode: int, stdout: str, stderr: str) -> None:
    if returncode != 0 or stdout or stderr:
        raise TrustedTimeImageVerificationError(
            "supervisor image lacks a nonempty system CA trust store"
        )


def validate_database_ca_metadata(returncode: int, stdout: str, stderr: str) -> None:
    if returncode != 0 or stderr or stdout != "0:0:444\n":
        raise TrustedTimeImageVerificationError("supervisor pinned database CA metadata drifted")


def validate_operational_schema_contract(
    returncode: int,
    stdout: str,
    stderr: str,
) -> None:
    expected = (
        '{"catalog_relations":["phase6_trusted_time_head_anchor_intents",'
        '"phase6_trusted_time_head_anchor_receipts"],'
        '"schema_revision":"0036_phase6_time_anchors"}'
    )
    if returncode != 0 or stderr or stdout != expected + "\n":
        raise TrustedTimeImageVerificationError("supervisor operational schema contract drifted")


def validate_config_hashes(
    *,
    source_output: str,
    supervisor_output: str,
) -> None:
    expected_source = f"{CONFIG_SHA256}  /etc/autoquant/trusted-time/chrony.conf\n"
    expected_supervisor = (
        expected_source
        + f"{AUTHORITY_SHA256}  /etc/autoquant/trusted-time/source-authority.json\n"
        + f"{DATABASE_CA_SHA256}  /etc/autoquant/trusted-time/supabase-prod-ca-2021.crt\n"
    )
    if source_output != expected_source or supervisor_output != expected_supervisor:
        raise TrustedTimeImageVerificationError("trusted-time protected image bytes drifted")


def _verify_supervisor_executable_import_manifest(
    supervisor_image_id: str,
    *,
    environment: Mapping[str, str] | tuple[tuple[str, str], ...],
) -> str:
    """Recompute the exact supervisor rootfs manifest and return its digest."""

    manifest_path = "/etc/autoquant/native/executable-import-manifest.jsonl"
    helper_path = "/usr/local/lib/autoquant-native-image-manifest.py"
    base_python = "/usr/local/bin/python"
    manifest_schema = "autoquant-native-executable-image-manifest-v2"
    if (
        manifest_path != SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_PATH
        or helper_path != SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_HELPER
        or base_python != SUPERVISOR_BASE_PYTHON
        or manifest_schema != SUPERVISOR_EXECUTABLE_IMPORT_MANIFEST_SCHEMA
    ):
        raise TrustedTimeImageVerificationError(
            "supervisor executable/import manifest contract drifted"
        )
    environment_snapshot = _immutable_environment_snapshot(
        environment,
        label="supervisor executable/import manifest environment",
    )
    metadata = _run_read_only(
        supervisor_image_id,
        "/usr/bin/stat",
        "-c",
        "%u:%g:%a:%h:%s",
        manifest_path,
        environment=environment_snapshot,
    )
    if _process_returncode(metadata) != 0 or _process_stderr(metadata):
        raise TrustedTimeImageVerificationError(
            "supervisor executable/import manifest metadata drifted"
        )
    metadata_match = re.fullmatch(
        r"0:0:444:1:([1-9][0-9]*)\n",
        _process_stdout(metadata),
    )
    if (
        metadata_match is None
        or int(metadata_match.group(1)) > _MAXIMUM_EXECUTABLE_IMPORT_MANIFEST_BYTES
    ):
        raise TrustedTimeImageVerificationError(
            "supervisor executable/import manifest metadata drifted"
        )
    verification = _run_rootfs_manifest_verifier(
        supervisor_image_id,
        "-I",
        "-B",
        "-S",
        helper_path,
        "verify",
        "/",
        manifest_path,
        environment=environment_snapshot,
    )
    verification_stdout = _process_stdout(verification)
    if (
        _process_returncode(verification) != 0
        or _process_stderr(verification)
        or not verification_stdout.endswith("\n")
        or verification_stdout.count("\n") != 1
    ):
        raise TrustedTimeImageVerificationError(
            "supervisor executable/import manifest verification failed"
        )
    receipt_prefix = '{"manifest_sha256":"'
    receipt_suffix = '","schema":"' + manifest_schema + '"}\n'
    manifest_sha256 = verification_stdout[
        len(receipt_prefix) : len(verification_stdout) - len(receipt_suffix)
    ]
    if (
        type(manifest_sha256) is not str
        or _SHA256_PATTERN.fullmatch(manifest_sha256) is None
        or verification_stdout != receipt_prefix + manifest_sha256 + receipt_suffix
    ):
        raise TrustedTimeImageVerificationError(
            "supervisor executable/import manifest receipt is malformed"
        )
    digest = _run_read_only(
        supervisor_image_id,
        "/usr/bin/sha256sum",
        manifest_path,
        environment=environment_snapshot,
    )
    if (
        _process_returncode(digest) != 0
        or _process_stderr(digest)
        or _process_stdout(digest) != f"{manifest_sha256}  {manifest_path}\n"
    ):
        raise TrustedTimeImageVerificationError(
            "supervisor executable/import manifest digest drifted"
        )
    final_environment_snapshot = _immutable_environment_snapshot(
        environment,
        label="supervisor executable/import manifest environment",
    )
    if final_environment_snapshot != environment_snapshot:
        raise TrustedTimeImageVerificationError(
            "supervisor executable/import manifest environment changed"
        )
    return manifest_sha256


def validate_secretless_supervisor(returncode: int, stdout: str, stderr: str) -> None:
    if returncode != 2 or stderr:
        raise TrustedTimeImageVerificationError(
            "secretless supervisor did not fail closed and quietly"
        )
    expected = _canonical_immutable_json_bytes(
        _immutable_json_object(
            (
                ("alert_delivery_authorized", False),
                ("arming_authorized", False),
                ("automatic_rearm_authorized", False),
                ("automatic_resume_authorized", False),
                ("broker_action_authorized", False),
                ("exposure_authorized", False),
                ("live_trading_authorized", False),
                ("new_exposure_authorized", False),
                ("operational_control_authorized", False),
                ("paper_trading_authorized", False),
                ("readiness_authorized", False),
                ("rearm_authorized", False),
                ("reason", "configuration_rejected"),
                ("service", "trusted-time-supervisor"),
                ("status", "fatal"),
            )
        )
    ).decode("ascii")
    if stdout != expected + "\n":
        raise TrustedTimeImageVerificationError(
            "secretless supervisor response is not the exact blocked contract"
        )


def validate_socket_volume_inspection(
    inspection: object,
    *,
    expected_name: str,
) -> None:
    if type(inspection) is not list or len(inspection) != 1:
        raise TrustedTimeImageVerificationError(
            "trusted-time socket volume inspection is malformed"
        )
    volume = _mapping(inspection[0], "trusted-time socket volume inspection")
    if (
        volume.get("Name") != expected_name
        or volume.get("Driver") != "local"
        or volume.get("Options") != SOCKET_VOLUME_DRIVER_OPTIONS
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time socket volume is not the exact tmpfs contract"
        )


def _validate_socket_mountinfo_probe(
    completed: _ImmutableTextSubprocessResult,
    *,
    label: str,
) -> None:
    if (
        _process_returncode(completed) != 0
        or _process_stderr(completed)
        or _process_stdout(completed) != _SOCKET_MOUNTINFO_RECEIPT
    ):
        raise TrustedTimeImageVerificationError(
            f"{label} socket mount is not the effective noexec tmpfs contract"
        )


def _minimal_docker_environment(
    additions: Mapping[str, str] | None = None,
) -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if key in _PASSTHROUGH_ENVIRONMENT
    }
    if additions is not None:
        environment.update(additions)
    return environment


def _immutable_environment_snapshot(
    environment: Mapping[str, str] | tuple[tuple[str, str], ...],
    *,
    label: str,
) -> tuple[tuple[str, str], ...]:
    try:
        snapshot = (
            environment
            if type(environment) is tuple
            else tuple(sorted(cast(Mapping[str, str], environment).items()))
        )
    except (AttributeError, RuntimeError, TypeError, ValueError):
        raise TrustedTimeImageVerificationError(f"{label} is invalid") from None
    if (
        type(snapshot) is not tuple
        or any(
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not str
            or not item[0]
            or "=" in item[0]
            or "\x00" in item[0]
            or "\x00" in item[1]
            for item in snapshot
        )
        or any(snapshot[index][0] >= snapshot[index + 1][0] for index in range(len(snapshot) - 1))
    ):
        raise TrustedTimeImageVerificationError(f"{label} is invalid")
    return snapshot


def _head_reviewed_input_entries(
    revision: str,
    *,
    environment: Mapping[str, str],
) -> Mapping[str, tuple[int, str]]:
    """Resolve the exact regular-file modes and blob IDs tracked at one HEAD."""

    pathspecs = (*_REVIEWED_FIXED_RELATIVE_PATHS, *_REVIEWED_DIRECTORY_RELATIVE_PATHS)
    try:
        completed = run_bounded_subprocess(
            (
                "git",
                "-c",
                "core.fsmonitor=false",
                "ls-tree",
                "-r",
                "-z",
                "--full-tree",
                revision,
                "--",
                *pathspecs,
            ),
            cwd=ROOT,
            environment=environment,
            timeout_seconds=5,
            maximum_stdout_bytes=_MAXIMUM_GIT_TREE_STDOUT_BYTES,
            maximum_stderr_bytes=_MAXIMUM_GIT_STDERR_BYTES,
        )
    except BoundedSubprocessError:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed inputs do not match Git HEAD"
        ) from None
    completed_stdout = _bytes_process_stdout(completed)
    if (
        _bytes_process_returncode(completed) != 0
        or _bytes_process_stderr(completed)
        or not completed_stdout.endswith(b"\0")
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed inputs do not match Git HEAD"
        )
    entries: dict[str, tuple[int, str]] = {}
    for record in completed_stdout[:-1].split(b"\0"):
        metadata, separator, encoded_path = record.partition(b"\t")
        fields = metadata.split(b" ")
        if separator != b"\t" or len(fields) != 3 or fields[1] != b"blob":
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            )
        mode = 0o644 if fields[0] == b"100644" else 0o755 if fields[0] == b"100755" else 0
        try:
            object_id = fields[2].decode("ascii", errors="strict")
            relative = os.fsdecode(encoded_path)
            _exact_relative_components(relative)
        except (UnicodeDecodeError, ValueError, TrustedTimeImageVerificationError):
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            ) from None
        if mode == 0 or _GIT_OBJECT_ID_PATTERN.fullmatch(object_id) is None or relative in entries:
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            )
        entries[relative] = (mode, object_id)
    return entries


def _read_head_blob_payloads(
    object_ids: Sequence[str],
    *,
    environment: Mapping[str, str],
) -> Mapping[str, bytes]:
    """Fetch exact HEAD blobs through Git's object validator and bounded batch protocol."""

    unique_object_ids = tuple(sorted(set(object_ids)))
    if (
        not unique_object_ids
        or len(unique_object_ids) != len(set(unique_object_ids))
        or any(_GIT_OBJECT_ID_PATTERN.fullmatch(item) is None for item in unique_object_ids)
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed inputs do not match Git HEAD"
        )
    request = b"".join(item.encode("ascii") + b"\n" for item in unique_object_ids)
    try:
        completed = run_bounded_subprocess(
            ("git", "-c", "core.fsmonitor=false", "cat-file", "--batch"),
            cwd=ROOT,
            environment=environment,
            timeout_seconds=10,
            maximum_stdout_bytes=_MAXIMUM_GIT_BATCH_STDOUT_BYTES,
            maximum_stderr_bytes=_MAXIMUM_GIT_STDERR_BYTES,
            stdin_bytes=request,
            maximum_stdin_bytes=_MAXIMUM_GIT_BATCH_STDIN_BYTES,
        )
    except BoundedSubprocessError:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed inputs do not match Git HEAD"
        ) from None
    maximum_total_bytes = _MAXIMUM_GIT_BATCH_STDOUT_BYTES
    maximum_file_bytes = 8 * 1_024 * 1_024
    completed_stdout = _bytes_process_stdout(completed)
    if (
        _bytes_process_returncode(completed) != 0
        or _bytes_process_stderr(completed)
        or len(completed_stdout) > maximum_total_bytes
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed inputs do not match Git HEAD"
        )
    payloads: dict[str, bytes] = {}
    offset = 0
    for requested_object_id in unique_object_ids:
        header_end = completed_stdout.find(b"\n", offset, offset + 256)
        if header_end < 0:
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            )
        header = completed_stdout[offset:header_end].split(b" ")
        if len(header) != 3 or header[1] != b"blob":
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            )
        try:
            observed_object_id = header[0].decode("ascii", errors="strict")
            encoded_size = header[2].decode("ascii", errors="strict")
        except UnicodeDecodeError:
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            ) from None
        if (
            observed_object_id != requested_object_id
            or not encoded_size.isascii()
            or not encoded_size.isdecimal()
            or (len(encoded_size) > 1 and encoded_size.startswith("0"))
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            )
        size = int(encoded_size)
        content_start = header_end + 1
        content_end = content_start + size
        if (
            size > maximum_file_bytes
            or content_end >= len(completed_stdout)
            or completed_stdout[content_end : content_end + 1] != b"\n"
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            )
        payloads[requested_object_id] = completed_stdout[content_start:content_end]
        offset = content_end + 1
    if offset != len(completed_stdout):
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed inputs do not match Git HEAD"
        )
    return payloads


def _head_reviewed_operator_authority_object(
    revision: str,
    *,
    environment: Mapping[str, str] | None = None,
    _exact_source_root: str = os.fspath(ROOT.resolve(strict=True)),
) -> tuple[str, str, bytes]:
    """Return the fixed operator authority from one exact reviewed Git commit.

    Production admission must cross-bind the definition-time source root to the
    admitted launcher, source, executable, and mount receipt.
    """

    def require_native_result(
        value: object,
        *,
        expected_argv: tuple[str, ...],
    ) -> tuple[int, bytes, bytes]:
        if (
            type(expected_argv) is not tuple
            or not expected_argv
            or any(type(item) is not str for item in expected_argv)
            or type(value) is not tuple
            or len(value) != 4
        ):
            raise UnicodeError
        argv = tuple.__getitem__(value, 0)
        returncode = tuple.__getitem__(value, 1)
        stdout = tuple.__getitem__(value, 2)
        stderr = tuple.__getitem__(value, 3)
        if (
            argv is not expected_argv
            or type(argv) is not tuple
            or not argv
            or any(type(item) is not str for item in argv)
            or type(returncode) is not int
            or type(stdout) is not bytes
            or type(stderr) is not bytes
        ):
            raise UnicodeError
        return (returncode, stdout, stderr)

    unavailable = "trusted-time reviewed operator authority Git object is unavailable"
    if type(revision) is not str or _GIT_REVISION_PATTERN.fullmatch(revision) is None:
        raise TrustedTimeImageVerificationError(unavailable)
    exact_environment = (
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_NO_LAZY_FETCH", "1"),
        ("GIT_NO_REPLACE_OBJECTS", "1"),
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("LC_ALL", "C"),
        ("PATH", "/usr/bin:/bin"),
        ("TMPDIR", "/tmp"),
    )
    if environment is not None:
        try:
            supplied_environment = dict(environment)
        except BaseException as error:
            if not isinstance(error, Exception):
                raise
            raise TrustedTimeImageVerificationError(unavailable) from None
        if supplied_environment != dict(exact_environment):
            raise TrustedTimeImageVerificationError(unavailable)
    try:
        if type(ROOT) is not type(Path()):
            raise ValueError
        root = os.fspath(ROOT)
        if (
            type(root) is not str
            or type(_exact_source_root) is not str
            or not os.path.isabs(_exact_source_root)
            or os.path.realpath(_exact_source_root) != _exact_source_root
            or root != _exact_source_root
        ):
            raise ValueError
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimeImageVerificationError(unavailable) from None
    exact_cwd = _exact_source_root

    revision_argv = (
        "/usr/bin/git",
        "-c",
        "core.fsmonitor=false",
        "rev-parse",
        "--verify",
        f"{revision}^{{commit}}",
    )
    try:
        resolved = _run_bounded_process(
            revision_argv,
            exact_cwd,
            exact_environment,
            b"",
            64,
            16_384,
            5_000_000_000,
        )
        resolved_returncode, resolved_stdout, resolved_stderr = require_native_result(
            resolved,
            expected_argv=revision_argv,
        )
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimeImageVerificationError(unavailable) from None
    if (
        resolved_returncode != 0
        or resolved_stderr
        or resolved_stdout != revision.encode("ascii") + b"\n"
    ):
        raise TrustedTimeImageVerificationError(unavailable)

    tree_argv = (
        "/usr/bin/git",
        "-c",
        "core.fsmonitor=false",
        "ls-tree",
        "-z",
        "--full-tree",
        revision,
        "--",
        "infra/trusted-time/post-enrollment-operator-attestation-authority.json",
    )
    try:
        tree = _run_bounded_process(
            tree_argv,
            exact_cwd,
            exact_environment,
            b"",
            1_024,
            16_384,
            5_000_000_000,
        )
        tree_returncode, tree_stdout, tree_stderr = require_native_result(
            tree,
            expected_argv=tree_argv,
        )
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimeImageVerificationError(unavailable) from None
    if tree_returncode != 0 or tree_stderr or not tree_stdout.endswith(b"\0"):
        raise TrustedTimeImageVerificationError(unavailable)
    records = tree_stdout[:-1].split(b"\0")
    if len(records) != 1:
        raise TrustedTimeImageVerificationError(unavailable)
    metadata, separator, encoded_path = records[0].partition(b"\t")
    fields = metadata.split(b" ")
    if (
        separator != b"\t"
        or encoded_path != _POST_ENROLLMENT_OPERATOR_AUTHORITY_RELATIVE_PATH.encode("ascii")
        or len(fields) != 3
        or fields[0] != b"100644"
        or fields[1] != b"blob"
    ):
        raise TrustedTimeImageVerificationError(unavailable)
    try:
        object_id = fields[2].decode("ascii", errors="strict")
    except UnicodeDecodeError:
        raise TrustedTimeImageVerificationError(unavailable) from None
    if _GIT_OBJECT_ID_PATTERN.fullmatch(object_id) is None:
        raise TrustedTimeImageVerificationError(unavailable)

    request = object_id.encode("ascii") + b"\n"
    if len(request) not in (41, 65):
        raise TrustedTimeImageVerificationError(unavailable)
    blob_argv = (
        "/usr/bin/git",
        "-c",
        "core.fsmonitor=false",
        "cat-file",
        "--batch",
    )
    try:
        blob = _run_bounded_process(
            blob_argv,
            exact_cwd,
            exact_environment,
            request,
            4_353,
            16_384,
            5_000_000_000,
        )
        blob_returncode, blob_stdout, blob_stderr = require_native_result(
            blob,
            expected_argv=blob_argv,
        )
    except BaseException as error:
        if not isinstance(error, Exception):
            raise
        raise TrustedTimeImageVerificationError(unavailable) from None
    if blob_returncode != 0 or blob_stderr:
        raise TrustedTimeImageVerificationError(unavailable)
    header_end = blob_stdout.find(b"\n", 0, 256)
    if header_end < 0:
        raise TrustedTimeImageVerificationError(unavailable)
    header = blob_stdout[:header_end].split(b" ")
    if len(header) != 3 or header[0] != fields[2] or header[1] != b"blob":
        raise TrustedTimeImageVerificationError(unavailable)
    try:
        encoded_size = header[2].decode("ascii", errors="strict")
    except UnicodeDecodeError:
        raise TrustedTimeImageVerificationError(unavailable) from None
    if (
        not encoded_size.isascii()
        or not encoded_size.isdecimal()
        or (len(encoded_size) > 1 and encoded_size.startswith("0"))
    ):
        raise TrustedTimeImageVerificationError(unavailable)
    size = int(encoded_size)
    content_start = header_end + 1
    content_end = content_start + size
    if (
        size > _MAXIMUM_OPERATOR_AUTHORITY_GIT_BYTES
        or content_end >= len(blob_stdout)
        or blob_stdout[content_end : content_end + 1] != b"\n"
        or content_end + 1 != len(blob_stdout)
    ):
        raise TrustedTimeImageVerificationError(unavailable)
    return "100644", object_id, blob_stdout[content_start:content_end]


def _head_reviewed_input_snapshot(
    revision: str,
    *,
    environment: Mapping[str, str],
) -> Mapping[str, tuple[int, bytes]]:
    """Return exact Git-validated bytes and modes for the reviewed HEAD tree."""

    entries = _head_reviewed_input_entries(revision, environment=environment)
    payloads = _read_head_blob_payloads(
        tuple(object_id for _, object_id in entries.values()),
        environment=environment,
    )
    return {
        relative: (mode, payloads[object_id]) for relative, (mode, object_id) in entries.items()
    }


def _head_reviewed_input_payload(
    revision: str,
    relative_path: str,
    *,
    environment: Mapping[str, str] | None = None,
) -> bytes:
    """Return one allowlisted reviewed file directly from the exact Git object."""

    if (
        _GIT_REVISION_PATTERN.fullmatch(revision) is None
        or relative_path not in _REVIEWED_FIXED_RELATIVE_PATHS
    ):
        raise TrustedTimeImageVerificationError("trusted-time reviewed Git payload is unavailable")
    snapshot = _head_reviewed_input_snapshot(
        revision,
        environment=(_minimal_git_environment() if environment is None else dict(environment)),
    )
    item = snapshot.get(relative_path)
    if item is None:
        raise TrustedTimeImageVerificationError("trusted-time reviewed Git payload is unavailable")
    return item[1]


def _require_ordinary_git_index_flags(*, environment: Mapping[str, str]) -> None:
    """Reject assume-unchanged and skip-worktree state anywhere in the index."""

    try:
        completed = run_bounded_subprocess(
            ("git", "-c", "core.fsmonitor=false", "ls-files", "-v", "-z"),
            cwd=ROOT,
            environment=environment,
            timeout_seconds=5,
            maximum_stdout_bytes=_MAXIMUM_GIT_TREE_STDOUT_BYTES,
            maximum_stderr_bytes=_MAXIMUM_GIT_STDERR_BYTES,
        )
    except BoundedSubprocessError:
        raise TrustedTimeImageVerificationError(
            "trusted-time clean Git revision is unavailable"
        ) from None
    completed_stdout = _bytes_process_stdout(completed)
    records = completed_stdout[:-1].split(b"\0") if completed_stdout.endswith(b"\0") else []
    if (
        _bytes_process_returncode(completed) != 0
        or _bytes_process_stderr(completed)
        or not records
        or any(not record.startswith(b"H ") for record in records)
    ):
        raise TrustedTimeImageVerificationError("trusted-time clean Git revision is unavailable")


def _require_head_reviewed_inputs(
    revision: str,
    *,
    environment: Mapping[str, str],
) -> None:
    """Require the current reviewed/build inputs to be exact raw HEAD blobs."""

    current_paths = _reviewed_input_relative_paths()
    expected = _head_reviewed_input_snapshot(revision, environment=environment)
    if set(current_paths) != set(expected):
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed inputs do not match Git HEAD"
        )
    for path in current_paths:
        required_mode, expected_payload = expected[path]
        if (
            hashlib.sha256(
                _native_reviewed_file_bytes(
                    path,
                    required_mode=required_mode,
                )
            ).hexdigest()
            != hashlib.sha256(expected_payload).hexdigest()
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time reviewed inputs do not match Git HEAD"
            )


def _minimal_git_environment() -> dict[str, str]:
    """Return the fixed secretless environment for Git object and tree reads."""

    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "TMPDIR": "/tmp",
    }


type _ImmutableTextSubprocessResult = tuple[tuple[str, ...], int, str, str]


def _require_bytes_process_result(value: object) -> BoundedSubprocessResult:
    if type(value) is not tuple or len(value) != 4:
        raise UnicodeError
    argv = tuple.__getitem__(value, 0)
    returncode = tuple.__getitem__(value, 1)
    stdout = tuple.__getitem__(value, 2)
    stderr = tuple.__getitem__(value, 3)
    if (
        type(argv) is not tuple
        or not argv
        or any(type(item) is not str for item in argv)
        or type(returncode) is not int
        or type(stdout) is not bytes
        or type(stderr) is not bytes
    ):
        raise UnicodeError
    return cast(BoundedSubprocessResult, value)


def _require_text_process_result(value: object) -> _ImmutableTextSubprocessResult:
    if type(value) is not tuple or len(value) != 4:
        raise UnicodeError
    argv = tuple.__getitem__(value, 0)
    returncode = tuple.__getitem__(value, 1)
    stdout = tuple.__getitem__(value, 2)
    stderr = tuple.__getitem__(value, 3)
    if (
        type(argv) is not tuple
        or not argv
        or any(type(item) is not str for item in argv)
        or type(returncode) is not int
        or type(stdout) is not str
        or type(stderr) is not str
    ):
        raise UnicodeError
    return cast(_ImmutableTextSubprocessResult, value)


def _process_argv(value: object) -> tuple[str, ...]:
    try:
        exact = _require_text_process_result(value)
    except UnicodeError:
        raise TrustedTimeImageVerificationError("bounded subprocess result is malformed") from None
    return cast(tuple[str, ...], tuple.__getitem__(exact, 0))


def _process_returncode(value: object) -> int:
    try:
        exact = _require_text_process_result(value)
    except UnicodeError:
        raise TrustedTimeImageVerificationError("bounded subprocess result is malformed") from None
    return cast(int, tuple.__getitem__(exact, 1))


def _process_stdout(value: object) -> str:
    try:
        exact = _require_text_process_result(value)
    except UnicodeError:
        raise TrustedTimeImageVerificationError("bounded subprocess result is malformed") from None
    return cast(str, tuple.__getitem__(exact, 2))


def _process_stderr(value: object) -> str:
    try:
        exact = _require_text_process_result(value)
    except UnicodeError:
        raise TrustedTimeImageVerificationError("bounded subprocess result is malformed") from None
    return cast(str, tuple.__getitem__(exact, 3))


def _bytes_process_returncode(value: object) -> int:
    try:
        exact = _require_bytes_process_result(value)
    except UnicodeError:
        raise TrustedTimeImageVerificationError("bounded subprocess result is malformed") from None
    return cast(int, tuple.__getitem__(exact, 1))


def _bytes_process_stdout(value: object) -> bytes:
    try:
        exact = _require_bytes_process_result(value)
    except UnicodeError:
        raise TrustedTimeImageVerificationError("bounded subprocess result is malformed") from None
    return cast(bytes, tuple.__getitem__(exact, 2))


def _bytes_process_stderr(value: object) -> bytes:
    try:
        exact = _require_bytes_process_result(value)
    except UnicodeError:
        raise TrustedTimeImageVerificationError("bounded subprocess result is malformed") from None
    return cast(bytes, tuple.__getitem__(exact, 3))


def _decode_bounded_subprocess(
    completed: BoundedSubprocessResult,
) -> _ImmutableTextSubprocessResult:
    """Decode one bounded command without accepting replacement characters."""

    exact = _require_bytes_process_result(completed)
    return _require_text_process_result(
        (
            tuple.__getitem__(exact, 0),
            tuple.__getitem__(exact, 1),
            cast(bytes, tuple.__getitem__(exact, 2)).decode("utf-8", errors="strict"),
            cast(bytes, tuple.__getitem__(exact, 3)).decode("utf-8", errors="strict"),
        )
    )


def _decode_exact_bounded_subprocess(
    completed: BoundedSubprocessResult,
) -> _ImmutableTextSubprocessResult:
    """Decode one exact immutable bounded command result."""

    return _decode_bounded_subprocess(completed)


def _current_clean_git_revision() -> str:
    """Resolve one stable commit with a clean tree and exact tracked inputs."""

    environment = _minimal_git_environment()
    revision_argv = (
        "git",
        "-c",
        "core.fsmonitor=false",
        "rev-parse",
        "--verify",
        "HEAD^{commit}",
    )
    status_argv = (
        "git",
        "-c",
        "core.fsmonitor=false",
        "status",
        "--porcelain=v1",
        "--untracked-files=normal",
        "--ignore-submodules=none",
    )

    def run_git(
        argv: tuple[str, ...],
        *,
        maximum_stdout_bytes: int,
    ) -> _ImmutableTextSubprocessResult:
        return _decode_bounded_subprocess(
            run_bounded_subprocess(
                argv,
                cwd=ROOT,
                environment=environment,
                timeout_seconds=2,
                maximum_stdout_bytes=maximum_stdout_bytes,
                maximum_stderr_bytes=_MAXIMUM_GIT_STDERR_BYTES,
            )
        )

    try:
        before = run_git(
            revision_argv,
            maximum_stdout_bytes=_MAXIMUM_GIT_REVISION_STDOUT_BYTES,
        )
        status_result = run_git(
            status_argv,
            maximum_stdout_bytes=_MAXIMUM_GIT_STATUS_STDOUT_BYTES,
        )
    except (BoundedSubprocessError, UnicodeError):
        raise TrustedTimeImageVerificationError(
            "trusted-time clean Git revision is unavailable"
        ) from None
    before_stdout = _process_stdout(before)
    revision = before_stdout.strip()
    if (
        _process_returncode(before) != 0
        or _process_stderr(before)
        or before_stdout != f"{revision}\n"
        or _GIT_REVISION_PATTERN.fullmatch(revision) is None
        or _process_returncode(status_result) != 0
        or _process_stdout(status_result)
        or _process_stderr(status_result)
    ):
        raise TrustedTimeImageVerificationError("trusted-time clean Git revision is unavailable")
    _require_ordinary_git_index_flags(environment=environment)
    _require_head_reviewed_inputs(revision, environment=environment)
    try:
        after_status_result = run_git(
            status_argv,
            maximum_stdout_bytes=_MAXIMUM_GIT_STATUS_STDOUT_BYTES,
        )
        after = run_git(
            revision_argv,
            maximum_stdout_bytes=_MAXIMUM_GIT_REVISION_STDOUT_BYTES,
        )
    except (BoundedSubprocessError, UnicodeError):
        raise TrustedTimeImageVerificationError(
            "trusted-time clean Git revision is unavailable"
        ) from None
    if (
        _process_returncode(after_status_result) != 0
        or _process_stdout(after_status_result)
        or _process_stderr(after_status_result)
        or _process_returncode(after) != 0
        or _process_stderr(after)
        or _process_stdout(after) != f"{revision}\n"
    ):
        raise TrustedTimeImageVerificationError("trusted-time clean Git revision is unavailable")
    return revision


def _sealed_head_build_context(revision: str) -> bytes:
    """Create one deterministic Docker tar context only from validated HEAD blobs."""

    if _GIT_REVISION_PATTERN.fullmatch(revision) is None:
        raise TrustedTimeImageVerificationError(
            "trusted-time immutable build context is unavailable"
        )
    snapshot = _head_reviewed_input_snapshot(
        revision,
        environment=_minimal_git_environment(),
    )
    selected: dict[str, tuple[int, bytes]] = {}
    for relative, item in snapshot.items():
        if (
            relative in _BUILD_CONTEXT_FIXED_RELATIVE_PATHS
            or (relative.startswith("apps/trusted_time_supervisor/") and relative.endswith(".py"))
            or (relative.startswith("packages/") and relative.endswith(".py"))
        ):
            selected[relative] = item
    if not _BUILD_CONTEXT_FIXED_RELATIVE_PATHS.issubset(selected):
        raise TrustedTimeImageVerificationError(
            "trusted-time immutable build context is unavailable"
        )
    dockerfile = selected.get(_TRUSTED_TIME_DOCKERFILE_RELATIVE_PATH)
    if dockerfile is None:
        raise TrustedTimeImageVerificationError(
            "trusted-time immutable build context is unavailable"
        )
    _validate_trusted_time_dockerfile_frontend(dockerfile[1])
    total_payload_bytes = sum(len(payload) for _, payload in selected.values())
    if not selected or total_payload_bytes > 64 * 1_024 * 1_024:
        raise TrustedTimeImageVerificationError(
            "trusted-time immutable build context is unavailable"
        )
    directory_names: set[str] = set()
    for relative in selected:
        parent = Path(relative).parent
        while parent != Path("."):
            directory_names.add(parent.as_posix())
            parent = parent.parent
    stream = io.BytesIO()
    try:
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for directory_name in sorted(
                directory_names,
                key=lambda item: (item.count("/"), item),
            ):
                info = tarfile.TarInfo(f"{directory_name}/")
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                archive.addfile(info)
            for relative in sorted(selected):
                mode, payload = selected[relative]
                info = tarfile.TarInfo(relative)
                info.type = tarfile.REGTYPE
                info.mode = mode
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
    except (OSError, tarfile.TarError, ValueError):
        raise TrustedTimeImageVerificationError(
            "trusted-time immutable build context is unavailable"
        ) from None
    encoded = stream.getvalue()
    if not encoded or len(encoded) > 72 * 1_024 * 1_024:
        raise TrustedTimeImageVerificationError(
            "trusted-time immutable build context is unavailable"
        )
    return encoded


def _validate_trusted_time_dockerfile_frontend(payload: bytes) -> None:
    """Require the exact content-addressed Dockerfile frontend directive."""

    if (
        type(payload) is not bytes
        or not payload.startswith(_TRUSTED_TIME_DOCKERFILE_FRONTEND)
        or payload.count(b"# syntax=") != 1
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time Dockerfile frontend is not content-addressed"
        )


def _docker(
    *arguments: str,
    timeout_seconds: float = 60,
    environment: Mapping[str, str] | tuple[tuple[str, str], ...] | None = None,
    stdin_bytes: bytes | None = None,
) -> _ImmutableTextSubprocessResult:
    if environment is None:
        process_environment: Mapping[str, str] | tuple[tuple[str, str], ...] = (
            _minimal_docker_environment()
        )
    elif type(environment) is tuple:
        process_environment = environment
    else:
        process_environment = dict(environment)
    maximum_stdout_bytes = (
        _MAXIMUM_DOCKER_BUILD_STDOUT_BYTES
        if arguments[:1] == ("build",)
        else (
            _MAXIMUM_DOCKER_INSPECTION_STDOUT_BYTES
            if "inspect" in arguments
            else _MAXIMUM_DOCKER_CONTROL_STDOUT_BYTES
        )
    )
    try:
        if stdin_bytes is not None and (
            type(stdin_bytes) is not bytes or len(stdin_bytes) > _MAXIMUM_DOCKER_BUILD_CONTEXT_BYTES
        ):
            raise BoundedSubprocessError("bounded subprocess contract is invalid")
        completed = run_bounded_subprocess(
            ("docker", *arguments),
            cwd=ROOT,
            environment=process_environment,
            timeout_seconds=timeout_seconds,
            maximum_stdout_bytes=maximum_stdout_bytes,
            maximum_stderr_bytes=_MAXIMUM_DOCKER_STDERR_BYTES,
            stdin_bytes=stdin_bytes,
            maximum_stdin_bytes=(0 if stdin_bytes is None else _MAXIMUM_DOCKER_BUILD_CONTEXT_BYTES),
        )
        return _decode_exact_bounded_subprocess(completed)
    except (BoundedSubprocessError, UnicodeError):
        raise TrustedTimeImageVerificationError("Docker is unavailable") from None


def _inspection(
    image_id: str,
    *,
    environment: Mapping[str, str] | tuple[tuple[str, str], ...] | None = None,
) -> _ImageInspectionProjection:
    inspection_format = (
        '{"cmd":{{json (index .Config "Cmd")}},'
        '"entrypoint":{{json (index .Config "Entrypoint")}},'
        '"env":{{json (index .Config "Env")}},'
        '"exposed_ports":{{json (index .Config "ExposedPorts")}},'
        '"healthcheck":{{json (index .Config "Healthcheck")}},"id":{{json .Id}},'
        '"shell":{{json (index .Config "Shell")}},'
        '"user":{{json (index .Config "User")}},'
        '"volumes":{{json (index .Config "Volumes")}},'
        '"working_dir":{{json (index .Config "WorkingDir")}}}'
    )
    if inspection_format != _IMAGE_INSPECTION_FORMAT:
        raise TrustedTimeImageVerificationError("Docker image inspection contract drifted")
    completed = _docker(
        "image",
        "inspect",
        "--format",
        inspection_format,
        image_id,
        environment=environment,
    )
    completed_stdout = _process_stdout(completed)
    if (
        _process_returncode(completed) != 0
        or _process_stderr(completed)
        or not completed_stdout.endswith("\n")
        or completed_stdout.count("\n") != 1
    ):
        raise TrustedTimeImageVerificationError("trusted-time image inspection failed")
    encoded = completed_stdout[:-1]
    payload = _decode_immutable_json_text(
        encoded,
        maximum_characters=16_384,
        maximum_nodes=128,
        label="trusted-time image inspection",
    )
    if _canonical_immutable_json_bytes(payload).decode("utf-8") != encoded:
        raise TrustedTimeImageVerificationError(
            "trusted-time image inspection returned malformed JSON"
        )
    return _image_inspection_projection(payload, expected_image_id=image_id)


def resolve_image_id(
    image_reference: str,
    *,
    environment: Mapping[str, str] | tuple[tuple[str, str], ...] | None = None,
) -> str:
    completed = _docker(
        "image",
        "inspect",
        "--format",
        "{{.Id}}",
        image_reference,
        environment=environment,
    )
    completed_stdout = _process_stdout(completed)
    image_id = completed_stdout.strip()
    if (
        _process_returncode(completed) != 0
        or _process_stderr(completed)
        or completed_stdout != f"{image_id}\n"
        or _IMAGE_ID_PATTERN.fullmatch(image_id) is None
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time image tag did not resolve to one immutable image ID"
        )
    return image_id


def build_trusted_time_images(
    git_revision: str,
    *,
    docker_environment: Mapping[str, str] | None = None,
) -> TrustedTimeImageIdentities:
    """Build both fixed targets from one immutable Git-object-derived context."""

    environment = (
        _minimal_docker_environment() if docker_environment is None else dict(docker_environment)
    )
    context = _sealed_head_build_context(git_revision)
    built_ids: list[str] = []
    for target, image in (
        ("chrony-source", SOURCE_IMAGE),
        ("trusted-time-supervisor", SUPERVISOR_IMAGE),
    ):
        completed = _docker(
            "build",
            "--quiet",
            "--file",
            "infra/docker/trusted-time.Dockerfile",
            "--target",
            target,
            "--tag",
            image,
            "-",
            timeout_seconds=1_800,
            environment=environment,
            stdin_bytes=context,
        )
        completed_stdout = _process_stdout(completed)
        image_id = completed_stdout.strip()
        if (
            _process_returncode(completed) != 0
            or _process_stderr(completed)
            or completed_stdout != f"{image_id}\n"
            or _IMAGE_ID_PATTERN.fullmatch(image_id) is None
        ):
            raise TrustedTimeImageVerificationError("trusted-time image build failed")
        built_ids.append(image_id)
    return TrustedTimeImageIdentities(
        source_id=built_ids[0],
        supervisor_id=built_ids[1],
    )


def _validate_trusted_time_dockerignore_contract(payload: bytes | None = None) -> None:
    """Require the trusted-time Dockerfile's deny-by-default context allowlist."""

    observed_sha256 = (
        _stable_file_sha256(ROOT / "infra" / "docker" / "trusted-time.Dockerfile.dockerignore")
        if payload is None
        else hashlib.sha256(payload).hexdigest()
    )
    if observed_sha256 != hashlib.sha256(_TRUSTED_TIME_DOCKERIGNORE_BYTES).hexdigest():
        raise TrustedTimeImageVerificationError(
            "trusted-time Docker build-context contract was rejected"
        )


def validate_prebuild_compose_contract(
    *,
    git_revision: str,
    docker_environment: Mapping[str, str],
) -> None:
    """Admit the fixed context and secretless Compose model before build."""

    from scripts.verify_trusted_time_compose import (
        PLACEHOLDER_DATABASE_SECRET_FILE,
        TrustedTimeComposeVerificationError,
        render_compose_model,
        validate_compose_model,
    )

    compose_payload = _head_reviewed_input_payload(
        git_revision,
        "infra/compose/trusted-time.compose.yaml",
    )
    dockerignore_payload = _head_reviewed_input_payload(
        git_revision,
        "infra/docker/trusted-time.Dockerfile.dockerignore",
    )
    _validate_trusted_time_dockerignore_contract(dockerignore_payload)
    try:
        model = render_compose_model(
            source_image=SOURCE_IMAGE,
            supervisor_image=SUPERVISOR_IMAGE,
            database_secret_file=PLACEHOLDER_DATABASE_SECRET_FILE,
            compose_payload=compose_payload,
            docker_environment=docker_environment,
        )
        validate_compose_model(
            model,
            expected_source_image=SOURCE_IMAGE,
            expected_supervisor_image=SUPERVISOR_IMAGE,
            expected_database_secret_file=PLACEHOLDER_DATABASE_SECRET_FILE,
        )
    except TrustedTimeComposeVerificationError:
        raise TrustedTimeImageVerificationError(
            "trusted-time prebuild Compose contract was rejected"
        ) from None


def _run_read_only(
    image: str,
    *command: str,
    environment: Mapping[str, str] | tuple[tuple[str, str], ...] | None = None,
) -> _ImmutableTextSubprocessResult:
    return _docker(
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "10001:10001",
        "--entrypoint",
        command[0],
        image,
        *command[1:],
        environment=environment,
    )


def _run_read_only_bytes(
    image: str,
    *command: str,
    environment: tuple[tuple[str, str], ...],
    _runner: Callable[..., object] = run_bounded_subprocess,
    _require_result: Callable[[object], BoundedSubprocessResult] = (_require_bytes_process_result),
    _root: Path = ROOT,
    _maximum_stdout_bytes: int = _MAXIMUM_DOCKER_CONTROL_STDOUT_BYTES,
    _maximum_stderr_bytes: int = _MAXIMUM_DOCKER_STDERR_BYTES,
) -> BoundedSubprocessResult:
    if (
        type(image) is not str
        or not image
        or type(command) is not tuple
        or not command
        or any(type(argument) is not str or not argument for argument in command)
        or type(environment) is not tuple
    ):
        raise TrustedTimeImageVerificationError("Docker is unavailable")
    argv = (
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "10001:10001",
        "--entrypoint",
        tuple.__getitem__(command, 0),
        image,
        *command[1:],
    )
    try:
        return _require_result(
            _runner(
                argv,
                cwd=_root,
                environment=environment,
                timeout_seconds=60.0,
                maximum_stdout_bytes=_maximum_stdout_bytes,
                maximum_stderr_bytes=_maximum_stderr_bytes,
                stdin_bytes=None,
                maximum_stdin_bytes=0,
            )
        )
    except (BoundedSubprocessError, UnicodeError):
        raise TrustedTimeImageVerificationError("Docker is unavailable") from None


def _run_rootfs_manifest_verifier(
    image: str,
    *command: str,
    environment: Mapping[str, str] | tuple[tuple[str, str], ...] | None = None,
) -> _ImmutableTextSubprocessResult:
    """Run the complete-rootfs manifest verifier as isolated root only."""

    if (
        command
        != (
            "-I",
            "-B",
            "-S",
            "/usr/local/lib/autoquant-native-image-manifest.py",
            "verify",
            "/",
            "/etc/autoquant/native/executable-import-manifest.jsonl",
        )
        or SUPERVISOR_BASE_PYTHON != "/usr/local/bin/python"
    ):
        raise TrustedTimeImageVerificationError(
            "supervisor executable/import manifest command drifted"
        )
    return _docker(
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "0:0",
        "--entrypoint",
        "/usr/local/bin/python",
        image,
        *command,
        environment=environment,
    )


def _decode_exact_docker_json_object(
    completed: _ImmutableTextSubprocessResult,
    *,
    label: str,
) -> tuple[object, ...]:
    stdout = _process_stdout(completed)
    if (
        _process_returncode(completed) != 0
        or _process_stderr(completed)
        or not stdout.endswith("\n")
        or stdout.count("\n") != 1
    ):
        raise TrustedTimeImageVerificationError(f"{label} failed")
    encoded = stdout[:-1]
    payload = _decode_immutable_json_text(
        encoded,
        maximum_characters=8_192,
        maximum_nodes=128,
        label=label,
    )
    if (
        _canonical_immutable_json_bytes(payload).decode("utf-8") != encoded
        or type(payload) is not tuple
        or len(payload) != 2
        or tuple.__getitem__(payload, 0) != 0
    ):
        raise TrustedTimeImageVerificationError(f"{label} returned malformed JSON") from None
    return cast(tuple[object, ...], payload)


def _validate_socket_volume_projection(
    completed: _ImmutableTextSubprocessResult,
    *,
    expected_name: str,
    expected_token: str,
) -> None:
    payload = _decode_exact_docker_json_object(
        completed,
        label="trusted-time socket probe volume inspection",
    )
    expected = _immutable_json_object(
        (
            ("driver", "local"),
            ("label_count", 1),
            ("label_token", expected_token),
            ("name", expected_name),
            ("option_count", 3),
            ("option_device", "tmpfs"),
            (
                "option_o",
                "rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0750",
            ),
            ("option_type", "tmpfs"),
            ("scope", "local"),
            ("status", None),
        )
    )
    if payload != expected:
        raise TrustedTimeImageVerificationError(
            "trusted-time socket volume is not the exact tmpfs contract"
        )


def _validate_source_probe_projection(
    completed: _ImmutableTextSubprocessResult,
    *,
    image_id: str,
    volume_name: str,
    expected_token: str,
) -> None:
    label = "trusted-time source topology inspection"
    payload = _decode_exact_docker_json_object(
        completed,
        label=label,
    )
    expected = _immutable_json_object(
        (
            ("bind_count", 0),
            ("cap_add_count", 0),
            ("cap_drop_0", "ALL"),
            ("cap_drop_count", 1),
            ("config_user", "10001:10001"),
            ("container_label_count", 1),
            ("container_label_token", expected_token),
            ("device_count", 0),
            ("device_request_count", 0),
            ("host_mount_count", 1),
            (
                "host_mount_driver_config",
                _immutable_json_object((("Name", "local"),)),
            ),
            ("host_mount_no_copy", True),
            ("host_mount_read_only", False),
            ("host_mount_source", volume_name),
            ("host_mount_target", "/run/chrony"),
            ("host_mount_type", "volume"),
            ("image", image_id),
            ("mount_count", 1),
            ("mount_destination", "/run/chrony"),
            ("mount_driver", "local"),
            ("mount_mode", "z"),
            ("mount_name", volume_name),
            ("mount_propagation", ""),
            ("mount_rw", True),
            ("mount_type", "volume"),
            ("network_mode", "none"),
            ("pids_limit", 32),
            ("port_binding_count", 0),
            ("privileged", False),
            ("readonly_rootfs", True),
            ("running", True),
            ("security_opt_0", "no-new-privileges"),
            ("security_opt_count", 1),
            ("tmpfs_count", 2),
            (
                "tmpfs_tmp",
                "rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0700",
            ),
            (
                "tmpfs_var_lib_chrony",
                "rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700",
            ),
        )
    )
    if payload != expected:
        payload_items = _immutable_json_object_items(payload, label=label)
        expected_items = _immutable_json_object_items(expected, label=label)
        payload_keys = tuple(key for key, _ in payload_items)
        expected_keys = tuple(key for key, _ in expected_items)
        if payload_keys != expected_keys:
            mismatch = "field_set"
        else:
            mismatched_fields = tuple(
                expected_key
                for (payload_key, payload_value), (expected_key, expected_value) in zip(
                    payload_items,
                    expected_items,
                    strict=True,
                )
                if payload_key != expected_key or payload_value != expected_value
            )
            mismatch = ",".join(mismatched_fields) or "unknown"
        raise TrustedTimeImageVerificationError(
            f"trusted-time source topology inspection drifted ({mismatch})"
        )


def _require_activity(completed: _ImmutableTextSubprocessResult, *, label: str) -> None:
    if (
        _process_returncode(completed) != 0
        or _process_stderr(completed)
        or not _process_stdout(completed).strip()
    ):
        raise TrustedTimeImageVerificationError(f"{label} could not use the shared socket")


def _named_container_absent(
    container_name: str,
    *,
    environment: Mapping[str, str] | tuple[tuple[str, str], ...] | None = None,
) -> bool:
    try:
        completed = _docker(
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            f"name=^/{container_name}$",
            environment=environment,
        )
    except TrustedTimeImageVerificationError:
        return False
    return (
        _process_returncode(completed) == 0
        and not _process_stderr(completed)
        and not _process_stdout(completed)
    )


def _named_volume_absent(
    volume_name: str,
    *,
    environment: Mapping[str, str] | tuple[tuple[str, str], ...] | None = None,
) -> bool:
    try:
        completed = _docker(
            "volume",
            "ls",
            "--quiet",
            "--filter",
            f"name=^{volume_name}$",
            environment=environment,
        )
    except TrustedTimeImageVerificationError:
        return False
    return (
        _process_returncode(completed) == 0
        and not _process_stderr(completed)
        and not _process_stdout(completed)
    )


def _probe_runtime_topology(
    source_id: str,
    supervisor_id: str,
    *,
    environment: Mapping[str, str] | tuple[tuple[str, str], ...] | None = None,
) -> None:
    token = secrets.token_hex(16)
    resource_prefix = f"aqt-trusted-time-admission-{token}"
    volume_name = f"{resource_prefix}-socket"
    source_name = f"{resource_prefix}-source"
    volume_create_attempted = False
    source_run_attempted = False
    primary_error: BaseException | None = None
    try:
        volume_create_attempted = True
        volume = _docker(
            "volume",
            "create",
            "--driver",
            "local",
            "--label",
            f"com.autoquanttrader.trusted-time-admission={token}",
            "--opt",
            "type=tmpfs",
            "--opt",
            "device=tmpfs",
            "--opt",
            "o=rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0750",
            volume_name,
            environment=environment,
        )
        if (
            _process_returncode(volume) != 0
            or _process_stderr(volume)
            or _process_stdout(volume) != f"{volume_name}\n"
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time socket probe volume creation failed"
            )
        volume_inspection_format = (
            '{"driver":{{json .Driver}},"label_count":{{len .Labels}},'
            '"label_token":{{json (index .Labels '
            '"com.autoquanttrader.trusted-time-admission")}},'
            '"name":{{json .Name}},"option_count":{{len .Options}},'
            '"option_device":{{json (index .Options "device")}},'
            '"option_o":{{json (index .Options "o")}},'
            '"option_type":{{json (index .Options "type")}},'
            '"scope":{{json .Scope}},"status":{{json .Status}}}'
        )
        _validate_socket_volume_projection(
            _docker(
                "volume",
                "inspect",
                "--format",
                volume_inspection_format,
                volume_name,
                environment=environment,
            ),
            expected_name=volume_name,
            expected_token=token,
        )

        source_run_attempted = True
        source = _docker(
            "run",
            "--detach",
            "--pull=never",
            "--name",
            source_name,
            "--label",
            f"com.autoquanttrader.trusted-time-admission={token}",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "10001:10001",
            "--pids-limit",
            "32",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0700",
            "--tmpfs",
            ("/var/lib/chrony:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700"),
            "--mount",
            (
                f"type=volume,source={volume_name},destination=/run/chrony,"
                "volume-nocopy,volume-driver=local"
            ),
            source_id,
            environment=environment,
        )
        if (
            _process_returncode(source) != 0
            or _process_stderr(source)
            or not _process_stdout(source).strip()
        ):
            raise TrustedTimeImageVerificationError("trusted-time source socket probe failed")

        source_inspection_format = (
            '{"bind_count":{{len .HostConfig.Binds}},'
            '"cap_add_count":{{len .HostConfig.CapAdd}},'
            '"cap_drop_0":{{json (index .HostConfig.CapDrop 0)}},'
            '"cap_drop_count":{{len .HostConfig.CapDrop}},'
            '"config_user":{{json .Config.User}},'
            '"container_label_count":{{len .Config.Labels}},'
            '"container_label_token":{{json (index .Config.Labels '
            '"com.autoquanttrader.trusted-time-admission")}},'
            '"device_count":{{len .HostConfig.Devices}},'
            '"device_request_count":{{len .HostConfig.DeviceRequests}},'
            '"host_mount_count":{{len .HostConfig.Mounts}},'
            '"host_mount_driver_config":'
            "{{json (index .HostConfig.Mounts 0).VolumeOptions.DriverConfig}},"
            '"host_mount_no_copy":'
            "{{json (index .HostConfig.Mounts 0).VolumeOptions.NoCopy}},"
            '"host_mount_read_only":{{json (index .HostConfig.Mounts 0).ReadOnly}},'
            '"host_mount_source":{{json (index .HostConfig.Mounts 0).Source}},'
            '"host_mount_target":{{json (index .HostConfig.Mounts 0).Target}},'
            '"host_mount_type":{{json (index .HostConfig.Mounts 0).Type}},'
            '"image":{{json .Image}},"mount_count":{{len .Mounts}},'
            '"mount_destination":{{json (index .Mounts 0).Destination}},'
            '"mount_driver":{{json (index .Mounts 0).Driver}},'
            '"mount_mode":{{json (index .Mounts 0).Mode}},'
            '"mount_name":{{json (index .Mounts 0).Name}},'
            '"mount_propagation":{{json (index .Mounts 0).Propagation}},'
            '"mount_rw":{{json (index .Mounts 0).RW}},'
            '"mount_type":{{json (index .Mounts 0).Type}},'
            '"network_mode":{{json .HostConfig.NetworkMode}},'
            '"pids_limit":{{json .HostConfig.PidsLimit}},'
            '"port_binding_count":{{len .HostConfig.PortBindings}},'
            '"privileged":{{json .HostConfig.Privileged}},'
            '"readonly_rootfs":{{json .HostConfig.ReadonlyRootfs}},'
            '"running":{{json .State.Running}},'
            '"security_opt_0":{{json (index .HostConfig.SecurityOpt 0)}},'
            '"security_opt_count":{{len .HostConfig.SecurityOpt}},'
            '"tmpfs_count":{{len .HostConfig.Tmpfs}},'
            '"tmpfs_tmp":{{json (index .HostConfig.Tmpfs "/tmp")}},'
            '"tmpfs_var_lib_chrony":'
            '{{json (index .HostConfig.Tmpfs "/var/lib/chrony")}}}'
        )
        _validate_source_probe_projection(
            _docker(
                "container",
                "inspect",
                "--format",
                source_inspection_format,
                source_name,
                environment=environment,
            ),
            image_id=source_id,
            volume_name=volume_name,
            expected_token=token,
        )

        source_mount = _docker(
            "container",
            "exec",
            "--user",
            "10001:10001",
            source_name,
            "/bin/sh",
            "-eu",
            "-c",
            _SOCKET_MOUNTINFO_CHECK,
            environment=environment,
        )
        _validate_socket_mountinfo_probe(
            source_mount,
            label="trusted-time source",
        )

        directory = _docker(
            "container",
            "exec",
            "--user",
            "10001:10001",
            source_name,
            "/bin/stat",
            "-c",
            "%u:%g:%a",
            "/run/chrony",
            environment=environment,
        )
        if (
            _process_returncode(directory) != 0
            or _process_stderr(directory)
            or _process_stdout(directory) != "10001:10001:750\n"
        ):
            raise TrustedTimeImageVerificationError(
                "trusted-time socket command directory permissions drifted"
            )

        deadline = time.monotonic() + 10
        while True:
            activity = _docker(
                "container",
                "exec",
                "--user",
                "10001:10001",
                source_name,
                "/usr/bin/chronyc",
                "-h",
                "/run/chrony/chronyd.sock",
                "activity",
                timeout_seconds=2,
                environment=environment,
            )
            if (
                _process_returncode(activity) == 0
                and not _process_stderr(activity)
                and _process_stdout(activity).strip()
            ):
                break
            if time.monotonic() >= deadline:
                raise TrustedTimeImageVerificationError(
                    "trusted-time source command socket did not become responsive"
                )
            time.sleep(0.1)

        supervisor_mount = _docker(
            "run",
            "--rm",
            "--pull=never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "10001:10001",
            "--mount",
            (
                f"type=volume,source={volume_name},destination=/run/chrony,"
                "volume-nocopy,volume-driver=local"
            ),
            "--entrypoint",
            "/bin/sh",
            supervisor_id,
            "-eu",
            "-c",
            _SOCKET_MOUNTINFO_CHECK,
            environment=environment,
        )
        _validate_socket_mountinfo_probe(
            supervisor_mount,
            label="trusted-time supervisor",
        )

        supervisor_activity = _docker(
            "run",
            "--rm",
            "--pull=never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "10001:10001",
            "--mount",
            (
                f"type=volume,source={volume_name},destination=/run/chrony,"
                "volume-nocopy,volume-driver=local"
            ),
            "--entrypoint",
            "/usr/local/bin/chronyc",
            supervisor_id,
            "-h",
            "/run/chrony/chronyd.sock",
            "activity",
            environment=environment,
        )
        _require_activity(supervisor_activity, label="trusted-time supervisor client")
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_failed = False
        if source_run_attempted:
            try:
                removed_source = _docker(
                    "container",
                    "rm",
                    "--force",
                    source_name,
                    environment=environment,
                )
            except TrustedTimeImageVerificationError:
                cleanup_failed = True
            else:
                cleanup_failed = (
                    _process_returncode(removed_source) != 0
                    or bool(_process_stderr(removed_source))
                ) and not _named_container_absent(
                    source_name,
                    environment=environment,
                )
        if volume_create_attempted:
            try:
                removed_volume = _docker(
                    "volume",
                    "rm",
                    volume_name,
                    environment=environment,
                )
            except TrustedTimeImageVerificationError:
                cleanup_failed = True
            else:
                volume_cleanup_failed = (
                    _process_returncode(removed_volume) != 0
                    or bool(_process_stderr(removed_volume))
                ) and not _named_volume_absent(
                    volume_name,
                    environment=environment,
                )
                cleanup_failed = cleanup_failed or volume_cleanup_failed
        if cleanup_failed:
            cleanup_error = TrustedTimeImageVerificationError(
                "trusted-time topology probe cleanup failed"
            )
            if primary_error is None:
                raise cleanup_error
            raise cleanup_error from primary_error


def _verify_images_with_manifest(
    source_image: str = SOURCE_IMAGE,
    supervisor_image: str = SUPERVISOR_IMAGE,
    *,
    docker_environment: Mapping[str, str] | None = None,
    _schema_probe: Callable[..., BoundedSubprocessResult] = _run_read_only_bytes,
) -> _VerifiedTrustedTimeImages:
    """Verify one pair and bind the supervisor rootfs executable manifest."""

    environment_source = (
        _minimal_docker_environment() if docker_environment is None else dict(docker_environment)
    )
    environment = _immutable_environment_snapshot(
        environment_source,
        label="trusted-time Docker environment",
    )
    resolved = _require_resolved_image_ids(
        _make_resolved_image_ids(
            resolve_image_id(source_image, environment=environment),
            resolve_image_id(supervisor_image, environment=environment),
        )
    )
    resolved_source_id = tuple.__getitem__(resolved, 1)
    resolved_supervisor_id = tuple.__getitem__(resolved, 2)
    validate_source_inspection(_inspection(resolved_source_id, environment=environment))
    validate_supervisor_inspection(_inspection(resolved_supervisor_id, environment=environment))
    supervisor_manifest_sha256 = _verify_supervisor_executable_import_manifest(
        resolved_supervisor_id,
        environment=environment,
    )

    chronyd = _run_read_only(
        resolved_source_id,
        "/usr/sbin/chronyd",
        "-v",
        environment=environment,
    )
    validate_chronyd_version(
        _process_returncode(chronyd),
        _process_stdout(chronyd),
        _process_stderr(chronyd),
    )
    chronyc = _run_read_only(
        resolved_supervisor_id,
        "/usr/local/bin/chronyc",
        "-v",
        environment=environment,
    )
    validate_chronyc_version(
        _process_returncode(chronyc),
        _process_stdout(chronyc),
        _process_stderr(chronyc),
    )
    static_chronyc = _run_read_only(
        resolved_supervisor_id,
        "/usr/local/bin/python",
        "-I",
        "-B",
        "-S",
        "-c",
        _STATIC_ELF_CHECK,
        environment=environment,
    )
    validate_static_chronyc(
        _process_returncode(static_chronyc),
        _process_stdout(static_chronyc),
        _process_stderr(static_chronyc),
    )
    ca_store = _run_read_only(
        resolved_supervisor_id,
        "/usr/local/bin/python",
        "-I",
        "-B",
        "-S",
        "-c",
        _CA_STORE_CHECK,
        environment=environment,
    )
    validate_ca_trust_store(
        _process_returncode(ca_store),
        _process_stdout(ca_store),
        _process_stderr(ca_store),
    )
    database_ca_metadata = _run_read_only(
        resolved_supervisor_id,
        "/usr/bin/stat",
        "-c",
        "%u:%g:%a",
        "/etc/autoquant/trusted-time/supabase-prod-ca-2021.crt",
        environment=environment,
    )
    validate_database_ca_metadata(
        _process_returncode(database_ca_metadata),
        _process_stdout(database_ca_metadata),
        _process_stderr(database_ca_metadata),
    )
    schema_contract = _schema_probe(
        resolved_supervisor_id,
        "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
        "image-schema-contract",
        environment=environment,
    )
    expected_schema_argv = (
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "10001:10001",
        "--entrypoint",
        "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python",
        resolved_supervisor_id,
        "image-schema-contract",
    )
    schema_stdout = schema_contract[2]
    if (
        schema_contract[0] != expected_schema_argv
        or schema_contract[1] != 0
        or schema_stdout
        != (
            b'{"catalog_relations":["phase6_trusted_time_head_anchor_intents",'
            b'"phase6_trusted_time_head_anchor_receipts"],'
            b'"schema_revision":"0036_phase6_time_anchors"}\n'
        )
        or schema_contract[3] != b""
    ):
        raise TrustedTimeImageVerificationError("supervisor operational schema contract drifted")
    validate_operational_schema_contract(
        schema_contract[1],
        schema_stdout.decode("ascii", errors="strict"),
        schema_contract[3].decode("ascii", errors="strict"),
    )

    source_hashes = _run_read_only(
        resolved_source_id,
        "/usr/bin/sha256sum",
        "/etc/autoquant/trusted-time/chrony.conf",
        environment=environment,
    )
    supervisor_hashes = _run_read_only(
        resolved_supervisor_id,
        "/usr/bin/sha256sum",
        "/etc/autoquant/trusted-time/chrony.conf",
        "/etc/autoquant/trusted-time/source-authority.json",
        "/etc/autoquant/trusted-time/supabase-prod-ca-2021.crt",
        environment=environment,
    )
    if (
        _process_returncode(source_hashes) != 0
        or _process_stderr(source_hashes)
        or _process_returncode(supervisor_hashes) != 0
        or _process_stderr(supervisor_hashes)
    ):
        raise TrustedTimeImageVerificationError("trusted-time image hash read failed")
    validate_config_hashes(
        source_output=_process_stdout(source_hashes),
        supervisor_output=_process_stdout(supervisor_hashes),
    )

    secretless = _docker(
        "run",
        "--rm",
        "--pull=never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        *_SECRETLESS_SUPERVISOR_DOCKER_ENVIRONMENT_ARGUMENTS,
        resolved_supervisor_id,
        environment=environment,
    )
    validate_secretless_supervisor(
        _process_returncode(secretless),
        _process_stdout(secretless),
        _process_stderr(secretless),
    )
    _probe_runtime_topology(
        resolved_source_id,
        resolved_supervisor_id,
        environment=environment,
    )
    return _require_verified_images(
        _make_verified_images(
            resolved_source_id,
            resolved_supervisor_id,
            supervisor_manifest_sha256,
        )
    )


def verify_images(
    source_image: str = SOURCE_IMAGE,
    supervisor_image: str = SUPERVISOR_IMAGE,
    *,
    docker_environment: Mapping[str, str] | None = None,
) -> TrustedTimeImageIdentities:
    """Verify one pair using only the exact Docker environment when supplied."""

    verified = _verify_images_with_manifest(
        source_image,
        supervisor_image,
        docker_environment=docker_environment,
    )
    verified = _require_verified_images(verified)
    return TrustedTimeImageIdentities(
        source_id=_verified_image_source_id(verified),
        supervisor_id=_verified_image_supervisor_id(verified),
    )


def build_and_verify_images() -> TrustedTimeImageIdentities:
    git_revision = _current_clean_git_revision()
    docker_environment = _minimal_docker_environment()
    before = reviewed_input_bindings()
    validate_prebuild_compose_contract(
        git_revision=git_revision,
        docker_environment=docker_environment,
    )
    if reviewed_input_bindings() != before:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed before image build"
        )
    built_identities = build_trusted_time_images(
        git_revision,
        docker_environment=docker_environment,
    )
    verified = _verify_images_with_manifest(
        built_identities.source_id,
        built_identities.supervisor_id,
        docker_environment=docker_environment,
    )
    verified = _require_verified_images(verified)
    if (
        _verified_image_source_id(verified) != built_identities.source_id
        or _verified_image_supervisor_id(verified) != built_identities.supervisor_id
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time built image identities changed before verification"
        )
    if reviewed_input_bindings() != before:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed during image build"
        )
    if _current_clean_git_revision() != git_revision:
        raise TrustedTimeImageVerificationError(
            "trusted-time clean Git revision changed during image build"
        )
    return TrustedTimeImageIdentities(
        source_id=_verified_image_source_id(verified),
        supervisor_id=_verified_image_supervisor_id(verified),
    )


def build_verify_and_write_image_admission(
    path: Path = DEFAULT_IMAGE_ADMISSION_ARTIFACT,
    *,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
) -> TrustedTimeImageAdmission:
    """Freshly build, fully verify, and atomically bind one immutable pair."""

    _absolute_artifact_path(path, ignored_root=ignored_root)
    git_revision = _current_clean_git_revision()
    docker_environment = _minimal_docker_environment()
    before = reviewed_input_bindings()
    validate_prebuild_compose_contract(
        git_revision=git_revision,
        docker_environment=docker_environment,
    )
    if reviewed_input_bindings() != before:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed before image build"
        )
    built_identities = build_trusted_time_images(
        git_revision,
        docker_environment=docker_environment,
    )
    verified = _verify_images_with_manifest(
        built_identities.source_id,
        built_identities.supervisor_id,
        docker_environment=docker_environment,
    )
    verified = _require_verified_images(verified)
    if (
        _verified_image_source_id(verified) != built_identities.source_id
        or _verified_image_supervisor_id(verified) != built_identities.supervisor_id
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time built image identities changed before verification"
        )
    if reviewed_input_bindings() != before:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed during image build"
        )
    if _current_clean_git_revision() != git_revision:
        raise TrustedTimeImageVerificationError(
            "trusted-time clean Git revision changed during image build"
        )
    admission = write_image_admission_artifact(
        path,
        TrustedTimeImageIdentities(
            source_id=_verified_image_source_id(verified),
            supervisor_id=_verified_image_supervisor_id(verified),
        ),
        git_revision=git_revision,
        supervisor_executable_import_manifest_sha256=(_verified_image_manifest_sha256(verified)),
        bindings=before,
        ignored_root=ignored_root,
    )
    if reviewed_input_bindings() != before:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed during image admission"
        )
    if _current_clean_git_revision() != git_revision:
        raise TrustedTimeImageVerificationError(
            "trusted-time clean Git revision changed during image admission"
        )
    return admission


def verify_and_write_existing_image_admission(
    path: Path,
    source_image_id: str,
    supervisor_image_id: str,
    *,
    ignored_root: Path = IGNORED_ARTIFACT_ROOT,
    docker_environment: Mapping[str, str] | None = None,
) -> TrustedTimeImageAdmission:
    """Admit an immutable pair only after reproducing it from reviewed inputs."""

    _absolute_artifact_path(path, ignored_root=ignored_root)
    requested = TrustedTimeImageIdentities(
        source_id=source_image_id,
        supervisor_id=supervisor_image_id,
    )
    git_revision = _current_clean_git_revision()
    environment = (
        _minimal_docker_environment() if docker_environment is None else dict(docker_environment)
    )
    before = reviewed_input_bindings()
    validate_prebuild_compose_contract(
        git_revision=git_revision,
        docker_environment=environment,
    )
    if reviewed_input_bindings() != before:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed before existing-image admission"
        )
    rebuilt = build_trusted_time_images(
        git_revision,
        docker_environment=environment,
    )
    if rebuilt != requested:
        raise TrustedTimeImageVerificationError(
            "trusted-time existing images do not match the reviewed source build"
        )
    verified = _verify_images_with_manifest(
        rebuilt.source_id,
        rebuilt.supervisor_id,
        docker_environment=environment,
    )
    verified = _require_verified_images(verified)
    if (
        _verified_image_source_id(verified) != requested.source_id
        or _verified_image_supervisor_id(verified) != requested.supervisor_id
    ):
        raise TrustedTimeImageVerificationError(
            "trusted-time existing image identities changed before admission"
        )
    if reviewed_input_bindings() != before or _current_clean_git_revision() != git_revision:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed during existing-image admission"
        )
    admission = write_image_admission_artifact(
        path,
        TrustedTimeImageIdentities(
            source_id=_verified_image_source_id(verified),
            supervisor_id=_verified_image_supervisor_id(verified),
        ),
        git_revision=git_revision,
        supervisor_executable_import_manifest_sha256=(_verified_image_manifest_sha256(verified)),
        bindings=before,
        ignored_root=ignored_root,
    )
    if reviewed_input_bindings() != before or _current_clean_git_revision() != git_revision:
        raise TrustedTimeImageVerificationError(
            "trusted-time reviewed input changed during existing-image admission"
        )
    return admission


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--build",
        action="store_true",
        help="build and admit the fixed nonsecret targets",
    )
    mode.add_argument(
        "--admit-existing",
        action="store_true",
        help="rebuild reviewed inputs and admit an exact matching immutable image pair",
    )
    parser.add_argument(
        "--artifact",
        type=Path,
        default=DEFAULT_IMAGE_ADMISSION_ARTIFACT,
        help=(
            "absolute owner-only artifact path below the repository artifacts root; "
            "used only with --build or --admit-existing"
        ),
    )
    parser.add_argument("source_image", nargs="?", default=SOURCE_IMAGE)
    parser.add_argument("supervisor_image", nargs="?", default=SUPERVISOR_IMAGE)
    arguments = parser.parse_args()
    if arguments.build and (
        arguments.source_image != SOURCE_IMAGE or arguments.supervisor_image != SUPERVISOR_IMAGE
    ):
        parser.error("--build is limited to the fixed Phase 6D build tags")
    if arguments.admit_existing and (
        _IMAGE_ID_PATTERN.fullmatch(arguments.source_image) is None
        or _IMAGE_ID_PATTERN.fullmatch(arguments.supervisor_image) is None
    ):
        parser.error("--admit-existing requires two exact immutable image IDs")
    if (
        not arguments.build
        and not arguments.admit_existing
        and arguments.artifact != DEFAULT_IMAGE_ADMISSION_ARTIFACT
    ):
        parser.error("--artifact requires --build or --admit-existing")
    if arguments.build:
        admission = build_verify_and_write_image_admission(arguments.artifact)
        identities = admission.identities
        artifact_sha256: str | None = admission.artifact_sha256
        boot_session_id: str | None = admission.boot_session_id
        git_revision: str | None = admission.git_revision
    elif arguments.admit_existing:
        admission = verify_and_write_existing_image_admission(
            arguments.artifact,
            arguments.source_image,
            arguments.supervisor_image,
        )
        identities = admission.identities
        artifact_sha256 = admission.artifact_sha256
        boot_session_id = admission.boot_session_id
        git_revision = admission.git_revision
    else:
        identities = verify_images(arguments.source_image, arguments.supervisor_image)
        artifact_sha256 = None
        boot_session_id = None
        git_revision = None
    print(
        json.dumps(
            {
                "artifact_sha256": artifact_sha256,
                "boot_session_id": boot_session_id,
                "git_revision": git_revision,
                "images": [identities.source_id, identities.supervisor_id],
                "new_exposure_authorized": False,
                "service": "trusted-time-image-verifier",
                "status": "admitted",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
