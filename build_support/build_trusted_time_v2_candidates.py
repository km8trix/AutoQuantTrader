"""Build unactivated Linux evidence for the six lifecycle-v2 native candidates.

The builder accepts one absent absolute output directory.  It compiles every
candidate twice, compares the ELF bytes and canonical link maps, and emits
only evidence artifacts.  It has no install, service-manager, or activation
operation.
"""

from __future__ import annotations

import _imp
import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import sysconfig
from dataclasses import dataclass
from pathlib import Path
from typing import Never

_ROOT = Path(__file__).resolve(strict=True).parents[1]
_NATIVE = _ROOT / "native"
_MONOCYPHER_ROOT = _ROOT / "third_party/monocypher/4.0.3"
_MONOCYPHER = _MONOCYPHER_ROOT / "src"
_MONOCYPHER_OPTIONAL = _MONOCYPHER / "optional"
_VENDORING = _MONOCYPHER_ROOT / "VENDORING.json"
_LICENSE = _MONOCYPHER_ROOT / "LICENCE.md"
_SECCOMP_MANIFEST_ROOT = _ROOT / "infra/trusted-time/graceful-stop-v2/seccomp"
_SECCOMP_MANIFEST_HELPER = _ROOT / "build_support/trusted_time_v2_seccomp_manifests.py"
_SECCOMP_MANIFEST_HARNESS = _ROOT / "tests/native/trusted_time_v2_seccomp_manifest_harness.c"
_CANDIDATE_IMPORT_SOURCE_ROOT = _ROOT / "build_support/trusted_time_v2_candidate_import_roots"
_SYSTEMD_CREDS = Path("/usr/bin/systemd-creds")
_RECEIPT_NAME = "candidate-build.json"
_LICENSE_OUTPUT_NAME = "MONOCYPHER-LICENCE.md"
_SECCOMP_MANIFEST_OUTPUT_NAMES = {
    "host": "seccomp-host.json",
    "provisioner": "seccomp-provisioner.json",
    "recovery": "seccomp-recovery.json",
    "supervisor": "seccomp-supervisor.json",
}
_SECCOMP_MANIFEST_PATHS = {
    profile: _SECCOMP_MANIFEST_ROOT / f"{profile}.json"
    for profile in _SECCOMP_MANIFEST_OUTPUT_NAMES
}
_ROLE_ENTRY_MODULES = {
    role: f"autoquant_trusted_time_v2_{role}_entry" for role in ("host", "recovery", "supervisor")
}
_ROLE_IMPORT_SOURCE_PATHS = {
    role: _CANDIDATE_IMPORT_SOURCE_ROOT / role / f"{module}.py"
    for role, module in _ROLE_ENTRY_MODULES.items()
}
_ROLE_RUNTIME_IMPORT_ROOTS = {
    "host": "/opt/autoquant/trusted-time-graceful-stop-v2-host/lib/python",
    "recovery": "/opt/autoquant/trusted-time-graceful-stop-v2-recovery/lib/python",
    "supervisor": "/opt/autoquant/trusted-time-graceful-stop-v2-supervisor/lib/python",
}
_RECOVERY_RUNTIME_ROOT = "/opt/autoquant/trusted-time-graceful-stop-v2-recovery/lib/python-runtime"
_RECOVERY_RUNTIME_RELATIVE_PATHS = (
    Path("LICENSE.txt"),
    Path("encodings/__init__.py"),
    Path("encodings/aliases.py"),
    Path("encodings/utf_8.py"),
)
_RECOVERY_RUNTIME_FORBIDDEN_RELATIVE_PREFIXES = (
    "__pycache__",
    "app",
    "asyncio",
    "concurrent",
    "ctypes",
    "docker",
    "endpoint",
    "http",
    "importlib",
    "lib-dynload",
    "multiprocessing",
    "pathlib.py",
    "pkgutil.py",
    "runpy.py",
    "shutil.py",
    "site-packages",
    "site.py",
    "socket.py",
    "subprocess.py",
    "threading.py",
    "transport",
    "urllib",
)
_RECOVERY_IMPORT_FORBIDDEN_FRAGMENTS = (
    "autoquant_trusted_time_v2_host_entry",
    "autoquant_trusted_time_v2_supervisor_entry",
    "docker",
    "endpoint",
    "lib-dynload",
    "transport",
)
_RECOVERY_FORBIDDEN_LOADED_MODULES = (
    "_ctypes",
    "_posixsubprocess",
    "_socket",
    "asyncio",
    "concurrent",
    "ctypes",
    "http",
    "importlib",
    "multiprocessing",
    "pathlib",
    "pkgutil",
    "runpy",
    "shutil",
    "socket",
    "subprocess",
    "urllib",
)
_MAXIMUM_COMMAND_OUTPUT = 32 * 1024 * 1024
_MAXIMUM_CANDIDATE_BYTES = 64 * 1024 * 1024
_MAXIMUM_LINK_MAP_BYTES = 32 * 1024 * 1024

_SOURCE_PATHS = {
    "authority": _NATIVE / "trusted_time_v2_authority.c",
    "descriptor_baseline": _NATIVE / "trusted_time_v2_descriptor_baseline.c",
    "endpoint": _NATIVE / "trusted_time_graceful_stop_v2_endpoint.c",
    "fork_guard": _NATIVE / "trusted_time_v2_fork_guard.c",
    "monocypher": _MONOCYPHER / "monocypher.c",
    "monocypher_ed25519": _MONOCYPHER_OPTIONAL / "monocypher-ed25519.c",
    "provisioner": _NATIVE / "trusted_time_v2_provisioner.c",
    "resources": _NATIVE / "trusted_time_graceful_stop_v2_resources.c",
    "role_launcher": _NATIVE / "trusted_time_v2_role_launcher.c",
    "seccomp": _NATIVE / "trusted_time_v2_seccomp.c",
    "secret_mount_admission": _NATIVE / "trusted_time_v2_secret_mount_admission.c",
    "signer": _NATIVE / "trusted_time_graceful_stop_v2_signer.c",
}

_ROLE_SOURCE_ALIASES = (
    "role_launcher",
    "descriptor_baseline",
    "fork_guard",
    "seccomp",
    "secret_mount_admission",
    "signer",
    "endpoint",
    "resources",
    "monocypher",
    "monocypher_ed25519",
)
_RECOVERY_SOURCE_ALIASES = tuple(
    alias for alias in _ROLE_SOURCE_ALIASES if alias not in {"endpoint", "resources"}
)
_PROVISIONER_SOURCE_ALIASES = (
    "provisioner",
    "authority",
    "descriptor_baseline",
    "fork_guard",
    "seccomp",
    "secret_mount_admission",
    "monocypher",
    "monocypher_ed25519",
)

_FORBIDDEN_DYNAMIC_DEPENDENCY_FRAGMENTS = (
    "libcrypto",
    "libmonocypher",
    "libsodium",
    "libssl",
)
_FORBIDDEN_EXPORTED_SYMBOL_FRAGMENTS = (
    "raw_secret",
    "test_inspection",
    "_for_test",
)
_FORBIDDEN_DEFINED_SYMBOL_FRAGMENTS = (
    "raw_secret",
    "test_inspection",
    "_for_test",
    "_test_",
)
_ROLE_SYMBOL_PREFIXES = {
    "host": (
        "aqt_host_",
        "aqt_trusted_time_graceful_stop_v2_host_",
        "aqt_trusted_time_v2_host_",
    ),
    "recovery": (
        "aqt_recovery_",
        "aqt_trusted_time_graceful_stop_v2_recovery_",
        "aqt_trusted_time_v2_recovery_",
    ),
    "supervisor": (
        "aqt_supervisor_",
        "aqt_trusted_time_graceful_stop_v2_supervisor_",
        "aqt_trusted_time_v2_supervisor_",
    ),
}
_ROLE_SIGNER_SYMBOLS = {
    "host": frozenset(
        {
            "aqt_trusted_time_v2_signer_sign_clean_stop_request",
            "aqt_trusted_time_v2_signer_sign_host_channel_confirmation",
            "aqt_trusted_time_v2_signer_sign_host_hello",
        }
    ),
    "recovery": frozenset({"aqt_trusted_time_v2_signer_sign_recovery_classification"}),
    "supervisor": frozenset(
        {
            "aqt_trusted_time_v2_signer_sign_clean_stop_error",
            "aqt_trusted_time_v2_signer_sign_clean_stop_result",
            "aqt_trusted_time_v2_signer_sign_supervisor_cleanup_commitment",
            "aqt_trusted_time_v2_signer_sign_supervisor_hello",
        }
    ),
}
_FORBIDDEN_RECOVERY_ROLE_STRINGS = (
    "host-ed25519.raw",
    "supervisor-ed25519.raw",
    "host-secrets",
    "supervisor-secrets",
    "supervisor.sock",
    "/run/autoquant/trusted-time/graceful-stop-v2/transport",
    "/var/run/docker.sock",
    "/v1.45",
    "stop?t=30",
    "v=false&force=false&link=false",
    "autoquant-trusted-time-graceful-stop-v2-host-provision",
    "autoquant-trusted-time-graceful-stop-v2-supervisor-provision",
    "autoquant_trusted_time_v2_host_entry",
    "autoquant_trusted_time_v2_supervisor_entry",
    "trusted_time_graceful_stop_v2_endpoint",
    "lib-dynload",
)
_FORBIDDEN_RECOVERY_PROVISIONER_STRINGS = (
    "host-ed25519.raw",
    "supervisor-ed25519.raw",
    "host-secrets",
    "supervisor-secrets",
    "supervisor.sock",
    "/run/autoquant/trusted-time/graceful-stop-v2/transport",
    "/var/run/docker.sock",
    "/v1.45",
    "stop?t=30",
    "v=false&force=false&link=false",
    "autoquant-trusted-time-graceful-stop-v2-host-provision",
    "autoquant-trusted-time-graceful-stop-v2-supervisor-provision",
    "autoquant_trusted_time_v2_host_entry",
    "autoquant_trusted_time_v2_supervisor_entry",
    "trusted_time_graceful_stop_v2_endpoint",
)
_FORBIDDEN_RECOVERY_UNDEFINED = frozenset(
    {
        "accept",
        "accept4",
        "bind",
        "clone",
        "clone3",
        "connect",
        "dlopen",
        "dlsym",
        "execl",
        "execle",
        "execlp",
        "execv",
        "execve",
        "execveat",
        "execvp",
        "execvpe",
        "fork",
        "listen",
        "popen",
        "posix_spawn",
        "posix_spawnp",
        "recv",
        "recvfrom",
        "recvmmsg",
        "recvmsg",
        "send",
        "sendmmsg",
        "sendmsg",
        "sendto",
        "shutdown",
        "socket",
        "socketpair",
        "system",
        "vfork",
    }
)
_NETWORK_UNDEFINED = frozenset(
    {
        "accept",
        "accept4",
        "bind",
        "connect",
        "listen",
        "recv",
        "recvfrom",
        "recvmmsg",
        "recvmsg",
        "send",
        "sendmmsg",
        "sendmsg",
        "sendto",
        "shutdown",
        "socket",
        "socketpair",
    }
)
_ALLOWED_FIRST_PARTY_CRYPTO_CALLS = frozenset(
    {
        "crypto_ed25519_check",
        "crypto_ed25519_key_pair",
        "crypto_ed25519_sign",
        "crypto_wipe",
    }
)
_NO_PIN_PROBE_SOURCE = r"""#include "trusted_time_v2_authority.h"
#include "trusted_time_v2_fork_guard.h"

#include <errno.h>
#include <string.h>

#ifndef ENOKEY
#error "The production no-pin evidence probe requires Linux ENOKEY."
#endif

int
main(void)
{
    AqtTrustedTimeV2AuthenticatedProvisioningGeneration generation;
    unsigned char zero[sizeof(generation)];
    int result;

    memset(&generation, 0xa5, sizeof(generation));
    memset(zero, 0, sizeof(zero));
    if (aqt_trusted_time_v2_fork_guard_initialize_before_python() != 0) {
        return 90;
    }
#if defined(AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE)
    result =
        aqt_trusted_time_graceful_stop_v2_consume_authenticated_host_provisioning_generation(
            &generation
        );
#elif defined(AQT_TRUSTED_TIME_V2_SUPERVISOR_PROVISIONER_PROFILE)
    result =
        aqt_trusted_time_graceful_stop_v2_consume_authenticated_supervisor_provisioning_generation(
            &generation
        );
#elif defined(AQT_TRUSTED_TIME_V2_RECOVERY_PROVISIONER_PROFILE)
    result =
        aqt_trusted_time_graceful_stop_v2_consume_authenticated_recovery_provisioning_generation(
            &generation
        );
#else
#error "Compile exactly one production no-pin role."
#endif
    if (result != ENOKEY
        || memcmp(&generation, zero, sizeof(generation)) != 0
        || aqt_trusted_time_v2_fork_guard_require_owner_table_empty() != 0) {
        return 91;
    }
    return 0;
}
"""


class CandidateBuildError(RuntimeError):
    """The Linux candidate evidence build failed closed."""


@dataclass(frozen=True, slots=True)
class _Role:
    name: str
    role_macro: str
    signer_macro: str
    executable: str
    provisioner_macro: str
    provisioner: str


@dataclass(frozen=True, slots=True)
class _BuildPlan:
    basename: str
    kind: str
    role: str
    definitions: tuple[str, ...]
    source_aliases: tuple[str, ...]
    python_link: bool


@dataclass(frozen=True, slots=True)
class _PythonBuild:
    compile_flags: tuple[str, ...]
    link_flags: tuple[str, ...]
    executable: Path
    home: Path
    include: Path
    standard_library: Path
    dynamic_extensions: Path
    library: Path
    soname: str


@dataclass(frozen=True, slots=True)
class _Toolchain:
    compiler: Path
    compiler_cc1: Path
    compiler_collect2: Path
    assembler: Path
    linker: Path
    nm: Path
    objdump: Path
    readelf: Path
    strings: Path


@dataclass(frozen=True, slots=True)
class _BuiltArtifact:
    binary: Path
    canonical_link_map: bytes
    commands: tuple[tuple[str, ...], ...]
    command_digest: str
    object_digests: tuple[tuple[str, str], ...]
    audit: dict[str, object]


_ROLES = (
    _Role(
        "host",
        "AQT_TRUSTED_TIME_V2_HOST_PROFILE",
        "AQT_TRUSTED_TIME_V2_SIGNER_HOST_PROFILE",
        "autoquant-trusted-time-graceful-stop-v2-host",
        "AQT_TRUSTED_TIME_V2_HOST_PROVISIONER_PROFILE",
        "autoquant-trusted-time-graceful-stop-v2-host-provision",
    ),
    _Role(
        "supervisor",
        "AQT_TRUSTED_TIME_V2_SUPERVISOR_PROFILE",
        "AQT_TRUSTED_TIME_V2_SIGNER_SUPERVISOR_PROFILE",
        "autoquant-trusted-time-graceful-stop-v2-supervisor",
        "AQT_TRUSTED_TIME_V2_SUPERVISOR_PROVISIONER_PROFILE",
        "autoquant-trusted-time-graceful-stop-v2-supervisor-provision",
    ),
    _Role(
        "recovery",
        "AQT_TRUSTED_TIME_V2_RECOVERY_PROFILE",
        "AQT_TRUSTED_TIME_V2_SIGNER_RECOVERY_PROFILE",
        "autoquant-trusted-time-graceful-stop-v2-recovery",
        "AQT_TRUSTED_TIME_V2_RECOVERY_PROVISIONER_PROFILE",
        "autoquant-trusted-time-graceful-stop-v2-recovery-provision",
    ),
)


def _fail(message: str) -> Never:
    raise CandidateBuildError(message)


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _command_environment() -> dict[str, str]:
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
        "SOURCE_DATE_EPOCH": "0",
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }


def _stat_identity(metadata: os.stat_result) -> dict[str, int]:
    return {
        "change_time_ns": metadata.st_ctime_ns,
        "device": metadata.st_dev,
        "gid": metadata.st_gid,
        "inode": metadata.st_ino,
        "link_count": metadata.st_nlink,
        "mode": stat.S_IMODE(metadata.st_mode),
        "modification_time_ns": metadata.st_mtime_ns,
        "size": metadata.st_size,
        "uid": metadata.st_uid,
    }


def _regular_file(path: Path, *, require_root: bool = False) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        _fail(f"required regular file is unavailable: {path}: {error}")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or (require_root and (metadata.st_uid != 0 or metadata.st_gid != 0))
    ):
        _fail(f"required regular file is not admitted: {path}")
    return metadata


def _tool(name: str) -> Path:
    located = shutil.which(name)
    if located is None:
        _fail(f"required candidate-build tool is unavailable: {name}")
    path = Path(located).resolve(strict=True)
    _regular_file(path)
    return path


def _compiler() -> Path:
    configured = sysconfig.get_config_var("CC")
    if type(configured) is not str or not configured:
        _fail("Python did not declare a C compiler")
    words = shlex.split(configured)
    if not words:
        _fail("Python declared an empty C compiler")
    return _tool(words[0])


def _run_expect_status(
    command: tuple[str, ...],
    expected_status: int,
    *,
    cwd: Path = _ROOT,
) -> bytes:
    if expected_status < 0 or expected_status > 255:
        _fail("candidate-build expected status is outside the process-status range")
    completed = subprocess.run(
        command,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=_command_environment(),
        check=False,
    )
    if len(completed.stdout) > _MAXIMUM_COMMAND_OUTPUT:
        _fail("candidate-build command output exceeded its bound")
    if completed.returncode != expected_status:
        output = completed.stdout.decode("utf-8", errors="replace")
        _fail(
            "candidate-build command returned "
            f"{completed.returncode}, expected {expected_status}:\n{output}"
        )
    return completed.stdout


def _run(command: tuple[str, ...], *, cwd: Path = _ROOT) -> bytes:
    return _run_expect_status(command, 0, cwd=cwd)


def _quoted_definition(name: str, value: Path | str) -> str:
    payload = str(value)
    if not payload or any(character in payload for character in ('"', "\\", "\n", "\r")):
        _fail(f"the {name} C string is not representable")
    return f'-D{name}="{payload}"'


def _validate_absent_output_directory(output_directory: Path) -> None:
    if not output_directory.is_absolute() or output_directory.exists():
        _fail("output directory must be one absent absolute path")
    parent = output_directory.parent.resolve(strict=True)
    if parent != output_directory.parent:
        _fail("the output-directory parent must be canonical")


def _python_build(toolchain: _Toolchain) -> _PythonBuild:
    if sys.implementation.name != "cpython" or sys.version_info[:2] not in {(3, 12), (3, 13)}:
        _fail("candidate builds require CPython 3.12 or 3.13")
    if sysconfig.get_config_var("PYTHONFRAMEWORK") not in (None, ""):
        _fail("candidate builds require standalone non-framework CPython")
    include_value = sysconfig.get_config_var("INCLUDEPY")
    library_root_value = sysconfig.get_config_var("LIBDIR")
    library_name = sysconfig.get_config_var("LDLIBRARY")
    dynamic_extensions_value = sysconfig.get_config_var("DESTSHARED")
    if not all(
        type(value) is str and value
        for value in (
            include_value,
            library_root_value,
            library_name,
            dynamic_extensions_value,
        )
    ):
        _fail("Python did not declare its standalone embed inputs")
    assert isinstance(include_value, str)
    assert isinstance(library_root_value, str)
    assert isinstance(library_name, str)
    assert isinstance(dynamic_extensions_value, str)
    if Path(library_name).name != library_name or not library_name.startswith("lib"):
        _fail("Python declared an invalid embed library name")
    include = Path(include_value).resolve(strict=True)
    library_root = Path(library_root_value).resolve(strict=True)
    library = (library_root / library_name).resolve(strict=True)
    home = Path(sys.base_prefix).resolve(strict=True)
    base_executable = home / "bin" / f"python{sys.version_info.major}.{sys.version_info.minor}"
    try:
        executable = base_executable.resolve(strict=True)
    except OSError:
        _fail("the qualification Python base executable is unavailable")
    standard_library = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
    dynamic_extensions = Path(dynamic_extensions_value).resolve(strict=True)
    _regular_file(library)
    _regular_file(executable)
    if not os.access(executable, os.X_OK):
        _fail("the qualification Python executable is not executable")
    if any(
        not path.is_relative_to(home)
        for path in (executable, include, library, standard_library, dynamic_extensions)
    ):
        _fail("a consumed Python input is outside the exact base prefix")
    linker_name = library_name[3:]
    for marker in (".so", ".dylib", ".a"):
        if marker in linker_name:
            linker_name = linker_name.split(marker, 1)[0]
            break
    if not linker_name:
        _fail("Python embed library did not produce a linker name")
    link_flags: list[str] = [
        f"-L{library_root}",
        f"-Wl,-rpath,{library_root}",
        f"-l{linker_name}",
    ]
    for variable in ("LIBS", "SYSLIBS", "LINKFORSHARED"):
        configured = sysconfig.get_config_var(variable)
        if type(configured) is str and configured:
            link_flags.extend(shlex.split(configured))
    return _PythonBuild(
        compile_flags=(f"-I{include}",),
        link_flags=tuple(link_flags),
        executable=executable,
        home=home,
        include=include,
        standard_library=standard_library,
        dynamic_extensions=dynamic_extensions,
        library=library,
        soname=_elf_soname(library, toolchain),
    )


def _python_file_record(path: Path, root: Path) -> dict[str, object]:
    metadata = _regular_file(path)
    if not path.is_relative_to(root):
        _fail(f"a Python provenance file escaped its declared root: {path}")
    return {
        "identity": _stat_identity(metadata),
        "path": str(path),
        "relative_path": path.relative_to(root).as_posix(),
        "sha256": _sha256(path),
        "size": metadata.st_size,
    }


def _python_include_manifest(include: Path) -> dict[str, object]:
    include_metadata = include.lstat()
    if not stat.S_ISDIR(include_metadata.st_mode) or include_metadata.st_mode & (
        stat.S_IWGRP | stat.S_IWOTH
    ):
        _fail("the Python include root is not an admitted directory")
    files: list[dict[str, object]] = []
    for path in sorted(include.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                _fail(f"a Python include directory is writable by another identity: {path}")
            continue
        if not stat.S_ISREG(metadata.st_mode):
            _fail(f"the Python include tree contains a link or special file: {path}")
        files.append(_python_file_record(path, include))
    if not files or any(not str(record["relative_path"]).endswith(".h") for record in files):
        _fail("the Python include tree is empty or contains a non-header input")
    payload = json.dumps(
        files,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return {
        "all_regular_headers_recursively_included": True,
        "file_count": len(files),
        "files": files,
        "manifest_sha256": _sha256_bytes(payload),
        "root": str(include),
    }


def _python_base_prefix_manifest(home: Path) -> dict[str, object]:
    home_metadata = home.lstat()
    if not stat.S_ISDIR(home_metadata.st_mode) or home_metadata.st_mode & (
        stat.S_IWGRP | stat.S_IWOTH
    ):
        _fail("the managed Python base prefix is not an admitted directory")
    records: list[dict[str, object]] = []
    regular_file_count = 0
    directory_count = 0
    symlink_count = 0
    total_regular_file_bytes = 0
    for path in sorted(home.rglob("*"), key=lambda entry: entry.relative_to(home).as_posix()):
        metadata = path.lstat()
        relative = path.relative_to(home).as_posix()
        mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
        if stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                _fail(f"the managed Python tree contains an unadmitted regular file: {path}")
            record = {
                "mode": mode,
                "path": relative,
                "sha256": _sha256(path),
                "size": metadata.st_size,
                "type": "file",
            }
            regular_file_count += 1
            total_regular_file_bytes += metadata.st_size
        elif stat.S_ISDIR(metadata.st_mode):
            if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                _fail(f"the managed Python tree contains an unadmitted directory: {path}")
            record = {"mode": mode, "path": relative, "type": "directory"}
            directory_count += 1
        elif stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(path)
            try:
                resolved_target = path.resolve(strict=True)
            except (OSError, RuntimeError):
                _fail(f"the managed Python tree contains an escaping symlink: {path}")
            if (
                metadata.st_nlink != 1
                or not target
                or Path(target).is_absolute()
                or not resolved_target.is_relative_to(home)
            ):
                _fail(f"the managed Python tree contains an escaping symlink: {path}")
            record = {
                "path": relative,
                "target": target,
                "type": "symlink",
            }
            symlink_count += 1
        else:
            _fail(f"the managed Python tree contains a special file: {path}")
        records.append(record)
    payload = json.dumps(
        records,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return {
        "directory_count": directory_count,
        "entry_count": len(records),
        "hardlinks_absent": True,
        "regular_file_count": regular_file_count,
        "root": str(home),
        "root_identity": _stat_identity(home_metadata),
        "special_files_absent": True,
        "symlink_count": symlink_count,
        "symlink_topology_bound": True,
        "total_regular_file_bytes": total_regular_file_bytes,
        "tree_sha256": _sha256_bytes(payload),
    }


def _python_record(python: _PythonBuild) -> dict[str, object]:
    startup_relative_paths = (
        "encodings/__init__.py",
        "encodings/aliases.py",
        "encodings/utf_8.py",
    )
    startup_files = [
        _python_file_record(python.standard_library / relative, python.standard_library)
        for relative in startup_relative_paths
    ]
    startup_payload = json.dumps(
        startup_files,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    executable = _python_file_record(python.executable, python.home)
    library = _python_file_record(python.library, python.home)
    return {
        "base_prefix_tree": _python_base_prefix_manifest(python.home),
        "dynamic_extensions": str(python.dynamic_extensions),
        "executable": executable,
        "home": str(python.home),
        "include_tree": _python_include_manifest(python.include),
        "library": str(python.library),
        "library_identity": library["identity"],
        "library_sha256": library["sha256"],
        "library_size": library["size"],
        "normal_role_startup_standard_library": {
            "all_loaded_files_bound_for_fixed_no_site_inert_entry": True,
            "file_count": len(startup_files),
            "files": startup_files,
            "manifest_sha256": _sha256_bytes(startup_payload),
            "other_standard_library_and_dynload_files_claimed_loaded": False,
            "root": str(python.standard_library),
        },
        "paths_within_base_prefix": True,
        "soname": python.soname,
        "standard_library": str(python.standard_library),
        "version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    }


def _validate_systemd_creds() -> tuple[str, int]:
    metadata = _regular_file(_SYSTEMD_CREDS, require_root=True)
    if not os.access(_SYSTEMD_CREDS, os.X_OK):
        _fail("the exact /usr/bin/systemd-creds is not executable")
    return _sha256(_SYSTEMD_CREDS), metadata.st_size


def _validate_sources() -> list[dict[str, object]]:
    paths = {
        *_SOURCE_PATHS.values(),
        *_SECCOMP_MANIFEST_PATHS.values(),
        *_ROLE_IMPORT_SOURCE_PATHS.values(),
        Path(__file__).resolve(strict=True),
        _SECCOMP_MANIFEST_HELPER,
        _SECCOMP_MANIFEST_HARNESS,
        _VENDORING,
        _LICENSE,
        _MONOCYPHER / "monocypher.h",
        _MONOCYPHER_OPTIONAL / "monocypher-ed25519.h",
        _NATIVE / "trusted_time_graceful_stop_v2_endpoint.h",
        _NATIVE / "trusted_time_graceful_stop_v2_resources.h",
        _NATIVE / "trusted_time_graceful_stop_v2_signer.h",
        _NATIVE / "trusted_time_v2_authority.h",
        _NATIVE / "trusted_time_v2_descriptor_baseline.h",
        _NATIVE / "trusted_time_v2_fork_guard.h",
        _NATIVE / "trusted_time_v2_provisioner.h",
        _NATIVE / "trusted_time_v2_role_launcher.h",
        _NATIVE / "trusted_time_v2_seccomp.h",
        _NATIVE / "trusted_time_v2_secret_mount_admission.h",
    }
    records: list[dict[str, object]] = []
    for path in sorted(paths):
        metadata = _regular_file(path)
        records.append(
            {
                "path": path.relative_to(_ROOT).as_posix(),
                "sha256": _sha256(path),
                "size": metadata.st_size,
            }
        )
    return records


def _expected_candidate_entry_source(role: str) -> bytes:
    if role not in _ROLE_ENTRY_MODULES:
        _fail(f"unknown candidate import-tree role: {role}")
    if role == "recovery":
        forbidden_modules = "".join(
            f'    "{module}",\n' for module in _RECOVERY_FORBIDDEN_LOADED_MODULES
        )
        return (
            '"""Inert entry for the unactivated lifecycle-v2 recovery candidate."""\n\n'
            "from __future__ import annotations\n\n"
            "import sys\n\n"
            "_EXPECTED_PATH = [\n"
            f'    "{_RECOVERY_RUNTIME_ROOT}",\n'
            f'    "{_ROLE_RUNTIME_IMPORT_ROOTS["recovery"]}",\n'
            "]\n"
            "_FORBIDDEN_LOADED_MODULES = (\n"
            f"{forbidden_modules}"
            ")\n\n\n"
            "def run() -> None:\n"
            '    """Refuse use until a later milestone supplies operational composition."""\n\n'
            "    if sys.path != _EXPECTED_PATH:\n"
            '        raise RuntimeError("the recovery candidate import path is not exact")\n'
            "    if any(\n"
            '        name == forbidden or name.startswith(f"{forbidden}.")\n'
            "        for name in sys.modules\n"
            "        for forbidden in _FORBIDDEN_LOADED_MODULES\n"
            "    ):\n"
            '        raise RuntimeError("the recovery candidate loaded a forbidden module")\n'
            '    print("AQT_WAVE7_INERT_RECOVERY_ENTRY_REACHED", flush=True)\n'
            '    raise RuntimeError("the lifecycle-v2 recovery candidate is unactivated")\n'
        ).encode("ascii")
    return (
        f'"""Inert entry for the unactivated lifecycle-v2 {role} candidate."""\n\n\n'
        "def run() -> None:\n"
        '    """Refuse use until a later milestone supplies operational composition."""\n\n'
        f'    print("AQT_WAVE7_INERT_{role.upper()}_ENTRY_REACHED", flush=True)\n'
        f'    raise RuntimeError("the lifecycle-v2 {role} candidate is unactivated")\n'
    ).encode("ascii")


def _validate_candidate_import_sources() -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for role, path in sorted(_ROLE_IMPORT_SOURCE_PATHS.items()):
        metadata = _regular_file(path)
        payload = path.read_bytes()
        if payload != _expected_candidate_entry_source(role):
            _fail(f"the inert {role} candidate entry is not exact")
        directory_entries = tuple(sorted(entry.name for entry in path.parent.iterdir()))
        if directory_entries != (path.name,):
            _fail(f"the {role} candidate source import tree is not single-file")
        if role == "recovery":
            lowered = payload.lower()
            found = [
                fragment
                for fragment in _RECOVERY_IMPORT_FORBIDDEN_FRAGMENTS
                if fragment.encode("ascii") in lowered
            ]
            if found:
                _fail(f"the recovery candidate import tree exposes forbidden capability: {found}")
        records[role] = {
            "entry_module": _ROLE_ENTRY_MODULES[role],
            "path": path.relative_to(_ROOT).as_posix(),
            "sha256": _sha256_bytes(payload),
            "size": metadata.st_size,
        }
    return records


def _emit_candidate_import_trees(
    output_directory: Path,
    source_records: dict[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    tree_parent = output_directory / "candidate-import-trees"
    manifest_parent = output_directory / "candidate-import-manifests"
    tree_parent.mkdir(mode=0o700)
    manifest_parent.mkdir(mode=0o700)
    result: dict[str, dict[str, object]] = {}
    for role, source_record in sorted(source_records.items()):
        tree = tree_parent / role
        tree.mkdir(mode=0o700)
        entry_module = source_record["entry_module"]
        if type(entry_module) is not str:
            _fail(f"the {role} candidate entry-module record is invalid")
        entry = tree / f"{entry_module}.py"
        shutil.copyfile(_ROLE_IMPORT_SOURCE_PATHS[role], entry)
        entry.chmod(0o444)
        file_record = {
            "mode": "0444",
            "path": entry.name,
            "sha256": _sha256(entry),
            "size": entry.stat().st_size,
            "source_path": source_record["path"],
            "source_sha256": source_record["sha256"],
        }
        if (
            file_record["sha256"] != source_record["sha256"]
            or file_record["size"] != source_record["size"]
        ):
            _fail(f"the emitted {role} candidate entry changed")
        files = [file_record]
        tree_sha256 = _sha256_bytes(
            json.dumps(
                files,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        )
        manifest: dict[str, object] = {
            "activation_authorized": False,
            "entry_module": entry_module,
            "file_count": 1,
            "files": files,
            "format": "autoquant-trusted-time-graceful-stop-v2-import-manifest-v1",
            "installed": False,
            "intended_runtime_root": _ROLE_RUNTIME_IMPORT_ROOTS[role],
            "operational_composition_included": False,
            "output_root": tree.relative_to(output_directory).as_posix(),
            "role": role,
            "status": "inert_fail_closed",
            "tree_sha256": tree_sha256,
        }
        if role == "recovery":
            manifest["recovery_forbidden_role_source_fragments_absent"] = list(
                _RECOVERY_IMPORT_FORBIDDEN_FRAGMENTS
            )
        payload = (
            json.dumps(
                manifest,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
        manifest_path = manifest_parent / f"{role}.json"
        manifest_path.write_bytes(payload)
        manifest_path.chmod(0o444)
        tree.chmod(0o555)
        result[role] = {
            **manifest,
            "manifest_output": manifest_path.relative_to(output_directory).as_posix(),
            "manifest_sha256": _sha256(manifest_path),
        }
    tree_parent.chmod(0o555)
    manifest_parent.chmod(0o555)
    return result


def _validate_recovery_runtime_sources(python: _PythonBuild) -> list[dict[str, object]]:
    required_frozen = (
        "_frozen_importlib",
        "_frozen_importlib_external",
        "abc",
        "codecs",
        "io",
        "os",
    )
    if any(not _imp.is_frozen(module) for module in required_frozen):
        _fail("CPython does not freeze the admitted recovery bootstrap modules")
    records: list[dict[str, object]] = []
    for relative in _RECOVERY_RUNTIME_RELATIVE_PATHS:
        path = (python.standard_library / relative).resolve(strict=True)
        if not path.is_relative_to(python.standard_library):
            _fail("a recovery runtime source escaped the fixed CPython standard library")
        metadata = _regular_file(path)
        records.append(
            {
                "mode": "0444",
                "path": relative.as_posix(),
                "sha256": _sha256(path),
                "size": metadata.st_size,
                "source_path": str(path),
            }
        )
    observed = tuple(record["path"] for record in records)
    expected = tuple(path.as_posix() for path in _RECOVERY_RUNTIME_RELATIVE_PATHS)
    if observed != expected or any(
        str(path).startswith(_RECOVERY_RUNTIME_FORBIDDEN_RELATIVE_PREFIXES) for path in observed
    ):
        _fail("the recovery minimal standard-library file set is not exact")
    return records


def _python_module_inventory() -> dict[str, object]:
    frozen_names = getattr(_imp, "_frozen_module_names", None)
    if not callable(frozen_names):
        _fail("CPython does not expose its exact frozen-module inventory")
    builtin = sorted(sys.builtin_module_names)
    frozen = sorted(frozen_names())
    for name, values in (("builtin", builtin), ("frozen", frozen)):
        if not values or any(type(value) is not str or not value for value in values):
            _fail(f"CPython emitted an invalid {name}-module inventory")
    return {
        "builtin_modules": builtin,
        "builtin_modules_sha256": _sha256_bytes(("\n".join(builtin) + "\n").encode("utf-8")),
        "frozen_modules": frozen,
        "frozen_modules_sha256": _sha256_bytes(("\n".join(frozen) + "\n").encode("utf-8")),
    }


def _emit_recovery_runtime(
    output_directory: Path,
    source_records: list[dict[str, object]],
    module_inventory: dict[str, object],
) -> dict[str, object]:
    runtime_parent = output_directory / "candidate-python-runtimes"
    manifest_parent = output_directory / "candidate-python-runtime-manifests"
    runtime = runtime_parent / "recovery"
    runtime.mkdir(parents=True, mode=0o700)
    manifest_parent.mkdir(mode=0o700)
    emitted: list[dict[str, object]] = []
    directories: set[Path] = {runtime, runtime_parent}
    for source_record in source_records:
        relative_value = source_record["path"]
        source_value = source_record["source_path"]
        if type(relative_value) is not str or type(source_value) is not str:
            _fail("a recovery runtime source record is invalid")
        relative = Path(relative_value)
        destination = runtime / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        directories.update((destination.parent, *destination.parents))
        shutil.copyfile(Path(source_value), destination)
        destination.chmod(0o444)
        _regular_file(destination)
        record = {
            "mode": "0444",
            "path": relative.as_posix(),
            "sha256": _sha256(destination),
            "size": destination.stat().st_size,
            "source_path": source_value,
            "source_sha256": source_record["sha256"],
        }
        if record["sha256"] != source_record["sha256"] or record["size"] != source_record["size"]:
            _fail("an emitted recovery runtime file changed")
        emitted.append(record)
    tree_sha256 = _sha256_bytes(
        json.dumps(
            emitted,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    )
    manifest: dict[str, object] = {
        "activation_authorized": False,
        "all_other_relative_paths_omitted": True,
        "dynamic_extensions_included": False,
        "file_count": len(emitted),
        "files": emitted,
        "format": "autoquant-trusted-time-graceful-stop-v2-recovery-runtime-manifest-v1",
        "full_standard_library_included": False,
        "installed": False,
        "intended_runtime_root": _RECOVERY_RUNTIME_ROOT,
        "omitted_source_capabilities": list(_RECOVERY_RUNTIME_FORBIDDEN_RELATIVE_PREFIXES),
        "omitted_suffix_families": [".pyc", ".pyo", ".pth", ".so", ".zip"],
        "output_root": runtime.relative_to(output_directory).as_posix(),
        "required_frozen_bootstrap_modules": [
            "_frozen_importlib",
            "_frozen_importlib_external",
            "abc",
            "codecs",
            "io",
            "os",
        ],
        "module_inventory": module_inventory,
        "runtime_search_path": [
            _RECOVERY_RUNTIME_ROOT,
            _ROLE_RUNTIME_IMPORT_ROOTS["recovery"],
        ],
        "forbidden_loaded_module_prefixes": list(_RECOVERY_FORBIDDEN_LOADED_MODULES),
        "security_boundary": {
            "arbitrary_python_compromise_safe": False,
            "embedded_native_modules_inventoried_not_claimed_absent": True,
            "inert_entry_has_no_input_or_effect_composition": True,
            "milestone_3_required_for_operational_composition": True,
            "network_syscalls_blocked_by_pre_python_recovery_seccomp": True,
            "process_and_exec_effects_blocked_by_pre_python_recovery_seccomp": True,
            "prot_exec_blocked_by_pre_python_recovery_seccomp": True,
            "write_open_blocked_by_pre_python_recovery_seccomp": True,
        },
        "status": "minimal_inert_runtime",
        "tree_sha256": tree_sha256,
    }
    payload = (
        json.dumps(
            manifest,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")
    manifest_path = manifest_parent / "recovery.json"
    manifest_path.write_bytes(payload)
    manifest_path.chmod(0o444)
    for directory in sorted(
        (path for path in directories if path.is_relative_to(runtime_parent)),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        directory.chmod(0o555)
    manifest_parent.chmod(0o555)
    return {
        **manifest,
        "manifest_output": manifest_path.relative_to(output_directory).as_posix(),
        "manifest_sha256": _sha256(manifest_path),
    }


def _validate_vendoring() -> dict[str, object]:
    try:
        manifest = json.loads(_VENDORING.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        _fail(f"the Monocypher vendoring record is invalid: {error}")
    if type(manifest) is not dict:
        _fail("the Monocypher vendoring record must be one object")
    expected_topology = {
        "schema": "autoquant-vendored-native-source-v1",
        "upstream": "https://github.com/LoupVaillant/Monocypher",
        "tag": "4.0.3",
        "commit": "ab2b16dd619ad5f6979a4fbe69cfa324a6fcc35f",
        "license_expression": "BSD-2-Clause OR CC0-1.0",
        "patches": [],
    }
    if set(manifest) != {*expected_topology, "archive", "files"}:
        _fail("the Monocypher vendoring record has an unexpected topology")
    for name, expected in expected_topology.items():
        if manifest.get(name) != expected:
            _fail(f"the Monocypher vendoring record has an unexpected {name}")
    archive = manifest.get("archive")
    expected_archive = {
        "name": "monocypher-4.0.3.tar.gz",
        "sha512": (
            "40904ada5c7ee4f7741733e38b69a30a4b0561cbffba5ffe7c2dce16136d540251ec0d9056"
            "ff606510d3b5b708fb8a40db7e0870d4a0b2dc17ba2bfb880f8965"
        ),
        "url": "https://monocypher.org/download/monocypher-4.0.3.tar.gz",
    }
    if archive != expected_archive:
        _fail("the Monocypher release archive digest is not admitted")
    files = manifest.get("files")
    if type(files) is not list:
        _fail("the Monocypher retained-file manifest is unavailable")
    expected_files = {
        "LICENCE.md": _LICENSE,
        "src/monocypher.c": _MONOCYPHER / "monocypher.c",
        "src/monocypher.h": _MONOCYPHER / "monocypher.h",
        "src/optional/monocypher-ed25519.c": (_MONOCYPHER_OPTIONAL / "monocypher-ed25519.c"),
        "src/optional/monocypher-ed25519.h": (_MONOCYPHER_OPTIONAL / "monocypher-ed25519.h"),
    }
    observed: set[str] = set()
    for record in files:
        if (
            type(record) is not dict
            or set(record) != {"path", "sha256", "size"}
            or type(record.get("path")) is not str
        ):
            _fail("the Monocypher retained-file record is invalid")
        relative = record["path"]
        if relative not in expected_files or relative in observed:
            _fail("the Monocypher retained-file set is not exact")
        path = expected_files[relative]
        metadata = _regular_file(path)
        if record.get("sha256") != _sha256(path) or record.get("size") != metadata.st_size:
            _fail(f"the retained Monocypher file does not match VENDORING.json: {relative}")
        observed.add(relative)
    if observed != set(expected_files):
        _fail("the Monocypher retained-file set is incomplete")
    return {
        "commit": expected_topology["commit"],
        "license_expression": expected_topology["license_expression"],
        "license_sha256": _sha256(_LICENSE),
        "release_archive_sha512": expected_archive["sha512"],
        "tag": expected_topology["tag"],
        "upstream": expected_topology["upstream"],
        "vendoring_sha256": _sha256(_VENDORING),
    }


def _validate_seccomp_manifests(
    *,
    verify_compiled_filters: bool,
    qualification_python: Path | None = None,
) -> dict[str, dict[str, object]]:
    if os.uname().machine != "x86_64":
        _fail("the retained canonical seccomp manifests require Linux x86_64")
    if verify_compiled_filters:
        if qualification_python is None:
            _fail("the seccomp verifier requires the qualification Python executable")
        _run(
            (
                str(qualification_python),
                "-I",
                "-B",
                str(_SECCOMP_MANIFEST_HELPER),
                "--check",
            )
        )
    expected_phases = {
        "host": ("initial",),
        "provisioner": ("initial", "child_exec", "post_child"),
        "recovery": ("initial",),
        "supervisor": ("initial",),
    }
    source_sha256 = _sha256(_SOURCE_PATHS["seccomp"])
    records: dict[str, dict[str, object]] = {}
    for profile, path in sorted(_SECCOMP_MANIFEST_PATHS.items()):
        _regular_file(path)
        payload = path.read_bytes()
        try:
            document = json.loads(payload)
        except (UnicodeError, json.JSONDecodeError) as error:
            _fail(f"canonical seccomp manifest is invalid: {path}: {error}")
        canonical = (
            json.dumps(
                document,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
        if payload != canonical or type(document) is not dict:
            _fail(f"canonical seccomp manifest encoding is invalid: {path}")
        if (
            document.get("activation_authorized") is not False
            or document.get("format")
            != "autoquant-trusted-time-graceful-stop-v2-seccomp-manifest-v1"
            or document.get("profile") != profile
            or document.get("seccomp_source")
            != {
                "path": "native/trusted_time_v2_seccomp.c",
                "sha256": source_sha256,
            }
        ):
            _fail(f"canonical seccomp manifest binding is invalid: {profile}")
        architecture = document.get("architecture")
        if (
            type(architecture) is not dict
            or architecture.get("audit_arch") != "AUDIT_ARCH_X86_64"
            or architecture.get("elf_machine") != "EM_X86_64"
            or architecture.get("endianness") != "little"
            or architecture.get("linux_machine") != "x86_64"
        ):
            _fail(f"canonical seccomp manifest architecture is invalid: {profile}")
        phases = document.get("phases")
        if type(phases) is not list:
            _fail(f"canonical seccomp manifest phase set is invalid: {profile}")
        phase_records: list[dict[str, object]] = []
        observed_phases: list[str] = []
        for phase in phases:
            if type(phase) is not dict:
                _fail(f"canonical seccomp phase is invalid: {profile}")
            phase_name = phase.get("phase")
            bpf_sha256 = phase.get("bpf_sha256")
            bpf_size = phase.get("bpf_size")
            instruction_count = phase.get("bpf_instruction_count")
            if (
                type(phase_name) is not str
                or type(bpf_sha256) is not str
                or re.fullmatch(r"[0-9a-f]{64}", bpf_sha256) is None
                or type(bpf_size) is not int
                or type(instruction_count) is not int
                or instruction_count <= 0
                or bpf_size != instruction_count * 8
            ):
                _fail(f"canonical seccomp phase evidence is invalid: {profile}")
            observed_phases.append(phase_name)
            phase_records.append(
                {
                    "bpf_instruction_count": instruction_count,
                    "bpf_sha256": bpf_sha256,
                    "bpf_size": bpf_size,
                    "phase": phase_name,
                }
            )
        if tuple(observed_phases) != expected_phases[profile]:
            _fail(f"canonical seccomp phase order is invalid: {profile}")
        records[profile] = {
            "architecture": {
                "audit_arch": architecture["audit_arch"],
                "elf_machine": architecture["elf_machine"],
                "endianness": architecture["endianness"],
                "linux_machine": architecture["linux_machine"],
            },
            "bpf_phases": phase_records,
            "manifest_path": path.relative_to(_ROOT).as_posix(),
            "manifest_sha256": _sha256_bytes(payload),
            "output_name": _SECCOMP_MANIFEST_OUTPUT_NAMES[profile],
            "source_path": "native/trusted_time_v2_seccomp.c",
            "source_sha256": source_sha256,
            "status": "bound",
        }
    return records


def _audit_first_party_crypto_calls() -> tuple[str, ...]:
    calls: set[str] = set()
    expression = re.compile(r"\b(crypto_[A-Za-z0-9_]+)\s*\(")
    for alias, path in _SOURCE_PATHS.items():
        if alias in {"monocypher", "monocypher_ed25519"}:
            continue
        calls.update(expression.findall(path.read_text(encoding="utf-8")))
    forbidden = calls - _ALLOWED_FIRST_PARTY_CRYPTO_CALLS
    if forbidden:
        _fail(f"first-party native code calls unadmitted crypto APIs: {sorted(forbidden)}")
    return tuple(sorted(calls))


def _common_compile_flags(toolchain: _Toolchain) -> tuple[str, ...]:
    return (
        str(toolchain.compiler),
        "-std=c11",
        "-O2",
        "-pipe",
        "-fno-lto",
        "-fno-ident",
        "-ffunction-sections",
        "-fdata-sections",
        f"-ffile-prefix-map={_ROOT}=.",
        f"-fmacro-prefix-map={_ROOT}=.",
        "-fPIE",
        "-fvisibility=hidden",
        "-fstack-protector-strong",
        "-D_FORTIFY_SOURCE=3",
        "-Wall",
        "-Wextra",
        "-Wconversion",
        "-Wdate-time",
        "-Wformat=2",
        "-Wshadow",
        "-Wpedantic",
        "-Werror",
        f"-I{_NATIVE}",
        f"-I{_MONOCYPHER}",
        f"-I{_MONOCYPHER_OPTIONAL}",
        "-pthread",
    )


def _link_flags(toolchain: _Toolchain) -> tuple[str, ...]:
    return (
        str(toolchain.compiler),
        "-fno-lto",
        "-fno-use-linker-plugin",
        "-pie",
        "-pthread",
        "-Wl,--build-id=none",
        "-Wl,--no-gc-sections",
        "-Wl,--no-undefined",
        "-Wl,--fatal-warnings",
        "-Wl,-z,noexecstack",
        "-Wl,-z,now",
        "-Wl,-z,relro",
    )


def _python_definitions(
    role: _Role,
    python: _PythonBuild,
    *,
    recovery_standard_library: Path | str | None = None,
) -> tuple[str, ...]:
    standard_library: Path | str = (
        recovery_standard_library or _RECOVERY_RUNTIME_ROOT
        if role.name == "recovery"
        else python.standard_library
    )
    definitions = [
        _quoted_definition("AQT_TRUSTED_TIME_V2_PYTHON_HOME", python.home),
        _quoted_definition("AQT_TRUSTED_TIME_V2_PYTHON_STDLIB", standard_library),
    ]
    if role.name != "recovery":
        definitions.append(
            _quoted_definition("AQT_TRUSTED_TIME_V2_PYTHON_DYNLOAD", python.dynamic_extensions)
        )
    return tuple(definitions)


def _plans(python: _PythonBuild, systemd_creds_sha256: str) -> tuple[_BuildPlan, ...]:
    result: list[_BuildPlan] = []
    for role in _ROLES:
        result.append(
            _BuildPlan(
                basename=role.executable,
                kind="role",
                role=role.name,
                definitions=(
                    f"-D{role.role_macro}=1",
                    f"-D{role.signer_macro}=1",
                    *_python_definitions(role, python),
                ),
                source_aliases=(
                    _RECOVERY_SOURCE_ALIASES if role.name == "recovery" else _ROLE_SOURCE_ALIASES
                ),
                python_link=True,
            )
        )
        result.append(
            _BuildPlan(
                basename=role.provisioner,
                kind="provisioner",
                role=role.name,
                definitions=(
                    f"-D{role.provisioner_macro}=1",
                    _quoted_definition(
                        "AQT_TRUSTED_TIME_V2_SYSTEMD_CREDS_SHA256",
                        systemd_creds_sha256,
                    ),
                ),
                source_aliases=_PROVISIONER_SOURCE_ALIASES,
                python_link=False,
            )
        )
    return tuple(result)


def _normalized_command(command: tuple[str, ...], build_root: Path) -> tuple[str, ...]:
    return tuple(
        argument.replace(str(build_root), "<BUILD_ROOT>").replace(str(_ROOT), "<SOURCE_ROOT>")
        for argument in command
    )


def _symbol_names(payload: bytes) -> frozenset[str]:
    names: set[str] = set()
    for line in payload.decode("utf-8", errors="strict").splitlines():
        words = line.split()
        if words:
            names.add(words[-1].partition("@")[0])
    return frozenset(names)


def _dynamic_dependencies(payload: bytes) -> tuple[str, ...]:
    expression = re.compile(r"Shared library: \[([^]]+)]")
    return tuple(sorted(set(expression.findall(payload.decode("utf-8", errors="strict")))))


def _elf_soname(path: Path, toolchain: _Toolchain) -> str:
    dynamic = _run((str(toolchain.readelf), "-W", "-d", str(path)))
    matches: list[str] = re.findall(
        r"Library soname: \[([^]]+)]",
        dynamic.decode("utf-8", errors="strict"),
    )
    if len(matches) != 1 or Path(matches[0]).name != matches[0]:
        _fail(f"the Python embed library does not declare one exact ELF SONAME: {path}")
    return matches[0]


def _opposite_role_symbols(role: str, symbols: frozenset[str]) -> tuple[str, ...]:
    forbidden: set[str] = set()
    for other_role in set(_ROLE_SYMBOL_PREFIXES) - {role}:
        prefixes = _ROLE_SYMBOL_PREFIXES[other_role]
        forbidden.update(symbol for symbol in symbols if symbol.startswith(prefixes))
        forbidden.update(symbols & _ROLE_SIGNER_SYMBOLS[other_role])
    return tuple(sorted(forbidden))


def _audit_monocypher_conditional_operations(
    object_path: Path,
    build_root: Path,
    toolchain: _Toolchain,
) -> dict[str, object]:
    expected_instruction_counts = {
        "fe_ccopy": {"and": 10, "neg": 1, "ret": 1, "xor": 20},
        "fe_cswap": {"and": 10, "neg": 1, "ret": 1, "xor": 30},
    }
    result: dict[str, object] = {}
    for symbol, expected_counts in expected_instruction_counts.items():
        command = (
            str(toolchain.objdump),
            "-drwC",
            f"--disassemble={symbol}",
            str(object_path),
        )
        payload = _run(command)
        canonical = payload.replace(str(build_root).encode("utf-8"), b"<BUILD_ROOT>").replace(
            str(_ROOT).encode("utf-8"), b"<SOURCE_ROOT>"
        )
        text = canonical.decode("utf-8", errors="strict")
        if text.count(f"<{symbol}>:") != 1:
            _fail(f"the exact Monocypher object does not retain one {symbol} function")
        mnemonics = re.findall(
            r"^\s*[0-9a-f]+:\s+(?:(?:[0-9a-f]{2})\s+)+([a-z][a-z0-9.]*)\b",
            text,
            flags=re.MULTILINE,
        )
        counts = {name: mnemonics.count(name) for name in expected_counts}
        forbidden_control_flow = sorted(
            {
                mnemonic
                for mnemonic in mnemonics
                if mnemonic.startswith(("call", "cmov", "j", "loop"))
            }
        )
        if counts != expected_counts or forbidden_control_flow:
            _fail(
                f"the exact compiler defeated the Monocypher {symbol} mitigation: "
                f"counts={counts}, control_flow={forbidden_control_flow}"
            )
        result[symbol] = {
            "branchless_assertion_passed": True,
            "command": list(_normalized_command(command, build_root)),
            "disassembly": text,
            "disassembly_sha256": _sha256_bytes(canonical),
            "instruction_count": len(mnemonics),
            "required_instruction_counts": expected_counts,
        }
    return {
        "exact_candidate_object": True,
        "mitigation_source_sha256": _sha256(_SOURCE_PATHS["monocypher"]),
        "object_sha256": _sha256(object_path),
        "operations": result,
        "same_compile_flags_as_candidate": True,
    }


def _audit_binary(
    plan: _BuildPlan,
    binary: Path,
    canonical_map: bytes,
    toolchain: _Toolchain,
    python: _PythonBuild,
) -> dict[str, object]:
    if binary.read_bytes()[:4] != b"\x7fELF":
        _fail(f"candidate is not an ELF executable: {plan.basename}")
    header = _run((str(toolchain.readelf), "-W", "-h", str(binary)))
    header_text = header.decode("utf-8", errors="strict")
    if (
        "Type:                              DYN (Position-Independent Executable file)"
        not in header_text
    ):
        _fail(f"candidate is not a position-independent executable: {plan.basename}")
    machine_matches = re.findall(r"^\s*Machine:\s*(.+?)\s*$", header_text, flags=re.MULTILINE)
    if machine_matches != ["Advanced Micro Devices X86-64"]:
        _fail(f"candidate ELF machine is not exact x86_64: {plan.basename}: {machine_matches}")
    dynamic = _run((str(toolchain.readelf), "-W", "-d", str(binary)))
    dynamic_text = dynamic.decode("utf-8", errors="strict")
    if "(BIND_NOW)" not in dynamic_text and "Flags: NOW" not in dynamic_text:
        _fail(f"candidate does not bind dynamic symbols eagerly: {plan.basename}")
    program_headers = _run((str(toolchain.readelf), "-W", "-l", str(binary))).decode(
        "utf-8", errors="strict"
    )
    stack_records = [line.split() for line in program_headers.splitlines() if "GNU_STACK" in line]
    if (
        "GNU_RELRO" not in program_headers
        or len(stack_records) != 1
        or len(stack_records[0]) < 2
        or "E" in stack_records[0][-2]
    ):
        _fail(f"candidate does not enforce RELRO and a non-executable stack: {plan.basename}")
    notes = _run((str(toolchain.readelf), "-W", "-n", str(binary))).decode("utf-8", errors="strict")
    if "Build ID:" in notes:
        _fail(f"candidate contains a nondeterministic build ID: {plan.basename}")
    dependencies = _dynamic_dependencies(dynamic)
    forbidden_dependencies = sorted(
        dependency
        for dependency in dependencies
        if any(
            fragment in dependency.lower() for fragment in _FORBIDDEN_DYNAMIC_DEPENDENCY_FRAGMENTS
        )
    )
    if forbidden_dependencies:
        _fail(f"candidate links a forbidden cryptographic dependency: {forbidden_dependencies}")
    expected_dependencies = {"libc.so.6"}
    if plan.kind == "role":
        expected_dependencies.add(python.soname)
    if set(dependencies) != expected_dependencies:
        _fail(
            f"candidate direct dependency set is not exact: {plan.basename}: "
            f"expected={sorted(expected_dependencies)}, observed={list(dependencies)}"
        )
    section_text = _run((str(toolchain.readelf), "-W", "-S", str(binary))).decode(
        "utf-8", errors="strict"
    )
    if ".gnu.lto_" in section_text:
        _fail(f"candidate contains link-time-optimization sections: {plan.basename}")
    exported = _symbol_names(_run((str(toolchain.nm), "-D", "--defined-only", str(binary))))
    forbidden_exports = sorted(
        symbol
        for symbol in exported
        if symbol.startswith("crypto_")
        or any(fragment in symbol for fragment in _FORBIDDEN_EXPORTED_SYMBOL_FRAGMENTS)
    )
    if forbidden_exports:
        _fail(f"candidate exports forbidden native symbols: {forbidden_exports}")
    defined = _symbol_names(_run((str(toolchain.nm), "--defined-only", str(binary))))
    forbidden_defined = sorted(
        symbol
        for symbol in defined
        if any(fragment in symbol for fragment in _FORBIDDEN_DEFINED_SYMBOL_FRAGMENTS)
    )
    if forbidden_defined:
        _fail(f"candidate contains forbidden test/secret symbols: {forbidden_defined}")
    opposite_role_symbols = (
        _opposite_role_symbols(plan.role, defined) if plan.kind == "role" else ()
    )
    if opposite_role_symbols:
        _fail(
            f"candidate contains opposite-role symbols: {plan.basename}: "
            f"{list(opposite_role_symbols)}"
        )
    undefined = _symbol_names(_run((str(toolchain.nm), "-u", str(binary))))
    binary_strings_payload = _run((str(toolchain.strings), "-a", str(binary)))
    binary_strings = binary_strings_payload.decode("utf-8", errors="strict")
    if plan.role == "recovery":
        forbidden_strings = (
            _FORBIDDEN_RECOVERY_ROLE_STRINGS
            if plan.kind == "role"
            else _FORBIDDEN_RECOVERY_PROVISIONER_STRINGS
        )
        found_strings = sorted(value for value in forbidden_strings if value in binary_strings)
        if found_strings:
            _fail(f"recovery {plan.kind} contains forbidden normal authority: {found_strings}")
        if plan.kind == "role":
            found_symbols = sorted(undefined & _FORBIDDEN_RECOVERY_UNDEFINED)
            if found_symbols:
                _fail(f"recovery role has forbidden undefined capabilities: {found_symbols}")
    if plan.kind == "provisioner":
        found_network = sorted(undefined & _NETWORK_UNDEFINED)
        if found_network:
            _fail(f"provisioner has forbidden network capabilities: {found_network}")
        role_socket_surface = "network_absent"
    elif plan.role == "host":
        forbidden_host = undefined & {"accept", "accept4", "bind", "listen"}
        if "connect" not in undefined or forbidden_host:
            _fail(f"host role socket surface is not connector-only: {sorted(forbidden_host)}")
        role_socket_surface = "connector_only"
    elif plan.role == "supervisor":
        required_supervisor = {"accept4", "bind", "listen"}
        if "connect" in undefined or not required_supervisor <= undefined:
            _fail("supervisor role socket surface is not listener-only")
        role_socket_surface = "listener_only"
    else:
        role_socket_surface = "network_absent"
    map_text = canonical_map.decode("utf-8", errors="strict")
    for alias in plan.source_aliases:
        if f"/{alias}.o" not in map_text:
            _fail(f"candidate link map omits its {alias} object: {plan.basename}")
    absent_aliases = set(_SOURCE_PATHS) - set(plan.source_aliases)
    unexpected_aliases = sorted(alias for alias in absent_aliases if f"/{alias}.o" in map_text)
    if unexpected_aliases:
        _fail(
            f"candidate link map contains cross-profile objects: {plan.basename}: "
            f"{unexpected_aliases}"
        )
    return {
        "binary_strings_sha256": _sha256_bytes(binary_strings_payload),
        "build_id_absent": True,
        "dynamic_dependencies": list(dependencies),
        "dynamic_dependency_allowlist": sorted(expected_dependencies),
        "dynamic_dependency_allowlist_enforced": True,
        "dynamic_dependency_exact": True,
        "dynamic_export_count": len(exported),
        "dynamic_exports_sha256": _sha256_bytes(
            ("\n".join(sorted(exported)) + "\n").encode("utf-8")
        ),
        "elf_pie": True,
        "elf_machine": "EM_X86_64",
        "defined_symbol_count": len(defined),
        "defined_symbols_sha256": _sha256_bytes(
            ("\n".join(sorted(defined)) + "\n").encode("utf-8")
        ),
        "forbidden_dynamic_dependencies_absent": True,
        "forbidden_exports_absent": True,
        "full_relro": True,
        "lto_absent": True,
        "nonexecutable_stack": True,
        "opposite_role_symbols_absent": True,
        "recovery_exclusions_passed": True,
        "role_socket_surface": role_socket_surface,
        "test_symbols_absent": True,
        "undefined_symbol_count": len(undefined),
        "undefined_symbols_sha256": _sha256_bytes(
            ("\n".join(sorted(undefined)) + "\n").encode("utf-8")
        ),
    }


def _audit_recovery_preprocessed_sources(
    plan: _BuildPlan,
    toolchain: _Toolchain,
    python: _PythonBuild,
) -> list[dict[str, object]]:
    if plan.role != "recovery":
        return []
    forbidden_strings = (
        _FORBIDDEN_RECOVERY_ROLE_STRINGS
        if plan.kind == "role"
        else _FORBIDDEN_RECOVERY_PROVISIONER_STRINGS
    )
    records: list[dict[str, object]] = []
    for alias in plan.source_aliases:
        source = _SOURCE_PATHS[alias]
        payload = _run(
            (
                *_common_compile_flags(toolchain),
                *(python.compile_flags if plan.python_link else ()),
                *plan.definitions,
                "-E",
                "-P",
                str(source.relative_to(_ROOT)),
            )
        )
        text = payload.decode("utf-8", errors="strict")
        found = sorted(value for value in forbidden_strings if value in text)
        if found:
            _fail(
                f"recovery {plan.kind} preprocessed {alias} source contains "
                f"forbidden normal authority: {found}"
            )
        records.append(
            {
                "alias": alias,
                "sha256": _sha256_bytes(payload),
                "size": len(payload),
            }
        )
    return records


def _build_artifact(
    plan: _BuildPlan,
    build_root: Path,
    toolchain: _Toolchain,
    python: _PythonBuild,
) -> _BuiltArtifact:
    artifact_root = build_root / plan.basename
    object_root = artifact_root / "objects"
    object_root.mkdir(parents=True, mode=0o700)
    normalized_commands: list[tuple[str, ...]] = []
    object_digests: list[tuple[str, str]] = []
    monocypher_conditional_operations: dict[str, object] | None = None
    for alias in plan.source_aliases:
        source = _SOURCE_PATHS[alias]
        output = object_root / f"{alias}.o"
        command = (
            *_common_compile_flags(toolchain),
            *(python.compile_flags if plan.python_link else ()),
            *plan.definitions,
            "-c",
            str(source.relative_to(_ROOT)),
            "-o",
            str(output),
        )
        _run(command)
        normalized_commands.append(_normalized_command(command, build_root))
        object_digests.append((alias, _sha256(output)))
        if alias == "monocypher":
            monocypher_conditional_operations = _audit_monocypher_conditional_operations(
                output,
                build_root,
                toolchain,
            )
    if monocypher_conditional_operations is None:
        _fail(f"candidate omits Monocypher conditional-operation evidence: {plan.basename}")
    binary = artifact_root / plan.basename
    raw_map = artifact_root / f"{plan.basename}.raw.map"
    object_paths = tuple(str(object_root / f"{alias}.o") for alias in plan.source_aliases)
    command = (
        *_link_flags(toolchain),
        *object_paths,
        f"-Wl,-Map,{raw_map}",
        "-o",
        str(binary),
        *(python.link_flags if plan.python_link else ()),
    )
    _run(command)
    normalized_commands.append(_normalized_command(command, build_root))
    if (
        binary.stat().st_size <= 0
        or binary.stat().st_size > _MAXIMUM_CANDIDATE_BYTES
        or raw_map.stat().st_size <= 0
        or raw_map.stat().st_size > _MAXIMUM_LINK_MAP_BYTES
    ):
        _fail(f"candidate or link map exceeded its evidence bound: {plan.basename}")
    binary.chmod(0o555)
    canonical_map = (
        raw_map.read_bytes()
        .replace(str(build_root).encode("utf-8"), b"<BUILD_ROOT>")
        .replace(str(_ROOT).encode("utf-8"), b"<SOURCE_ROOT>")
    )
    audit = _audit_binary(plan, binary, canonical_map, toolchain, python)
    audit["monocypher_conditional_operations"] = monocypher_conditional_operations
    audit["recovery_preprocessed_sources"] = _audit_recovery_preprocessed_sources(
        plan,
        toolchain,
        python,
    )
    command_bytes = json.dumps(
        normalized_commands,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return _BuiltArtifact(
        binary=binary,
        canonical_link_map=canonical_map,
        commands=tuple(normalized_commands),
        command_digest=_sha256_bytes(command_bytes),
        object_digests=tuple(object_digests),
        audit=audit,
    )


def _probe_no_release_pin(
    probe_root: Path,
    toolchain: _Toolchain,
) -> dict[str, str]:
    probe_root.mkdir(mode=0o700)
    source = probe_root / "authority-no-release-pin-probe.c"
    source.write_text(_NO_PIN_PROBE_SOURCE, encoding="ascii")
    results: dict[str, str] = {}
    for role in _ROLES:
        output = probe_root / f"{role.name}-authority-no-release-pin-probe"
        command = (
            *_common_compile_flags(toolchain),
            f"-D{role.provisioner_macro}=1",
            str(source),
            str(_SOURCE_PATHS["authority"]),
            str(_SOURCE_PATHS["fork_guard"]),
            str(_SOURCE_PATHS["monocypher"]),
            str(_SOURCE_PATHS["monocypher_ed25519"]),
            "-o",
            str(output),
        )
        if any("TEST_ROOT_PIN" in argument for argument in command):
            _fail("the production no-release-pin probe selected a test root")
        _run(command)
        _run((str(output),))
        results[role.name] = "ENOKEY"
    return results


def _compiler_subtool(compiler: Path, name: str) -> Path:
    payload = _run((str(compiler), f"-print-prog-name={name}"))
    try:
        declared = payload.decode("utf-8", errors="strict").strip()
    except UnicodeError as error:
        _fail(f"the compiler emitted an invalid {name} path: {error}")
    if not declared or "\n" in declared or "\r" in declared:
        _fail(f"the compiler did not declare exactly one {name} path")
    candidate = Path(declared)
    if candidate.is_absolute():
        path = candidate.resolve(strict=True)
    elif len(candidate.parts) > 1:
        path = (_ROOT / candidate).resolve(strict=True)
    else:
        located = shutil.which(declared, path=_command_environment()["PATH"])
        if located is None:
            _fail(f"the compiler-declared {name} is unavailable: {declared}")
        path = Path(located).resolve(strict=True)
    _regular_file(path)
    return path


def _toolchain() -> _Toolchain:
    compiler = _compiler()
    return _Toolchain(
        compiler=compiler,
        compiler_cc1=_compiler_subtool(compiler, "cc1"),
        compiler_collect2=_compiler_subtool(compiler, "collect2"),
        assembler=_compiler_subtool(compiler, "as"),
        linker=_compiler_subtool(compiler, "ld"),
        nm=_tool("nm"),
        objdump=_tool("objdump"),
        readelf=_tool("readelf"),
        strings=_tool("strings"),
    )


def _native_tool_record(
    path: Path,
    *,
    version_arguments: tuple[str, ...] = ("--version",),
) -> dict[str, object]:
    metadata = _regular_file(path)
    version_payload = _run((str(path), *version_arguments))
    version = version_payload.decode("utf-8", errors="strict")
    lines = version.splitlines()
    if not lines:
        _fail(f"native tool did not report its identity: {path}")
    return {
        "identity": _stat_identity(metadata),
        "path": str(path),
        "sha256": _sha256(path),
        "version": lines[0],
        "version_command": [str(path), *version_arguments],
        "version_output_sha256": _sha256_bytes(version_payload),
    }


def _driver_evidence(
    command: tuple[str, ...],
    *,
    forbid_linker_plugin: bool = False,
) -> dict[str, object]:
    payload = _run(command)
    lowered = payload.lower()
    if forbid_linker_plugin and b"liblto_plugin" in lowered:
        _fail("the compiler driver selected a linker plugin despite the no-LTO contract")
    temporary_root = re.escape(_command_environment()["TMPDIR"].rstrip("/"))
    driver_temporary = (
        rb"(?:"
        + temporary_root.encode("utf-8")
        + rb"|/tmp)/cc[A-Za-z0-9]+(?=(?:\.[A-Za-z0-9]+)?(?:\s|$))"
    )
    payload = re.sub(
        driver_temporary,
        b"<DRIVER_TEMP>",
        payload,
    )
    return {
        "command": list(command),
        "output": payload.decode("utf-8", errors="strict"),
        "output_sha256": _sha256_bytes(payload),
    }


def _compiler_record(toolchain: _Toolchain) -> dict[str, object]:
    driver = _native_tool_record(toolchain.compiler)
    target_payload = _run((str(toolchain.compiler), "-dumpmachine"))
    target_triple = target_payload.decode("ascii", errors="strict").strip()
    if not target_triple or any(character.isspace() for character in target_triple):
        _fail("the native compiler did not report one target triple")
    target_components = target_triple.split("-")
    if target_components[0] != "x86_64" or "linux" not in target_components:
        _fail(f"the native compiler target is not Linux x86_64: {target_triple}")
    sysroot_payload = _run((str(toolchain.compiler), "-print-sysroot"))
    sysroot_text = sysroot_payload.decode("utf-8", errors="strict").strip()
    if sysroot_text:
        sysroot = Path(sysroot_text)
        if not sysroot.is_absolute():
            _fail("the native compiler declared a relative sysroot")
        resolved_sysroot = sysroot.resolve(strict=True)
        sysroot_record: dict[str, object] = {
            "implicit_default": False,
            "identity": _stat_identity(resolved_sysroot.stat()),
            "path": str(resolved_sysroot),
        }
    else:
        sysroot_record = {"implicit_default": True, "identity": None, "path": None}
    search_payload = _run((str(toolchain.compiler), "-print-search-dirs"))
    include_search_payload = _run(
        (
            str(toolchain.compiler),
            "-E",
            "-x",
            "c",
            "-v",
            "/dev/null",
            "-o",
            "/dev/null",
        )
    )
    compile_topology_command = (
        *_common_compile_flags(toolchain),
        "-###",
        "-x",
        "c",
        "-c",
        "/dev/null",
        "-o",
        "/dev/null",
    )
    link_topology_command = (
        *_link_flags(toolchain),
        "-###",
        "-x",
        "c",
        "/dev/null",
        "-o",
        "/dev/null",
    )
    compile_topology = _driver_evidence(compile_topology_command)
    link_topology = _driver_evidence(
        link_topology_command,
        forbid_linker_plugin=True,
    )
    compile_output = compile_topology["output"]
    link_output = link_topology["output"]
    if type(compile_output) is not str or type(link_output) is not str:
        _fail("the compiler driver topology evidence is invalid")
    if str(toolchain.compiler_cc1) not in compile_output:
        _fail("the compile topology does not select the bound cc1 executable")
    if str(toolchain.compiler_cc1) not in link_output:
        _fail("the link topology does not select the bound cc1 executable")
    if str(toolchain.compiler_collect2) not in link_output:
        _fail("the link topology does not select the bound collect2 executable")
    return {
        **driver,
        "assembler": _native_tool_record(toolchain.assembler),
        "delegated_executables": {
            "cc1": _native_tool_record(
                toolchain.compiler_cc1,
                version_arguments=("-version", "-quiet", "-o", "/dev/null", "/dev/null"),
            ),
            "collect2": _native_tool_record(toolchain.compiler_collect2),
        },
        "driver_topology": {
            "compile": compile_topology,
            "link": link_topology,
            "selected_executables_bound": True,
        },
        "include_search": {
            "output": include_search_payload.decode("utf-8", errors="strict"),
            "output_sha256": _sha256_bytes(include_search_payload),
        },
        "linker": _native_tool_record(toolchain.linker),
        "lto": {
            "compiler_flag": "-fno-lto",
            "linker_plugin_disabled": True,
            "linker_plugin_used": False,
        },
        "search_directories": {
            "output": search_payload.decode("utf-8", errors="strict"),
            "output_sha256": _sha256_bytes(search_payload),
        },
        "sysroot": sysroot_record,
        "target_triple": target_triple,
    }


def _audit_tool_records(toolchain: _Toolchain) -> dict[str, dict[str, object]]:
    return {
        name: _native_tool_record(path)
        for name, path in (
            ("nm", toolchain.nm),
            ("objdump", toolchain.objdump),
            ("readelf", toolchain.readelf),
            ("strings", toolchain.strings),
        )
    }


def _artifact_record(
    plan: _BuildPlan,
    first: _BuiltArtifact,
    second: _BuiltArtifact,
    destination: Path,
    vendor: dict[str, object],
    import_trees: dict[str, dict[str, object]],
    recovery_runtime: dict[str, object],
    seccomp_manifests: dict[str, dict[str, object]],
) -> dict[str, object]:
    first_digest = _sha256(first.binary)
    second_digest = _sha256(second.binary)
    if (
        first_digest != second_digest
        or first.binary.read_bytes() != second.binary.read_bytes()
        or first.canonical_link_map != second.canonical_link_map
        or first.commands != second.commands
        or first.command_digest != second.command_digest
        or first.object_digests != second.object_digests
        or first.audit != second.audit
    ):
        _fail(f"candidate is not reproducible across two clean builds: {plan.basename}")
    final_binary = destination / plan.basename
    final_map = destination / f"{plan.basename}.link-map.txt"
    shutil.copyfile(first.binary, final_binary)
    final_binary.chmod(0o555)
    final_map.write_bytes(first.canonical_link_map)
    final_map.chmod(0o444)
    seccomp_profile = plan.role if plan.kind == "role" else "provisioner"
    seccomp_manifest = seccomp_manifests[seccomp_profile]
    import_tree = None
    if plan.kind == "role":
        role_import_tree = import_trees[plan.role]
        import_tree = {
            "entry_module": role_import_tree["entry_module"],
            "intended_runtime_root": role_import_tree["intended_runtime_root"],
            "manifest_output": role_import_tree["manifest_output"],
            "manifest_sha256": role_import_tree["manifest_sha256"],
            "tree_sha256": role_import_tree["tree_sha256"],
        }
    python_runtime = None
    if plan.kind == "role" and plan.role == "recovery":
        recovery_runtime_root = recovery_runtime["intended_runtime_root"]
        if type(recovery_runtime_root) is not str:
            _fail("the recovery runtime intended root is invalid")
        python_runtime = {
            "compile_definition": _quoted_definition(
                "AQT_TRUSTED_TIME_V2_PYTHON_STDLIB",
                recovery_runtime_root,
            ),
            "intended_runtime_root": recovery_runtime["intended_runtime_root"],
            "manifest_output": recovery_runtime["manifest_output"],
            "manifest_sha256": recovery_runtime["manifest_sha256"],
            "tree_sha256": recovery_runtime["tree_sha256"],
        }
    return {
        "audit": first.audit,
        "basename": plan.basename,
        "build_commands": [list(command) for command in first.commands],
        "build_command_sha256": first.command_digest,
        "kind": plan.kind,
        "import_tree": import_tree,
        "link_map": final_map.name,
        "link_map_sha256": _sha256(final_map),
        "monocypher": {
            "commit": vendor["commit"],
            "license": _LICENSE_OUTPUT_NAME,
            "license_expression": vendor["license_expression"],
            "license_sha256": vendor["license_sha256"],
            "release_archive_sha512": vendor["release_archive_sha512"],
            "tag": vendor["tag"],
            "upstream": vendor["upstream"],
            "vendoring_sha256": vendor["vendoring_sha256"],
        },
        "object_sha256": dict(first.object_digests),
        "python_runtime": python_runtime,
        "reproducible_build_count": 2,
        "role": plan.role,
        "seccomp_profile": seccomp_profile,
        "seccomp_binding": {
            "bpf_phases": seccomp_manifest["bpf_phases"],
            "manifest_sha256": seccomp_manifest["manifest_sha256"],
            "profile": seccomp_profile,
            "source_sha256": seccomp_manifest["source_sha256"],
        },
        "sha256": first_digest,
        "size": final_binary.stat().st_size,
        "source_aliases": list(plan.source_aliases),
    }


def _running_on_linux() -> bool:
    return sys.platform == "linux"


def build(output_directory: Path) -> dict[str, object]:
    if not _running_on_linux():
        _fail("real lifecycle-v2 candidate packaging is Linux-only")
    if os.uname().machine != "x86_64":
        _fail("real lifecycle-v2 candidate packaging requires Linux x86_64")
    _validate_absent_output_directory(output_directory)
    output_directory.mkdir(mode=0o700)
    first_root = output_directory / ".build-one"
    second_root = output_directory / ".build-two"
    probe_root = output_directory / ".no-pin-probes"
    first_root.mkdir(mode=0o700)
    second_root.mkdir(mode=0o700)

    toolchain = _toolchain()
    python = _python_build(toolchain)
    python_record = _python_record(python)
    compiler_record = _compiler_record(toolchain)
    audit_tools = _audit_tool_records(toolchain)
    source_manifest = _validate_sources()
    vendor = _validate_vendoring()
    seccomp_manifests = _validate_seccomp_manifests(
        verify_compiled_filters=True,
        qualification_python=python.executable,
    )
    import_tree_sources = _validate_candidate_import_sources()
    recovery_runtime_sources = _validate_recovery_runtime_sources(python)
    recovery_module_inventory = _python_module_inventory()
    crypto_calls = _audit_first_party_crypto_calls()
    systemd_creds_sha256, systemd_creds_size = _validate_systemd_creds()
    plans = _plans(python, systemd_creds_sha256)
    if len(plans) != 6 or len({plan.basename for plan in plans}) != 6:
        _fail("the candidate topology is not exactly six distinct executables")

    first = {plan.basename: _build_artifact(plan, first_root, toolchain, python) for plan in plans}
    second = {
        plan.basename: _build_artifact(plan, second_root, toolchain, python) for plan in plans
    }
    no_pin_results = _probe_no_release_pin(probe_root, toolchain)
    license_output = output_directory / _LICENSE_OUTPUT_NAME
    shutil.copyfile(_LICENSE, license_output)
    license_output.chmod(0o444)
    if _sha256(license_output) != vendor["license_sha256"]:
        _fail("the emitted Monocypher license does not match the vendoring record")
    for profile, manifest in seccomp_manifests.items():
        output_name = manifest["output_name"]
        manifest_sha256 = manifest["manifest_sha256"]
        if type(output_name) is not str or type(manifest_sha256) is not str:
            _fail(f"the bound seccomp output record is invalid: {profile}")
        destination = output_directory / output_name
        shutil.copyfile(_SECCOMP_MANIFEST_PATHS[profile], destination)
        destination.chmod(0o444)
        if _sha256(destination) != manifest_sha256:
            _fail(f"the copied seccomp manifest changed: {profile}")
    import_trees = _emit_candidate_import_trees(output_directory, import_tree_sources)
    recovery_runtime = _emit_recovery_runtime(
        output_directory,
        recovery_runtime_sources,
        recovery_module_inventory,
    )
    artifacts = [
        _artifact_record(
            plan,
            first[plan.basename],
            second[plan.basename],
            output_directory,
            vendor,
            import_trees,
            recovery_runtime,
            seccomp_manifests,
        )
        for plan in plans
    ]
    artifact_elf_machines: set[object] = set()
    for artifact in artifacts:
        audit = artifact["audit"]
        if type(audit) is not dict:
            _fail("a candidate binary audit record is invalid")
        artifact_elf_machines.add(audit.get("elf_machine"))
    if artifact_elf_machines != {"EM_X86_64"}:
        _fail("candidate ELF machines do not equal the compiler/seccomp architecture")
    if (
        _validate_sources() != source_manifest
        or _validate_vendoring() != vendor
        or _validate_seccomp_manifests(verify_compiled_filters=False) != seccomp_manifests
        or _validate_candidate_import_sources() != import_tree_sources
        or _validate_recovery_runtime_sources(python) != recovery_runtime_sources
        or _python_module_inventory() != recovery_module_inventory
        or _compiler_record(toolchain) != compiler_record
        or _audit_tool_records(toolchain) != audit_tools
        or _python_record(python) != python_record
        or _validate_systemd_creds() != (systemd_creds_sha256, systemd_creds_size)
    ):
        _fail("a candidate-build input changed while evidence was being generated")
    shutil.rmtree(first_root)
    shutil.rmtree(second_root)
    shutil.rmtree(probe_root)

    result: dict[str, object] = {
        "activation_authorized": False,
        "artifacts": sorted(artifacts, key=lambda record: str(record["basename"])),
        "architecture_binding": {
            "all_candidate_elf_machines": ["EM_X86_64"],
            "all_equal": True,
            "compiler_target_triple": compiler_record["target_triple"],
            "kernel_machine": "x86_64",
            "seccomp_audit_arch": "AUDIT_ARCH_X86_64",
            "seccomp_elf_machine": "EM_X86_64",
        },
        "build_platform": {
            "machine": os.uname().machine,
            "sysname": os.uname().sysname,
        },
        "command_environment": _command_environment(),
        "command_path_placeholders": {
            "<BUILD_ROOT>": "one of two clean per-build scratch roots",
            "<SOURCE_ROOT>": (
                "the canonical source root used for this build, including an extracted-sdist "
                "root during locked qualification"
            ),
        },
        "compiler": compiler_record,
        "audit_tools": audit_tools,
        "first_party_crypto_calls": list(crypto_calls),
        "monocypher": vendor,
        "production_release_root": {
            "available": False,
            "provisioner_authority_results": no_pin_results,
            "production_provisioners_compiled_without_release_pin": True,
            "test_pin_compiled": False,
        },
        "role_import_trees": import_trees,
        "role_import_trees_included": True,
        "python": python_record,
        "recovery_python_runtime": recovery_runtime,
        "reproducible_build_count": 2,
        "schema": "autoquant-trusted-time-graceful-stop-v2-candidate-build-v1",
        "seccomp_manifests": seccomp_manifests,
        "seccomp_manifests_included": True,
        "source_manifest": source_manifest,
        "status": "candidate_unactivated",
        "systemd_creds": {
            "path": str(_SYSTEMD_CREDS),
            "sha256": systemd_creds_sha256,
            "size": systemd_creds_size,
        },
    }
    receipt = output_directory / _RECEIPT_NAME
    receipt.write_text(
        json.dumps(
            result,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="ascii",
    )
    receipt.chmod(0o444)
    return result


def main(argument_values: tuple[str, ...] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--output-directory", required=True)
    arguments = parser.parse_args(argument_values)
    result = build(Path(arguments.output_directory))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
