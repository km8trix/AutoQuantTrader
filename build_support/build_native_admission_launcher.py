"""Build a reviewed, still-unactivated trusted-time admission launcher candidate.

This builder is deliberately separate from the wheel build.  It consumes one
clean detached source checkout (the checkout containing this file) and one
explicit dependency-runtime candidate.  It never installs into the production
prefix and never resolves dependencies.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import shlex
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
import zlib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Never

_PREFIX = PurePosixPath("/opt/autoquant/trusted-time-admission")
_LAUNCHER_BASENAME = "autoquant-trusted-time-python-admission"
_LAUNCHER_RELATIVE_PATH = PurePosixPath("bin") / _LAUNCHER_BASENAME
_SOURCE_RELATIVE_PATH = PurePosixPath("share/autoquant-trader/source")
_NATIVE_RELATIVE_PATH = PurePosixPath("share/autoquant-trader/native")
_BUILD_MANIFEST_BASENAME = "native_admission_launcher_build.json"
_SOURCE_MANIFEST_BASENAME = "native_admission_source_manifest.jsonl"
_RUNTIME_MANIFEST_BASENAME = "native_admission_runtime_manifest.jsonl"
_INSTALL_RECEIPT_BASENAME = "native_admission_launcher_install_receipt.json"
_BUILD_MANIFEST_SCHEMA = "autoquant-native-admission-launcher-build-v1"
_SOURCE_MANIFEST_SCHEMA = "autoquant-native-admission-source-manifest-v1"
_RUNTIME_MANIFEST_SCHEMA = "autoquant-native-admission-runtime-manifest-v1"
_INSTALL_RECEIPT_SCHEMA = "autoquant-native-admission-launcher-install-receipt-v1"
_BUILD_RESULT_SCHEMA = "autoquant-native-admission-launcher-build-result-v1"
_MAXIMUM_TOOL_OUTPUT_BYTES = 64 * 1024 * 1024
_MAXIMUM_ENTRIES = 250_000
_MAXIMUM_FILE_BYTES = 2 * 1024 * 1024 * 1024
_MAXIMUM_BUILD_MANIFEST_BYTES = 1024 * 1024
_MAXIMUM_MANIFEST_BYTES = 128 * 1024 * 1024
_MAXIMUM_RECEIPT_BYTES = 64 * 1024
_MAXIMUM_EMBEDDED_WRAPPER_BYTES = 4 * 1024 * 1024
_SUPPORTED_PYTHON_MINORS = frozenset(((3, 12), (3, 13)))
_SUPPORTED_PLATFORMS = frozenset(("darwin", "linux"))
_FORBIDDEN_RUNTIME_BASENAMES = frozenset(
    ("sitecustomize.py", "usercustomize.py", "_virtualenv.pth")
)
_FORBIDDEN_RUNTIME_TOP_LEVEL = frozenset(("apps", "packages", "scripts"))
_EXTERNAL_BOUNDARIES = (
    "git_executable_and_helper_bytes_admitted",
    "docker_executable_and_helper_bytes_admitted",
    "cgroup_descendant_containment",
    "setsid_escape_containment",
    "loader_environment_pre_entry_admitted",
    "same_uid_injection_denied",
    "effective_mount_boundary_admitted",
)
_TARGET_IDS = (
    "verify-compose",
    "verify-images-build",
    "verify-images-readmit",
    "start",
    "admit-unenrolled",
    "enroll-first",
    "recover-first-enrollment",
    "post-enrollment-start",
    "operator-authority-prepare",
    "operator-authority-install",
    "graceful-stop-authority-prepare",
    "graceful-stop-authority-install",
    "operator-attestation-prepare",
    "operator-attestation-verify",
    "graceful-stop-decision-prepare",
    "graceful-stop-attestation-prepare",
    "graceful-stop-attestation-verify",
    "runtime-diagnostic",
    "inspect",
)
_EXPECTED_SOURCES = (
    (
        "native/owned_file_descriptor.c",
        "01b9834c343f4b173198ac7bfb22df37c6da6fb3093e7a93875aef56410b9fd9",
    ),
    (
        "native/bounded_process.c",
        "be08d5c95a2a5ce6aa9b06a4434c09473ee74ad941a417b8022885a7ef1f5cbd",
    ),
    (
        "native/trusted_time_python_launcher.c",
        "b0c684309818c6b238da1c96c174d9ad9148b017ee8dde1a51b13933b8451f0e",
    ),
    (
        "packages/adapters/trusted_time/_owned_file_descriptor.py",
        "a5c3a0f1ec32ae95d6a058cdf52f8530fe505c5a97f1a2cf61106d94c2baa9ab",
    ),
    (
        "packages/adapters/trusted_time/_bounded_process.py",
        "0bdf6cda1f0ab75d08df768d0d75bb40f2c8ef0cb490d09a18d843fb96a2a006",
    ),
)


class NativeAdmissionLauncherBuildError(RuntimeError):
    """The exact native admission launcher candidate could not be built."""


@dataclass(frozen=True, slots=True)
class _TreeRecord:
    path: str
    type: str
    mode: int
    uid: int
    gid: int
    nlink: int | None = None
    size: int | None = None
    sha256: str | None = None

    def document(self) -> dict[str, object]:
        result: dict[str, object] = {
            "gid": self.gid,
            "mode": self.mode,
            "path": self.path,
            "type": self.type,
            "uid": self.uid,
        }
        if self.type == "file":
            result.update(
                {
                    "nlink": self.nlink,
                    "sha256": self.sha256,
                    "size": self.size,
                }
            )
        return result


@dataclass(frozen=True, slots=True)
class _PythonRuntime:
    compiler: Path
    include: Path
    extension_suffix: str
    library: Path
    home: Path
    stdlib: Path
    dynload: Path
    executable: Path


@dataclass(frozen=True, slots=True)
class _CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def _fail(message: str) -> Never:
    raise NativeAdmissionLauncherBuildError(message)


def _require_nonroot_builder() -> None:
    if os.getuid() == 0 or os.geteuid() == 0 or os.getgid() == 0 or os.getegid() == 0:
        _fail("native admission builder must run without root privilege")


def _canonical_json(document: object) -> bytes:
    try:
        return (
            json.dumps(
                document,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _fail("native admission metadata could not be encoded canonically")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    descriptor = -1
    digest = hashlib.sha256()
    try:
        descriptor = _open_nofollow(path)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 0
            or before.st_size > _MAXIMUM_FILE_BYTES
        ):
            _fail("native admission hash input is not one bounded regular file")
        received = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, before.st_size + 1 - received),
            )
            if not chunk:
                break
            digest.update(chunk)
            received += len(chunk)
            if received > before.st_size:
                _fail("native admission hash input grew while it was read")
        after = os.fstat(descriptor)
        path_after = path.lstat()
        if (
            received != before.st_size
            or _identity(before) != _identity(after)
            or _identity(before) != _identity(path_after)
        ):
            _fail("native admission hash input changed while it was read")
    except OSError:
        _fail("native admission input could not be hashed")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return digest.hexdigest()


def _read_regular_bytes(path: Path, maximum: int) -> bytes:
    descriptor = -1
    chunks: list[bytes] = []
    try:
        descriptor = _open_nofollow(path)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum
        ):
            _fail("native admission byte input is not one bounded regular file")
        received = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, before.st_size + 1 - received),
            )
            if not chunk:
                break
            chunks.append(chunk)
            received += len(chunk)
            if received > before.st_size:
                _fail("native admission byte input grew while it was read")
        after = os.fstat(descriptor)
        path_after = path.lstat()
        if (
            received != before.st_size
            or _identity(before) != _identity(after)
            or _identity(before) != _identity(path_after)
        ):
            _fail("native admission byte input changed while it was read")
        return b"".join(chunks)
    except OSError:
        _fail("native admission byte input could not be read")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _fd_has_extended_metadata(descriptor: int) -> bool:
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        operation = getattr(libc, "flistxattr", None)
        if operation is None:
            _fail("native admission build cannot inspect extended metadata")
        operation.argtypes = (
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_int,
        )
        operation.restype = ctypes.c_ssize_t
        result = int(operation(descriptor, None, 0, 0))
    elif sys.platform == "linux":
        operation = getattr(libc, "flistxattr", None)
        if operation is None:
            _fail("native admission build cannot inspect extended metadata")
        operation.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t)
        operation.restype = ctypes.c_ssize_t
        result = int(operation(descriptor, None, 0))
    else:
        _fail("native admission build platform is unsupported")
    if result < 0:
        _fail("native admission build could not inspect extended metadata")
    return result != 0


def _open_nofollow(path: Path, *, directory: bool = False) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    else:
        flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        return os.open(path, flags)
    except OSError:
        _fail("native admission input could not be opened without following links")


def _validate_directory(
    path: Path,
    *,
    uid: int,
    gid: int | None = None,
    exact_mode: int | None = None,
) -> os.stat_result:
    descriptor = _open_nofollow(path, directory=True)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != uid
            or (gid is not None and metadata.st_gid != gid)
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or (exact_mode is not None and stat.S_IMODE(metadata.st_mode) != exact_mode)
            or _fd_has_extended_metadata(descriptor)
        ):
            _fail("native admission input directory metadata is invalid")
        return metadata
    finally:
        os.close(descriptor)


def _validate_relative_path(value: str) -> str:
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        _fail("native admission path is not strict UTF-8")
    path = PurePosixPath(value)
    if (
        not encoded
        or b"\0" in encoded
        or b"\n" in encoded
        or b"\r" in encoded
        or value.startswith("/")
        or path.as_posix() != value
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        _fail("native admission relative path is invalid")
    return value


def _canonical_existing_directory(value: str, label: str) -> Path:
    path = Path(value)
    try:
        canonical = path.resolve(strict=True)
    except (OSError, RuntimeError):
        _fail(f"{label} is unavailable")
    if not path.is_absolute() or path != canonical:
        _fail(f"{label} must be canonical and absolute")
    return canonical


def _canonical_new_directory(value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or Path(os.path.normpath(value)) != path:
        _fail(f"{label} must be normalized and absolute")
    try:
        if path.exists() or path.is_symlink():
            _fail(f"{label} must not already exist")
        parent = path.parent.resolve(strict=True)
    except (OSError, RuntimeError):
        _fail(f"{label} parent is unavailable")
    if path.parent != parent:
        _fail(f"{label} parent must be canonical")
    _validate_directory(parent, uid=os.geteuid())
    return path


def _validate_root_owned_chain(path: Path) -> None:
    if not path.is_absolute() or path != path.resolve(strict=True):
        _fail("native admission external build path is not canonical")
    current = Path("/")
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError:
            _fail("native admission external build path is unavailable")
        if (
            stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            _fail("native admission external build path is mutable")


def _canonical_tool(name: str) -> Path:
    candidate = shutil.which(name)
    if candidate is None:
        _fail(f"native admission build tool is unavailable: {name}")
    try:
        path = Path(candidate).resolve(strict=True)
        metadata = path.stat()
    except OSError:
        _fail("native admission build tool identity is unavailable")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink < 1
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        _fail("native admission build tool metadata is invalid")
    _validate_root_owned_chain(path)
    return path


def _command_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "SOURCE_DATE_EPOCH": "0",
        "TMPDIR": "/tmp",
    }


def _run(
    command: Sequence[str],
    *,
    cwd: Path,
    accepted_returncodes: frozenset[int] = frozenset((0,)),
) -> _CommandResult:
    try:
        completed = subprocess.run(
            tuple(command),
            check=False,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=_command_environment(),
        )
    except OSError:
        _fail("native admission build command could not be executed")
    if (
        completed.returncode not in accepted_returncodes
        or len(completed.stdout) > _MAXIMUM_TOOL_OUTPUT_BYTES
        or len(completed.stderr) > _MAXIMUM_TOOL_OUTPUT_BYTES
    ):
        output = (completed.stdout + completed.stderr)[:262_144].decode("utf-8", errors="replace")
        _fail(f"native admission build command failed:\n{output}")
    return _CommandResult(completed.returncode, completed.stdout, completed.stderr)


def _run_with_input(command: Sequence[str], *, cwd: Path, input_payload: bytes) -> bytes:
    if len(input_payload) > _MAXIMUM_TOOL_OUTPUT_BYTES:
        _fail("native admission build command input exceeded its bound")
    try:
        completed = subprocess.run(
            tuple(command),
            check=False,
            cwd=cwd,
            input=input_payload,
            capture_output=True,
            env=_command_environment(),
        )
    except OSError:
        _fail("native admission build command could not be executed")
    if (
        completed.returncode != 0
        or completed.stderr
        or len(completed.stdout) > _MAXIMUM_TOOL_OUTPUT_BYTES
    ):
        _fail("native admission build object command failed")
    return completed.stdout


def _run_git(
    git: Path,
    repository: Path,
    arguments: Sequence[str],
    *,
    accepted_returncodes: frozenset[int] = frozenset((0,)),
) -> _CommandResult:
    return _run(
        (str(git), "-c", "core.fsmonitor=false", "-C", str(repository), *arguments),
        cwd=repository,
        accepted_returncodes=accepted_returncodes,
    )


def _git_source_snapshot(source_root: Path, git: Path) -> tuple[str, tuple[tuple[str, int], ...]]:
    _validate_directory(source_root, uid=os.geteuid())
    git_directory = source_root / ".git"
    _validate_directory(git_directory, uid=os.geteuid())
    if not git_directory.is_dir() or git_directory.is_symlink():
        _fail("native admission source must have one ordinary .git directory")
    top_level = _run_git(git, source_root, ("rev-parse", "--show-toplevel")).stdout
    if top_level != (str(source_root) + "\n").encode("utf-8"):
        _fail("native admission source is not its Git worktree root")
    detached = _run_git(
        git,
        source_root,
        ("symbolic-ref", "-q", "HEAD"),
        accepted_returncodes=frozenset((0, 1)),
    )
    if detached.returncode != 1 or detached.stdout or detached.stderr:
        _fail("native admission source HEAD must be detached")
    revision_bytes = _run_git(git, source_root, ("rev-parse", "--verify", "HEAD^{commit}")).stdout
    try:
        revision = revision_bytes.decode("ascii").removesuffix("\n")
    except UnicodeError:
        _fail("native admission source revision is malformed")
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        _fail("native admission source revision is malformed")
    status_result = _run_git(
        git,
        source_root,
        ("status", "--porcelain=v2", "--untracked-files=all"),
    )
    if status_result.stdout or status_result.stderr:
        _fail("native admission source checkout is not clean")
    flags = _run_git(git, source_root, ("ls-files", "-v", "-z")).stdout
    flag_records = flags[:-1].split(b"\0") if flags.endswith(b"\0") else ()
    if not flag_records or any(not record.startswith(b"H ") for record in flag_records):
        _fail("native admission source index flags are not ordinary")
    staged = _run_git(git, source_root, ("ls-files", "--stage", "-z")).stdout
    staged_records = staged[:-1].split(b"\0") if staged.endswith(b"\0") else ()
    parsed: list[tuple[str, int]] = []
    for record in staged_records:
        try:
            prefix, raw_path = record.split(b"\t", maxsplit=1)
            raw_mode, raw_digest, raw_stage = prefix.split(b" ")
            relative = raw_path.decode("utf-8", errors="strict")
            mode = int(raw_mode, 8)
        except (ValueError, UnicodeError):
            _fail("native admission source index is malformed")
        if (
            raw_stage != b"0"
            or mode not in (0o100644, 0o100755)
            or len(raw_digest) != 40
            or any(byte not in b"0123456789abcdef" for byte in raw_digest)
        ):
            _fail("native admission source index contains a nonordinary entry")
        parsed.append((_validate_relative_path(relative), mode))
    if (
        not parsed
        or parsed != sorted(parsed, key=lambda item: item[0].encode("utf-8"))
        or len({path for path, _mode in parsed}) != len(parsed)
        or any(path == ".gitmodules" or path.startswith("artifacts/") for path, _ in parsed)
    ):
        _fail("native admission tracked source set is invalid")
    submodules = _run_git(git, source_root, ("submodule", "status", "--recursive"))
    if submodules.stdout or submodules.stderr:
        _fail("native admission source must not contain submodules")
    git_config = _run_git(git, source_root, ("config", "--local", "--list", "--null")).stdout
    lowered_config = git_config.lower()
    if any(
        marker in lowered_config
        for marker in (
            b"core.hookspath",
            b"extensions.worktreeconfig",
            b"promisor",
            b"partialclonefilter",
        )
    ):
        _fail("native admission source Git configuration is not closed")
    forbidden_git_paths = (
        git_directory / "objects/info/alternates",
        git_directory / "objects/info/http-alternates",
        git_directory / "refs/replace",
        git_directory / "modules",
    )
    if any(path.exists() or path.is_symlink() for path in forbidden_git_paths):
        _fail("native admission source Git object graph is externally mutable")
    if any(path.name.endswith(".promisor") for path in (git_directory / "objects").rglob("*")):
        _fail("native admission source Git object graph is partial")
    return revision, tuple(parsed)


def _validate_regular_input(
    path: Path,
    *,
    expected_mode: int | None = None,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
    allow_extended_metadata: bool = False,
) -> os.stat_result:
    descriptor = _open_nofollow(path)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size < 0
            or metadata.st_size > _MAXIMUM_FILE_BYTES
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or (expected_mode is not None and stat.S_IMODE(metadata.st_mode) != expected_mode)
            or (expected_uid is not None and metadata.st_uid != expected_uid)
            or (expected_gid is not None and metadata.st_gid != expected_gid)
            or (not allow_extended_metadata and _fd_has_extended_metadata(descriptor))
        ):
            _fail("native admission input file metadata is invalid")
        return metadata
    finally:
        os.close(descriptor)


def _source_paths_are_closed(
    source_root: Path,
    tracked: tuple[tuple[str, int], ...],
) -> tuple[int, int]:
    tracked_files = {path for path, _mode in tracked}
    tracked_directories: set[str] = set()
    for relative in tracked_files:
        parent = PurePosixPath(relative).parent
        while parent != PurePosixPath("."):
            tracked_directories.add(parent.as_posix())
            parent = parent.parent
    expected_uid = os.geteuid()
    try:
        artifact_root_metadata = (source_root / "artifacts").lstat()
    except OSError:
        _fail("native admission source requires one owner-only artifacts directory")
    operator_uid = artifact_root_metadata.st_uid
    operator_gid = artifact_root_metadata.st_gid
    if operator_uid != expected_uid:
        _fail("native admission artifact owner differs from the builder")
    seen = 0
    for root, directories, files in os.walk(source_root, topdown=True, followlinks=False):
        directories.sort()
        files.sort()
        root_path = Path(root)
        relative_root = root_path.relative_to(source_root).as_posix()
        if relative_root == ".git" or relative_root.startswith(".git/"):
            directories[:] = []
            continue
        for name in (*directories, *files):
            seen += 1
            if seen > _MAXIMUM_ENTRIES:
                _fail("native admission source entry count exceeded its bound")
            path = root_path / name
            relative = path.relative_to(source_root).as_posix()
            _validate_relative_path(relative)
            allowed = (
                relative == ".git"
                or relative == "artifacts"
                or relative.startswith("artifacts/")
                or relative in tracked_files
                or relative in tracked_directories
            )
            if not allowed:
                _fail("native admission source contains an untracked non-artifact entry")
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                _fail("native admission source contains a symbolic link")
            if relative == ".git":
                continue
            if relative == "artifacts" or relative.startswith("artifacts/"):
                if stat.S_ISDIR(metadata.st_mode):
                    _validate_directory(
                        path,
                        uid=operator_uid,
                        gid=operator_gid,
                        exact_mode=0o700,
                    )
                elif stat.S_ISREG(metadata.st_mode):
                    _validate_regular_input(
                        path,
                        expected_mode=0o600,
                        expected_uid=operator_uid,
                        expected_gid=operator_gid,
                    )
                else:
                    _fail("native admission artifacts contain a nonordinary entry")
            elif relative in tracked_files:
                index_mode = dict(tracked)[relative]
                expected_mode = 0o755 if index_mode == 0o100755 else 0o644
                _validate_regular_input(
                    path,
                    expected_mode=expected_mode,
                    expected_uid=expected_uid,
                )
            elif relative in tracked_directories:
                _validate_directory(path, uid=expected_uid)
            else:
                _fail("native admission source tree is structurally invalid")
    artifacts = source_root / "artifacts"
    if not artifacts.is_dir() or artifacts.is_symlink():
        _fail("native admission source requires one owner-only artifacts directory")
    return operator_uid, operator_gid


def _runtime_paths(runtime_root: Path) -> tuple[tuple[str, Path], ...]:
    python_directory_name = f"python{sys.version_info.major}.{sys.version_info.minor}"
    site_packages_relative = PurePosixPath("lib") / python_directory_name / "site-packages"
    site_packages = runtime_root.joinpath(*site_packages_relative.parts)
    _validate_directory(runtime_root, uid=os.geteuid())
    if not site_packages.is_dir() or site_packages.is_symlink():
        _fail("native admission runtime candidate lacks the exact site-packages directory")
    results: list[tuple[str, Path]] = []
    seen = 0
    for root, directories, files in os.walk(runtime_root, topdown=True, followlinks=False):
        directories.sort()
        files.sort()
        root_path = Path(root)
        for name in (*directories, *files):
            seen += 1
            if seen > _MAXIMUM_ENTRIES:
                _fail("native admission runtime entry count exceeded its bound")
            path = root_path / name
            relative = path.relative_to(runtime_root).as_posix()
            _validate_relative_path(relative)
            if relative in (
                "lib",
                f"lib/{python_directory_name}",
                site_packages_relative.as_posix(),
            ):
                pass
            elif not relative.startswith(site_packages_relative.as_posix() + "/"):
                _fail("native admission runtime candidate contains an unexpected path")
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                _fail("native admission runtime candidate contains a symbolic link")
            if stat.S_ISDIR(metadata.st_mode):
                _validate_directory(path, uid=os.geteuid())
            elif stat.S_ISREG(metadata.st_mode):
                _validate_regular_input(path, expected_uid=os.geteuid())
            else:
                _fail("native admission runtime candidate contains a nonordinary entry")
            if relative.startswith(site_packages_relative.as_posix() + "/"):
                relative_under_site = PurePosixPath(relative).relative_to(site_packages_relative)
                top_level = relative_under_site.parts[0]
                if (
                    name in _FORBIDDEN_RUNTIME_BASENAMES
                    or name.endswith(".pth")
                    or name.endswith((".pyc", ".pyo"))
                    or name == "__pycache__"
                    or top_level in _FORBIDDEN_RUNTIME_TOP_LEVEL
                    or top_level.startswith("autoquant_trader-")
                    or name.startswith("_autoquant_native_")
                ):
                    _fail("native admission runtime candidate contains a forbidden import path")
            results.append((relative, path))
    if tuple(relative for relative, _path in results[:3]) != (
        "lib",
        f"lib/{python_directory_name}",
        site_packages_relative.as_posix(),
    ):
        _fail("native admission runtime candidate layout is not exact")
    if not any(path.is_file() for _relative, path in results):
        _fail("native admission runtime candidate has no dependency payload")
    return tuple(results)


def _copy_regular(source: Path, destination: Path, mode: int) -> tuple[int, str]:
    source_descriptor = _open_nofollow(source)
    destination_descriptor = -1
    try:
        before = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > _MAXIMUM_FILE_BYTES
            or _fd_has_extended_metadata(source_descriptor)
        ):
            _fail("native admission input changed before it could be copied")
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            offset = 0
            while offset < len(chunk):
                written = os.write(destination_descriptor, chunk[offset:])
                if written <= 0:
                    _fail("native admission output write did not progress")
                offset += written
        after = os.fstat(source_descriptor)
        path_after = source.lstat()
        if _identity(before) != _identity(after) or _identity(before) != _identity(path_after):
            _fail("native admission input changed while it was copied")
        os.fchmod(destination_descriptor, mode)
        os.fsync(destination_descriptor)
        return size, digest.hexdigest()
    except OSError:
        _fail("native admission input could not be copied exactly")
    finally:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
        os.close(source_descriptor)


def _write_exclusive(path: Path, payload: bytes, mode: int) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                _fail("native admission metadata write did not progress")
            offset += written
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    except OSError:
        _fail("native admission metadata could not be written exclusively")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _mkdir(path: Path, mode: int = 0o700) -> None:
    try:
        path.mkdir(mode=mode)
    except OSError:
        _fail("native admission output directory could not be created exclusively")


def _validate_empty_build_directory(
    path: Path,
    expected_identity: tuple[int, ...],
) -> None:
    descriptor = _open_nofollow(path, directory=True)
    try:
        opened = os.fstat(descriptor)
        lexical = path.lstat()
        if (
            _identity(opened) != expected_identity
            or _identity(lexical) != expected_identity
            or not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
            or _fd_has_extended_metadata(descriptor)
            or os.listdir(descriptor)
        ):
            _fail("native admission precreated build directory identity is invalid")
    except OSError:
        _fail("native admission precreated build directory could not be validated")
    finally:
        os.close(descriptor)


def _make_identity_recorded_build_directory(
    *,
    parent: Path,
    prefix: str,
) -> tuple[Path, tuple[int, ...]]:
    _require_nonroot_builder()
    try:
        path = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    except OSError:
        _fail("native admission retained build directory could not be created")
    descriptor = _open_nofollow(path, directory=True)
    try:
        metadata = os.fstat(descriptor)
        lexical = path.lstat()
        identity = _identity(metadata)
        if (
            identity != _identity(lexical)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or _fd_has_extended_metadata(descriptor)
            or os.listdir(descriptor)
        ):
            _fail("native admission retained build directory identity is invalid")
        return path, identity
    except OSError:
        _fail("native admission retained build directory could not be recorded")
    finally:
        os.close(descriptor)


def _mkdir_parents(root: Path, relative: str) -> None:
    current = root
    for part in PurePosixPath(relative).parts:
        current /= part
        if current.exists():
            if not current.is_dir() or current.is_symlink():
                _fail("native admission output directory collided with a non-directory")
            continue
        _mkdir(current)


def _copy_runtime(
    runtime_root: Path,
    output_root: Path,
    runtime_paths: tuple[tuple[str, Path], ...],
) -> list[_TreeRecord]:
    records: list[_TreeRecord] = []
    for relative, source in runtime_paths:
        destination = output_root.joinpath(*PurePosixPath(relative).parts)
        metadata = source.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            _mkdir(destination)
            records.append(_TreeRecord(relative, "directory", 0o555, 0, 0))
        else:
            size, digest = _copy_regular(source, destination, 0o444)
            records.append(_TreeRecord(relative, "file", 0o444, 0, 0, 1, size, digest))
    if runtime_root == output_root:
        _fail("native admission runtime input and output must be distinct")
    return records


def _copy_artifacts(
    source: Path,
    destination: Path,
    relative_root: str,
    *,
    operator_uid: int,
    operator_gid: int,
) -> list[_TreeRecord]:
    records: list[_TreeRecord] = []
    _mkdir(destination)
    records.append(_TreeRecord(relative_root, "directory", 0o700, operator_uid, operator_gid))
    for root, directories, files in os.walk(source, topdown=True, followlinks=False):
        directories.sort()
        files.sort()
        root_path = Path(root)
        relative_parent = root_path.relative_to(source)
        destination_parent = destination / relative_parent
        for name in directories:
            child_source = root_path / name
            child_destination = destination_parent / name
            _validate_directory(
                child_source,
                uid=operator_uid,
                gid=operator_gid,
                exact_mode=0o700,
            )
            _mkdir(child_destination)
            relative = (PurePosixPath(relative_root) / relative_parent / name).as_posix()
            records.append(_TreeRecord(relative, "directory", 0o700, operator_uid, operator_gid))
        for name in files:
            child_source = root_path / name
            child_destination = destination_parent / name
            _validate_regular_input(
                child_source,
                expected_mode=0o600,
                expected_uid=operator_uid,
                expected_gid=operator_gid,
            )
            size, digest = _copy_regular(child_source, child_destination, 0o600)
            relative = (PurePosixPath(relative_root) / relative_parent / name).as_posix()
            records.append(
                _TreeRecord(relative, "file", 0o600, operator_uid, operator_gid, 1, size, digest)
            )
    return records


def _minimal_git_object_ids(
    source_root: Path,
    git: Path,
    revision: str,
) -> tuple[tuple[str, str], ...]:
    root_tree_payload = _run_git(
        git,
        source_root,
        ("rev-parse", "--verify", f"{revision}^{{tree}}"),
    ).stdout
    try:
        root_tree = root_tree_payload.decode("ascii", errors="strict").removesuffix("\n")
    except UnicodeError:
        _fail("native admission Git root tree is malformed")
    if len(root_tree) != 40 or any(character not in "0123456789abcdef" for character in root_tree):
        _fail("native admission Git root tree is malformed")
    tree = _run_git(
        git,
        source_root,
        ("ls-tree", "-r", "-t", "--full-tree", "-z", revision),
    ).stdout
    records = tree[:-1].split(b"\0") if tree.endswith(b"\0") else ()
    objects: dict[str, str] = {revision: "commit", root_tree: "tree"}
    for record in records:
        try:
            prefix, raw_path = record.split(b"\t", maxsplit=1)
            _raw_mode, raw_type, raw_object = prefix.split(b" ")
            object_type = raw_type.decode("ascii", errors="strict")
            object_id = raw_object.decode("ascii", errors="strict")
            relative = raw_path.decode("utf-8", errors="strict")
        except (ValueError, UnicodeError):
            _fail("native admission Git tree object set is malformed")
        if (
            object_type not in ("blob", "tree")
            or len(object_id) != 40
            or any(character not in "0123456789abcdef" for character in object_id)
        ):
            _fail("native admission Git tree contains a nonordinary object")
        _validate_relative_path(relative)
        prior = objects.setdefault(object_id, object_type)
        if prior != object_type:
            _fail("native admission Git object type is ambiguous")
    if len(objects) > _MAXIMUM_ENTRIES:
        _fail("native admission Git object count exceeded its bound")
    return tuple(sorted(objects.items()))


def _copy_minimal_git_objects(
    source_root: Path,
    destination_git: Path,
    git: Path,
    revision: str,
) -> None:
    objects = _minimal_git_object_ids(source_root, git, revision)
    request = b"".join((object_id + "\n").encode("ascii") for object_id, _ in objects)
    response = _run_with_input(
        (
            str(git),
            "-c",
            "core.fsmonitor=false",
            "-C",
            str(source_root),
            "cat-file",
            "--batch",
        ),
        cwd=source_root,
        input_payload=request,
    )
    destination_objects = destination_git / "objects"
    _mkdir(destination_objects)
    cursor = 0
    for expected_id, expected_type in objects:
        header_end = response.find(b"\n", cursor)
        if header_end < 0:
            _fail("native admission Git object batch response is truncated")
        try:
            raw_id, raw_type, raw_size = response[cursor:header_end].split(b" ")
            object_id = raw_id.decode("ascii", errors="strict")
            object_type = raw_type.decode("ascii", errors="strict")
            size = int(raw_size)
        except (ValueError, UnicodeError):
            _fail("native admission Git object batch response is malformed")
        data_start = header_end + 1
        data_end = data_start + size
        if (
            object_id != expected_id
            or object_type != expected_type
            or size < 0
            or size > _MAXIMUM_FILE_BYTES
            or data_end >= len(response)
            or response[data_end : data_end + 1] != b"\n"
        ):
            _fail("native admission Git object batch identity is invalid")
        payload = response[data_start:data_end]
        loose = f"{object_type} {size}\0".encode("ascii") + payload
        if hashlib.sha1(loose, usedforsecurity=False).hexdigest() != object_id:
            _fail("native admission Git object content differs from its identity")
        object_directory = destination_objects / object_id[:2]
        if not object_directory.exists():
            _mkdir(object_directory)
        _write_exclusive(object_directory / object_id[2:], zlib.compress(loose), 0o444)
        cursor = data_end + 1
    if cursor != len(response):
        _fail("native admission Git object batch response has trailing bytes")


def _copy_source(
    source_root: Path,
    destination: Path,
    revision: str,
    tracked: tuple[tuple[str, int], ...],
    git: Path,
    operator_uid: int,
    operator_gid: int,
) -> list[_TreeRecord]:
    records: list[_TreeRecord] = []
    _mkdir(destination)
    created_directories: set[str] = set()
    for relative, index_mode in tracked:
        pure = PurePosixPath(relative)
        parent = pure.parent
        missing: list[PurePosixPath] = []
        while parent != PurePosixPath(".") and parent.as_posix() not in created_directories:
            missing.append(parent)
            parent = parent.parent
        for directory in reversed(missing):
            _mkdir(destination.joinpath(*directory.parts))
            created_directories.add(directory.as_posix())
            records.append(_TreeRecord(directory.as_posix(), "directory", 0o555, 0, 0))
        source = source_root.joinpath(*pure.parts)
        target = destination.joinpath(*pure.parts)
        mode = 0o555 if index_mode == 0o100755 else 0o444
        size, digest = _copy_regular(source, target, mode)
        records.append(_TreeRecord(relative, "file", mode, 0, 0, 1, size, digest))

    git_destination = destination / ".git"
    _mkdir(git_destination)
    records.append(_TreeRecord(".git", "directory", 0o555, 0, 0))
    _copy_minimal_git_objects(source_root, git_destination, git, revision)
    _mkdir(git_destination / "refs")
    config_payload = (
        b"[core]\n"
        b"\trepositoryformatversion = 0\n"
        b"\tfilemode = true\n"
        b"\tbare = false\n"
        b"\tlogallrefupdates = false\n"
    )
    _write_exclusive(git_destination / "config", config_payload, 0o444)
    _write_exclusive(git_destination / "HEAD", (revision + "\n").encode("ascii"), 0o444)
    _run(
        (
            str(git),
            "--git-dir",
            str(git_destination),
            "--work-tree",
            str(destination),
            "read-tree",
            revision,
        ),
        cwd=destination,
    )
    index_path = git_destination / "index"
    _validate_regular_input(index_path, expected_uid=os.geteuid())
    os.chmod(index_path, 0o444)
    status = _run(
        (
            str(git),
            "--git-dir",
            str(git_destination),
            "--work-tree",
            str(destination),
            "status",
            "--porcelain=v2",
            "--untracked-files=all",
        ),
        cwd=destination,
    )
    if status.stdout or status.stderr:
        _fail("detached native admission source copy is not clean")

    for root, directories, files in os.walk(git_destination, topdown=True, followlinks=False):
        directories.sort()
        files.sort()
        root_path = Path(root)
        relative_parent = root_path.relative_to(destination).as_posix()
        for name in directories:
            relative = f"{relative_parent}/{name}"
            if relative == ".git/objects":
                pass
            records.append(_TreeRecord(relative, "directory", 0o555, 0, 0))
        for name in files:
            path = root_path / name
            relative = f"{relative_parent}/{name}"
            metadata = _validate_regular_input(path, expected_uid=os.geteuid())
            records.append(
                _TreeRecord(
                    relative,
                    "file",
                    0o444,
                    0,
                    0,
                    1,
                    metadata.st_size,
                    _sha256_file(path),
                )
            )
    records.extend(
        _copy_artifacts(
            source_root / "artifacts",
            destination / "artifacts",
            "artifacts",
            operator_uid=operator_uid,
            operator_gid=operator_gid,
        )
    )
    return records


def _python_runtime(*, require_root_owned: bool) -> _PythonRuntime:
    if (
        sys.implementation.name != "cpython"
        or sys.version_info[:2] not in _SUPPORTED_PYTHON_MINORS
        or sys.platform not in _SUPPORTED_PLATFORMS
    ):
        _fail("native admission build requires admitted CPython 3.12 or 3.13")
    configured_compiler = sysconfig.get_config_var("CC")
    if type(configured_compiler) is not str or not configured_compiler:
        _fail("Python did not declare a native compiler")
    compiler_words = shlex.split(configured_compiler)
    if not compiler_words:
        _fail("Python declared an empty native compiler command")
    compiler = _canonical_tool(compiler_words[0])
    include_value = sysconfig.get_path("include")
    library_directory_value = sysconfig.get_config_var("LIBDIR")
    library_name = sysconfig.get_config_var("LDLIBRARY")
    extension_suffix = sysconfig.get_config_var("EXT_SUFFIX")
    stdlib_value = sysconfig.get_path("stdlib")
    dynload_value = sysconfig.get_config_var("DESTSHARED")
    if not all(
        type(value) is str and value
        for value in (
            include_value,
            library_directory_value,
            library_name,
            extension_suffix,
            stdlib_value,
            dynload_value,
        )
    ):
        _fail("Python runtime build identity is incomplete")
    include = Path(str(include_value)).resolve(strict=True)
    library = (Path(str(library_directory_value)) / str(library_name)).resolve(strict=True)
    home = Path(sys.base_prefix).resolve(strict=True)
    stdlib = Path(str(stdlib_value)).resolve(strict=True)
    dynload = Path(str(dynload_value)).resolve(strict=True)
    base_executable = getattr(sys, "_base_executable", None)
    if type(base_executable) is not str or not base_executable:
        _fail("Python base executable identity is unavailable")
    executable = Path(base_executable).resolve(strict=True)
    if not str(extension_suffix).startswith(".cpython-") or not str(extension_suffix).endswith(
        ".so"
    ):
        _fail("Python extension suffix is not admitted")
    for directory in (include, home, stdlib, dynload, library.parent):
        metadata = directory.stat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or (require_root_owned and (metadata.st_uid != 0 or metadata.st_gid != 0))
        ):
            _fail("Python runtime directory metadata is not admitted")
        if require_root_owned:
            _validate_root_owned_chain(directory)
    for file_path in (library, executable, include / "Python.h"):
        metadata = _validate_regular_input(
            file_path,
            allow_extended_metadata=not require_root_owned,
        )
        if require_root_owned and (metadata.st_uid != 0 or metadata.st_gid != 0):
            _fail("Python runtime file ownership is not admitted")
    return _PythonRuntime(
        compiler,
        include,
        str(extension_suffix),
        library,
        home,
        stdlib,
        dynload,
        executable,
    )


def _write_embedded_header(source: Path, output: Path, symbol: str) -> None:
    payload = _read_regular_bytes(source, _MAXIMUM_EMBEDDED_WRAPPER_BYTES)
    if not payload or b"\0" in payload:
        _fail("native admission wrapper bytes are invalid")
    values = (*payload, 0)
    rows = tuple(
        ", ".join(f"0x{value:02x}" for value in values[index : index + 16])
        for index in range(0, len(values), 16)
    )
    output.write_text(
        f"static const unsigned char {symbol}[] = {{\n"
        + "\n".join(f"    {row}," for row in rows)
        + "\n};\n",
        encoding="ascii",
    )


def _quoted_definition(name: str, value: str) -> str:
    if any(character in value for character in ('"', "\\", "\n", "\r")):
        _fail("native admission compiled path cannot be represented exactly")
    return f'-D{name}="{value}"'


def _python_library_link_name(path: Path) -> str:
    name = path.name
    if not name.startswith("lib"):
        _fail("Python library name is invalid")
    if ".dylib" in name:
        return name.removeprefix("lib").split(".dylib", maxsplit=1)[0]
    if ".so" in name:
        return name.removeprefix("lib").split(".so", maxsplit=1)[0]
    _fail("Python library suffix is invalid")


def _platform_compile_flags() -> tuple[tuple[str, ...], tuple[str, ...], dict[str, str]]:
    machine = platform.machine()
    system = platform.system()
    if system == "Darwin":
        if machine not in ("arm64", "x86_64"):
            _fail("native admission Darwin architecture is unsupported")
        xcrun = _canonical_tool("xcrun")
        sdk_payload = _run((str(xcrun), "--show-sdk-path"), cwd=Path.cwd()).stdout
        try:
            sdk = Path(sdk_payload.decode("utf-8").strip()).resolve(strict=True)
        except (UnicodeError, OSError, RuntimeError):
            _fail("native admission Darwin SDK identity is invalid")
        settings = sdk / "SDKSettings.json"
        if not settings.is_file():
            _fail("native admission Darwin SDK settings are unavailable")
        return (
            ("-arch", machine, "-isysroot", str(sdk), "-mmacosx-version-min=11.0"),
            ("-Wl,-dead_strip",),
            {
                "architecture": machine,
                "deployment_target": "11.0",
                "sdk": sdk.name,
                "sdk_settings_sha256": _sha256_file(settings),
            },
        )
    if system == "Linux" and machine in ("aarch64", "x86_64"):
        return (
            ("-pthread",),
            ("-Wl,-z,relro,-z,now,-z,noexecstack",),
            {"architecture": machine},
        )
    _fail("native admission build architecture is unsupported")


def _normalized_command(command: Sequence[str], replacements: dict[str, str]) -> list[str]:
    return [replacements.get(argument, argument) for argument in command]


def _compile_once(
    *,
    source_root: Path,
    runtime: _PythonRuntime,
    temporary_root: Path,
    platform_flags: tuple[str, ...],
    link_security_flags: tuple[str, ...],
) -> tuple[Path, tuple[tuple[str, ...], ...]]:
    core_source = source_root / _EXPECTED_SOURCES[0][0]
    process_source = source_root / _EXPECTED_SOURCES[1][0]
    launcher_source = source_root / _EXPECTED_SOURCES[2][0]
    owner_wrapper = source_root / _EXPECTED_SOURCES[3][0]
    process_wrapper = source_root / _EXPECTED_SOURCES[4][0]
    _write_embedded_header(
        owner_wrapper,
        temporary_root / "embedded_owned_file_descriptor_wrapper.h",
        "aqt_embedded_owned_file_descriptor_wrapper",
    )
    _write_embedded_header(
        process_wrapper,
        temporary_root / "embedded_bounded_process_wrapper.h",
        "aqt_embedded_bounded_process_wrapper",
    )
    core_object = temporary_root / "owned_file_descriptor.o"
    process_object = temporary_root / "bounded_process.o"
    launcher_object = temporary_root / "trusted_time_python_launcher.o"
    launcher = temporary_root / _LAUNCHER_BASENAME
    common = (
        str(runtime.compiler),
        "-std=c11",
        "-O2",
        "-fPIE",
        "-fvisibility=hidden",
        "-fstack-protector-strong",
        "-D_FORTIFY_SOURCE=2",
        "-Wall",
        "-Wextra",
        "-Wconversion",
        "-Wshadow",
        "-Wpedantic",
        "-Werror=implicit-function-declaration",
        "-Werror=return-type",
        f"-I{runtime.include}",
    )
    definitions = (
        (
            _quoted_definition("AQT_NATIVE_EXTENSION_SUFFIX", runtime.extension_suffix),
            _quoted_definition("AQT_NATIVE_MODULE_NAME", "_autoquant_native_owned_file_descriptor"),
            _quoted_definition("AQT_NATIVE_LAUNCHER_BASENAME", _LAUNCHER_BASENAME),
            "-DAQT_NATIVE_EMBEDDED_LAUNCHER=1",
        ),
        (
            _quoted_definition(
                "AQT_NATIVE_PROCESS_MODULE_NAME", "_autoquant_native_bounded_process"
            ),
            _quoted_definition("AQT_NATIVE_PROCESS_LAUNCHER_BASENAME", _LAUNCHER_BASENAME),
        ),
        (
            "-DAQT_NATIVE_LAUNCHER_ADMISSION_PROFILE=1",
            _quoted_definition("AQT_TRUSTED_TIME_PREFIX", _PREFIX.as_posix()),
            _quoted_definition("AQT_PYTHON_HOME", str(runtime.home)),
            _quoted_definition("AQT_PYTHON_STDLIB", str(runtime.stdlib)),
            _quoted_definition("AQT_PYTHON_DYNLOAD", str(runtime.dynload)),
            _quoted_definition(
                "AQT_TRUSTED_TIME_SOURCE_ROOT", (_PREFIX / _SOURCE_RELATIVE_PATH).as_posix()
            ),
        ),
    )
    commands: list[tuple[str, ...]] = []
    for source, output, source_definitions in zip(
        (core_source, process_source, launcher_source),
        (core_object, process_object, launcher_object),
        definitions,
        strict=True,
    ):
        generated_include = (f"-I{temporary_root}",) if source == launcher_source else ()
        command = (
            *common,
            *source_definitions,
            *platform_flags,
            *generated_include,
            "-c",
            str(source),
            "-o",
            str(output),
        )
        _run(command, cwd=source_root)
        commands.append(command)
    configured_libraries = sysconfig.get_config_var("LIBS")
    configured_system_libraries = sysconfig.get_config_var("SYSLIBS")
    if type(configured_libraries) is not str or type(configured_system_libraries) is not str:
        _fail("Python embedding library flags are incomplete")
    link_command = (
        str(runtime.compiler),
        *platform_flags,
        *link_security_flags,
        f"-Wl,-rpath,{runtime.library.parent}",
        str(core_object),
        str(process_object),
        str(launcher_object),
        f"-L{runtime.library.parent}",
        f"-l{_python_library_link_name(runtime.library)}",
        *shlex.split(configured_libraries),
        *shlex.split(configured_system_libraries),
        "-o",
        str(launcher),
    )
    _run(link_command, cwd=source_root)
    commands.append(link_command)
    os.chmod(launcher, 0o555)
    return launcher, tuple(commands)


def _audit_dynamic_binary(launcher: Path, python_library: Path) -> dict[str, object]:
    if platform.system() == "Darwin":
        otool = _canonical_tool("otool")
        dependencies_output = _run((str(otool), "-L", str(launcher)), cwd=launcher.parent).stdout
        load_output = _run((str(otool), "-l", str(launcher)), cwd=launcher.parent).stdout
        dependencies_text = dependencies_output.decode("utf-8", errors="strict")
        load_text = load_output.decode("utf-8", errors="strict")
        darwin_dependencies = {
            line.strip().split(" ", maxsplit=1)[0]
            for line in dependencies_text.splitlines()[1:]
            if line.startswith("\t")
        }
        expected = {
            str(python_library),
            "/usr/lib/libSystem.B.dylib",
            "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
        }
        if darwin_dependencies != expected:
            _fail("native admission launcher has an unexpected dynamic dependency")
        lines = load_text.splitlines()
        rpaths = tuple(
            lines[index + 2].strip().split(" ", maxsplit=2)[1]
            for index, line in enumerate(lines[:-2])
            if line.strip() == "cmd LC_RPATH" and lines[index + 2].strip().startswith("path ")
        )
        if rpaths != (str(python_library.parent),):
            _fail("native admission launcher has an unexpected runtime path")
        return {
            "dependencies": sorted(darwin_dependencies),
            "rpath": list(rpaths),
            "tool": str(otool),
            "tool_sha256": _sha256_file(otool),
        }
    readelf = _canonical_tool("readelf")
    dynamic_output = _run((str(readelf), "-d", str(launcher)), cwd=launcher.parent).stdout
    dynamic = dynamic_output.decode("utf-8", errors="strict")
    if "(RPATH)" in dynamic or "(TEXTREL)" in dynamic:
        _fail("native admission launcher contains a forbidden ELF dynamic tag")
    linux_dependencies = sorted(
        line.split("[", maxsplit=1)[1].split("]", maxsplit=1)[0]
        for line in dynamic.splitlines()
        if "(NEEDED)" in line and "[" in line and "]" in line
    )
    expected_by_architecture = {
        "aarch64": sorted(("ld-linux-aarch64.so.1", "libc.so.6", python_library.name)),
        "x86_64": sorted(("libc.so.6", python_library.name)),
    }
    linux_expected = expected_by_architecture.get(platform.machine())
    if linux_expected is None or linux_dependencies != linux_expected:
        _fail("native admission launcher has an unexpected dynamic dependency")
    runpaths = tuple(
        line.split("[", maxsplit=1)[1].split("]", maxsplit=1)[0]
        for line in dynamic.splitlines()
        if "(RUNPATH)" in line and "[" in line and "]" in line
    )
    if runpaths != (str(python_library.parent),):
        _fail("native admission launcher has an unexpected runtime path")
    return {
        "dependencies": linux_dependencies,
        "rpath": list(runpaths),
        "tool": str(readelf),
        "tool_sha256": _sha256_file(readelf),
    }


def _normalize_commands(
    commands: tuple[tuple[str, ...], ...],
    *,
    source_root: Path,
    runtime: _PythonRuntime,
    temporary_root: Path,
) -> list[list[str]]:
    replacements = {
        str(runtime.compiler): "$COMPILER",
        str(source_root / _EXPECTED_SOURCES[0][0]): "$OWNED_SOURCE",
        str(source_root / _EXPECTED_SOURCES[1][0]): "$PROCESS_SOURCE",
        str(source_root / _EXPECTED_SOURCES[2][0]): "$LAUNCHER_SOURCE",
        f"-I{runtime.include}": "-I$PYTHON_INCLUDE",
        f"-I{temporary_root}": "-I$GENERATED_INCLUDE",
        f"-L{runtime.library.parent}": "-L$PYTHON_LIBDIR",
        f"-Wl,-rpath,{runtime.library.parent}": "-Wl,-rpath,$PYTHON_LIBDIR",
        _quoted_definition("AQT_NATIVE_EXTENSION_SUFFIX", runtime.extension_suffix): (
            "-DAQT_NATIVE_EXTENSION_SUFFIX=$EXT_SUFFIX"
        ),
        _quoted_definition("AQT_PYTHON_HOME", str(runtime.home)): "-DAQT_PYTHON_HOME=$PYTHON_HOME",
        _quoted_definition("AQT_PYTHON_STDLIB", str(runtime.stdlib)): (
            "-DAQT_PYTHON_STDLIB=$PYTHON_STDLIB"
        ),
        _quoted_definition("AQT_PYTHON_DYNLOAD", str(runtime.dynload)): (
            "-DAQT_PYTHON_DYNLOAD=$PYTHON_DYNLOAD"
        ),
    }
    for name in (
        "owned_file_descriptor.o",
        "bounded_process.o",
        "trusted_time_python_launcher.o",
        _LAUNCHER_BASENAME,
    ):
        replacements[str(temporary_root / name)] = f"$BUILD/{name}"
    return [_normalized_command(command, replacements) for command in commands]


def _manifest_bytes(schema: str, root: str, records: Sequence[_TreeRecord]) -> bytes:
    ordered = sorted(records, key=lambda record: record.path.encode("utf-8"))
    if len(ordered) > _MAXIMUM_ENTRIES or len({record.path for record in ordered}) != len(ordered):
        _fail("native admission manifest entry set is invalid")
    header = {
        "entry_count": len(ordered),
        "root": root,
        "schema": schema,
    }
    payload = b"".join(
        (_canonical_json(header), *(_canonical_json(record.document()) for record in ordered))
    )
    if len(payload) > _MAXIMUM_MANIFEST_BYTES:
        _fail("native admission manifest exceeded its byte bound")
    return payload


def _lock_tree(root: Path, *, artifact_prefix: str) -> None:
    directories: list[Path] = []
    for directory_name, _child_directories, files in os.walk(root, topdown=True, followlinks=False):
        path = Path(directory_name)
        directories.append(path)
        relative = path.relative_to(root).as_posix()
        for name in files:
            child = path / name
            child_relative = child.relative_to(root).as_posix()
            child_in_artifacts = child_relative.startswith(artifact_prefix + "/")
            os.chmod(child, 0o600 if child_in_artifacts else stat.S_IMODE(child.stat().st_mode))
    for directory_path in reversed(directories):
        relative = directory_path.relative_to(root).as_posix()
        mode = (
            0o700
            if relative == artifact_prefix or relative.startswith(artifact_prefix + "/")
            else 0o555
        )
        os.chmod(directory_path, mode)
        descriptor = _open_nofollow(directory_path, directory=True)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _artifact_description(path: str, payload: bytes, *, mode: int = 0o444) -> dict[str, object]:
    return {
        "gid": 0,
        "mode": mode,
        "path": path,
        "sha256": _sha256_bytes(payload),
        "size": len(payload),
        "uid": 0,
    }


def _build_candidate_once(
    *,
    source_root: Path,
    runtime_candidate: Path,
    output_directory: Path,
    expected_output_identity: tuple[int, ...],
    require_production_runtime: bool,
) -> dict[str, object]:
    _require_nonroot_builder()
    _validate_empty_build_directory(output_directory, expected_output_identity)
    git = _canonical_tool("git")
    revision, tracked = _git_source_snapshot(source_root, git)
    operator_uid, operator_gid = _source_paths_are_closed(source_root, tracked)
    source_hashes = {
        relative: _sha256_file(source_root / relative) for relative, _ in _EXPECTED_SOURCES
    }
    if source_hashes != dict(_EXPECTED_SOURCES):
        _fail("native admission launcher source identity is unreviewed")
    runtime_paths = _runtime_paths(runtime_candidate)
    runtime = _python_runtime(require_root_owned=require_production_runtime)
    try:
        runtime_records = _copy_runtime(runtime_candidate, output_directory, runtime_paths)
        source_destination = output_directory.joinpath(*_SOURCE_RELATIVE_PATH.parts)
        native_destination = output_directory.joinpath(*_NATIVE_RELATIVE_PATH.parts)
        _mkdir_parents(output_directory, _SOURCE_RELATIVE_PATH.parent.as_posix())
        source_records = _copy_source(
            source_root,
            source_destination,
            revision,
            tracked,
            git,
            operator_uid,
            operator_gid,
        )
        _mkdir(native_destination)
        bin_directory = output_directory / "bin"
        _mkdir(bin_directory)
        platform_flags, link_security_flags, platform_attestation = _platform_compile_flags()
        build_root, build_root_identity = _make_identity_recorded_build_directory(
            parent=output_directory.parent,
            prefix=f".{output_directory.name}.compiler-scratch-",
        )
        _validate_empty_build_directory(build_root, build_root_identity)
        launcher, build_commands = _compile_once(
            source_root=source_root,
            runtime=runtime,
            temporary_root=build_root,
            platform_flags=platform_flags,
            link_security_flags=link_security_flags,
        )
        launcher_hash = _sha256_file(launcher)
        launcher_size = launcher.stat().st_size
        commands = _normalize_commands(
            build_commands,
            source_root=source_root,
            runtime=runtime,
            temporary_root=build_root,
        )
        dynamic_audit = _audit_dynamic_binary(launcher, runtime.library)
        launcher_destination = output_directory.joinpath(*_LAUNCHER_RELATIVE_PATH.parts)
        _copy_regular(launcher, launcher_destination, 0o555)

        runtime_records.extend(
            (
                _TreeRecord("bin", "directory", 0o555, 0, 0),
                _TreeRecord(
                    _LAUNCHER_RELATIVE_PATH.as_posix(),
                    "file",
                    0o555,
                    0,
                    0,
                    1,
                    launcher_size,
                    launcher_hash,
                ),
            )
        )
        source_manifest = _manifest_bytes(
            _SOURCE_MANIFEST_SCHEMA,
            (_PREFIX / _SOURCE_RELATIVE_PATH).as_posix(),
            source_records,
        )
        runtime_manifest = _manifest_bytes(
            _RUNTIME_MANIFEST_SCHEMA,
            _PREFIX.as_posix(),
            runtime_records,
        )
        source_manifest_path = native_destination / _SOURCE_MANIFEST_BASENAME
        runtime_manifest_path = native_destination / _RUNTIME_MANIFEST_BASENAME
        _write_exclusive(source_manifest_path, source_manifest, 0o444)
        _write_exclusive(runtime_manifest_path, runtime_manifest, 0o444)
        compiler_version = _run((str(runtime.compiler), "--version"), cwd=source_root).stdout
        python_library_metadata = runtime.library.stat()
        python_executable_metadata = runtime.executable.stat()
        python_header = runtime.include / "Python.h"
        python_header_metadata = python_header.stat()
        output_metadata = output_directory.stat()
        build_document = {
            "build_commands": commands,
            "builder_identity": {
                "candidate_gid": output_metadata.st_gid,
                "candidate_uid": output_metadata.st_uid,
                "git": str(git),
                "git_sha256": _sha256_file(git),
            },
            "compiler": {
                "path": str(runtime.compiler),
                "sha256": _sha256_file(runtime.compiler),
                "version_sha256": _sha256_bytes(compiler_version),
            },
            "dynamic": dynamic_audit,
            "git_revision": revision,
            "launcher": {
                "basename": _LAUNCHER_BASENAME,
                "path": (_PREFIX / _LAUNCHER_RELATIVE_PATH).as_posix(),
                "profile": "admission",
                "sha256": launcher_hash,
                "size": launcher_size,
                "target_ids": list(_TARGET_IDS),
            },
            "platform": sys.platform,
            "platform_attestation": platform_attestation,
            "python_runtime": {
                "dynload": str(runtime.dynload),
                "executable": {
                    "gid": python_executable_metadata.st_gid,
                    "mode": stat.S_IMODE(python_executable_metadata.st_mode),
                    "nlink": python_executable_metadata.st_nlink,
                    "path": str(runtime.executable),
                    "sha256": _sha256_file(runtime.executable),
                    "size": python_executable_metadata.st_size,
                    "uid": python_executable_metadata.st_uid,
                },
                "extension_suffix": runtime.extension_suffix,
                "header": {
                    "gid": python_header_metadata.st_gid,
                    "mode": stat.S_IMODE(python_header_metadata.st_mode),
                    "nlink": python_header_metadata.st_nlink,
                    "path": str(python_header),
                    "sha256": _sha256_file(python_header),
                    "size": python_header_metadata.st_size,
                    "uid": python_header_metadata.st_uid,
                },
                "home": str(runtime.home),
                "implementation": sys.implementation.name,
                "library": {
                    "gid": python_library_metadata.st_gid,
                    "mode": stat.S_IMODE(python_library_metadata.st_mode),
                    "nlink": python_library_metadata.st_nlink,
                    "path": str(runtime.library),
                    "sha256": _sha256_file(runtime.library),
                    "size": python_library_metadata.st_size,
                    "uid": python_library_metadata.st_uid,
                },
                "stdlib": str(runtime.stdlib),
                "version": platform.python_version(),
            },
            "reproducible_build_count": 2,
            "runtime_manifest": {
                "path": (_PREFIX / _NATIVE_RELATIVE_PATH / _RUNTIME_MANIFEST_BASENAME).as_posix(),
                "schema": _RUNTIME_MANIFEST_SCHEMA,
                "sha256": _sha256_bytes(runtime_manifest),
                "size": len(runtime_manifest),
            },
            "schema": _BUILD_MANIFEST_SCHEMA,
            "source_manifest": {
                "path": (_PREFIX / _NATIVE_RELATIVE_PATH / _SOURCE_MANIFEST_BASENAME).as_posix(),
                "schema": _SOURCE_MANIFEST_SCHEMA,
                "sha256": _sha256_bytes(source_manifest),
                "size": len(source_manifest),
            },
            "sources": source_hashes,
            "trusted_time_prefix": _PREFIX.as_posix(),
        }
        build_manifest = _canonical_json(build_document)
        build_manifest_path = native_destination / _BUILD_MANIFEST_BASENAME
        _write_exclusive(build_manifest_path, build_manifest, 0o444)
        artifacts = {
            "build_manifest": _artifact_description(
                (_PREFIX / _NATIVE_RELATIVE_PATH / _BUILD_MANIFEST_BASENAME).as_posix(),
                build_manifest,
            ),
            "launcher": {
                "gid": 0,
                "mode": 0o555,
                "path": (_PREFIX / _LAUNCHER_RELATIVE_PATH).as_posix(),
                "sha256": launcher_hash,
                "size": launcher_size,
                "uid": 0,
            },
            "runtime_manifest": _artifact_description(
                (_PREFIX / _NATIVE_RELATIVE_PATH / _RUNTIME_MANIFEST_BASENAME).as_posix(),
                runtime_manifest,
            ),
            "source_manifest": _artifact_description(
                (_PREFIX / _NATIVE_RELATIVE_PATH / _SOURCE_MANIFEST_BASENAME).as_posix(),
                source_manifest,
            ),
        }
        receipt_document = {
            "activation_authorized": False,
            "artifacts": artifacts,
            "external_boundaries": {name: False for name in _EXTERNAL_BOUNDARIES},
            "profile": "admission",
            "schema": _INSTALL_RECEIPT_SCHEMA,
            "source_root": (_PREFIX / _SOURCE_RELATIVE_PATH).as_posix(),
            "status": "candidate_unactivated",
            "target_ids": list(_TARGET_IDS),
            "trusted_time_prefix": _PREFIX.as_posix(),
        }
        receipt = _canonical_json(receipt_document)
        if len(receipt) > _MAXIMUM_RECEIPT_BYTES:
            _fail("native admission install receipt exceeded its byte bound")
        receipt_path = native_destination / _INSTALL_RECEIPT_BASENAME
        _write_exclusive(receipt_path, receipt, 0o444)
        _lock_tree(
            output_directory,
            artifact_prefix=(_SOURCE_RELATIVE_PATH / "artifacts").as_posix(),
        )
        result: dict[str, object] = {
            "build_manifest_sha256": _sha256_bytes(build_manifest),
            "candidate_directory": str(output_directory),
            "compiler_scratch_directory": str(build_root),
            "receipt_path": str(receipt_path),
            "receipt_sha256": _sha256_bytes(receipt),
            "runtime_manifest_sha256": _sha256_bytes(runtime_manifest),
            "schema": _BUILD_RESULT_SCHEMA,
            "source_manifest_sha256": _sha256_bytes(source_manifest),
        }
        return result
    except BaseException:
        # A failed build is never an install candidate.  Keep the identity-recorded
        # output and compiler scratch directories for forensic inspection instead
        # of trying to repair or delete either retained residue.
        raise


def _snapshot_candidate_directory(
    path: Path,
    *,
    expected_owner: tuple[int, int] | None,
) -> os.stat_result:
    descriptor = _open_nofollow(path, directory=True)
    try:
        before = os.fstat(descriptor)
        path_after = path.lstat()
        if (
            not stat.S_ISDIR(before.st_mode)
            or (expected_owner is not None and (before.st_uid, before.st_gid) != expected_owner)
            or _identity(before) != _identity(path_after)
            or _fd_has_extended_metadata(descriptor)
        ):
            _fail("native admission candidate directory metadata is inconsistent")
        return before
    except OSError:
        _fail("native admission candidate directory could not be snapshotted")
    finally:
        os.close(descriptor)


def _snapshot_candidate_file(
    path: Path,
    *,
    expected_owner: tuple[int, int],
) -> tuple[os.stat_result, str]:
    descriptor = _open_nofollow(path)
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > _MAXIMUM_FILE_BYTES
            or (before.st_uid, before.st_gid) != expected_owner
            or _fd_has_extended_metadata(descriptor)
        ):
            _fail("native admission candidate file metadata is inconsistent")
        received = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, before.st_size + 1 - received),
            )
            if not chunk:
                break
            digest.update(chunk)
            received += len(chunk)
            if received > before.st_size:
                _fail("native admission candidate file grew during its snapshot")
        after = os.fstat(descriptor)
        path_after = path.lstat()
        if (
            received != before.st_size
            or _identity(before) != _identity(after)
            or _identity(before) != _identity(path_after)
        ):
            _fail("native admission candidate file changed during its snapshot")
        return before, digest.hexdigest()
    except OSError:
        _fail("native admission candidate file could not be snapshotted")
    finally:
        os.close(descriptor)


def _revalidate_candidate_identity(
    path: Path,
    expected_identity: tuple[int, ...],
    *,
    directory: bool,
) -> None:
    descriptor = _open_nofollow(path, directory=directory)
    try:
        opened = os.fstat(descriptor)
        path_metadata = path.lstat()
        if (
            _identity(opened) != expected_identity
            or _identity(path_metadata) != expected_identity
            or _fd_has_extended_metadata(descriptor)
        ):
            _fail("native admission candidate identity changed after its snapshot")
    except OSError:
        _fail("native admission candidate identity could not be revalidated")
    finally:
        os.close(descriptor)


def _candidate_payload_snapshot(
    root: Path,
) -> tuple[tuple[int, ...], tuple[tuple[object, ...], ...]]:
    records: list[tuple[object, ...]] = []
    root_metadata = _snapshot_candidate_directory(root, expected_owner=None)
    expected_owner = (root_metadata.st_uid, root_metadata.st_gid)
    if root_metadata.st_uid != os.geteuid() or stat.S_IMODE(root_metadata.st_mode) != 0o555:
        _fail("native admission candidate root metadata is inconsistent")
    observed_identities: list[tuple[Path, tuple[int, ...], bool]] = []

    def fail_walk(_error: OSError) -> Never:
        _fail("native admission candidate traversal was incomplete")

    for directory_name, directories, files in os.walk(
        root,
        topdown=True,
        onerror=fail_walk,
        followlinks=False,
    ):
        directories.sort()
        files.sort()
        directory = Path(directory_name)
        for name in directories:
            child_directory = directory / name
            relative_directory = child_directory.relative_to(root).as_posix()
            metadata = _snapshot_candidate_directory(
                child_directory,
                expected_owner=expected_owner,
            )
            observed_identities.append((child_directory, _identity(metadata), True))
            records.append(
                (
                    relative_directory,
                    "directory",
                    stat.S_IMODE(metadata.st_mode),
                    metadata.st_uid,
                    metadata.st_gid,
                )
            )
        for name in files:
            path = directory / name
            relative = path.relative_to(root).as_posix()
            metadata, digest = _snapshot_candidate_file(path, expected_owner=expected_owner)
            observed_identities.append((path, _identity(metadata), False))
            records.append(
                (
                    relative,
                    "file",
                    stat.S_IMODE(metadata.st_mode),
                    metadata.st_uid,
                    metadata.st_gid,
                    metadata.st_nlink,
                    metadata.st_size,
                    digest,
                )
            )
    for path, expected_identity, is_directory in observed_identities:
        _revalidate_candidate_identity(
            path,
            expected_identity,
            directory=is_directory,
        )
    _revalidate_candidate_identity(root, _identity(root_metadata), directory=True)
    return _identity(root_metadata), tuple(records)


def _open_directory_name_at(parent_descriptor: int, name: str) -> int:
    _validate_relative_path(name)
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_DIRECTORY", 0),
            dir_fd=parent_descriptor,
        )
    except OSError:
        _fail("native admission retained build directory could not be opened safely")
    return descriptor


def _publication_identity(identity: tuple[int, ...]) -> tuple[int, ...]:
    return identity[:7]


def _publish_candidate_noreplace(
    source: Path,
    destination: Path,
    *,
    expected_source_identity: tuple[int, ...],
) -> None:
    if source.parent != destination.parent:
        _fail("native admission candidate publication is not one sibling rename")
    _validate_relative_path(source.name)
    _validate_relative_path(destination.name)
    parent_descriptor = _open_nofollow(destination.parent, directory=True)
    source_descriptor = -1
    try:
        try:
            lexical_source = os.stat(
                source.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError:
            _fail("native admission publication source is unavailable")
        source_descriptor = _open_directory_name_at(parent_descriptor, source.name)
        opened_source = os.fstat(source_descriptor)
        if (
            _identity(lexical_source) != expected_source_identity
            or _identity(opened_source) != expected_source_identity
        ):
            _fail("native admission publication source changed after reproducibility review")
        libc = ctypes.CDLL(None, use_errno=True)
        source_bytes = os.fsencode(source.name)
        destination_bytes = os.fsencode(destination.name)
        system_name = platform.system()
        if system_name == "Linux":
            operation = getattr(libc, "renameat2", None)
            if operation is None:
                _fail("native admission builder lacks atomic no-replace rename")
            operation.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            )
            operation.restype = ctypes.c_int
            result = int(
                operation(
                    parent_descriptor,
                    source_bytes,
                    parent_descriptor,
                    destination_bytes,
                    1,
                )
            )
        elif system_name == "Darwin":
            operation = getattr(libc, "renameatx_np", None)
            if operation is None:
                _fail("native admission builder lacks atomic no-replace rename")
            operation.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            )
            operation.restype = ctypes.c_int
            result = int(
                operation(
                    parent_descriptor,
                    source_bytes,
                    parent_descriptor,
                    destination_bytes,
                    0x00000004,
                )
            )
        else:
            _fail("native admission builder platform is unsupported")
        if result != 0:
            _fail("native admission candidate could not be published without replacement")
        try:
            published = os.stat(
                destination.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError:
            _fail("native admission candidate publication outcome is unavailable")
        opened_after = os.fstat(source_descriptor)
        if _identity(published) != _identity(opened_after) or _publication_identity(
            _identity(published)
        ) != _publication_identity(expected_source_identity):
            _fail("native admission candidate publication identity is ambiguous")
        os.fsync(parent_descriptor)
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        os.close(parent_descriptor)


def _build_candidate(
    *,
    source_root: Path,
    runtime_candidate: Path,
    output_directory: Path,
    require_production_runtime: bool,
) -> dict[str, object]:
    _require_nonroot_builder()
    first, first_prebuild_identity = _make_identity_recorded_build_directory(
        parent=output_directory.parent,
        prefix=f".{output_directory.name}.build-a-",
    )
    second, second_prebuild_identity = _make_identity_recorded_build_directory(
        parent=output_directory.parent,
        prefix=f".{output_directory.name}.build-b-",
    )
    first_result = _build_candidate_once(
        source_root=source_root,
        runtime_candidate=runtime_candidate,
        output_directory=first,
        expected_output_identity=first_prebuild_identity,
        require_production_runtime=require_production_runtime,
    )
    second_result = _build_candidate_once(
        source_root=source_root,
        runtime_candidate=runtime_candidate,
        output_directory=second,
        expected_output_identity=second_prebuild_identity,
        require_production_runtime=require_production_runtime,
    )
    first_identity, first_snapshot = _candidate_payload_snapshot(first)
    _second_identity, second_snapshot = _candidate_payload_snapshot(second)
    if first_snapshot != second_snapshot:
        _fail("independent native admission candidate builds are not byte reproducible")
    if output_directory.exists() or output_directory.is_symlink():
        _fail("native admission output appeared during the reproducibility build")
    _publish_candidate_noreplace(
        first,
        output_directory,
        expected_source_identity=first_identity,
    )
    native_directory = output_directory.joinpath(*_NATIVE_RELATIVE_PATH.parts)
    receipt = _read_regular_bytes(
        native_directory / _INSTALL_RECEIPT_BASENAME,
        _MAXIMUM_RECEIPT_BYTES,
    )
    build_manifest = _read_regular_bytes(
        native_directory / _BUILD_MANIFEST_BASENAME,
        _MAXIMUM_BUILD_MANIFEST_BYTES,
    )
    source_manifest = _read_regular_bytes(
        native_directory / _SOURCE_MANIFEST_BASENAME,
        _MAXIMUM_MANIFEST_BYTES,
    )
    runtime_manifest = _read_regular_bytes(
        native_directory / _RUNTIME_MANIFEST_BASENAME,
        _MAXIMUM_MANIFEST_BYTES,
    )
    first_scratch = first_result.get("compiler_scratch_directory")
    second_scratch = second_result.get("compiler_scratch_directory")
    if type(first_scratch) is not str or type(second_scratch) is not str:
        _fail("native admission retained compiler scratch identity is unavailable")
    return {
        "build_manifest_sha256": _sha256_bytes(build_manifest),
        "candidate_directory": str(output_directory),
        "receipt_path": str(native_directory / _INSTALL_RECEIPT_BASENAME),
        "receipt_sha256": _sha256_bytes(receipt),
        "retained_non_authorizing_residue": {
            "authorizing": False,
            "comparison_equal": True,
            "comparison_fields": [
                "path",
                "type",
                "mode",
                "uid",
                "gid",
                "nlink",
                "size",
                "sha256",
            ],
            "directories": {
                "first_compiler_scratch": first_scratch,
                "second_candidate": str(second),
                "second_compiler_scratch": second_scratch,
            },
        },
        "runtime_manifest_sha256": _sha256_bytes(runtime_manifest),
        "schema": _BUILD_RESULT_SCHEMA,
        "source_manifest_sha256": _sha256_bytes(source_manifest),
    }


def _parse_arguments(argument_values: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-candidate", required=True)
    parser.add_argument("--output-directory", required=True)
    return parser.parse_args(tuple(argument_values))


def main(argument_values: Sequence[str] | None = None) -> int:
    _require_nonroot_builder()
    arguments = _parse_arguments(sys.argv[1:] if argument_values is None else argument_values)
    runtime_candidate = _canonical_existing_directory(
        arguments.runtime_candidate,
        "native admission runtime candidate",
    )
    output_directory = _canonical_new_directory(
        arguments.output_directory,
        "native admission output directory",
    )
    source_root = Path(__file__).resolve(strict=True).parents[1]
    result = _build_candidate(
        source_root=source_root,
        runtime_candidate=runtime_candidate,
        output_directory=output_directory,
        require_production_runtime=True,
    )
    sys.stdout.buffer.write(_canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
