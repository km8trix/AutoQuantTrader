from __future__ import annotations

import _imp
import ast
import dis
import errno
import fcntl
import gc
import importlib.machinery
import importlib.util
import inspect
import os
import pickle
import platform
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import sysconfig
import textwrap
import threading
import tomllib
import weakref
from collections.abc import Iterator
from pathlib import Path
from types import BuiltinFunctionType, CodeType, ModuleType
from typing import NamedTuple

import pytest

from build_support import build_native_test_launcher as native_test_builder
from packages.adapters.trusted_time import _owned_file_descriptor as owned_fd_module
from packages.adapters.trusted_time._owned_file_descriptor import (
    _acquire_trusted_time_launch_lock,
    _create_child_regular_exclusive,
    _fchmod_0600,
    _flock,
    _fstat,
    _fsync,
    _ftruncate,
    _list_snapshot,
    _native_owned_file_descriptor_capabilities,
    _native_owned_file_descriptor_self_test,
    _open_child_directory,
    _open_child_regular,
    _open_root_directory,
    _OwnedFileDescriptor,
    _read_snapshot,
    _rename_child_noreplace,
    _statat,
    _TrustedTimeLaunchLockLease,
    _validate_trusted_time_launch_lock,
    _write_all,
)

_MAX_NATIVE_BYTES = 16 * 1024 * 1024
_SUPERSEDED_DYNAMIC_LOADER_TEST = pytest.mark.skip(
    reason="the admitted launcher replaced the rejected dynamic-extension loader"
)


def _open_directory(path: Path) -> _OwnedFileDescriptor:
    absolute = path.resolve(strict=True)
    if not absolute.is_dir():
        raise NotADirectoryError(absolute)
    owner = _open_root_directory()
    try:
        for component in absolute.parts[1:]:
            next_owner = _open_child_directory(owner, component)
            owner.close()
            owner = next_owner
    except BaseException:
        owner.close()
        raise
    return owner


def _open_regular(path: Path) -> _OwnedFileDescriptor:
    directory = _open_directory(path.parent)
    try:
        return _open_child_regular(directory, path.name)
    finally:
        directory.close()


def _open_native_directory(native_module: ModuleType, path: Path) -> object:
    absolute = path.resolve(strict=True)
    owner = native_module._open_root_directory()
    try:
        for component in absolute.parts[1:]:
            next_owner = native_module._open_child_directory(owner, component)
            owner.close()
            owner = next_owner
    except BaseException:
        owner.close()
        raise
    return owner


def _base_python_executable() -> str:
    candidate = (
        Path(sys.base_prefix) / "bin" / f"python{sys.version_info.major}.{sys.version_info.minor}"
    )
    assert candidate.is_file() and not candidate.is_symlink()
    return str(candidate)


@pytest.fixture(scope="module")
def native_test_build(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[tuple[ModuleType, Path, Path]]:
    build_directory = tmp_path_factory.mktemp("native-owned-fd-test-build")
    source = Path(__file__).resolve().parents[2] / "native/owned_file_descriptor.c"
    suffix = sysconfig.get_config_var("EXT_SUFFIX")
    assert type(suffix) is str
    extension = build_directory / f"_native_owned_file_descriptor{suffix}"
    configured_compiler = sysconfig.get_config_var("CC")
    assert type(configured_compiler) is str
    compiler_words = shlex.split(configured_compiler)
    compiler = shutil.which(compiler_words[0])
    assert compiler is not None
    command = [
        compiler,
        "-std=c11",
        "-O2",
        "-fPIC",
        "-fvisibility=hidden",
        "-DAQT_NATIVE_TEST_HOOKS=1",
        f'-DAQT_NATIVE_EXTENSION_SUFFIX="{suffix}"',
        f"-I{sysconfig.get_path('include')}",
    ]
    if sys.platform == "darwin":
        sdk = subprocess.run(
            ["xcrun", "--show-sdk-path"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        command.extend(
            [
                "-arch",
                platform.machine(),
                "-isysroot",
                sdk,
                "-mmacosx-version-min=11.0",
                "-bundle",
                "-undefined",
                "dynamic_lookup",
            ]
        )
    else:
        command.extend(["-shared", "-pthread", "-Wl,-z,relro,-z,now,-z,noexecstack"])
    base_command = tuple(command)
    link_tail = (str(source), *(("-ldl",) if sys.platform == "linux" else ()), "-o")
    command = [
        *base_command,
        f'-DAQT_NATIVE_TEST_EXPECTED_ORIGIN="{extension}"',
        *link_tail,
        str(extension),
    ]
    compiler_environment = {**os.environ, "TMPDIR": str(build_directory)}
    subprocess.run(
        command,
        check=True,
        capture_output=True,
        env=compiler_environment,
    )
    failed_extension = build_directory / f"failed_exec_native_owned_file_descriptor{suffix}"
    failed_command = [
        *base_command,
        "-DAQT_NATIVE_TEST_FAIL_EXEC=1",
        f'-DAQT_NATIVE_TEST_EXPECTED_ORIGIN="{failed_extension}"',
        *link_tail,
        str(failed_extension),
    ]
    subprocess.run(
        failed_command,
        check=True,
        capture_output=True,
        env=compiler_environment,
    )

    module_name = "native_owned_fd_test._native_owned_file_descriptor"
    loader = importlib.machinery.ExtensionFileLoader(module_name, str(extension))
    spec = importlib.util.spec_from_file_location(module_name, extension, loader=loader)
    assert spec is not None
    native_module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = native_module
    try:
        loader.exec_module(native_module)
        yield native_module, extension, failed_extension
    finally:
        sys.modules.pop(module_name, None)


def _live_descriptors(limit: int = 512) -> set[int]:
    live: set[int] = set()
    for descriptor in range(limit):
        try:
            fcntl.fcntl(descriptor, fcntl.F_GETFD)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
        else:
            live.add(descriptor)
    return live


def _claim_monitoring_tool(label: str) -> int:
    for candidate in range(5, -1, -1):
        try:
            sys.monitoring.use_tool_id(candidate, label)
        except ValueError:
            continue
        return candidate
    pytest.skip("no sys.monitoring tool ID is available")


def _call_before_store_offset(code: CodeType, stored_name: str) -> int:
    instructions = tuple(dis.get_instructions(code))
    store_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname in {"STORE_FAST", "STORE_NAME"} and instruction.argval == stored_name
    )
    call = instructions[store_index - 1]
    assert call.opname == "CALL"
    return call.offset


def _create_unregistered_test_module(extension: Path, namespace: str) -> ModuleType:
    class _NativeTestExtensionSpec(NamedTuple):
        name: str
        origin: str

    module_name = f"{namespace}._native_owned_file_descriptor"
    assert module_name not in sys.modules
    spec = _NativeTestExtensionSpec(module_name, str(extension))
    candidate = _imp.create_dynamic(spec)
    assert type(candidate) is ModuleType
    assert module_name not in sys.modules
    return candidate


def test_multiphase_module_is_inert_before_exec_and_active_exactly_once(
    native_test_build: tuple[ModuleType, Path, Path],
) -> None:
    _active_module, extension, _failed_extension = native_test_build
    module = _create_unregistered_test_module(extension, "native_owned_fd_preexec")
    before = _live_descriptors()
    preexec_calls = (
        (module._open_root_directory, ()),
        (module._open_child_directory, ()),
        (module._open_child_regular, ()),
        (module._create_child_regular_exclusive, ()),
        (module._rename_child_noreplace, ()),
        (module._fstat, (object(),)),
        (module._statat, ()),
        (module._read_snapshot, ()),
        (module._list_snapshot, (object(),)),
        (module._flock, ()),
        (module._fsync, (object(),)),
        (module._write_all, ()),
        (module._ftruncate, ()),
        (module._fchmod_0600, (object(),)),
        (module._acquire_trusted_time_launch_lock, (str(Path.cwd()),)),
        (module._validate_trusted_time_launch_lock, (object(),)),
        (module._capabilities, ()),
        (module._self_test, ()),
        (module._force_second_exec_for_test, ()),
        (module._configure_post_close_test_hook, ()),
        (module._descriptor_number_for_test, (object(),)),
        (module._launch_lock_descriptor_number_for_test, (object(),)),
        (module._configure_stat_identity_allocation_failure_for_test, (object(),)),
    )
    for method, arguments in preexec_calls:
        with pytest.raises(RuntimeError, match="not active"):
            method(*arguments)
    assert _live_descriptors() == before
    assert _imp.exec_dynamic(module) == 0
    assert module.__name__ not in sys.modules
    assert module._self_test() is None
    with pytest.raises(ImportError, match="already initialized"):
        module._force_second_exec_for_test()


def test_failed_multiphase_exec_stays_unregistered_and_permanently_inert(
    native_test_build: tuple[ModuleType, Path, Path],
) -> None:
    _active_module, _extension, failed_extension = native_test_build
    module = _create_unregistered_test_module(
        failed_extension,
        "native_owned_fd_failed_exec",
    )
    before = _live_descriptors()
    with pytest.raises(ImportError, match="forced native module exec failure"):
        _imp.exec_dynamic(module)
    assert module.__name__ not in sys.modules
    with pytest.raises(RuntimeError, match="not active"):
        module._open_root_directory()
    assert _imp.exec_dynamic(module) == 0
    with pytest.raises(RuntimeError, match="not active"):
        module._self_test()
    assert module.__name__ not in sys.modules
    assert _live_descriptors() == before


def test_owner_is_exact_private_nonserializable_and_has_no_raw_fd(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"owned")
    owner = _open_regular(artifact)

    assert owned_fd_module.__all__ == ()
    assert type(owner) is _OwnedFileDescriptor
    assert owner.closed is False
    assert not hasattr(owner, "fileno")
    assert not hasattr(owner, "detach")
    assert " fd=" not in repr(owner)
    with pytest.raises(TypeError):
        _OwnedFileDescriptor()
    with pytest.raises(TypeError):

        class _ForbiddenOwnerSubclass(_OwnedFileDescriptor):  # type: ignore[misc]
            pass

    with pytest.raises(AttributeError):
        owner.arbitrary_attribute = True  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        owner.closed = True  # type: ignore[misc]
    with pytest.raises(TypeError):
        weakref.ref(owner)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(owner)

    owner.close()
    owner.close()
    assert owner.closed is True


def test_launch_lock_lease_is_exact_opaque_and_holds_one_descriptor(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "ignored"
    before = _live_descriptors()
    lease = _acquire_trusted_time_launch_lock(str(ignored_root))
    during = _live_descriptors()

    assert type(lease) is _TrustedTimeLaunchLockLease
    assert lease.closed is False
    assert during - before and len(during - before) == 1
    assert not hasattr(lease, "fileno")
    assert not hasattr(lease, "detach")
    assert " fd=" not in repr(lease)
    assert type(_acquire_trusted_time_launch_lock) is BuiltinFunctionType
    assert type(_validate_trusted_time_launch_lock) is BuiltinFunctionType
    assert not hasattr(_acquire_trusted_time_launch_lock, "__code__")
    assert not hasattr(_validate_trusted_time_launch_lock, "__code__")
    with pytest.raises(TypeError):
        _TrustedTimeLaunchLockLease()
    with pytest.raises(TypeError):

        class _ForbiddenLeaseSubclass(_TrustedTimeLaunchLockLease):  # type: ignore[misc]
            pass

    with pytest.raises(AttributeError):
        lease.arbitrary_attribute = True  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        lease.closed = True  # type: ignore[misc]
    with pytest.raises(TypeError):
        weakref.ref(lease)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(lease)
    with pytest.raises(TypeError, match="exact native owned"):
        _fstat(lease)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="exact native owned"):
        _flock(lease, fcntl.LOCK_UN)  # type: ignore[arg-type]

    assert _validate_trusted_time_launch_lock(lease) is None
    lease.close()
    lease.close()
    assert lease.closed is True
    assert _live_descriptors() == before
    with pytest.raises(OSError) as closed_lease:
        _validate_trusted_time_launch_lock(lease)
    assert closed_lease.value.errno == errno.EBADF


def test_launch_lock_acquire_creates_exact_artifacts_and_excludes_contenders(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "ignored"
    lock_parent = ignored_root / "trusted-time"
    lock_path = lock_parent / "trusted-time-launch.lock"
    first = _acquire_trusted_time_launch_lock(str(ignored_root))
    try:
        ignored_metadata = ignored_root.stat()
        parent_metadata = lock_parent.stat()
        lock_metadata = lock_path.stat()
        assert stat.S_ISDIR(ignored_metadata.st_mode)
        assert stat.S_IMODE(ignored_metadata.st_mode) == 0o700
        assert ignored_metadata.st_uid == os.geteuid()
        assert stat.S_ISDIR(parent_metadata.st_mode)
        assert stat.S_IMODE(parent_metadata.st_mode) == 0o700
        assert parent_metadata.st_uid == os.geteuid()
        assert stat.S_ISREG(lock_metadata.st_mode)
        assert stat.S_IMODE(lock_metadata.st_mode) == 0o600
        assert lock_metadata.st_uid == os.geteuid()
        assert lock_metadata.st_nlink == 1
        assert lock_metadata.st_size == 0
        with pytest.raises(BlockingIOError) as contention:
            _acquire_trusted_time_launch_lock(str(ignored_root))
        assert contention.value.errno in {errno.EACCES, errno.EAGAIN}

        # Directory link-count, size, mtime, and ctime are deliberately live.
        ignored_churn = ignored_root / "ignored-churn"
        parent_churn = lock_parent / "parent-churn"
        ignored_churn.write_bytes(b"")
        parent_churn.write_bytes(b"")
        ignored_churn.unlink()
        parent_churn.unlink()
        assert _validate_trusted_time_launch_lock(first) is None
    finally:
        first.close()

    second = _acquire_trusted_time_launch_lock(str(ignored_root))
    second.close()


def test_launch_lock_deallocation_releases_the_hidden_generation(tmp_path: Path) -> None:
    ignored_root = tmp_path / "ignored"
    before = _live_descriptors()
    lease = _acquire_trusted_time_launch_lock(str(ignored_root))
    lease_descriptors = _live_descriptors() - before
    assert len(lease_descriptors) == 1
    lease_descriptor = next(iter(lease_descriptors))

    del lease
    gc.collect()

    with pytest.raises(OSError) as closed_descriptor:
        fcntl.fcntl(lease_descriptor, fcntl.F_GETFD)
    assert closed_descriptor.value.errno == errno.EBADF
    replacement = _acquire_trusted_time_launch_lock(str(ignored_root))
    replacement.close()


def test_launch_lock_fresh_file_is_fchmoded_but_existing_wrong_mode_is_not_repaired(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "ignored"
    lock_parent = ignored_root / "trusted-time"
    lock_parent.mkdir(parents=True, mode=0o700)
    ignored_root.chmod(0o700)
    lock_parent.chmod(0o700)
    lock_path = lock_parent / "trusted-time-launch.lock"

    previous_umask = os.umask(0o777)
    try:
        lease = _acquire_trusted_time_launch_lock(str(ignored_root))
    finally:
        os.umask(previous_umask)
    lease.close()
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600

    lock_path.chmod(0o640)
    with pytest.raises(OSError) as invalid_mode:
        _acquire_trusted_time_launch_lock(str(ignored_root))
    assert invalid_mode.value.errno == errno.ESTALE
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o640


def test_launch_lock_root_admission_is_exact_utf8_and_creates_no_ancestors(
    tmp_path: Path,
) -> None:
    class _StringSubclass(str):
        pass

    valid_root = str(tmp_path / "ignored")
    for invalid in (
        "",
        "/",
        "relative",
        f"{valid_root}/",
        f"{tmp_path}//ignored",
        f"{tmp_path}/./ignored",
        f"{tmp_path}/../ignored",
        f"{tmp_path}/ignored\0suffix",
    ):
        with pytest.raises((TypeError, ValueError)):
            _acquire_trusted_time_launch_lock(invalid)
    with pytest.raises(TypeError, match="exact str"):
        _acquire_trusted_time_launch_lock(Path(valid_root))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="exact str"):
        _acquire_trusted_time_launch_lock(_StringSubclass(valid_root))
    with pytest.raises(UnicodeEncodeError):
        _acquire_trusted_time_launch_lock(f"{tmp_path}/\udcff")
    with pytest.raises(TypeError):
        _acquire_trusted_time_launch_lock(ignored_root=valid_root)  # type: ignore[call-arg]

    missing_ancestor = tmp_path / "missing" / "ignored"
    with pytest.raises(FileNotFoundError):
        _acquire_trusted_time_launch_lock(str(missing_ancestor))
    assert not (tmp_path / "missing").exists()

    wrong_mode = tmp_path / "wrong-mode"
    wrong_mode.mkdir(mode=0o755)
    wrong_mode.chmod(0o755)
    with pytest.raises(PermissionError):
        _acquire_trusted_time_launch_lock(str(wrong_mode))
    assert stat.S_IMODE(wrong_mode.stat().st_mode) == 0o755
    assert not (wrong_mode / "trusted-time").exists()


def test_launch_lock_validate_rejects_lock_and_directory_replacement_without_creation(
    tmp_path: Path,
) -> None:
    ignored_root = tmp_path / "ignored"
    lock_parent = ignored_root / "trusted-time"
    lock_path = lock_parent / "trusted-time-launch.lock"

    lock_lease = _acquire_trusted_time_launch_lock(str(ignored_root))
    retired_lock = lock_parent / "retired.lock"
    lock_path.rename(retired_lock)
    lock_path.write_bytes(b"")
    lock_path.chmod(0o600)
    try:
        with pytest.raises(OSError) as replaced_lock:
            _validate_trusted_time_launch_lock(lock_lease)
        assert replaced_lock.value.errno == errno.ESTALE
    finally:
        lock_lease.close()

    lock_path.unlink()
    retired_lock.unlink()
    metadata_lease = _acquire_trusted_time_launch_lock(str(ignored_root))
    lock_metadata = lock_path.stat()
    os.utime(
        lock_path,
        ns=(lock_metadata.st_atime_ns, lock_metadata.st_mtime_ns + 1_000_000),
    )
    try:
        with pytest.raises(OSError) as changed_lock_metadata:
            _validate_trusted_time_launch_lock(metadata_lease)
        assert changed_lock_metadata.value.errno == errno.ESTALE
    finally:
        metadata_lease.close()

    lock_path.unlink()
    parent_lease = _acquire_trusted_time_launch_lock(str(ignored_root))
    retired_parent = ignored_root / "retired-trusted-time"
    lock_parent.rename(retired_parent)
    try:
        with pytest.raises(FileNotFoundError):
            _validate_trusted_time_launch_lock(parent_lease)
        assert not lock_parent.exists()
        lock_parent.mkdir(mode=0o700)
        lock_path.write_bytes(b"")
        lock_path.chmod(0o600)
        with pytest.raises(OSError) as replaced_parent:
            _validate_trusted_time_launch_lock(parent_lease)
        assert replaced_parent.value.errno == errno.ESTALE
    finally:
        parent_lease.close()


def test_operation_specific_root_and_component_opens_are_exact(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"immutable")
    directory = _open_directory(tmp_path)
    owner = _open_child_regular(directory, b"artifact")

    payload, before, after = _read_snapshot(owner, 9)
    assert payload == b"immutable"
    assert before == after == _fstat(owner)
    assert type(before) is tuple and len(before) == 9
    assert all(type(field) is int for field in before)

    with pytest.raises(TypeError, match="exact native owned"):
        _open_child_regular(object(), "artifact")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="authority profile"):
        _open_child_regular(owner, "artifact")
    owner.close()
    directory.close()
    with pytest.raises(ValueError, match="closed"):
        _open_child_regular(directory, "artifact")


def test_component_paths_reject_conversion_traversal_and_symlink_following(
    tmp_path: Path,
) -> None:
    class _StringSubclass(str):
        pass

    class _BytesSubclass(bytes):
        pass

    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"target")
    link = tmp_path / "link"
    link.symlink_to(artifact.name)
    directory = _open_directory(tmp_path)
    try:
        for invalid in ("", ".", "..", "/", "../artifact", "a/b", "\0"):
            with pytest.raises((TypeError, ValueError)):
                _open_child_regular(directory, invalid)
        with pytest.raises(TypeError, match="exact str or bytes"):
            _open_child_regular(directory, _StringSubclass("artifact"))
        with pytest.raises(TypeError, match="exact str or bytes"):
            _open_child_regular(directory, _BytesSubclass(b"artifact"))
        with pytest.raises(OSError) as open_error:
            _open_child_regular(directory, "link")
        assert open_error.value.errno in {errno.ELOOP, errno.EMLINK}
        link_metadata = _statat(directory, "link")
        assert stat.S_ISLNK(link_metadata[2])
        with pytest.raises(FileNotFoundError):
            _open_child_regular(directory, "missing")
        with pytest.raises(NotADirectoryError):
            _open_child_directory(directory, "artifact")
    finally:
        directory.close()


def test_read_snapshot_is_offset_zero_stable_and_bounded(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"0123456789")
    owner = _open_regular(artifact)
    try:
        assert _read_snapshot(owner, 10)[0] == b"0123456789"
        assert _read_snapshot(owner, 10)[0] == b"0123456789"
        with pytest.raises(ValueError, match="exceeds"):
            _read_snapshot(owner, 9)
        with pytest.raises(TypeError, match="exact int"):
            _read_snapshot(owner, True)
        with pytest.raises(ValueError, match="admitted range"):
            _read_snapshot(owner, _MAX_NATIVE_BYTES + 1)
    finally:
        owner.close()


def test_directory_snapshot_is_sorted_bounded_and_deeply_immutable(tmp_path: Path) -> None:
    for name in ("zeta", "alpha", "middle"):
        (tmp_path / name).write_bytes(name.encode())
    directory = _open_directory(tmp_path)
    try:
        names, before, after = _list_snapshot(directory)
        assert names == ("alpha", "middle", "zeta")
        assert type(names) is tuple
        assert all(type(name) is str for name in names)
        assert before == after == _fstat(directory)
        with pytest.raises(ValueError, match="authority profile"):
            regular = _open_child_regular(directory, "alpha")
            try:
                _list_snapshot(regular)
            finally:
                regular.close()
    finally:
        directory.close()


def test_writer_profile_is_bounded_exact_and_cannot_mutate_read_authority(
    tmp_path: Path,
) -> None:
    class _BytesSubclass(bytes):
        pass

    class _IntegerSubclass(int):
        pass

    directory = _open_directory(tmp_path)
    writer = _create_child_regular_exclusive(directory, "candidate")
    try:
        _write_all(writer, b"candidate-payload")
        _ftruncate(writer, 9)
        _fchmod_0600(writer)
        _fsync(writer)
        payload, before, after = _read_snapshot(writer, 9)
        assert payload == b"candidate"
        assert before == after
        assert stat.S_IMODE(_fstat(writer)[2]) == 0o600
        with pytest.raises(TypeError, match="exact bytes"):
            _write_all(writer, _BytesSubclass(b"invalid"))
        with pytest.raises(TypeError, match="exact int"):
            _ftruncate(writer, _IntegerSubclass(0))
        with pytest.raises(ValueError, match="admitted range"):
            _ftruncate(writer, _MAX_NATIVE_BYTES + 1)
        with pytest.raises(FileExistsError):
            _create_child_regular_exclusive(directory, "candidate")
    finally:
        writer.close()

    reader = _open_child_regular(directory, "candidate")
    try:
        for operation in (
            lambda: _write_all(reader, b"x"),
            lambda: _ftruncate(reader, 0),
            lambda: _fchmod_0600(reader),
        ):
            with pytest.raises(ValueError, match="writable regular-file authority"):
                operation()
        with pytest.raises(ValueError, match="write bound"):
            _write_all(reader, b"x" * (_MAX_NATIVE_BYTES + 1))
    finally:
        reader.close()
        _fsync(directory)
        directory.close()


def test_owned_staging_rename_is_noreplace_and_identity_bound(tmp_path: Path) -> None:
    directory = _open_directory(tmp_path)
    first = _create_child_regular_exclusive(directory, "first-staging")
    try:
        _write_all(first, b"first")
        _fsync(first)
        first_identity = _fstat(first)
        _rename_child_noreplace(directory, first, "first-staging", "artifact")
        assert not (tmp_path / "first-staging").exists()
        assert _statat(directory, "artifact")[:7] == first_identity[:7]

        second = _create_child_regular_exclusive(directory, "second-staging")
        try:
            _write_all(second, b"second")
            _fsync(second)
            with pytest.raises(FileExistsError):
                _rename_child_noreplace(directory, second, "second-staging", "artifact")
            assert (tmp_path / "second-staging").read_bytes() == b"second"
            assert (tmp_path / "artifact").read_bytes() == b"first"
        finally:
            second.close()
    finally:
        first.close()
        directory.close()


def test_flock_is_native_nonblocking_and_accepts_directory_authority(tmp_path: Path) -> None:
    first = _open_directory(tmp_path)
    second = _open_directory(tmp_path)
    try:
        _flock(first, fcntl.LOCK_SH | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError) as contention:
            _flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert contention.value.errno in {errno.EACCES, errno.EAGAIN}
        _flock(first, fcntl.LOCK_UN)
        _flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _flock(second, fcntl.LOCK_UN)
        with pytest.raises(ValueError, match="nonblocking"):
            _flock(first, fcntl.LOCK_SH)
        with pytest.raises(TypeError, match="exact int"):
            _flock(first, True)
    finally:
        first.close()
        second.close()


def test_close_is_idempotent_and_concurrent(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"concurrent")
    owner = _open_regular(artifact)
    barrier = threading.Barrier(17)
    failures: list[BaseException] = []

    def close_owner() -> None:
        barrier.wait()
        try:
            owner.close()
        except BaseException as error:  # pragma: no cover - asserted empty
            failures.append(error)

    threads = [threading.Thread(target=close_owner) for _ in range(16)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=5)

    assert all(not thread.is_alive() for thread in threads)
    assert failures == []
    assert owner.closed is True
    owner.close()


def test_deallocation_closes_the_hidden_generation(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"deallocate")
    before = _live_descriptors()
    owner = _open_regular(artifact)
    during = _live_descriptors()
    assert before < during
    owner_descriptors = during - before
    assert len(owner_descriptors) == 1
    owner_descriptor = next(iter(owner_descriptors))

    del owner
    gc.collect()

    with pytest.raises(OSError) as closed_descriptor:
        fcntl.fcntl(owner_descriptor, fcntl.F_GETFD)
    assert closed_descriptor.value.errno == errno.EBADF


def test_every_native_open_alias_has_no_python_frame_and_call_store_is_safe(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"call-store")
    child_directory = tmp_path / "child"
    child_directory.mkdir()
    directory = _open_directory(tmp_path)

    assert type(_open_root_directory) is BuiltinFunctionType
    assert type(_open_child_directory) is BuiltinFunctionType
    assert type(_open_child_regular) is BuiltinFunctionType
    assert type(_create_child_regular_exclusive) is BuiltinFunctionType
    assert _open_root_directory is owned_fd_module._native_open_root_directory
    assert _open_child_directory is owned_fd_module._native_open_child_directory
    assert _open_child_regular is owned_fd_module._native_open_child_regular
    assert _create_child_regular_exclusive is owned_fd_module._native_create_child_regular_exclusive
    for native_open in (
        _open_root_directory,
        _open_child_directory,
        _open_child_regular,
        _create_child_regular_exclusive,
    ):
        assert not hasattr(native_open, "__code__")

    def interrupted_root() -> None:
        owner_after_store = _open_root_directory()
        owner_after_store.close()

    def interrupted_child_directory() -> None:
        owner_after_store = _open_child_directory(directory, "child")
        owner_after_store.close()

    def interrupted_child_regular() -> None:
        owner_after_store = _open_child_regular(directory, "artifact")
        owner_after_store.close()

    def interrupted_create() -> None:
        owner_after_store = _create_child_regular_exclusive(directory, "interrupted-candidate")
        owner_after_store.close()

    interrupted_functions = (
        interrupted_root,
        interrupted_child_directory,
        interrupted_child_regular,
        interrupted_create,
    )
    store_offsets = {
        function.__code__: next(
            instruction.offset
            for instruction in dis.get_instructions(function)
            if instruction.opname == "STORE_FAST" and instruction.argval == "owner_after_store"
        )
        for function in interrupted_functions
    }
    monitoring = sys.monitoring
    tool_id: int | None = None
    for candidate in range(5, -1, -1):
        try:
            monitoring.use_tool_id(candidate, "native-owned-fd-call-store-test")
        except ValueError:
            continue
        tool_id = candidate
        break
    if tool_id is None:
        directory.close()
        pytest.skip("no sys.monitoring tool ID is available")

    def interrupt_before_store(code: CodeType, instruction_offset: int) -> None:
        if store_offsets.get(code) == instruction_offset:
            raise KeyboardInterrupt

    monitoring.register_callback(tool_id, monitoring.events.INSTRUCTION, interrupt_before_store)
    try:
        for function in interrupted_functions:
            gc.collect()
            before = _live_descriptors()
            monitoring.set_local_events(
                tool_id,
                function.__code__,
                monitoring.events.INSTRUCTION,
            )
            try:
                with pytest.raises(KeyboardInterrupt):
                    function()
            finally:
                monitoring.set_local_events(tool_id, function.__code__, 0)
            gc.collect()
            assert _live_descriptors() == before
    finally:
        monitoring.register_callback(tool_id, monitoring.events.INSTRUCTION, None)
        monitoring.free_tool_id(tool_id)
        directory.close()


def test_post_kernel_close_interruption_never_retries_reused_number(
    native_test_build: tuple[ModuleType, Path, Path],
    tmp_path: Path,
) -> None:
    native_module, _extension, _failed_extension = native_test_build
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"generation")
    directory = _open_native_directory(native_module, tmp_path)
    owner = native_module._open_child_regular(directory, "artifact")
    directory.close()
    released_descriptor = native_module._descriptor_number_for_test(owner)
    ready_read, ready_write = os.pipe()
    resume_read, resume_write = os.pipe()
    replacements: list[int] = []
    native_module._configure_post_close_test_hook(ready_write, resume_read)

    def reuse_closed_generation() -> None:
        assert os.read(ready_read, 1) == b"1"
        replacement = os.open(artifact, os.O_RDONLY | os.O_CLOEXEC)
        replacements.append(replacement)
        os.write(resume_write, b"1")

    reuser = threading.Thread(target=reuse_closed_generation)
    reuser.start()
    try:
        with pytest.raises(KeyboardInterrupt):
            owner.close()
        reuser.join(timeout=5)
        assert not reuser.is_alive()
        assert replacements == [released_descriptor]
        replacement = replacements[0]
        assert os.fstat(replacement).st_ino == artifact.stat().st_ino
        owner.close()
        os.fstat(replacement)
    finally:
        for descriptor in (ready_read, ready_write, resume_read, resume_write):
            os.close(descriptor)
        for descriptor in replacements:
            os.close(descriptor)


def test_launch_lock_post_close_interruption_never_retries_reused_number(
    native_test_build: tuple[ModuleType, Path, Path],
    tmp_path: Path,
) -> None:
    native_module, _extension, _failed_extension = native_test_build
    ignored_root = tmp_path / "ignored"
    lock_path = ignored_root / "trusted-time" / "trusted-time-launch.lock"
    lease = native_module._acquire_trusted_time_launch_lock(str(ignored_root))
    released_descriptor = native_module._launch_lock_descriptor_number_for_test(lease)
    ready_read, ready_write = os.pipe()
    resume_read, resume_write = os.pipe()
    replacements: list[int] = []
    native_module._configure_post_close_test_hook(ready_write, resume_read)

    def reuse_closed_generation() -> None:
        assert os.read(ready_read, 1) == b"1"
        replacement = os.open(lock_path, os.O_RDONLY | os.O_CLOEXEC)
        replacements.append(replacement)
        os.write(resume_write, b"1")

    reuser = threading.Thread(target=reuse_closed_generation)
    reuser.start()
    try:
        with pytest.raises(KeyboardInterrupt):
            lease.close()
        reuser.join(timeout=5)
        assert not reuser.is_alive()
        assert replacements == [released_descriptor]
        replacement = replacements[0]
        assert os.fstat(replacement).st_ino == lock_path.stat().st_ino
        lease.close()
        os.fstat(replacement)
    finally:
        for descriptor in (ready_read, ready_write, resume_read, resume_write):
            os.close(descriptor)
        for descriptor in replacements:
            os.close(descriptor)


def test_stat_identity_allocation_failure_cleans_partial_tuple(
    native_test_build: tuple[ModuleType, Path, Path],
    tmp_path: Path,
) -> None:
    native_module, _extension, _failed_extension = native_test_build
    directory = _open_native_directory(native_module, tmp_path)
    native_module._configure_stat_identity_allocation_failure_for_test(4)
    try:
        with pytest.raises(MemoryError):
            native_module._fstat(directory)
        assert len(native_module._fstat(directory)) == 9
    finally:
        directory.close()


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin fdguard contract")
def test_darwin_guard_rejects_ordinary_close_in_subprocess(
    native_test_build: tuple[ModuleType, Path, Path],
    tmp_path: Path,
) -> None:
    _native_module, extension, _failed_extension = native_test_build
    script = r"""
import importlib.machinery
import importlib.util
import os
import pathlib
import sys

module_name = "native_guard_subprocess._native_owned_file_descriptor"
extension = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2]).resolve(strict=True)
loader = importlib.machinery.ExtensionFileLoader(module_name, str(extension))
spec = importlib.util.spec_from_file_location(module_name, extension, loader=loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)
owner = module._open_root_directory()
for component in target.parts[1:]:
    next_owner = module._open_child_directory(owner, component)
    owner.close()
    owner = next_owner
descriptor = module._descriptor_number_for_test(owner)
os.close(descriptor)
raise SystemExit(91)
"""
    completed = subprocess.run(
        [
            _base_python_executable(),
            "-I",
            "-B",
            "-c",
            script,
            str(extension),
            str(tmp_path),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=10,
        env={"PYTHONDONTWRITEBYTECODE": "1"},
    )

    assert completed.returncode == -signal.SIGKILL


@pytest.mark.skipif(not hasattr(os, "fork"), reason="native atfork contract is POSIX-only")
def test_atfork_child_invalidates_before_child_python(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"fork")
    owner = _open_regular(artifact)
    lease = _acquire_trusted_time_launch_lock(str(tmp_path / "ignored"))
    read_pipe, write_pipe = os.pipe()
    child_pid = os.fork()

    if child_pid == 0:
        os.close(read_pipe)
        child_ok = owner.closed and lease.closed
        try:
            _fstat(owner)
        except RuntimeError:
            pass
        else:
            child_ok = False
        try:
            _open_root_directory()
        except RuntimeError:
            pass
        else:
            child_ok = False
        try:
            _validate_trusted_time_launch_lock(lease)
        except RuntimeError:
            pass
        else:
            child_ok = False
        os.write(write_pipe, b"1" if child_ok else b"0")
        os.close(write_pipe)
        os._exit(0 if child_ok else 91)

    os.close(write_pipe)
    child_report = os.read(read_pipe, 1)
    os.close(read_pipe)
    waited_pid, wait_status = os.waitpid(child_pid, 0)
    try:
        assert waited_pid == child_pid
        assert os.waitstatus_to_exitcode(wait_status) == 0
        assert child_report == b"1"
        assert owner.closed is False
        assert lease.closed is False
        assert _read_snapshot(owner, 4)[0] == b"fork"
        assert _validate_trusted_time_launch_lock(lease) is None
    finally:
        lease.close()
        owner.close()


def test_capabilities_and_installed_binary_origin_are_exact() -> None:
    _native_owned_file_descriptor_self_test()
    expected_platform_close = (
        "darwin-fdguard-generation-close"
        if sys.platform == "darwin"
        else "linux-close-once-no-retry"
    )
    assert _native_owned_file_descriptor_capabilities() == (
        "cpython-c-extension-owned-fd-v4",
        "no-python-visible-descriptor",
        "atomic-owner-cell",
        "operation-specific-open-profiles",
        "o-cloexec-and-nofollow-mandatory",
        "native-owner-authority-syscalls",
        "bounded-offset-zero-read-write-snapshots",
        "bounded-sorted-directory-snapshot",
        "same-directory-native-noreplace-rename",
        "nonblocking-flock-and-fsync",
        "opaque-trusted-time-launch-lock-lease",
        "two-phase-current-path-launch-lock-validation",
        "pthread-atfork-child-sweep",
        expected_platform_close,
    )

    native_module = owned_fd_module._native_module
    assert set(vars(native_module)) == {
        "__doc__",
        "__name__",
        "_OwnedFileDescriptor",
        "_TrustedTimeLaunchLockLease",
        *owned_fd_module._NATIVE_FUNCTION_NAMES,
    }
    assert not hasattr(native_module, "_open")
    assert not hasattr(native_module, "_descriptor_number_for_test")
    assert not hasattr(native_module, "_configure_post_close_test_hook")
    assert not hasattr(native_module, "__file__")
    assert not hasattr(native_module, "__loader__")
    assert not hasattr(native_module, "__package__")
    assert not hasattr(native_module, "__spec__")
    assert owned_fd_module._NATIVE_MODULE_NAME not in sys.modules
    launcher_path = Path(sys.executable)
    assert launcher_path.name == "autoquant-trusted-time-python-test"
    assert launcher_path.is_file() and not launcher_path.is_symlink()
    binary = launcher_path.read_bytes()
    assert b"_descriptor_number_for_test" not in binary
    assert b"_configure_post_close_test_hook" not in binary
    assert b"_force_second_exec_for_test" not in binary
    assert b"_autoquant_native_owned_file_descriptor" in binary

    source_root = Path(__file__).resolve().parents[2]
    native_source = (source_root / "native/owned_file_descriptor.c").read_text()
    assert "Py_GetProgramFullPath()" in native_source
    assert "Py_GetPrefix" not in native_source
    assert "dladdr(" in native_source
    assert "AQT_NATIVE_EXTENSION_SUFFIX" in native_source
    assert "Py_MOD_MULTIPLE_INTERPRETERS_NOT_SUPPORTED" in native_source
    launcher_source = (source_root / "native/trusted_time_python_launcher.c").read_text()
    assert "PyImport_AppendInittab" in launcher_source
    assert "PyConfig_InitIsolatedConfig" in launcher_source
    assert "config.site_import = 0" in launcher_source
    assert "config.use_environment = 0" in launcher_source

    assert list(source_root.glob("packages/**/*.so")) == []
    assert list(source_root.glob("apps/**/*.so")) == []
    assert list(source_root.glob("scripts/**/*.so")) == []


@_SUPERSEDED_DYNAMIC_LOADER_TEST
def test_origin_boundary_rejects_symlink_hardlink_mode_and_rename_replacement(
    tmp_path: Path,
) -> None:
    prefix = tmp_path / "prefix"
    native_directory = prefix / "share/autoquant-trader/native"
    native_directory.mkdir(parents=True)
    original = native_directory / "original.so"
    original.write_bytes(b"binary")
    original.chmod(0o755)
    original_metadata = owned_fd_module._validate_prefix_file(
        str(original),
        expected_mode=0o755,
        prefix=str(prefix),
    )

    symlink = native_directory / "symlink.so"
    symlink.symlink_to(original.name)
    with pytest.raises(
        owned_fd_module._NativeOwnedFileDescriptorLoadError,
        match=r"canonical|symlink",
    ):
        owned_fd_module._validate_prefix_file(
            str(symlink),
            expected_mode=0o755,
            prefix=str(prefix),
        )

    hardlink = native_directory / "hardlink.so"
    os.link(original, hardlink)
    with pytest.raises(
        owned_fd_module._NativeOwnedFileDescriptorLoadError,
        match="singly-linked",
    ):
        owned_fd_module._validate_prefix_file(
            str(original),
            expected_mode=0o755,
            prefix=str(prefix),
        )
    hardlink.unlink()

    replacement = native_directory / "replacement.so"
    replacement.write_bytes(b"replacement")
    replacement.chmod(0o755)
    os.replace(replacement, original)
    with pytest.raises(
        owned_fd_module._NativeOwnedFileDescriptorLoadError,
        match="replaced",
    ):
        owned_fd_module._require_unchanged_file(str(original), original_metadata)

    native_directory.chmod(0o775)
    with pytest.raises(
        owned_fd_module._NativeOwnedFileDescriptorLoadError,
        match="group/world writable",
    ):
        owned_fd_module._validate_prefix_file(
            str(original),
            expected_mode=0o755,
            prefix=str(prefix),
        )


def _installed_attestation_path() -> Path:
    return (
        Path(sysconfig.get_path("data"))
        / "share/autoquant-trader/native/native_owned_file_descriptor.json"
    )


def _assert_frozen_json_tree(value: object) -> None:
    assert type(value) not in (dict, list, set)
    if type(value) is owned_fd_module._FrozenJsonObject:
        record = value
        assert type(record.fields) is tuple
        for key, field_value in record.fields:
            assert type(key) is str
            _assert_frozen_json_tree(field_value)
    elif type(value) is owned_fd_module._FrozenJsonArray:
        array = value
        assert type(array.values) is tuple
        for item in array.values:
            _assert_frozen_json_tree(item)
    else:
        assert value is None or type(value) in (bool, int, str)


@_SUPERSEDED_DYNAMIC_LOADER_TEST
def test_attestation_decoder_publishes_only_a_deeply_immutable_tree() -> None:
    record = owned_fd_module._read_attestation(str(_installed_attestation_path()))

    _assert_frozen_json_tree(record)
    with pytest.raises(AttributeError):
        record.fields = ()
    dynamic = owned_fd_module._exact_object(record, "dynamic")
    dependencies = owned_fd_module._frozen_object_value(dynamic, "dependencies")
    assert type(dependencies) is owned_fd_module._FrozenJsonArray
    with pytest.raises(AttributeError):
        dependencies.values = ()


@pytest.mark.parametrize(
    "mutation",
    (
        "source_sha256",
        "build_dependencies",
        "compile_command",
        "platform_architecture",
        "dependencies",
    ),
)
@_SUPERSEDED_DYNAMIC_LOADER_TEST
def test_attestation_freeze_rejects_initial_final_trace_ab_mutation(
    mutation: str,
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "native_owned_file_descriptor.json"
    candidate.write_bytes(_installed_attestation_path().read_bytes())
    freeze_code = owned_fd_module._freeze_json.__code__
    mutated_target: object | None = None
    original_value: object | None = None
    mutation_was_restored = False

    def trace_ab_mutation(frame: object, event: str, _argument: object) -> object:
        nonlocal mutated_target, mutation_was_restored, original_value
        if not hasattr(frame, "f_code") or frame.f_code is not freeze_code:  # type: ignore[attr-defined]
            return trace_ab_mutation
        value = frame.f_locals.get("value")  # type: ignore[attr-defined]
        if event == "call" and mutated_target is None:
            if mutation == "source_sha256" and type(value) is dict:
                if "source_sha256" in value:
                    mutated_target = value
                    original_value = value["source_sha256"]
                    value["source_sha256"] = "0" * 64
            elif mutation == "compile_command" and type(value) is list:
                if "-std=c11" in value:
                    mutated_target = value
                    original_value = tuple(value)
                    value.append("-DAQT_TRACE_FORGERY=1")
            elif mutation == "build_dependencies" and type(value) is list:
                if "hatchling==1.32.0" in value:
                    mutated_target = value
                    original_value = tuple(value)
                    value.append("forged-build-dependency==1")
            elif mutation == "platform_architecture" and type(value) is dict:
                if "architecture" in value:
                    mutated_target = value
                    original_value = value["architecture"]
                    value["architecture"] = "forged-architecture"
            elif (
                mutation == "dependencies"
                and type(value) is list
                and any(
                    type(item) is str and ("libSystem" in item or item.startswith("libc.so"))
                    for item in value
                )
            ):
                mutated_target = value
                original_value = tuple(value)
                value.append("libforged.so")
        elif event == "return" and value is mutated_target:
            if type(value) is dict:
                key = "source_sha256" if mutation == "source_sha256" else "architecture"
                value[key] = original_value
            else:
                assert type(value) is list and type(original_value) is tuple
                value[:] = original_value
            mutation_was_restored = True
        return trace_ab_mutation

    previous_trace = sys.gettrace()
    sys.settrace(trace_ab_mutation)
    try:
        with pytest.raises(
            owned_fd_module._NativeOwnedFileDescriptorLoadError,
            match="canonical JSON",
        ):
            owned_fd_module._read_attestation(str(candidate))
    finally:
        sys.settrace(previous_trace)

    assert mutated_target is not None
    assert mutation_was_restored is True


@_SUPERSEDED_DYNAMIC_LOADER_TEST
def test_loader_and_validator_have_no_mutable_authority_locals() -> None:
    admission_functions = (
        owned_fd_module._distribution_record_declares_exact_files,
        owned_fd_module._validate_attestation,
        owned_fd_module._load_native_module,
    )
    forbidden_nodes = (
        ast.Dict,
        ast.DictComp,
        ast.List,
        ast.ListComp,
        ast.Set,
        ast.SetComp,
    )
    for function in admission_functions:
        tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
        assert not any(isinstance(node, forbidden_nodes) for node in ast.walk(tree))
        assert not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"dict", "list", "set"}
            for node in ast.walk(tree)
        )


@_SUPERSEDED_DYNAMIC_LOADER_TEST
def test_loader_rejects_mutable_path_and_import_spec_substitutions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    mutable_path = Path(first)
    object.__setattr__(mutable_path, "_raw_paths", [str(second)])
    assert str(mutable_path) == str(second)
    with pytest.raises(
        owned_fd_module._NativeOwnedFileDescriptorLoadError,
        match="canonical",
    ):
        owned_fd_module._validate_prefix_file(  # type: ignore[arg-type]
            mutable_path,
            expected_mode=0o644,
            prefix=str(tmp_path),
        )

    class _WrongExtensionSpec(NamedTuple):
        name: str
        origin: str

    monkeypatch.setattr(owned_fd_module, "_FrozenExtensionSpec", _WrongExtensionSpec)
    with pytest.raises(
        owned_fd_module._NativeOwnedFileDescriptorLoadError,
        match="immutable extension spec",
    ):
        owned_fd_module._load_native_module()
    assert owned_fd_module._NATIVE_MODULE_NAME not in sys.modules


@_SUPERSEDED_DYNAMIC_LOADER_TEST
def test_frozen_extension_spec_class_and_import_builtins_are_identity_pinned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec_type = owned_fd_module._FrozenExtensionSpec
    spec = spec_type("module._native_owned_file_descriptor", "/immutable/origin.so")
    assert type(spec) is spec_type
    assert tuple(spec) == ("module._native_owned_file_descriptor", "/immutable/origin.so")
    with pytest.raises(AttributeError):
        object.__setattr__(spec, "origin", "/forged.so")

    original_origin_member = spec_type.origin
    type.__setattr__(spec_type, "origin", property(lambda _self: "/forged.so"))
    try:
        with pytest.raises(
            owned_fd_module._NativeOwnedFileDescriptorLoadError,
            match="immutable extension spec",
        ):
            owned_fd_module._load_native_module()
    finally:
        type.__setattr__(spec_type, "origin", original_origin_member)
    assert owned_fd_module._NATIVE_MODULE_NAME not in sys.modules

    monkeypatch.setattr(
        owned_fd_module,
        "_CREATE_DYNAMIC",
        owned_fd_module._EXEC_DYNAMIC,
    )
    with pytest.raises(
        owned_fd_module._NativeOwnedFileDescriptorLoadError,
        match="dynamic import primitive changed",
    ):
        owned_fd_module._load_native_module()
    assert owned_fd_module._NATIVE_MODULE_NAME not in sys.modules


@pytest.mark.parametrize("substitution", ("copied_native", "alternate_extension"))
@_SUPERSEDED_DYNAMIC_LOADER_TEST
def test_create_dynamic_call_descriptor_ab_substitution_never_activates(
    substitution: str,
    tmp_path: Path,
) -> None:
    suffix = sysconfig.get_config_var("EXT_SUFFIX")
    assert type(suffix) is str
    installed_native = (
        Path(sysconfig.get_path("data"))
        / "share/autoquant-trader/native"
        / f"_native_owned_file_descriptor{suffix}"
    )
    if substitution == "copied_native":
        alternate_name = owned_fd_module._NATIVE_MODULE_NAME
        alternate_origin_path = tmp_path / f"copied_native{suffix}"
        shutil.copy2(installed_native, alternate_origin_path)
        alternate_origin = str(alternate_origin_path)
    else:
        alternate_spec = importlib.util.find_spec("_cffi_backend")
        if alternate_spec is None or type(alternate_spec.origin) is not str:
            pytest.skip("no alternate installed CPython extension is available")
        alternate_name = "_cffi_backend"
        alternate_origin = os.path.realpath(alternate_spec.origin)

    loader_code = owned_fd_module._load_native_module.__code__
    create_call_offset = _call_before_store_offset(loader_code, "candidate")
    spec_type = owned_fd_module._FrozenExtensionSpec
    original_name_member = vars(spec_type)["name"]
    original_origin_member = vars(spec_type)["origin"]
    mutation_active = False
    mutation_observed = False
    mutation_restored = False
    tool_id = _claim_monitoring_tool("native-owned-fd-create-spec-ab-test")

    def restore_spec_members() -> None:
        nonlocal mutation_active, mutation_restored
        if mutation_active:
            type.__setattr__(spec_type, "name", original_name_member)
            type.__setattr__(spec_type, "origin", original_origin_member)
            mutation_active = False
            mutation_restored = True

    def mutate_only_during_create_call(code: CodeType, offset: int) -> None:
        nonlocal mutation_active, mutation_observed
        if code is not loader_code:
            return
        if offset == create_call_offset:
            type.__setattr__(
                spec_type,
                "name",
                property(lambda _spec: alternate_name),
            )
            type.__setattr__(
                spec_type,
                "origin",
                property(lambda _spec: alternate_origin),
            )
            mutation_active = True
            mutation_observed = True
        elif mutation_active:
            restore_spec_members()

    gc.collect()
    before = _live_descriptors()
    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        mutate_only_during_create_call,
    )
    sys.monitoring.set_local_events(
        tool_id,
        loader_code,
        sys.monitoring.events.INSTRUCTION,
    )
    expected_error = (
        "binary could not be initialized"
        if substitution == "copied_native"
        else "created module state is invalid"
    )
    try:
        with pytest.raises(
            owned_fd_module._NativeOwnedFileDescriptorLoadError,
            match=expected_error,
        ):
            owned_fd_module._load_native_module()
    finally:
        sys.monitoring.set_local_events(tool_id, loader_code, 0)
        sys.monitoring.register_callback(
            tool_id,
            sys.monitoring.events.INSTRUCTION,
            None,
        )
        sys.monitoring.free_tool_id(tool_id)
        restore_spec_members()

    gc.collect()
    assert mutation_observed is True
    assert mutation_restored is True
    assert vars(spec_type)["name"] is original_name_member
    assert vars(spec_type)["origin"] is original_origin_member
    assert owned_fd_module._NATIVE_MODULE_NAME not in sys.modules
    assert _live_descriptors() == before

    retry_module, _retry_owner_type, retry_functions = owned_fd_module._load_native_module()
    assert retry_functions[-1]() is None
    assert retry_module.__name__ == owned_fd_module._NATIVE_MODULE_NAME
    assert owned_fd_module._NATIVE_MODULE_NAME not in sys.modules


@_SUPERSEDED_DYNAMIC_LOADER_TEST
def test_load_native_module_async_instruction_sweep_leaves_no_namespace_or_fd() -> None:
    loader = owned_fd_module._load_native_module
    loader_code = loader.__code__
    create_call_offset = _call_before_store_offset(loader_code, "candidate")
    tool_id = _claim_monitoring_tool("native-owned-fd-loader-async-sweep")
    executed_offsets: list[int] = []

    def record_instruction(code: CodeType, offset: int) -> None:
        if code is loader_code:
            executed_offsets.append(offset)

    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        record_instruction,
    )
    sys.monitoring.set_local_events(
        tool_id,
        loader_code,
        sys.monitoring.events.INSTRUCTION,
    )
    recorded_module, _recorded_owner_type, recorded_functions = loader()
    assert recorded_functions[-1]() is None
    del recorded_module, recorded_functions
    critical_offsets = tuple(
        dict.fromkeys(offset for offset in executed_offsets if offset >= create_call_offset)
    )
    assert critical_offsets

    current_offset = -1
    current_exception: type[BaseException] = KeyboardInterrupt

    def interrupt_instruction(code: CodeType, offset: int) -> None:
        if code is loader_code and offset == current_offset:
            raise current_exception()

    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        interrupt_instruction,
    )
    gc.collect()
    baseline = _live_descriptors()
    try:
        for index, offset in enumerate(critical_offsets):
            current_offset = offset
            current_exception = KeyboardInterrupt if index % 2 == 0 else SystemExit
            with pytest.raises(current_exception):
                loader()
            gc.collect()
            assert owned_fd_module._NATIVE_MODULE_NAME not in sys.modules
            assert _live_descriptors() == baseline

            sys.monitoring.set_local_events(tool_id, loader_code, 0)
            retry_module, _retry_owner_type, retry_functions = loader()
            assert retry_functions[-1]() is None
            assert retry_module.__name__ == owned_fd_module._NATIVE_MODULE_NAME
            assert owned_fd_module._NATIVE_MODULE_NAME not in sys.modules
            del retry_module, retry_functions
            sys.monitoring.set_local_events(
                tool_id,
                loader_code,
                sys.monitoring.events.INSTRUCTION,
            )
    finally:
        sys.monitoring.set_local_events(tool_id, loader_code, 0)
        sys.monitoring.register_callback(
            tool_id,
            sys.monitoring.events.INSTRUCTION,
            None,
        )
        sys.monitoring.free_tool_id(tool_id)


@_SUPERSEDED_DYNAMIC_LOADER_TEST
def test_wrapper_module_init_async_instruction_sweep_never_registers_native() -> None:
    source = inspect.getsource(owned_fd_module)
    module_code = compile(source, "<owned-fd-wrapper-opcode-sweep>", "exec")
    instructions = tuple(dis.get_instructions(module_code))
    load_index = next(
        index
        for index, instruction in enumerate(instructions)
        if instruction.opname == "LOAD_NAME" and instruction.argval == "_load_native_module"
    )
    load_call = next(
        instruction
        for instruction in instructions[load_index + 1 :]
        if instruction.opname == "CALL"
    )
    tool_id = _claim_monitoring_tool("native-owned-fd-module-init-async-sweep")
    executed_offsets: list[int] = []

    def execute_wrapper() -> dict[str, object]:
        namespace: dict[str, object] = {
            "__name__": "owned_fd_wrapper_opcode_probe",
            "__package__": "packages.adapters.trusted_time",
        }
        exec(module_code, namespace)
        return namespace

    def record_instruction(code: CodeType, offset: int) -> None:
        if code is module_code:
            executed_offsets.append(offset)

    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        record_instruction,
    )
    sys.monitoring.set_local_events(
        tool_id,
        module_code,
        sys.monitoring.events.INSTRUCTION,
    )
    recorded_namespace = execute_wrapper()
    assert type(recorded_namespace["_open_root_directory"]) is BuiltinFunctionType
    del recorded_namespace
    critical_offsets = tuple(
        dict.fromkeys(offset for offset in executed_offsets if offset >= load_call.offset)
    )
    assert critical_offsets

    current_offset = -1
    current_exception: type[BaseException] = KeyboardInterrupt

    def interrupt_instruction(code: CodeType, offset: int) -> None:
        if code is module_code and offset == current_offset:
            raise current_exception()

    sys.monitoring.register_callback(
        tool_id,
        sys.monitoring.events.INSTRUCTION,
        interrupt_instruction,
    )
    gc.collect()
    baseline = _live_descriptors()
    try:
        for index, offset in enumerate(critical_offsets):
            current_offset = offset
            current_exception = KeyboardInterrupt if index % 2 == 0 else SystemExit
            with pytest.raises(current_exception):
                execute_wrapper()
            gc.collect()
            assert owned_fd_module._NATIVE_MODULE_NAME not in sys.modules
            assert _live_descriptors() == baseline

            sys.monitoring.set_local_events(tool_id, module_code, 0)
            retry_namespace = execute_wrapper()
            retry_self_test = retry_namespace["_native_self_test"]
            assert type(retry_self_test) is BuiltinFunctionType
            assert retry_self_test() is None
            assert owned_fd_module._NATIVE_MODULE_NAME not in sys.modules
            del retry_namespace, retry_self_test
            sys.monitoring.set_local_events(
                tool_id,
                module_code,
                sys.monitoring.events.INSTRUCTION,
            )
    finally:
        sys.monitoring.set_local_events(tool_id, module_code, 0)
        sys.monitoring.register_callback(
            tool_id,
            sys.monitoring.events.INSTRUCTION,
            None,
        )
        sys.monitoring.free_tool_id(tool_id)


@_SUPERSEDED_DYNAMIC_LOADER_TEST
def test_frozen_spec_has_one_exact_class_binding_and_no_mutable_loader_objects() -> None:
    source = inspect.getsource(owned_fd_module)
    tree = ast.parse(source)
    spec_classes = tuple(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == "_FrozenExtensionSpec"
    )
    assert len(spec_classes) == 1
    spec_class = spec_classes[0]
    assert len(spec_class.bases) == 1
    assert isinstance(spec_class.bases[0], ast.Name)
    assert spec_class.bases[0].id == "NamedTuple"
    assert tuple(
        statement.target.id
        for statement in spec_class.body
        if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name)
    ) == ("name", "origin")
    assert not any(
        isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign))
        and any(
            isinstance(target, ast.Name) and target.id == "_FrozenExtensionSpec"
            for target in (node.targets if isinstance(node, ast.Assign) else (node.target,))
        )
        for node in ast.walk(tree)
    )
    assert "pathlib" not in source
    assert "ExtensionFileLoader" not in source
    assert "ModuleSpec" not in source
    assert not any(
        isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Subscript)
            and isinstance(target.value, ast.Attribute)
            and isinstance(target.value.value, ast.Name)
            and target.value.value.id == "sys"
            and target.value.attr == "modules"
            for target in node.targets
        )
        for node in ast.walk(tree)
    )


def test_binary_trust_boundary_and_kcmp_deferral_are_explicit() -> None:
    documentation = owned_fd_module.__doc__
    assert documentation is not None
    assert "root-owned" in documentation and "read-only" in documentation
    assert "kcmp" in documentation and "defense in depth" in documentation
    assert "ctypes" in documentation and "/proc/self/fd" in documentation


@pytest.mark.skip(reason="superseded by the static-launcher packaging assertions")
def test_packaging_matrix_and_production_image_gate_are_explicit() -> None:
    source_root = Path(__file__).resolve().parents[2]
    dockerfile = (source_root / "infra/docker/trusted-time.Dockerfile").read_text()
    dockerignore = (source_root / "infra/docker/trusted-time.Dockerfile.dockerignore").read_text()
    manifest_source = (source_root / "build_support/native_image_manifest.py").read_text()
    constraints = (source_root / "build_support/native_build_constraints.txt").read_text()
    workflow = (source_root / ".github/workflows/ci.yml").read_text()
    pyproject_raw = (source_root / "pyproject.toml").read_bytes()
    pyproject = pyproject_raw.decode()
    pyproject_data = tomllib.loads(pyproject)

    expected_build_dependencies = (
        "hatchling==1.32.0",
        "packaging==26.3",
        "pathspec==1.1.1",
        "pluggy==1.6.0",
        "tomlkit==0.15.1",
        "trove-classifiers==2026.6.1.19",
    )

    assert "AS trusted-time-supervisor-build" in dockerfile
    assert (
        "ARG PYTHON_BUILDER_IMAGE=python:3.12.13-bookworm@sha256:"
        "3cd9086bdb30f7c9bc08a3fa621d9842e0d3f6f9291aeb4677e0547817c10b12" in dockerfile
    )
    assert "FROM ${PYTHON_BUILDER_IMAGE} AS trusted-time-supervisor-build" in dockerfile
    assert "apt-get" not in dockerfile
    assert "BINUTILS_VERSION" not in dockerfile
    assert "GCC_VERSION" not in dockerfile
    assert "LIBC6_DEV_VERSION" not in dockerfile
    assert "75e997ec62297a6484f491bae28ab0ccb489daba23e398fd10fe68e9e6f0def8" in dockerfile
    assert "dc53dbc5a583d03ae8ed6272ca9afc0f58873f9f9b86dd7d448b17fb3f88a8d0" in dockerfile
    assert "729ef157f6026e6e1b3104593f87dddc597c3b83b60c7c2965878c62a56c6f7d" in dockerfile
    assert "UV_COMPILE_BYTECODE=1" not in dockerfile
    assert dockerfile.count("UV_COMPILE_BYTECODE=0") == 2
    assert 'LD_LIBRARY_PATH=""' in dockerfile
    assert 'LD_PRELOAD=""' in dockerfile
    assert "autoquant-native-image-manifest.py" in dockerfile
    assert "chmod 0550 /var/cache/apt/archives/partial" in dockerfile
    assert "os.chmod(extension, 0o555)" in dockerfile
    assert "os.chmod(attestation, 0o444)" in dockerfile
    assert "write / /etc/autoquant/native/executable-import-manifest.jsonl" in dockerfile
    assert "verify / /etc/autoquant/native/executable-import-manifest.jsonl" in dockerfile
    manifest_invocation = (
        "/usr/local/bin/python -I -B -S \\\n"
        "        /usr/local/lib/autoquant-native-image-manifest.py"
    )
    assert dockerfile.count(manifest_invocation) == 2
    assert dockerfile.index("write / /etc/autoquant/native/executable-import-manifest.jsonl") < (
        dockerfile.index("_native_owned_file_descriptor_self_test()")
    )
    assert "/opt/venv/bin/python -I -B -S -c" in dockerfile
    assert 'startup_hook = "/opt/venv/lib/python3.12/site-packages/_virtualenv.pth"' in dockerfile
    assert "os.unlink(startup_hook)" in dockerfile
    assert "_native_owned_file_descriptor_self_test()" in dockerfile
    assert "build_support/native_owned_file_descriptor_hook.py" in dockerignore
    assert "build_support/native_image_manifest.py" in dockerignore
    assert "build_support/native_build_constraints.txt" in dockerignore
    assert "native/owned_file_descriptor.c" in dockerignore

    assert "autoquant-native-executable-image-manifest-v2" in manifest_source
    assert "metadata.st_uid != 0" in manifest_source
    assert "metadata.st_gid != 0" in manifest_source
    assert "metadata.st_nlink != 1" in manifest_source
    assert "stat.S_IMODE(metadata.st_mode) != 0o555" in manifest_source
    assert '_EXCLUDED_TOP_LEVEL = frozenset(("dev", "proc", "sys", "tmp"))' in manifest_source
    assert '"run/chrony"' in manifest_source
    assert 'b"PyInit_" + b"_native_owned_file_descriptor"' in manifest_source
    assert 'b"PyInit__native_owned_file_descriptor"' not in manifest_source
    assert "contains_initializer = _contains_initializer(entry.path)" in manifest_source
    assert 'entry.name.endswith(".pth")' in manifest_source
    assert '"sitecustomize.py"' in manifest_source
    assert '"usercustomize.py"' in manifest_source
    assert '"etc/mtab"' in manifest_source
    assert "O_EXCL | os.O_CLOEXEC" in manifest_source

    assert "native-packaging:" in workflow
    assert "ubuntu-24.04" in workflow and "macos-14" in workflow
    assert 'python-version:\n          - "3.12.13"\n          - "3.13.3"' in workflow
    assert 'SOURCE_DATE_EPOCH: "0"' in workflow
    assert "Require byte-for-byte reproducible wheels" in workflow
    assert "--no-install-project" in workflow and "--no-deps" in workflow
    assert 'requires-python = ">=3.12,<3.14"' in pyproject
    assert tuple(pyproject_data["build-system"]["requires"]) == expected_build_dependencies
    assert (
        tuple(pyproject_data["tool"]["uv"]["build-constraint-dependencies"])
        == expected_build_dependencies
    )
    sdist_force_include = pyproject_data["tool"]["hatch"]["build"]["targets"]["sdist"][
        "force-include"
    ]
    assert frozenset(sdist_force_include) == frozenset(
        (
            "build_support/native_build_constraints.txt",
            "build_support/native_image_manifest.py",
            "build_support/native_owned_file_descriptor_hook.py",
            "native/owned_file_descriptor.c",
        )
    )
    constraint_projects = tuple(re.findall(r"(?m)^([a-z0-9-]+)==[^ ]+ \\$", constraints))
    assert constraint_projects == tuple(
        dependency.partition("==")[0] for dependency in expected_build_dependencies
    )
    assert constraints.count("--hash=sha256:") == 2 * len(expected_build_dependencies)

    architecture_job = workflow.split("\n  architecture:\n", 1)[1].split("\n  backend:\n", 1)[0]
    backend_job = workflow.split("\n  backend:\n", 1)[1].split("\n  native-packaging:\n", 1)[0]
    native_job = workflow.split("\n  native-packaging:\n", 1)[1].split("\n  frontend:\n", 1)[0]
    container_job = workflow.split("\n  containers:\n", 1)[1]
    isolated_checker_flags = (
        "uv run\n"
        "          --isolated\n"
        "          --no-project\n"
        "          --no-config\n"
        "          --offline\n"
        "          --no-python-downloads\n"
    )
    assert isolated_checker_flags in architecture_job
    assert "--python 3.12" in architecture_job
    assert "UV_BUILD_CONSTRAINT" not in architecture_job
    assert "uv sync" not in architecture_job and "uv build" not in architecture_job
    assert "needs:\n      - architecture" in backend_job
    assert "needs:\n      - architecture" in native_job
    assert backend_job.count(isolated_checker_flags) == 2
    assert "UV_BUILD_CONSTRAINT: build_support/native_build_constraints.txt" in backend_job
    assert backend_job.index("uv sync --all-groups --locked") < backend_job.index(
        isolated_checker_flags
    )
    assert "uv sync --all-groups --locked --no-install-project --no-build" in backend_job
    assert backend_job.count("--build-constraints build_support/native_build_constraints.txt") == 2
    assert backend_job.count("--require-hashes") == 2
    assert native_job.count(isolated_checker_flags) == 2
    assert "UV_BUILD_CONSTRAINT: build_support/native_build_constraints.txt" in native_job
    assert native_job.index("uv sync --all-groups --locked") < native_job.index(
        isolated_checker_flags
    )
    assert native_job.index("uv build --sdist") < native_job.rindex(isolated_checker_flags)
    assert "uv sync --all-groups --locked --no-install-project --no-build" in native_job
    assert native_job.count("--build-constraints build_support/native_build_constraints.txt") == 3
    assert native_job.count("--require-hashes") == 3
    assert container_job.count(isolated_checker_flags) == 2
    assert "UV_BUILD_CONSTRAINT: build_support/native_build_constraints.txt" in container_job
    assert "TRUSTED_TIME_PYTHON: .venv/bin/python -I -B" in container_job
    assert "uv sync --all-groups --locked --no-install-project --no-build" in container_job
    assert (
        container_job.count("--build-constraints build_support/native_build_constraints.txt") == 2
    )
    assert container_job.count("--require-hashes") == 2
    assert "uv run\n          --isolated\n          --locked" not in container_job
    assert ".venv/bin/python -B scripts/verify_paper_preflight_image.py" in container_job


def test_image_manifest_receipt_and_initializer_scan_are_exact(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[2] / "build_support/native_image_manifest.py"
    spec = importlib.util.spec_from_file_location("aqt_native_image_manifest_test", source)
    assert spec is not None and spec.loader is not None
    manifest_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manifest_module)

    manifest_module._HASH_CHUNK_BYTES = 8
    initializer = b"PyInit_" + b"_native_owned_file_descriptor"
    candidate = tmp_path / "candidate.so"
    candidate.write_bytes(b"1234567" + initializer + b"tail")

    assert manifest_module._contains_initializer(str(candidate)) is True
    assert initializer not in source.read_bytes()
    assert manifest_module._NATIVE_LAUNCHER_RELATIVE_PATH == (
        "opt/autoquant/trusted-time/bin/autoquant-trusted-time-python"
    )
    assert manifest_module._receipt("0" * 64) == (
        b'{"manifest_sha256":"'
        + b"0" * 64
        + b'","schema":"autoquant-native-executable-image-manifest-v2"}\n'
    )


def test_image_manifest_scans_every_regular_file_for_native_initializer(
    tmp_path: Path,
) -> None:
    source = Path(__file__).resolve().parents[2] / "build_support/native_image_manifest.py"
    spec = importlib.util.spec_from_file_location("aqt_native_image_manifest_xattr_test", source)
    assert spec is not None and spec.loader is not None
    manifest_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manifest_module)
    if not hasattr(os, "listxattr"):
        manifest_module._reject_extended_metadata = lambda _path: None

    hidden = tmp_path / "suffixless-native"
    hidden.write_bytes(b"prefix" + b"PyInit_" + b"_native_owned_file_descriptor")
    hidden.chmod(0o400)
    with pytest.raises(
        manifest_module.NativeImageManifestError,
        match="initializer exists outside",
    ):
        tuple(manifest_module._walk(str(tmp_path), "expected/launcher"))


def test_image_manifest_rejects_extended_metadata(tmp_path: Path) -> None:
    if not hasattr(os, "setxattr") or not hasattr(os, "listxattr"):
        pytest.skip("extended attributes are unavailable")
    source = Path(__file__).resolve().parents[2] / "build_support/native_image_manifest.py"
    spec = importlib.util.spec_from_file_location("aqt_native_image_manifest_xattr_test", source)
    assert spec is not None and spec.loader is not None
    manifest_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manifest_module)

    candidate = tmp_path / "extended-metadata"
    candidate.write_bytes(b"ordinary")
    try:
        os.setxattr(candidate, "user.autoquant-test", b"forbidden")
    except OSError:
        pytest.skip("the test filesystem does not admit extended attributes")
    with pytest.raises(
        manifest_module.NativeImageManifestError,
        match="extended metadata",
    ):
        tuple(manifest_module._walk(str(tmp_path), "expected/launcher"))


def test_site_pth_runs_without_no_site_and_is_rejected_by_manifest(
    tmp_path: Path,
) -> None:
    environment = tmp_path / "venv"
    subprocess.run(
        [
            _base_python_executable(),
            "-I",
            "-B",
            "-m",
            "venv",
            "--without-pip",
            str(environment),
        ],
        check=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    interpreter = environment / "bin/python"
    site_packages = (
        environment
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    startup_sentinel = tmp_path / "startup-sentinel"
    payload_sentinel = tmp_path / "payload-sentinel"
    startup_hook = site_packages / "malicious-exit-zero.pth"
    startup_hook.write_text(
        f"import os; open({str(startup_sentinel)!r}, 'w').write('pth'); os._exit(0)\n"
    )
    payload_code = f"open({str(payload_sentinel)!r}, 'w').write('payload')"

    unsafe = subprocess.run(
        [str(interpreter), "-I", "-B", "-c", payload_code],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert unsafe.returncode == 0
    assert startup_sentinel.read_text() == "pth"
    assert not payload_sentinel.exists()

    startup_sentinel.unlink()
    safe = subprocess.run(
        [str(interpreter), "-I", "-B", "-S", "-c", payload_code],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert safe.returncode == 0
    assert not startup_sentinel.exists()
    assert payload_sentinel.read_text() == "payload"

    source = Path(__file__).resolve().parents[2] / "build_support/native_image_manifest.py"
    spec = importlib.util.spec_from_file_location("aqt_native_image_manifest_pth_test", source)
    assert spec is not None and spec.loader is not None
    manifest_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manifest_module)
    if not hasattr(os, "listxattr"):
        manifest_module._reject_extended_metadata = lambda _path: None
    with pytest.raises(manifest_module.NativeImageManifestError, match="startup hook"):
        tuple(manifest_module._walk(str(tmp_path), "missing-native-extension.so"))


def test_project_independent_uv_bootstrap_does_not_load_a_malicious_hook(
    tmp_path: Path,
) -> None:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to exercise the CI bootstrap boundary")

    sentinel = tmp_path / "PROJECT_HOOK_EXECUTED"
    (tmp_path / "pyproject.toml").write_text(
        textwrap.dedent(
            """
            [build-system]
            requires = ["hatchling==1.32.0"]
            build-backend = "hatchling.build"

            [project]
            name = "malicious-bootstrap-probe"
            version = "0.0.0"
            requires-python = ">=3.12,<3.14"

            [tool.hatch.build.targets.wheel.hooks.custom]
            path = "malicious_hook.py"
            """
        ).lstrip()
    )
    (tmp_path / "malicious_hook.py").write_text(
        textwrap.dedent(
            """
            from pathlib import Path

            Path("PROJECT_HOOK_EXECUTED").write_text("project hook was imported")

            from hatchling.builders.hooks.plugin.interface import BuildHookInterface


            class CustomBuildHook(BuildHookInterface):
                pass
            """
        ).lstrip()
    )
    checker = tmp_path / "bootstrap_checker.py"
    checker.write_text('print("project-independent-checker-ran")\n')

    completed = subprocess.run(
        [
            uv,
            "run",
            "--isolated",
            "--no-project",
            "--no-config",
            "--offline",
            "--no-python-downloads",
            "--python",
            _base_python_executable(),
            "python",
            "-I",
            "-B",
            str(checker),
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "UV_CACHE_DIR": str(tmp_path / "uv-cache"),
        },
    )

    assert completed.stdout.strip() == "project-independent-checker-ran"
    assert completed.stderr == ""
    assert not sentinel.exists()


def test_static_launcher_wrapper_has_no_dynamic_loader_or_owner_return_frame() -> None:
    source = inspect.getsource(owned_fd_module)
    tree = ast.parse(source)

    assert "_load_native_module" not in source
    assert "ExtensionFileLoader" not in source
    assert "create_dynamic" not in source
    assert "_FrozenExtensionSpec" not in source
    assert owned_fd_module._NATIVE_MODULE_NAME not in sys.modules
    for operation_name in (
        "_open_root_directory",
        "_open_child_directory",
        "_open_child_regular",
        "_create_child_regular_exclusive",
        "_rename_child_noreplace",
    ):
        operation = getattr(owned_fd_module, operation_name)
        native_operation = getattr(owned_fd_module, f"_native{operation_name}")
        assert operation is native_operation
        assert type(operation) is BuiltinFunctionType
        assert not hasattr(operation, "__code__")
    assert not any(
        isinstance(node, ast.FunctionDef)
        and node.name.startswith("_open_")
        and not any(
            isinstance(parent, ast.If)
            and isinstance(parent.test, ast.Name)
            and parent.test.id == "TYPE_CHECKING"
            and node in parent.body
            for parent in ast.walk(tree)
        )
        for node in ast.walk(tree)
    )


def test_ordinary_python_cannot_bootstrap_the_private_wrapper() -> None:
    wrapper = Path(owned_fd_module.__file__).resolve(strict=True)
    probe = textwrap.dedent(
        """
        import runpy
        import sys

        try:
            runpy.run_path(sys.argv[1])
        except ImportError as error:
            if "requires the admitted launcher" in str(error):
                raise SystemExit(0)
        raise SystemExit(91)
        """
    )

    completed = subprocess.run(
        [_base_python_executable(), "-I", "-B", "-c", probe, str(wrapper)],
        check=False,
        capture_output=True,
        text=True,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
    )

    assert completed.returncode == 0, completed.stderr


def test_static_launcher_profiles_and_sdist_inputs_are_exact() -> None:
    source_root = Path(__file__).resolve().parents[2]
    launcher = (source_root / "native/trusted_time_python_launcher.c").read_text()
    hook = (source_root / "build_support/native_owned_file_descriptor_hook.py").read_text()
    dockerfile = (source_root / "infra/docker/trusted-time.Dockerfile").read_text()
    dockerignore = (source_root / "infra/docker/trusted-time.Dockerfile.dockerignore").read_text()
    workflow = (source_root / ".github/workflows/ci.yml").read_text()
    project = tomllib.loads((source_root / "pyproject.toml").read_text())

    assert "AQT_NATIVE_LAUNCHER_OPERATIONAL_PROFILE" in launcher
    assert "AQT_NATIVE_LAUNCHER_ADMISSION_PROFILE" in launcher
    assert "AQT_NATIVE_LAUNCHER_TEST_PROFILE" in launcher
    assert "#include <signal.h>" in launcher
    assert "struct sigaction disposition;" in launcher
    assert "disposition.sa_handler = SIG_IGN;" in launcher
    assert "sigemptyset(&disposition.sa_mask) < 0" in launcher
    assert "sigaction(SIGPIPE, &disposition, NULL) < 0" in launcher
    assert launcher.count("aqt_ignore_sigpipe_before_python();") == 1
    assert launcher.index("aqt_ignore_sigpipe_before_python();") < launcher.index(
        "PyConfig_InitIsolatedConfig(&config);"
    )
    assert "config.install_signal_handlers = 1" not in launcher
    assert launcher.count("Py_RunMain()") == 1
    assert '"test-suite", "pytest", "console_main"' in launcher
    assert '"supervisor", "apps.trusted_time_supervisor.main", "main"' in launcher
    assert '"verify-images-build"' in launcher
    assert "operational policy targets do not accept arguments" in launcher
    operational_targets = launcher.split(
        "#elif defined(AQT_NATIVE_LAUNCHER_OPERATIONAL_PROFILE)",
        maxsplit=1,
    )[1].split("#elif defined(AQT_NATIVE_LAUNCHER_TEST_PROFILE)", maxsplit=1)[0]
    admission_targets = launcher.split(
        "#ifdef AQT_NATIVE_LAUNCHER_ADMISSION_PROFILE",
        maxsplit=1,
    )[1].split("#elif defined(AQT_NATIVE_LAUNCHER_OPERATIONAL_PROFILE)", maxsplit=1)[0]
    test_targets = launcher.split(
        "#elif defined(AQT_NATIVE_LAUNCHER_TEST_PROFILE)",
        maxsplit=1,
    )[1].split("#endif", maxsplit=1)[0]
    assert (
        '{"verify-images-build", "scripts.verify_trusted_time_images", NULL, "--build", 1},'
        in test_targets
    )
    assert "if (argument_count != 2)" in launcher
    target_pattern = re.compile(
        r'\{\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]+)",\s*'
        r'(NULL|"[^"]+"),\s*([01])\s*\}'
    )
    first_enrollment_release_targets = {
        target[0]: target[1:]
        for target in target_pattern.findall(operational_targets)
        if target[0].startswith("first-enrollment-")
    }
    assert first_enrollment_release_targets == {
        "first-enrollment-recovery-release": (
            "apps.trusted_time_supervisor.first_enrollment",
            "release_main",
            '"--recover-pending"',
            "0",
        ),
        "first-enrollment-release": (
            "apps.trusted_time_supervisor.first_enrollment",
            "release_main",
            "NULL",
            "0",
        ),
    }
    fixed_read_targets = {
        target[0]: target[1:]
        for target in target_pattern.findall(operational_targets)
        if target[0]
        in {
            "image-schema-contract",
            "post-enrollment-persistent-barrier-read",
            "post-enrollment-pre-effect-runtime-absence",
            "post-enrollment-staged-barrier-read",
        }
    }
    assert fixed_read_targets == {
        "image-schema-contract": (
            "apps.trusted_time_supervisor.image_schema_contract",
            "schema_contract_main",
            "NULL",
            "0",
        ),
        "post-enrollment-persistent-barrier-read": (
            "apps.trusted_time_supervisor.post_enrollment_read_probes",
            "persistent_barrier_main",
            "NULL",
            "0",
        ),
        "post-enrollment-pre-effect-runtime-absence": (
            "apps.trusted_time_supervisor.post_enrollment_read_probes",
            "pre_effect_runtime_absence_main",
            "NULL",
            "0",
        ),
        "post-enrollment-staged-barrier-read": (
            "apps.trusted_time_supervisor.post_enrollment_read_probes",
            "staged_barrier_main",
            "NULL",
            "0",
        ),
    }
    for target_id in fixed_read_targets:
        assert target_id not in admission_targets
        assert target_id not in test_targets
    assert "config.site_import = 0" in launcher
    assert "config.use_environment = 0" in launcher
    assert "config.module_search_paths_set = 1" in launcher
    assert "PyImport_AppendInittab" in launcher
    assert "_autoquant_native_bounded_process" in launcher

    assert '"-DAQT_NATIVE_LAUNCHER_OPERATIONAL_PROFILE=1"' in hook
    assert 'f"-ffile-prefix-map={source_root}=."' in hook
    assert '"-ffile-prefix-map=$SOURCE_ROOT=."' in hook
    assert workflow.count('python-version: "3.12.13"') == 3
    assert 'python-version:\n          - "3.12.13"\n          - "3.13.3"' in workflow
    assert 'UV_MANAGED_PYTHON: "1"' in workflow
    assert "Require reviewed managed standalone CPython" in workflow
    assert 'sysconfig.get_config_var("PYTHONFRAMEWORK") not in (None, "")' in workflow
    hook_tree = ast.parse(hook)
    operational_target_ids = next(
        ast.literal_eval(node.value)
        for node in hook_tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "_OPERATIONAL_TARGET_IDS"
            for target in node.targets
        )
    )
    assert operational_target_ids == (
        "first-enrollment",
        "first-enrollment-recovery-release",
        "first-enrollment-release",
        "image-schema-contract",
        "post-enrollment-persistent-barrier-read",
        "post-enrollment-pre-effect-runtime-absence",
        "post-enrollment-release",
        "post-enrollment-runtime-state",
        "post-enrollment-staged-barrier-read",
        "supervisor",
    )
    assert "AQT_NATIVE_LAUNCHER_ADMISSION_PROFILE" not in hook
    assert "bounded_process.c" not in hook

    fixed_launcher = "/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python"
    assert "/opt/venv" not in dockerfile
    assert fixed_launcher in dockerfile
    assert f'CMD ["{fixed_launcher}", "supervisor"]' in dockerfile
    assert dockerfile.count("SOURCE_DATE_EPOCH=0") == 1
    assert "COPY native/trusted_time_python_launcher.c" in dockerfile
    assert "COPY native/bounded_process.c" in dockerfile
    assert "/usr/local/bin/python -I -B -S" in dockerfile
    assert "native_owned_file_descriptor_launcher.json" in dockerfile
    assert "native/trusted_time_python_launcher.c" in dockerignore
    assert "native/bounded_process.c" in dockerignore
    assert "build_support/build_native_test_launcher.py" not in dockerignore
    assert workflow.count(".venv/bin/python -I -B build_support/build_native_test_launcher.py") == 2
    assert workflow.count("autoquant-trusted-time-python-test") == 2

    wheel_target = project["tool"]["hatch"]["build"]["targets"]["wheel"]
    assert wheel_target["exclude"] == ["packages/adapters/trusted_time/_bounded_process.py"]
    force_include = project["tool"]["hatch"]["build"]["targets"]["sdist"]["force-include"]
    assert project["tool"]["hatch"]["build"]["targets"]["sdist"]["exclude"] == [
        "/.uv-cache",
        "build_support/build_native_test_launcher.py",
    ]
    assert frozenset(force_include) == frozenset(
        (
            "build_support/native_build_constraints.txt",
            "build_support/native_image_manifest.py",
            "build_support/native_owned_file_descriptor_hook.py",
            "native/bounded_process.c",
            "native/owned_file_descriptor.c",
            "native/trusted_time_python_launcher.c",
            "packages/adapters/trusted_time/_bounded_process.py",
        )
    )


@pytest.mark.parametrize(
    "argument_values",
    (
        (),
        ("test-suite", "--artifact", "/tmp/result.json"),
        ("verify-images-build",),
        ("verify-images-build", "--artifact"),
        ("verify-images-build", "--artifact", "artifacts/result.json"),
        ("verify-images-build", "--artifact", "/tmp/result.json", "extra"),
    ),
)
def test_native_test_launcher_policy_exec_rejects_every_other_shape(
    argument_values: tuple[str, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    build_called = False

    def unexpected_build() -> Path:
        nonlocal build_called
        build_called = True
        raise AssertionError("invalid policy arguments reached the native build")

    monkeypatch.setattr(native_test_builder, "_build_launcher", unexpected_build)

    with pytest.raises(
        native_test_builder.NativeTestLauncherBuildError,
        match="execution arguments are not admitted",
    ):
        native_test_builder._exec_policy_target(argument_values)

    assert build_called is False


def test_native_test_launcher_policy_exec_requires_disposable_isolated_prefix(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository_root = Path(__file__).resolve().parents[2]
    artifact = repository_root / "artifacts/trusted-time/test.json"
    arguments = ("verify-images-build", "--artifact", str(artifact))

    monkeypatch.setattr(sys, "prefix", str(repository_root))
    with pytest.raises(
        native_test_builder.NativeTestLauncherBuildError,
        match="execution runtime is not isolated",
    ):
        native_test_builder._validated_policy_arguments(arguments)

    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    assert native_test_builder._validated_policy_arguments(arguments) == arguments
