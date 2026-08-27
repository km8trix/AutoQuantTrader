from __future__ import annotations

import errno
import os
import stat
import threading
from pathlib import Path
from typing import Any, cast

import pytest

from packages.adapters.trusted_time import _lifecycle_v2_artifact_store as physical
from packages.domain.trusted_time_graceful_stop_v2 import LIFECYCLE_ROOT_FILE_NAME
from packages.persistence import trusted_time_graceful_stop_v2 as repository_module
from packages.persistence.trusted_time_graceful_stop_v2 import (
    LifecycleV2ArtifactAlreadyExists,
    LifecycleV2ArtifactPublicationUncertain,
    LifecycleV2RetentionUnconfirmed,
)

_STAGING = ".post-enrollment-graceful-stop-v2-record-staging"
_FINAL = "trusted-time-post-enrollment-graceful-stop-v2-record-01-" + "a" * 64 + ".json"


def _artifact_directory(tmp_path: Path) -> Path:
    ignored_root = tmp_path / "ignored"
    ignored_root.mkdir(parents=True, mode=0o700)
    artifact_directory = ignored_root / "trusted-time"
    artifact_directory.mkdir(mode=0o700)
    artifact_directory.chmod(0o700)
    return artifact_directory


def _store(
    artifact_directory: Path,
    **overrides: object,
) -> Any:
    identity = os.stat(artifact_directory, follow_symlinks=False)
    arguments: dict[str, object] = {
        "artifact_directory_path": str(artifact_directory),
        "expected_directory_device": identity.st_dev,
        "expected_directory_inode": identity.st_ino,
        "expected_owner_uid": identity.st_uid,
        "expected_owner_gid": identity.st_gid,
    }
    arguments.update(overrides)
    return physical._open_injected_lifecycle_v2_physical_artifact_store(**cast(Any, arguments))


def _write_owner_only(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o600)


def test_physical_store_publishes_root_and_immutable_artifact_with_exact_identity(
    tmp_path: Path,
) -> None:
    artifact_directory = _artifact_directory(tmp_path)
    store = _store(artifact_directory)
    root_bytes = b'{"root":"v2"}\n'
    artifact_bytes = b'{"record":1}\n'
    try:
        store.create_root_exclusive(LIFECYCLE_ROOT_FILE_NAME, root_bytes)
        store.publish_immutable(
            staging_name=_STAGING,
            final_name=_FINAL,
            encoded=artifact_bytes,
        )

        assert store.inventory() == (LIFECYCLE_ROOT_FILE_NAME, _FINAL)
        assert store.read_stable(LIFECYCLE_ROOT_FILE_NAME) == root_bytes
        assert store.read_stable(_FINAL) == artifact_bytes
        assert not (artifact_directory / _STAGING).exists()
        directory_identity = os.stat(artifact_directory, follow_symlinks=False)
        for name in (LIFECYCLE_ROOT_FILE_NAME, _FINAL):
            identity = os.stat(artifact_directory / name, follow_symlinks=False)
            assert stat.S_ISREG(identity.st_mode)
            assert stat.S_IMODE(identity.st_mode) == 0o600
            assert identity.st_nlink == 1
            assert identity.st_uid == directory_identity.st_uid
            assert identity.st_gid == directory_identity.st_gid
    finally:
        store.close()
    assert store.closed is True


def test_exact_existing_final_is_revalidated_but_conflict_is_never_replaced(
    tmp_path: Path,
) -> None:
    artifact_directory = _artifact_directory(tmp_path)
    encoded = b'{"record":1}\n'
    store = _store(artifact_directory)
    try:
        store.publish_immutable(staging_name=_STAGING, final_name=_FINAL, encoded=encoded)
        identity_before = os.stat(artifact_directory / _FINAL, follow_symlinks=False)

        store.publish_immutable(staging_name=_STAGING, final_name=_FINAL, encoded=encoded)
        identity_after = os.stat(artifact_directory / _FINAL, follow_symlinks=False)
        assert (identity_before.st_dev, identity_before.st_ino) == (
            identity_after.st_dev,
            identity_after.st_ino,
        )

        with pytest.raises(LifecycleV2ArtifactAlreadyExists):
            store.publish_immutable(
                staging_name=_STAGING,
                final_name=_FINAL,
                encoded=b'{"record":2}\n',
            )
        assert (artifact_directory / _FINAL).read_bytes() == encoded
        assert not (artifact_directory / _STAGING).exists()
        assert store.closed is False
    finally:
        store.close()


def test_existing_staging_and_root_are_exact_eexist_boundaries(tmp_path: Path) -> None:
    artifact_directory = _artifact_directory(tmp_path)
    _write_owner_only(artifact_directory / _STAGING, b"staging")
    _write_owner_only(artifact_directory / LIFECYCLE_ROOT_FILE_NAME, b"root")
    store = _store(artifact_directory)
    try:
        with pytest.raises(LifecycleV2ArtifactAlreadyExists):
            store.publish_immutable(
                staging_name=_STAGING,
                final_name=_FINAL,
                encoded=b"record",
            )
        with pytest.raises(LifecycleV2ArtifactAlreadyExists):
            store.create_root_exclusive(LIFECYCLE_ROOT_FILE_NAME, b"replacement")
        assert (artifact_directory / _STAGING).read_bytes() == b"staging"
        assert (artifact_directory / LIFECYCLE_ROOT_FILE_NAME).read_bytes() == b"root"
    finally:
        store.close()


@pytest.mark.parametrize(
    ("boundary", "artifact_present"),
    (
        ("create", False),
        ("write", True),
        ("file_fsync", True),
        ("created_readback", True),
        ("directory_fsync", True),
        ("reopened_readback", True),
    ),
)
def test_every_physical_root_publication_fault_is_ambiguous_and_closes_all_owners(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    artifact_present: bool,
) -> None:
    artifact_directory = _artifact_directory(tmp_path)
    store = _store(artifact_directory)
    physical_any = cast(Any, physical)
    real_create: Any = physical_any._create_child_regular_exclusive
    real_write: Any = physical_any._write_all
    real_fsync: Any = physical_any._fsync
    real_read: Any = physical_any._read_snapshot
    fsync_calls = 0
    read_calls = 0

    def create(*args: object) -> object:
        if boundary == "create":
            raise OSError(errno.EIO, "injected root-create ambiguity")
        return real_create(*args)

    def write(*args: object) -> None:
        if boundary == "write":
            raise OSError(errno.EIO, "injected root-write ambiguity")
        real_write(*args)

    def fsync(*args: object) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if boundary == "file_fsync" and fsync_calls == 1:
            raise OSError(errno.EIO, "injected root-file-fsync ambiguity")
        if boundary == "directory_fsync" and fsync_calls == 2:
            raise OSError(errno.EIO, "injected root-directory-fsync ambiguity")
        real_fsync(*args)

    def read(*args: object) -> Any:
        nonlocal read_calls
        read_calls += 1
        result = real_read(*args)
        if (boundary == "created_readback" and read_calls == 1) or (
            boundary == "reopened_readback" and read_calls == 2
        ):
            payload, before, after = result
            return b"drift" + payload, before, after
        return result

    monkeypatch.setattr(physical, "_create_child_regular_exclusive", create)
    monkeypatch.setattr(physical, "_write_all", write)
    monkeypatch.setattr(physical, "_fsync", fsync)
    monkeypatch.setattr(physical, "_read_snapshot", read)

    with pytest.raises(LifecycleV2ArtifactPublicationUncertain):
        store.create_root_exclusive(LIFECYCLE_ROOT_FILE_NAME, b'{"root":"v2"}\n')

    assert store.closed is True
    assert (artifact_directory / LIFECYCLE_ROOT_FILE_NAME).exists() is artifact_present


@pytest.mark.parametrize(
    ("boundary", "expected_name"),
    (
        ("create", None),
        ("write", _STAGING),
        ("file_fsync", _STAGING),
        ("rename", _STAGING),
        ("directory_fsync", _FINAL),
        ("held_readback", _FINAL),
        ("reopened_readback", _FINAL),
    ),
)
def test_every_physical_publication_fault_is_ambiguous_and_closes_all_owners(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    expected_name: str | None,
) -> None:
    artifact_directory = _artifact_directory(tmp_path)
    store = _store(artifact_directory)
    physical_any = cast(Any, physical)
    real_create: Any = physical_any._create_child_regular_exclusive
    real_write: Any = physical_any._write_all
    real_fsync: Any = physical_any._fsync
    real_rename: Any = physical_any._rename_child_noreplace
    real_read: Any = physical_any._read_snapshot
    fsync_calls = 0
    read_calls = 0

    def create(*args: object) -> object:
        if boundary == "create":
            raise OSError(errno.EIO, "injected create ambiguity")
        return real_create(*args)

    def write(*args: object) -> None:
        if boundary == "write":
            raise OSError(errno.EIO, "injected write ambiguity")
        real_write(*args)

    def fsync(*args: object) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if boundary == "file_fsync" and fsync_calls == 1:
            raise OSError(errno.EIO, "injected file-fsync ambiguity")
        if boundary == "directory_fsync" and fsync_calls == 2:
            raise OSError(errno.EIO, "injected directory-fsync ambiguity")
        real_fsync(*args)

    def rename(*args: object) -> None:
        if boundary == "rename":
            raise OSError(errno.EIO, "injected rename ambiguity")
        real_rename(*args)

    def read(*args: object) -> Any:
        nonlocal read_calls
        read_calls += 1
        result = real_read(*args)
        if (boundary == "held_readback" and read_calls == 2) or (
            boundary == "reopened_readback" and read_calls == 3
        ):
            payload, before, after = result
            return b"drift" + payload, before, after
        return result

    monkeypatch.setattr(physical, "_create_child_regular_exclusive", create)
    monkeypatch.setattr(physical, "_write_all", write)
    monkeypatch.setattr(physical, "_fsync", fsync)
    monkeypatch.setattr(physical, "_rename_child_noreplace", rename)
    monkeypatch.setattr(physical, "_read_snapshot", read)

    with pytest.raises(LifecycleV2ArtifactPublicationUncertain):
        store.publish_immutable(
            staging_name=_STAGING,
            final_name=_FINAL,
            encoded=b'{"record":1}\n',
        )

    assert store.closed is True
    names = tuple(sorted(item.name for item in artifact_directory.iterdir()))
    assert names == (() if expected_name is None else (expected_name,))


def test_rename_eexist_race_preserves_staging_and_never_normalizes_the_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_directory = _artifact_directory(tmp_path)
    store = _store(artifact_directory)
    real_rename: Any = cast(Any, physical)._rename_child_noreplace

    def race(*args: object) -> None:
        _write_owner_only(artifact_directory / _FINAL, b"racing-winner")
        real_rename(*args)

    monkeypatch.setattr(physical, "_rename_child_noreplace", race)
    with pytest.raises(LifecycleV2ArtifactPublicationUncertain, match="raced"):
        store.publish_immutable(
            staging_name=_STAGING,
            final_name=_FINAL,
            encoded=b"candidate",
        )

    assert store.closed is True
    assert (artifact_directory / _STAGING).read_bytes() == b"candidate"
    assert (artifact_directory / _FINAL).read_bytes() == b"racing-winner"


@pytest.mark.parametrize("attack", ["mode", "hardlink", "symlink"])
def test_stable_readback_rejects_mode_link_and_symlink_ambiguity(
    tmp_path: Path,
    attack: str,
) -> None:
    artifact_directory = _artifact_directory(tmp_path)
    artifact = artifact_directory / _FINAL
    if attack == "symlink":
        target = artifact_directory / "target"
        _write_owner_only(target, b"payload")
        artifact.symlink_to(target.name)
    else:
        _write_owner_only(artifact, b"payload")
        if attack == "mode":
            artifact.chmod(0o640)
        else:
            os.link(artifact, artifact_directory / "second-link")
    store = _store(artifact_directory)

    with pytest.raises(LifecycleV2ArtifactPublicationUncertain):
        store.read_stable(_FINAL)

    assert store.closed is True


def test_directory_path_identity_owner_and_mode_are_exact(tmp_path: Path) -> None:
    artifact_directory = _artifact_directory(tmp_path)
    identity = os.stat(artifact_directory, follow_symlinks=False)

    with pytest.raises(LifecycleV2ArtifactPublicationUncertain):
        _store(
            artifact_directory,
            expected_directory_inode=identity.st_ino + 1,
        )
    with pytest.raises(LifecycleV2ArtifactPublicationUncertain):
        _store(
            artifact_directory,
            expected_owner_uid=identity.st_uid + 1,
        )

    artifact_directory.chmod(0o750)
    with pytest.raises(LifecycleV2ArtifactPublicationUncertain):
        _store(artifact_directory)

    real_directory = tmp_path / "real" / "trusted-time"
    real_directory.parent.mkdir(mode=0o700)
    real_directory.mkdir(mode=0o700)
    symlink_parent = tmp_path / "linked"
    symlink_parent.symlink_to(real_directory.parent, target_is_directory=True)
    linked_path = symlink_parent / "trusted-time"
    linked_identity = os.stat(linked_path, follow_symlinks=False)
    with pytest.raises(OSError):
        _store(
            linked_path,
            expected_directory_device=linked_identity.st_dev,
            expected_directory_inode=linked_identity.st_ino,
            expected_owner_uid=linked_identity.st_uid,
            expected_owner_gid=linked_identity.st_gid,
        )


def test_open_directory_owner_rejects_current_path_inode_replacement(tmp_path: Path) -> None:
    artifact_directory = _artifact_directory(tmp_path)
    store = _store(artifact_directory)
    retired = artifact_directory.with_name("trusted-time-retired")
    artifact_directory.rename(retired)
    artifact_directory.mkdir(mode=0o700)
    artifact_directory.chmod(0o700)

    with pytest.raises(LifecycleV2ArtifactPublicationUncertain, match="path"):
        store.inventory()

    assert store.closed is True


def test_inventory_bound_is_exact_and_overflow_burns_the_store(tmp_path: Path) -> None:
    exact_directory = _artifact_directory(tmp_path / "exact")
    for index in range(128):
        _write_owner_only(exact_directory / f"artifact-{index:03d}", b"x")
    exact_store = _store(exact_directory)
    try:
        assert len(exact_store.inventory()) == 128
    finally:
        exact_store.close()

    overflow_directory = _artifact_directory(tmp_path / "overflow")
    for index in range(129):
        _write_owner_only(overflow_directory / f"artifact-{index:03d}", b"x")
    overflow_store = _store(overflow_directory)
    with pytest.raises(LifecycleV2ArtifactPublicationUncertain, match="exceeds"):
        overflow_store.inventory()
    assert overflow_store.closed is True


def test_inventory_rejects_a_namespace_mutation_after_the_native_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_directory = _artifact_directory(tmp_path)
    store = _store(artifact_directory)
    real_list: Any = cast(Any, physical)._list_snapshot

    def mutate_after_snapshot(*args: object) -> Any:
        snapshot = real_list(*args)
        _write_owner_only(artifact_directory / "racing-artifact", b"x")
        return snapshot

    monkeypatch.setattr(physical, "_list_snapshot", mutate_after_snapshot)

    with pytest.raises(LifecycleV2ArtifactPublicationUncertain, match="changed"):
        store.inventory()

    assert store.closed is True


def test_wrong_thread_rejects_before_native_registry_use(tmp_path: Path) -> None:
    store = _store(_artifact_directory(tmp_path))
    results: list[BaseException] = []

    def use_from_wrong_thread() -> None:
        try:
            store.inventory()
        except BaseException as error:
            results.append(error)

    thread = threading.Thread(target=use_from_wrong_thread)
    thread.start()
    thread.join()
    try:
        assert len(results) == 1
        assert isinstance(results[0], LifecycleV2ArtifactPublicationUncertain)
        assert store.closed is False
        assert store.inventory() == ()
    finally:
        store.close()


def test_repository_burn_closes_the_physical_descriptor_registry(tmp_path: Path) -> None:
    artifact_directory = _artifact_directory(tmp_path)
    _write_owner_only(artifact_directory / "unknown.json", b"{}\n")
    store = _store(artifact_directory)

    with pytest.raises(LifecycleV2RetentionUnconfirmed, match="unknown"):
        repository_module._open_injected_lifecycle_v2_repository(
            store,
            artifact_directory_path=str(artifact_directory),
        )

    assert store.closed is True


@pytest.mark.skipif(not hasattr(os, "fork"), reason="native fork invalidation is POSIX-only")
def test_fork_child_loses_physical_store_descriptors_before_python(tmp_path: Path) -> None:
    store = _store(_artifact_directory(tmp_path))
    read_pipe, write_pipe = os.pipe()
    child_pid = os.fork()

    if child_pid == 0:
        os.close(read_pipe)
        child_ok = store.closed is True
        try:
            store.inventory()
        except LifecycleV2ArtifactPublicationUncertain:
            pass
        else:
            child_ok = False
        os.write(write_pipe, b"1" if child_ok else b"0")
        os.close(write_pipe)
        os._exit(0 if child_ok else 92)

    os.close(write_pipe)
    child_report = os.read(read_pipe, 1)
    os.close(read_pipe)
    waited_pid, wait_status = os.waitpid(child_pid, 0)
    try:
        assert waited_pid == child_pid
        assert os.waitstatus_to_exitcode(wait_status) == 0
        assert child_report == b"1"
        assert store.closed is False
        assert store.inventory() == ()
    finally:
        store.close()


def test_physical_store_has_no_default_root_caller_effect_or_signer_authority() -> None:
    assert physical.lifecycle_v2_physical_store_non_authority_facts() == {
        "default_artifact_root_present": False,
        "production_caller_present": False,
        "effect_authority_present": False,
        "recovery_signer_present": False,
        "confirmed_success_writer_present": False,
    }
