from __future__ import annotations

import os
import pickle
import select
import threading
from collections.abc import Mapping
from copy import copy, deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import scripts.trusted_time_post_enrollment_topology_reader as reader
from packages.adapters.trusted_time._owned_file_descriptor import (
    _acquire_trusted_time_launch_lock,
    _TrustedTimeLaunchLockLease,
    _validate_trusted_time_launch_lock,
)
from scripts.start_trusted_time_supervisor import LocalDockerDaemonIdentity
from tests.unit import test_trusted_time_post_enrollment_topology_reader as fixtures


def _cursor_values() -> dict[str, Any]:
    return {
        "session_sha256": "1" * 64,
        "transcript_sha256": "2" * 64,
        "cursor_ordinal": 1,
        "staged_observation_count": 1,
        "created_observation_sha256": "3" * 64,
        "last_observation_sha256": "4" * 64,
        "first_staged_snapshot_sha256": "5" * 64,
    }


def _open_cursor_issuer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    cursor_read_count: int,
    staged_observation_count: int = 1,
) -> tuple[
    reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
    fixtures._QueuedRunner,
]:
    socket_path = fixtures._short_socket_path(tmp_path)
    executable = tmp_path / "trusted-docker"
    fixtures._make_executable(executable)
    queued = fixtures._QueuedRunner(
        [
            fixtures._json_line("LOCAL:DAEMON:1"),
            *[fixtures._json_line("LOCAL:DAEMON:1") for _ in range(cursor_read_count)],
        ]
    )
    issuer = fixtures._public_open(
        monkeypatch,
        tmp_path,
        queued,
        socket_path,
        executable,
    )
    if staged_observation_count:
        issuer._issued_created_observation_sha256 = "3" * 64
        issuer._last_observation_sha256 = "4" * 64
        issuer._first_staged_snapshot_sha256 = "5" * 64
        issuer._staged_observation_count = staged_observation_count
    return issuer, queued


def test_module_exposes_no_capability_registrar_or_authentication_builder() -> None:
    for name in (
        "_new_authenticated_issuer_capability",
        "_authenticated_observation_open",
        "_authenticated_observation_issuance",
        "_build_observation_sealer",
        "_PRODUCTION_OPEN_PROOF",
    ):
        assert not hasattr(reader, name)


def test_forged_capability_cannot_use_guarded_signer() -> None:
    owner = object.__new__(reader.TrustedTimePostEnrollmentTopologyObservationIssuer)
    capability = object.__new__(reader._AuthenticatedIssuerCapability)

    with pytest.raises(
        reader.TrustedTimePostEnrollmentTopologyReaderError,
        match="observation seal is unavailable",
    ):
        reader._seal_observation(
            owner,
            capability,
            reader._cursor_payload(**_cursor_values()),
            "cursor",
        )


def test_real_cursor_issuance_uses_one_read_and_enforces_three_positions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, queued = _open_cursor_issuer(
        monkeypatch,
        tmp_path,
        cursor_read_count=3,
    )
    open_call_count = len(queued.calls)

    first = issuer.issue_observation_cursor()
    second = issuer.issue_observation_cursor()
    issuer._staged_observation_count = 2
    issuer._last_observation_sha256 = "6" * 64
    third = issuer.issue_observation_cursor()

    assert [first.cursor_ordinal, second.cursor_ordinal, third.cursor_ordinal] == [1, 2, 3]
    assert [
        first.staged_observation_count,
        second.staged_observation_count,
        third.staged_observation_count,
    ] == [1, 1, 2]
    assert third.last_observation_sha256 == "6" * 64
    assert len(queued.calls) - open_call_count == 3
    assert first.observation_cursor_authenticated is True
    assert first.observation_provenance_authenticated is True
    assert first.lock_session_authenticated is True
    assert first.daemon_session_authenticated is True

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer.issue_observation_cursor()
    assert queued.outputs == []
    issuer.close()


def test_cursor_rejects_clone_copy_deepcopy_and_pickle_replay(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_cursor_issuer(
        monkeypatch,
        tmp_path,
        cursor_read_count=1,
    )
    cursor = issuer.issue_observation_cursor()

    for operation in (
        lambda: replace(cursor),
        lambda: copy(cursor),
        lambda: deepcopy(cursor),
        lambda: pickle.dumps(cursor),
    ):
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            operation()
    cursor.__post_init__()
    issuer.close()


def test_uninitialized_cursor_cannot_assert_authentication() -> None:
    forged = object.__new__(reader.TrustedTimePostEnrollmentTopologyObservationCursor)

    for name in (
        "observation_cursor_authenticated",
        "observation_provenance_authenticated",
        "lock_session_authenticated",
        "daemon_session_authenticated",
    ):
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            getattr(forged, name)


def test_observation_subclasses_cannot_override_authentication_or_digest_validation() -> None:
    endpoint = "unix:///trusted/docker.sock"
    created_snapshot = fixtures._created_snapshot(endpoint)
    staged_snapshot = fixtures._staged_snapshot(endpoint, created_snapshot)

    class ForgedCreated(reader.TrustedTimePostEnrollmentCreatedTopologyObservation):
        def __post_init__(self) -> None:
            return

    class ForgedStaged(reader.TrustedTimePostEnrollmentStagedTopologyObservation):
        def __post_init__(self) -> None:
            return

    class ForgedCursor(reader.TrustedTimePostEnrollmentTopologyObservationCursor):
        def __post_init__(self) -> None:
            return

    forged_created = ForgedCreated(
        session_sha256="1" * 64,
        transcript_sha256="2" * 64,
        observation_count=14,
        snapshot=created_snapshot,
        _seal=b"forged",
    )
    forged_staged = ForgedStaged(
        session_sha256="1" * 64,
        transcript_sha256="2" * 64,
        observation_count=16,
        created_observation_sha256="3" * 64,
        staged_observation_ordinal=1,
        predecessor_observation_sha256="3" * 64,
        snapshot=staged_snapshot,
        _seal=b"forged",
    )
    forged_cursor = ForgedCursor(**_cursor_values(), _seal=b"forged")

    for candidate, authenticated_property, digest_property in (
        (forged_created, "observation_provenance_authenticated", "observation_sha256"),
        (forged_staged, "observation_provenance_authenticated", "observation_sha256"),
        (forged_cursor, "observation_cursor_authenticated", "cursor_sha256"),
    ):
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            getattr(candidate, authenticated_property)
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            getattr(candidate, digest_property)
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            candidate.payload()


def test_fully_populated_raw_observations_cannot_project_authenticated_payloads() -> None:
    endpoint = "unix:///trusted/docker.sock"
    created_snapshot = fixtures._created_snapshot(endpoint)
    staged_snapshot = fixtures._staged_snapshot(endpoint, created_snapshot)
    raw_created = object.__new__(reader.TrustedTimePostEnrollmentCreatedTopologyObservation)
    raw_staged = object.__new__(reader.TrustedTimePostEnrollmentStagedTopologyObservation)
    raw_cursor = object.__new__(reader.TrustedTimePostEnrollmentTopologyObservationCursor)
    for name, value in {
        "session_sha256": "1" * 64,
        "transcript_sha256": "2" * 64,
        "observation_count": 14,
        "snapshot": created_snapshot,
        "_seal": b"forged",
    }.items():
        object.__setattr__(raw_created, name, value)
    for name, value in {
        "session_sha256": "1" * 64,
        "transcript_sha256": "2" * 64,
        "observation_count": 16,
        "created_observation_sha256": "3" * 64,
        "staged_observation_ordinal": 1,
        "predecessor_observation_sha256": "3" * 64,
        "snapshot": staged_snapshot,
        "_seal": b"forged",
    }.items():
        object.__setattr__(raw_staged, name, value)
    for name, value in {**_cursor_values(), "_seal": b"forged"}.items():
        object.__setattr__(raw_cursor, name, value)

    for candidate in (raw_created, raw_staged, raw_cursor):
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            candidate.payload()


def test_cursor_is_invalid_in_forked_child(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable")
    issuer, _ = _open_cursor_issuer(
        monkeypatch,
        tmp_path,
        cursor_read_count=1,
    )
    cursor = issuer.issue_observation_cursor()
    read_descriptor, write_descriptor = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - asserted through the pipe
        os.close(read_descriptor)
        rejected = 0
        for operation in (cursor.__post_init__, cursor.payload):
            try:
                operation()
            except reader.TrustedTimePostEnrollmentTopologyReaderError:
                rejected += 1
        try:
            os.write(write_descriptor, b"rejected" if rejected == 2 else b"accepted")
        finally:
            os.close(write_descriptor)
        os._exit(0)

    os.close(write_descriptor)
    try:
        assert os.read(read_descriptor, 16) == b"rejected"
    finally:
        os.close(read_descriptor)
        os.waitpid(child_pid, 0)
        issuer.close()


def test_inherited_issuer_capability_is_rejected_in_forked_child(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable")
    issuer, _ = _open_cursor_issuer(
        monkeypatch,
        tmp_path,
        cursor_read_count=0,
    )
    capability = issuer._authentication_capability
    read_descriptor, write_descriptor = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - asserted through the pipe
        os.close(read_descriptor)
        try:
            active = reader._authenticated_issuer_capability_is_active(issuer, capability)
            os.write(write_descriptor, b"accepted" if active else b"rejected")
        finally:
            os.close(write_descriptor)
        os._exit(0)

    os.close(write_descriptor)
    try:
        assert os.read(read_descriptor, 16) == b"rejected"
    finally:
        os.close(read_descriptor)
        os.waitpid(child_pid, 0)
        issuer.close()


def test_fork_child_closes_and_scrubs_inherited_opaque_launch_lock_lease(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable")
    issuer, _ = _open_cursor_issuer(
        monkeypatch,
        tmp_path,
        cursor_read_count=0,
    )
    inherited_lease = issuer._launch_lock_lease
    assert type(inherited_lease) is _TrustedTimeLaunchLockLease
    read_descriptor, write_descriptor = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - asserted through the pipe
        os.close(read_descriptor)
        try:
            state_closed = (
                inherited_lease.closed is True
                and issuer._launch_lock_lease is None
                and issuer._closed is True
                and issuer._poisoned is True
                and issuer._authentication_capability is None
            )
            os.write(
                write_descriptor,
                b"closed" if state_closed else b"inherited",
            )
        finally:
            os.close(write_descriptor)
        os._exit(0)

    os.close(write_descriptor)
    try:
        assert os.read(read_descriptor, 16) == b"closed"
    finally:
        os.close(read_descriptor)
        os.waitpid(child_pid, 0)
        issuer.close()


@pytest.mark.filterwarnings(
    r"ignore:This process .* is multi-threaded, "
    r"use of fork\(\) may lead to deadlocks.*:DeprecationWarning"
)
def test_fork_child_rejects_before_inherited_parent_thread_mutex_access(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable")
    issuer, _ = _open_cursor_issuer(
        monkeypatch,
        tmp_path,
        cursor_read_count=0,
    )
    launch_lock_lease = issuer._launch_lock_lease
    assert type(launch_lock_lease) is _TrustedTimeLaunchLockLease
    lock_held = threading.Event()
    release_lock = threading.Event()

    def hold_lifecycle_lock() -> None:
        issuer._lifecycle_lock.acquire()
        try:
            lock_held.set()
            assert release_lock.wait(timeout=5.0)
        finally:
            issuer._lifecycle_lock.release()

    worker = threading.Thread(target=hold_lifecycle_lock)
    worker.start()
    assert lock_held.wait(timeout=2.0)
    read_descriptor, write_descriptor = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - asserted through the pipe
        os.close(read_descriptor)
        status = b"failed"
        try:
            object.__setattr__(issuer, "_owner_pid", os.getpid())
            close_rejected = False
            activate_rejected = False
            try:
                issuer.close()
            except reader.TrustedTimePostEnrollmentTopologyReaderError:
                close_rejected = True
            try:
                issuer.activate(
                    expected_daemon_identity=LocalDockerDaemonIdentity(
                        context_name="<DOCKER_HOST>",
                        endpoint="unix:///var/run/docker.sock",
                        daemon_id="LOCAL:DAEMON:1",
                    ),
                    docker_environment={},
                )
            except reader.TrustedTimePostEnrollmentTopologyReaderError:
                activate_rejected = True
            if (
                close_rejected
                and activate_rejected
                and launch_lock_lease.closed is True
                and issuer._launch_lock_lease is None
            ):
                status = b"rejected"
        finally:
            os.write(write_descriptor, status)
            os.close(write_descriptor)
        os._exit(0)

    os.close(write_descriptor)
    child_status = b""
    try:
        ready, _, _ = select.select([read_descriptor], [], [], 2.0)
        assert ready == [read_descriptor]
        child_status = os.read(read_descriptor, 16)
    finally:
        os.close(read_descriptor)
        release_lock.set()
        worker.join(timeout=2.0)
        os.waitpid(child_pid, 0)

    assert not worker.is_alive()
    assert child_status == b"rejected"
    assert launch_lock_lease.closed is False
    _validate_trusted_time_launch_lock(launch_lock_lease)
    issuer.close()
    assert launch_lock_lease.closed is True


def test_revocation_failure_during_open_error_does_not_strand_global_lock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = fixtures._short_socket_path(tmp_path)
    executable = tmp_path / "trusted-docker"
    fixtures._make_executable(executable)
    queued = fixtures._QueuedRunner([fixtures._json_line("WRONG:DAEMON")])
    ignored_root = tmp_path / "artifacts"

    def fail_revocation(*_: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(reader, "_revoke_authenticated_issuer_capability", fail_revocation)
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        fixtures._public_open(
            monkeypatch,
            tmp_path,
            queued,
            socket_path,
            executable,
        )

    lease = _acquire_trusted_time_launch_lock(os.fspath(ignored_root))
    _validate_trusted_time_launch_lock(lease)
    lease.close()


def test_revocation_failure_during_close_still_releases_global_lock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_cursor_issuer(
        monkeypatch,
        tmp_path,
        cursor_read_count=0,
    )
    inherited_lease = issuer._launch_lock_lease
    assert type(inherited_lease) is _TrustedTimeLaunchLockLease

    def fail_revocation(*_: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(reader, "_revoke_authenticated_issuer_capability", fail_revocation)
    issuer.close()

    assert issuer._launch_lock_lease is None
    assert issuer._authentication_capability is None
    assert inherited_lease.closed is True
    lease = _acquire_trusted_time_launch_lock(os.fspath(issuer._ignored_root))
    _validate_trusted_time_launch_lock(lease)
    lease.close()


def test_cursor_before_staged_ordinal_one_fails_without_daemon_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, queued = _open_cursor_issuer(
        monkeypatch,
        tmp_path,
        cursor_read_count=0,
        staged_observation_count=0,
    )
    call_count = len(queued.calls)

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer.issue_observation_cursor()

    assert len(queued.calls) == call_count
    issuer.close()


def test_close_revokes_capability_but_preserves_issued_cursor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_cursor_issuer(
        monkeypatch,
        tmp_path,
        cursor_read_count=1,
    )
    cursor = issuer.issue_observation_cursor()
    capability = issuer._authentication_capability

    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        reader._seal_observation(
            issuer,
            capability,
            cursor.payload(),
            "cursor",
        )
    issuer.close()

    assert issuer._authentication_capability is None
    assert issuer._closed is True
    assert not reader._authenticated_issuer_capability_is_active(issuer, capability)
    cursor.__post_init__()
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        reader._seal_observation(
            issuer,
            capability,
            reader._cursor_payload(**_cursor_values()),
            "cursor",
        )


def test_cross_thread_cursor_call_rejects_before_seal_or_commit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_cursor_issuer(
        monkeypatch,
        tmp_path,
        cursor_read_count=1,
    )
    seal_ready = threading.Event()
    issued: list[reader.TrustedTimePostEnrollmentTopologyObservationCursor] = []
    errors: list[BaseException] = []
    seal = reader._seal_observation

    def delayed_seal(
        _owner: object,
        _capability: object,
        _material: Mapping[str, object],
        _kind: str,
    ) -> bytes:
        seal_ready.set()
        raise AssertionError("cross-thread issuance reached the seal")

    def issue() -> None:
        try:
            issued.append(issuer.issue_observation_cursor())
        except BaseException as error:
            errors.append(error)

    monkeypatch.setattr(reader, "_seal_observation", delayed_seal)

    worker = threading.Thread(target=issue)
    worker.start()
    worker.join(timeout=2.0)

    assert not worker.is_alive()
    assert not seal_ready.is_set()
    assert issued == []
    assert len(errors) == 1
    assert isinstance(errors[0], reader.TrustedTimePostEnrollmentTopologyReaderError)
    assert issuer._poisoned is False
    assert issuer._busy is False
    monkeypatch.setattr(reader, "_seal_observation", seal)
    assert issuer.issue_observation_cursor().cursor_ordinal == 1
    issuer.close()


def test_two_cross_thread_cursor_calls_reject_before_daemon_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_cursor_issuer(
        monkeypatch,
        tmp_path,
        cursor_read_count=1,
    )
    observe_started = threading.Event()
    issued: list[reader.TrustedTimePostEnrollmentTopologyObservationCursor] = []
    errors: list[BaseException] = []
    observe = reader.TrustedTimePostEnrollmentTopologyObservationIssuer._observe_daemon

    def delayed_observe(
        _owner: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        _receipts: list[reader._ReadReceipt],
    ) -> LocalDockerDaemonIdentity:
        observe_started.set()
        raise AssertionError("cross-thread issuance reached the daemon")

    def issue() -> None:
        try:
            issued.append(issuer.issue_observation_cursor())
        except BaseException as error:
            errors.append(error)

    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_observe_daemon",
        delayed_observe,
    )
    first = threading.Thread(target=issue)
    second = threading.Thread(target=issue)
    first.start()
    second.start()
    first.join(timeout=2.0)
    second.join(timeout=2.0)

    assert not first.is_alive()
    assert not second.is_alive()
    assert not observe_started.is_set()
    assert issued == []
    assert len(errors) == 2
    assert all(
        isinstance(error, reader.TrustedTimePostEnrollmentTopologyReaderError) for error in errors
    )
    assert issuer._cursor_count == 0
    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_observe_daemon",
        observe,
    )
    assert issuer.issue_observation_cursor().cursor_ordinal == 1
    issuer.close()


def test_reentrant_close_during_issuance_uses_closure_token_not_heap_flags(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_cursor_issuer(
        monkeypatch,
        tmp_path,
        cursor_read_count=1,
    )
    launch_lock_lease = issuer._launch_lock_lease
    assert type(launch_lock_lease) is _TrustedTimeLaunchLockLease
    observe = reader.TrustedTimePostEnrollmentTopologyObservationIssuer._observe_daemon
    close_rejected = False

    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_poison_locked",
        lambda _issuer: None,
    )

    def close_during_observe(
        owner: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        receipts: list[reader._ReadReceipt],
    ) -> LocalDockerDaemonIdentity:
        nonlocal close_rejected
        owner._busy = False
        owner._choreography_inflight = False
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            owner.close()
        close_rejected = True
        assert launch_lock_lease.closed is False
        assert owner._authentication_capability is None
        return observe(owner, receipts)

    monkeypatch.setattr(
        reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        "_observe_daemon",
        close_during_observe,
    )
    with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
        issuer.issue_observation_cursor()

    assert close_rejected is True
    assert launch_lock_lease.closed is False
    issuer.close()
    assert launch_lock_lease.closed is True
    replacement = _acquire_trusted_time_launch_lock(os.fspath(issuer._ignored_root))
    _validate_trusted_time_launch_lock(replacement)
    replacement.close()


def test_real_issuer_binds_capability_to_exact_owner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_cursor_issuer(
        monkeypatch,
        tmp_path,
        cursor_read_count=0,
    )
    capability = issuer._authentication_capability
    foreign = object.__new__(reader.TrustedTimePostEnrollmentTopologyObservationIssuer)

    assert reader._authenticated_issuer_capability_is_active(issuer, capability)
    assert not reader._authenticated_issuer_capability_is_active(foreign, capability)
    issuer.close()


def test_cross_thread_created_call_rejects_before_seal_or_commit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = fixtures._short_socket_path(tmp_path)
    executable = tmp_path / "trusted-docker"
    fixtures._make_executable(executable)
    endpoint = f"unix://{socket_path}"
    fixtures._install_pure_validator_stubs(monkeypatch, endpoint=endpoint)
    paths = fixtures._staged_paths(tmp_path / "retired")
    queued = fixtures._QueuedRunner(
        [
            fixtures._json_line("LOCAL:DAEMON:1"),
            *fixtures._state_outputs("created"),
        ]
    )
    issuer = fixtures._public_open(
        monkeypatch,
        tmp_path,
        queued,
        socket_path,
        executable,
    )
    seal_ready = threading.Event()
    issued: list[reader.TrustedTimePostEnrollmentCreatedTopologyObservation] = []
    errors: list[BaseException] = []
    seal = reader._seal_observation

    def delayed_seal(
        _owner: object,
        _capability: object,
        _material: Mapping[str, object],
        _kind: str,
    ) -> bytes:
        seal_ready.set()
        raise AssertionError("cross-thread issuance reached the seal")

    def issue() -> None:
        try:
            issued.append(issuer.issue_created_snapshot(**fixtures._issue_arguments(paths)))
        except BaseException as error:
            errors.append(error)

    monkeypatch.setattr(reader, "_seal_observation", delayed_seal)
    worker = threading.Thread(target=issue)
    worker.start()
    worker.join(timeout=2.0)

    assert not worker.is_alive()
    assert not seal_ready.is_set()
    assert issued == []
    assert len(errors) == 1
    assert isinstance(errors[0], reader.TrustedTimePostEnrollmentTopologyReaderError)
    assert issuer._issued_created_observation_sha256 is None
    assert issuer._last_observation_sha256 is None
    assert issuer._staged_observation_count == 0
    monkeypatch.setattr(reader, "_seal_observation", seal)
    created = issuer.issue_created_snapshot(**fixtures._issue_arguments(paths))
    assert created.observation_sha256 == issuer._issued_created_observation_sha256
    issuer.close()


def test_cross_thread_staged_call_rejects_before_seal_or_commit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = fixtures._short_socket_path(tmp_path)
    executable = tmp_path / "trusted-docker"
    fixtures._make_executable(executable)
    endpoint = f"unix://{socket_path}"
    fixtures._install_pure_validator_stubs(monkeypatch, endpoint=endpoint)
    paths = fixtures._staged_paths(tmp_path / "retired")
    queued = fixtures._QueuedRunner(
        [
            fixtures._json_line("LOCAL:DAEMON:1"),
            *fixtures._state_outputs("created"),
            *fixtures._state_outputs("staged_unreleased"),
        ]
    )
    issuer = fixtures._public_open(
        monkeypatch,
        tmp_path,
        queued,
        socket_path,
        executable,
    )
    created = issuer.issue_created_snapshot(**fixtures._issue_arguments(paths))
    seal_ready = threading.Event()
    issued: list[reader.TrustedTimePostEnrollmentStagedTopologyObservation] = []
    errors: list[BaseException] = []
    seal = reader._seal_observation

    def delayed_seal(
        _owner: object,
        _capability: object,
        _material: Mapping[str, object],
        _kind: str,
    ) -> bytes:
        seal_ready.set()
        raise AssertionError("cross-thread issuance reached the seal")

    def issue() -> None:
        try:
            issued.append(
                issuer.issue_staged_unreleased_snapshot(
                    created_observation=created,
                    **fixtures._issue_arguments(paths),
                )
            )
        except BaseException as error:
            errors.append(error)

    monkeypatch.setattr(reader, "_seal_observation", delayed_seal)
    worker = threading.Thread(target=issue)
    worker.start()
    worker.join(timeout=2.0)

    assert not worker.is_alive()
    assert not seal_ready.is_set()
    assert issued == []
    assert len(errors) == 1
    assert isinstance(errors[0], reader.TrustedTimePostEnrollmentTopologyReaderError)
    assert issuer._staged_observation_count == 0
    assert issuer._last_observation_sha256 == created.observation_sha256
    monkeypatch.setattr(reader, "_seal_observation", seal)
    staged = issuer.issue_staged_unreleased_snapshot(
        created_observation=created,
        **fixtures._issue_arguments(paths),
    )
    assert staged.staged_observation_ordinal == 1
    issuer.close()
