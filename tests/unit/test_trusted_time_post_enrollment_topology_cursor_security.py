from __future__ import annotations

import os
import pickle
import threading
from collections.abc import Mapping
from copy import copy, deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import scripts.trusted_time_post_enrollment_topology_reader as reader
from scripts.start_trusted_time_supervisor import (
    LocalDockerDaemonIdentity,
    _acquire_trusted_time_launch_lock,
    _release_trusted_time_launch_lock,
)
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


def test_fork_child_closes_inherited_global_lock_descriptor(
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
    inherited_descriptor = issuer._lock_descriptor
    read_descriptor, write_descriptor = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - asserted through the pipe
        os.close(read_descriptor)
        try:
            descriptor_closed = False
            try:
                os.fstat(inherited_descriptor)
            except OSError:
                descriptor_closed = True
            state_closed = (
                issuer._lock_descriptor == -1
                and issuer._closed is True
                and issuer._poisoned is True
                and issuer._authentication_capability is None
            )
            os.write(
                write_descriptor,
                b"closed" if descriptor_closed and state_closed else b"inherited",
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


def test_revocation_failure_during_open_error_does_not_strand_global_lock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    socket_path = fixtures._short_socket_path(tmp_path)
    executable = tmp_path / "trusted-docker"
    fixtures._make_executable(executable)
    queued = fixtures._QueuedRunner([fixtures._json_line("WRONG:DAEMON")])
    ignored_root = tmp_path / "artifacts"
    lock_path = ignored_root / "trusted-time" / "trusted-time-launch.lock"

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

    descriptor = _acquire_trusted_time_launch_lock(
        path=lock_path,
        ignored_root=ignored_root,
    )
    _release_trusted_time_launch_lock(descriptor)


def test_revocation_failure_during_close_still_releases_global_lock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_cursor_issuer(
        monkeypatch,
        tmp_path,
        cursor_read_count=0,
    )
    inherited_descriptor = issuer._lock_descriptor

    def fail_revocation(*_: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(reader, "_revoke_authenticated_issuer_capability", fail_revocation)
    issuer.close()

    assert issuer._lock_descriptor == -1
    assert issuer._authentication_capability is None
    with pytest.raises(OSError):
        os.fstat(inherited_descriptor)
    descriptor = _acquire_trusted_time_launch_lock(
        path=issuer._lock_path,
        ignored_root=issuer._ignored_root,
    )
    _release_trusted_time_launch_lock(descriptor)


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


def test_close_race_before_cursor_commit_fails_without_issuing_cursor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_cursor_issuer(
        monkeypatch,
        tmp_path,
        cursor_read_count=1,
    )
    seal_ready = threading.Event()
    allow_seal_return = threading.Event()
    issued: list[reader.TrustedTimePostEnrollmentTopologyObservationCursor] = []
    errors: list[BaseException] = []
    seal = reader._seal_observation

    def delayed_seal(
        owner: object,
        capability: object,
        material: Mapping[str, object],
        kind: str,
    ) -> bytes:
        result = seal(owner, capability, material, kind)
        seal_ready.set()
        if not allow_seal_return.wait(timeout=2.0):
            raise TimeoutError
        return result

    def issue() -> None:
        try:
            issued.append(issuer.issue_observation_cursor())
        except BaseException as error:
            errors.append(error)

    monkeypatch.setattr(reader, "_seal_observation", delayed_seal)

    worker = threading.Thread(target=issue)
    worker.start()
    try:
        assert seal_ready.wait(timeout=2.0)
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer.close()
    finally:
        allow_seal_return.set()
        worker.join(timeout=2.0)

    assert not worker.is_alive()
    assert issued == []
    assert len(errors) == 1
    assert isinstance(errors[0], reader.TrustedTimePostEnrollmentTopologyReaderError)
    assert issuer._poisoned is True
    assert issuer._busy is False
    assert issuer._authentication_capability is None
    issuer.close()


def test_concurrent_cursor_calls_issue_no_duplicate_position(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    issuer, _ = _open_cursor_issuer(
        monkeypatch,
        tmp_path,
        cursor_read_count=1,
    )
    observe_started = threading.Event()
    allow_observe = threading.Event()
    issued: list[reader.TrustedTimePostEnrollmentTopologyObservationCursor] = []
    errors: list[BaseException] = []
    observe = reader.TrustedTimePostEnrollmentTopologyObservationIssuer._observe_daemon

    def delayed_observe(
        owner: reader.TrustedTimePostEnrollmentTopologyObservationIssuer,
        receipts: list[reader._ReadReceipt],
    ) -> LocalDockerDaemonIdentity:
        observe_started.set()
        if not allow_observe.wait(timeout=2.0):
            raise TimeoutError
        return observe(owner, receipts)

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
    try:
        assert observe_started.wait(timeout=2.0)
        second.start()
        second.join(timeout=2.0)
    finally:
        allow_observe.set()
        first.join(timeout=2.0)
        second.join(timeout=2.0)

    assert not first.is_alive()
    assert not second.is_alive()
    assert issued == []
    assert len(errors) == 2
    assert all(
        isinstance(error, reader.TrustedTimePostEnrollmentTopologyReaderError) for error in errors
    )
    assert issuer._cursor_count == 0
    issuer.close()


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


def test_close_race_before_created_commit_cannot_issue_observation(
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
    allow_seal_return = threading.Event()
    issued: list[reader.TrustedTimePostEnrollmentCreatedTopologyObservation] = []
    errors: list[BaseException] = []
    seal = reader._seal_observation

    def delayed_seal(
        owner: object,
        capability: object,
        material: Mapping[str, object],
        kind: str,
    ) -> bytes:
        result = seal(owner, capability, material, kind)
        if kind == "created":
            seal_ready.set()
            if not allow_seal_return.wait(timeout=2.0):
                raise TimeoutError
        return result

    def issue() -> None:
        try:
            issued.append(issuer.issue_created_snapshot(**fixtures._issue_arguments(paths)))
        except BaseException as error:
            errors.append(error)

    monkeypatch.setattr(reader, "_seal_observation", delayed_seal)
    worker = threading.Thread(target=issue)
    worker.start()
    try:
        assert seal_ready.wait(timeout=2.0)
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer.close()
    finally:
        allow_seal_return.set()
        worker.join(timeout=2.0)

    assert not worker.is_alive()
    assert issued == []
    assert len(errors) == 1
    assert isinstance(errors[0], reader.TrustedTimePostEnrollmentTopologyReaderError)
    assert issuer._issued_created_observation_sha256 is None
    assert issuer._last_observation_sha256 is None
    assert issuer._staged_observation_count == 0
    issuer.close()


def test_close_race_before_staged_commit_cannot_issue_ordinal(
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
    allow_seal_return = threading.Event()
    issued: list[reader.TrustedTimePostEnrollmentStagedTopologyObservation] = []
    errors: list[BaseException] = []
    seal = reader._seal_observation

    def delayed_seal(
        owner: object,
        capability: object,
        material: Mapping[str, object],
        kind: str,
    ) -> bytes:
        result = seal(owner, capability, material, kind)
        if kind == "staged_unreleased":
            seal_ready.set()
            if not allow_seal_return.wait(timeout=2.0):
                raise TimeoutError
        return result

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
    try:
        assert seal_ready.wait(timeout=2.0)
        with pytest.raises(reader.TrustedTimePostEnrollmentTopologyReaderError):
            issuer.close()
    finally:
        allow_seal_return.set()
        worker.join(timeout=2.0)

    assert not worker.is_alive()
    assert issued == []
    assert len(errors) == 1
    assert isinstance(errors[0], reader.TrustedTimePostEnrollmentTopologyReaderError)
    assert issuer._staged_observation_count == 0
    assert issuer._last_observation_sha256 == created.observation_sha256
    issuer.close()
