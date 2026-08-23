from __future__ import annotations

import hashlib
import json
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import pytest

from apps.trusted_time_supervisor import post_enrollment_runtime_state as runtime_state
from apps.trusted_time_supervisor.config import TrustedTimeSupervisorConfigurationError

ROOT = Path(__file__).resolve().parents[2]

_RELEASE_BYTES = b"phase6d-post-enrollment-start-release-v1\n"
_READY_BYTES = b"phase6d-post-enrollment-start-sequence-two-ready-v1\n"
_BOOT_BYTES = b"01234567-89ab-cdef-0123-456789abcdef\n"
_ISSUED_NS = 1_000_000_000
_DEADLINE_NS = 121_000_000_000
_NO_OVERRIDE = object()


def _deadline_bytes(
    *,
    boot_payload: bytes = _BOOT_BYTES,
    issued_ns: int = _ISSUED_NS,
    deadline_ns: int = _DEADLINE_NS,
) -> bytes:
    return (
        b'{"boot_id_sha256":"'
        + hashlib.sha256(boot_payload).hexdigest().encode("ascii")
        + b'","contract_version":"phase6d-post-enrollment-start-sequence-two-deadline-v1",'
        + b'"deadline_boottime_ns":'
        + str(deadline_ns).encode("ascii")
        + b',"issued_at_boottime_ns":'
        + str(issued_ns).encode("ascii")
        + b',"release_marker_sha256":"'
        + b"0207100f7073e92f22a5acf8ae06e0735ac33e8dfaef7e60c62d387cd0355731"
        + b'"}\n'
    )


def _directory_stat(*, inode: int, modified: int = 10, changed: int = 11) -> tuple[int, ...]:
    return (
        1,
        inode,
        stat.S_IFDIR | 0o755,
        0,
        0,
        2,
        4_096,
        modified,
        changed,
    )


def _file_stat(
    payload: bytes,
    *,
    inode: int,
    mode: int = 0o400,
    uid: int = 10_001,
    gid: int = 10_001,
    link_count: int = 1,
    size: int | None = None,
) -> tuple[int, ...]:
    return (
        1,
        inode,
        stat.S_IFREG | mode,
        uid,
        gid,
        link_count,
        len(payload) if size is None else size,
        20 + inode,
        30 + inode,
    )


def _replace_stat_slot(
    metadata: tuple[int, ...],
    index: int,
    value: int,
) -> tuple[int, ...]:
    values = list(metadata)
    values[index] = value
    return tuple(values)


def _marker_observations() -> tuple[
    tuple[bytes, tuple[int, ...]],
    tuple[bytes, tuple[int, ...]],
    tuple[bytes, tuple[int, ...]],
    tuple[bytes, tuple[int, ...]],
]:
    deadline = _deadline_bytes()
    return (
        (_RELEASE_BYTES, _file_stat(_RELEASE_BYTES, inode=100)),
        (deadline, _file_stat(deadline, inode=101)),
        (_READY_BYTES, _file_stat(_READY_BYTES, inode=102)),
        (
            _BOOT_BYTES,
            _file_stat(
                _BOOT_BYTES,
                inode=103,
                mode=0o444,
                uid=0,
                gid=0,
                size=0,
            ),
        ),
    )


@dataclass
class _FakeOwner:
    path: str
    metadata: tuple[int, ...]
    events: list[tuple[str, str]]
    close_failures: list[BaseException] = field(default_factory=list)
    closed: bool = False

    def close(self) -> None:
        self.events.append(("close", self.path))
        if self.close_failures:
            raise self.close_failures.pop(0)
        self.closed = True


class _NativeHarness:
    def __init__(self) -> None:
        release, deadline, ready, boot = _marker_observations()
        self.directories = {
            "/": _directory_stat(inode=2),
            "/tmp": _directory_stat(inode=3),
            "/proc": _directory_stat(inode=4),
            "/proc/sys": _directory_stat(inode=5),
            "/proc/sys/kernel": _directory_stat(inode=6),
            "/proc/sys/kernel/random": _directory_stat(inode=7),
        }
        self.files = {
            "/tmp/post-enrollment-start-release": release,
            "/tmp/post-enrollment-start-sequence-two-deadline": deadline,
            "/tmp/post-enrollment-start-sequence-two-ready": ready,
            "/proc/sys/kernel/random/boot_id": boot,
        }
        self.events: list[tuple[str, str]] = []
        self.owners: list[_FakeOwner] = []
        self.call_counts: dict[tuple[str, str], int] = {}
        self.failures: dict[tuple[str, str, int], BaseException] = {}
        self.overrides: dict[tuple[str, str, int], object] = {}
        self.close_failures: dict[str, list[BaseException]] = {}
        self.read_errors: dict[str, BaseException] = {}
        self.live_file_owners = 0
        self.maximum_live_file_owners = 0

    @staticmethod
    def _child(parent: str, component: str) -> str:
        return f"/{component}" if parent == "/" else f"{parent}/{component}"

    def _record(self, operation: str, path: str) -> object:
        self.events.append((operation, path))
        pair = (operation, path)
        call = self.call_counts.get(pair, 0) + 1
        self.call_counts[pair] = call
        key = (operation, path, call)
        failure = self.failures.get(key)
        if failure is not None:
            raise failure
        return self.overrides.get(key, _NO_OVERRIDE)

    def _new_owner(self, path: str, metadata: tuple[int, ...]) -> _FakeOwner:
        owner = _FakeOwner(
            path,
            metadata,
            self.events,
            list(self.close_failures.get(path, ())),
        )
        self.owners.append(owner)
        return owner

    def open_root(self) -> _FakeOwner:
        self._record("open", "/")
        return self._new_owner("/", self.directories["/"])

    def open_directory(self, owner: _FakeOwner, component: str) -> _FakeOwner:
        assert not owner.closed
        path = self._child(owner.path, component)
        self._record("open", path)
        return self._new_owner(path, self.directories[path])

    def open_regular(self, owner: _FakeOwner, component: str) -> _FakeOwner:
        assert not owner.closed
        path = self._child(owner.path, component)
        self._record("open", path)
        opened = self._new_owner(path, self.files[path][1])
        self.live_file_owners += 1
        self.maximum_live_file_owners = max(
            self.maximum_live_file_owners,
            self.live_file_owners,
        )
        real_close = opened.close

        def close() -> None:
            was_closed = opened.closed
            real_close()
            if not was_closed and opened.closed:
                self.live_file_owners -= 1

        opened.close = close  # type: ignore[method-assign]
        return opened

    def fstat(self, owner: _FakeOwner) -> tuple[int, ...]:
        assert not owner.closed
        overridden = self._record("fstat", owner.path)
        if overridden is not _NO_OVERRIDE:
            return cast(tuple[int, ...], overridden)
        return owner.metadata

    def statat(self, owner: _FakeOwner, component: str) -> tuple[int, ...]:
        assert not owner.closed
        path = self._child(owner.path, component)
        overridden = self._record("statat", path)
        if overridden is not _NO_OVERRIDE:
            return cast(tuple[int, ...], overridden)
        if path in self.directories:
            return self.directories[path]
        if path in self.files:
            return self.files[path][1]
        raise FileNotFoundError(path)

    def read_snapshot(
        self,
        owner: _FakeOwner,
        maximum_bytes: int,
    ) -> tuple[bytes, tuple[int, ...], tuple[int, ...]]:
        assert not owner.closed
        overridden = self._record("read", owner.path)
        if overridden is not _NO_OVERRIDE:
            return cast(tuple[bytes, tuple[int, ...], tuple[int, ...]], overridden)
        failure = self.read_errors.get(owner.path)
        if failure is not None:
            raise failure
        payload, metadata = self.files[owner.path]
        assert len(payload) <= maximum_bytes
        return payload, metadata, metadata


def _read_regular_with_harness(
    harness: _NativeHarness,
    parent_owner: object,
    component: str,
    maximum_bytes: int,
) -> tuple[bytes, tuple[int, ...]]:
    return runtime_state._read_regular_snapshot(
        cast(Any, parent_owner),
        component,
        maximum_bytes,
        _fstat_exact=harness.fstat,
        _statat_exact=harness.statat,
        _open_regular_exact=harness.open_regular,
        _read_snapshot_exact=harness.read_snapshot,
    )


def _read_tmp_with_harness(
    harness: _NativeHarness,
    marker_components: tuple[str, ...],
    absence_components: tuple[str, ...],
    *,
    reader: Any = runtime_state._read_tmp_snapshot,
) -> tuple[tuple[bytes, tuple[int, ...]], ...]:
    def read_regular(
        owner: object,
        component: str,
        maximum_bytes: int,
    ) -> tuple[bytes, tuple[int, ...]]:
        return _read_regular_with_harness(harness, owner, component, maximum_bytes)

    def observe_absences(owner: object, components: tuple[str, ...]) -> tuple[str, ...]:
        return runtime_state._require_absences(
            cast(Any, owner),
            components,
            _fstat_exact=harness.fstat,
            _statat_exact=harness.statat,
        )

    def require_context(
        root_owner: object,
        tmp_owner: object,
        *,
        root_before: tuple[int, ...],
        tmp_before: tuple[int, ...],
    ) -> None:
        runtime_state._require_tmp_context(
            cast(Any, root_owner),
            cast(Any, tmp_owner),
            root_before=cast(Any, root_before),
            tmp_before=cast(Any, tmp_before),
            _fstat_exact=harness.fstat,
            _statat_exact=harness.statat,
        )

    return reader(
        marker_components,
        absence_components,
        _open_root=harness.open_root,
        _open_directory=harness.open_directory,
        _fstat_exact=harness.fstat,
        _statat_exact=harness.statat,
        _read_regular=read_regular,
        _observe_absences=observe_absences,
        _require_context=require_context,
    )


def _read_boot_with_harness(
    harness: _NativeHarness,
) -> tuple[bytes, tuple[int, ...]]:
    def read_regular(
        owner: object,
        component: str,
        maximum_bytes: int,
    ) -> tuple[bytes, tuple[int, ...]]:
        return _read_regular_with_harness(harness, owner, component, maximum_bytes)

    return runtime_state._read_boot_id_snapshot(
        _open_root=harness.open_root,
        _open_directory=harness.open_directory,
        _fstat_exact=harness.fstat,
        _statat_exact=harness.statat,
        _read_regular=read_regular,
    )


def _read_initial_with_harness(
    harness: _NativeHarness,
) -> tuple[tuple[bytes, tuple[int, ...]], tuple[bytes, tuple[int, ...]]]:
    return runtime_state._read_initial_markers(
        _read=lambda markers, absences: _read_tmp_with_harness(
            harness,
            markers,
            absences,
        )
    )


def _read_final_with_harness(
    harness: _NativeHarness,
) -> tuple[
    tuple[bytes, tuple[int, ...]],
    tuple[bytes, tuple[int, ...]],
    tuple[bytes, tuple[int, ...]],
]:
    return runtime_state._read_final_markers(
        _read=lambda markers, absences: _read_tmp_with_harness(
            harness,
            markers,
            absences,
        )
    )


def _read_ready_with_harness(
    harness: _NativeHarness,
) -> tuple[bytes, tuple[int, ...]]:
    return runtime_state._read_ready_marker(
        _read=lambda markers, absences: _read_tmp_with_harness(
            harness,
            markers,
            absences,
        )
    )


def _projection_with_harness(
    harness: _NativeHarness,
) -> tuple[str, int, bytes]:
    clock_values = iter((2_000_000_000, 2_000_000_000, 2_000_000_000, 2_000_000_000))

    def wait_ready(deadline: int) -> tuple[bytes, tuple[int, ...]]:
        return runtime_state._wait_for_ready_marker(
            deadline,
            _clock=lambda: next(clock_values),
            _sleep=lambda _seconds: None,
            _read_ready=lambda: _read_ready_with_harness(harness),
        )

    return runtime_state._read_runtime_state_projection(
        _read_initial=lambda: _read_initial_with_harness(harness),
        _read_boot=lambda: _read_boot_with_harness(harness),
        _wait_ready=wait_ready,
        _read_final=lambda: _read_final_with_harness(harness),
    )


def _canonical_receipt(deadline_sha256: str) -> bytes:
    return (
        json.dumps(
            {
                "alert_delivery_authorized": False,
                "arming_authorized": False,
                "automatic_rearm_authorized": False,
                "automatic_resume_authorized": False,
                "broker_action_authorized": False,
                "contract_version": "phase6d-post-enrollment-runtime-state-v1",
                "exposure_authorized": False,
                "live_trading_authorized": False,
                "new_exposure_authorized": False,
                "operational_control_authorized": False,
                "paper_trading_authorized": False,
                "readiness_authorized": False,
                "rearm_authorized": False,
                "release_marker_sha256": (
                    "0207100f7073e92f22a5acf8ae06e0735ac33e8dfaef7e60c62d387cd0355731"
                ),
                "sequence_two_deadline_marker_sha256": deadline_sha256,
                "sequence_two_ready_marker_sha256": (
                    "f8faaa629107c4b26b7c70677ee8cc98d67a69741c21fb91300e78b2d9bf5c6d"
                ),
                "service": "trusted-time-supervisor",
                "status": "sequence_two_ready_observed",
            },
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )


def test_runtime_state_native_projection_emits_exact_canonical_bytes_and_closes_owners() -> None:
    harness = _NativeHarness()

    projection = _projection_with_harness(harness)
    encoded = runtime_state._runtime_state_bytes(_observe=lambda: projection)

    expected_deadline_sha256 = hashlib.sha256(_deadline_bytes()).hexdigest()
    assert projection == (
        "trusted-time-runtime-state-projection-v1",
        _DEADLINE_NS,
        expected_deadline_sha256.encode("ascii"),
    )
    assert encoded == _canonical_receipt(expected_deadline_sha256)
    assert harness.maximum_live_file_owners == 1
    assert harness.live_file_owners == 0
    assert harness.owners
    assert all(owner.closed for owner in harness.owners)
    assert ("open", "/tmp") in harness.events
    assert ("open", "/proc/sys/kernel/random") in harness.events
    assert all("fileno" not in event for event in harness.events)


def test_boot_id_traversal_revalidates_every_directory_and_closes_child_first() -> None:
    harness = _NativeHarness()

    observed = _read_boot_with_harness(harness)

    assert observed == harness.files["/proc/sys/kernel/random/boot_id"]
    assert all(owner.closed for owner in harness.owners)
    closes = [path for operation, path in harness.events if operation == "close"]
    assert closes == [
        "/proc/sys/kernel/random/boot_id",
        "/proc/sys/kernel/random",
        "/proc/sys/kernel",
        "/proc/sys",
        "/proc",
        "/",
    ]


@pytest.mark.parametrize(
    "mutation",
    ["boot", "leading-zero", "window", "contract", "trailing-byte"],
)
def test_deadline_parser_rejects_every_noncanonical_or_wrong_boot_payload(mutation: str) -> None:
    release, deadline, _ready, boot = _marker_observations()
    del release
    payload = deadline[0]
    if mutation == "boot":
        payload = payload.replace(
            hashlib.sha256(_BOOT_BYTES).hexdigest().encode("ascii"), b"f" * 64
        )
    elif mutation == "leading-zero":
        payload = payload.replace(b'"deadline_boottime_ns":121', b'"deadline_boottime_ns":0121')
    elif mutation == "window":
        payload = payload.replace(
            b'"issued_at_boottime_ns":1000000000', b'"issued_at_boottime_ns":1000000001'
        )
    elif mutation == "contract":
        payload = payload.replace(b"phase6d-post-enrollment", b"phase7d-post-enrollment", 1)
    else:
        payload += b" "
    mutated_deadline = (payload, _file_stat(payload, inode=101))

    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        runtime_state._parse_deadline_marker(mutated_deadline, boot)


@pytest.mark.parametrize(
    ("slot", "value"),
    [
        (2, stat.S_IFDIR | 0o400),
        (3, 0),
        (4, 0),
        (5, 2),
        (6, 1),
    ],
    ids=("type", "uid", "gid", "link-count", "size"),
)
def test_fixed_marker_validator_rejects_each_metadata_violation(slot: int, value: int) -> None:
    marker = (
        _RELEASE_BYTES,
        _replace_stat_slot(_file_stat(_RELEASE_BYTES, inode=100), slot, value),
    )

    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        runtime_state._require_fixed_marker(marker, expected_payload=_RELEASE_BYTES)


@pytest.mark.parametrize(
    ("operation", "path", "call", "override_kind"),
    [
        ("statat", "/tmp/post-enrollment-start-release", 1, "file"),
        ("fstat", "/tmp/post-enrollment-start-release", 1, "file"),
        ("read", "/tmp/post-enrollment-start-release", 1, "read-before"),
        ("read", "/tmp/post-enrollment-start-release", 1, "read-after"),
        ("fstat", "/tmp/post-enrollment-start-release", 2, "file"),
        ("statat", "/tmp/post-enrollment-start-release", 2, "file"),
        ("fstat", "/tmp", 2, "parent"),
    ],
    ids=(
        "named-before",
        "opened-before",
        "read-before",
        "read-after",
        "opened-after",
        "named-after",
        "parent-after",
    ),
)
def test_native_marker_read_rejects_every_identity_drift_and_closes_owner(
    operation: str,
    path: str,
    call: int,
    override_kind: str,
) -> None:
    harness = _NativeHarness()
    metadata = harness.files["/tmp/post-enrollment-start-release"][1]
    changed = _replace_stat_slot(metadata, 8, metadata[8] + 1)
    if override_kind == "read-before":
        override: object = (_RELEASE_BYTES, changed, metadata)
    elif override_kind == "read-after":
        override = (_RELEASE_BYTES, metadata, changed)
    elif override_kind == "parent":
        parent = harness.directories["/tmp"]
        override = _replace_stat_slot(parent, 8, parent[8] + 1)
    else:
        override = changed
    harness.overrides[(operation, path, call)] = override
    tmp_owner = harness._new_owner("/tmp", harness.directories["/tmp"])

    with pytest.raises(OSError):
        _read_regular_with_harness(
            harness,
            tmp_owner,
            "post-enrollment-start-release",
            len(_RELEASE_BYTES),
        )

    file_owners = [
        owner for owner in harness.owners if owner.path == "/tmp/post-enrollment-start-release"
    ]
    assert len(file_owners) <= 1
    assert all(owner.closed for owner in file_owners)
    assert harness.live_file_owners == 0


@pytest.mark.parametrize("absence_pass", [1, 2], ids=("first-pass", "second-pass"))
def test_tmp_snapshot_rejects_staging_presence_during_either_pass(absence_pass: int) -> None:
    harness = _NativeHarness()
    staging = "/tmp/.post-enrollment-start-release-staging"
    harness.overrides[("statat", staging, absence_pass)] = _file_stat(b"x", inode=300)

    with pytest.raises(OSError):
        _read_initial_with_harness(harness)

    assert all(owner.closed for owner in harness.owners)
    assert harness.live_file_owners == 0


@pytest.mark.parametrize(
    "changed",
    ["release", "deadline", "ready", "boot"],
)
def test_projection_rejects_cross_observation_marker_or_boot_currentness_drift(
    changed: str,
) -> None:
    release, deadline, ready, boot = _marker_observations()
    changed_index = {"release": 0, "deadline": 1, "ready": 2, "boot": 3}[changed]
    values = [release, deadline, ready, boot]
    payload, metadata = values[changed_index]
    values[changed_index] = (payload, _replace_stat_slot(metadata, 1, metadata[1] + 1_000))
    final_release, final_deadline, final_ready, final_boot = values
    boot_reads = iter((boot, final_boot))
    wait_reads = iter((ready, final_ready if changed == "ready" else ready))

    with pytest.raises(TrustedTimeSupervisorConfigurationError, match="changed"):
        runtime_state._read_runtime_state_projection(
            _read_initial=lambda: (release, deadline),
            _read_boot=lambda: next(boot_reads),
            _wait_ready=lambda _deadline: next(wait_reads),
            _read_final=lambda: (final_release, final_deadline, final_ready),
        )


def test_wait_preserves_absolute_deadline_and_returns_only_a_confirmed_ready_marker() -> None:
    _release, _deadline, ready, _boot = _marker_observations()
    clocks = iter((2_000_000_000, 3_000_000_000, 3_000_000_000))
    observations: list[float] = []
    reads = iter((FileNotFoundError(), ready))

    def read_ready() -> tuple[bytes, tuple[int, ...]]:
        observed = next(reads)
        if isinstance(observed, BaseException):
            raise observed
        return observed

    result = runtime_state._wait_for_ready_marker(
        _DEADLINE_NS,
        _clock=lambda: next(clocks),
        _sleep=observations.append,
        _read_ready=read_ready,
    )

    assert result == ready
    assert observations == [0.1]


@pytest.mark.parametrize(
    ("clocks", "read_failure"),
    [
        ((121_000_000_000,), FileNotFoundError()),
        ((2_000_000_000, 1_000_000_000), FileNotFoundError()),
    ],
    ids=("already-expired", "clock-regressed"),
)
def test_wait_fails_closed_at_expiry_or_clock_regression(
    clocks: tuple[int, ...],
    read_failure: BaseException,
) -> None:
    clock_values = iter(clocks)

    with pytest.raises(TrustedTimeSupervisorConfigurationError):
        runtime_state._wait_for_ready_marker(
            _DEADLINE_NS,
            _clock=lambda: next(clock_values),
            _sleep=lambda _seconds: None,
            _read_ready=lambda: (_ for _ in ()).throw(read_failure),
        )


@pytest.mark.parametrize(
    ("body_error", "cleanup_error", "expected"),
    [
        (KeyboardInterrupt, ValueError, KeyboardInterrupt),
        (ValueError, KeyboardInterrupt, KeyboardInterrupt),
        (KeyboardInterrupt, SystemExit, KeyboardInterrupt),
    ],
)
def test_native_marker_cleanup_retries_and_preserves_async_priority(
    body_error: type[BaseException],
    cleanup_error: type[BaseException],
    expected: type[BaseException],
) -> None:
    harness = _NativeHarness()
    path = "/tmp/post-enrollment-start-release"
    harness.read_errors[path] = body_error()
    harness.close_failures[path] = [cleanup_error()]
    tmp_owner = harness._new_owner("/tmp", harness.directories["/tmp"])

    with pytest.raises(expected):
        _read_regular_with_harness(
            harness,
            tmp_owner,
            "post-enrollment-start-release",
            len(_RELEASE_BYTES),
        )

    file_owner = next(owner for owner in harness.owners if owner.path == path)
    assert file_owner.closed is True
    assert [event for event in harness.events if event == ("close", path)] == [
        ("close", path),
        ("close", path),
    ]


def test_definition_bound_profiles_validators_hash_stat_and_grammar_ignore_global_relabels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release, deadline, ready, boot = _marker_observations()
    original_projection = runtime_state._read_runtime_state_projection
    original_bytes = runtime_state._runtime_state_bytes
    original_tmp_reader = runtime_state._read_tmp_snapshot
    projection_defaults = cast(dict[str, object], original_projection.__kwdefaults__)
    tmp_defaults = cast(dict[str, object], original_tmp_reader.__kwdefaults__)
    parser_defaults = cast(dict[str, object], runtime_state._parse_deadline_marker.__kwdefaults__)
    bytes_defaults = cast(dict[str, object], original_bytes.__kwdefaults__)
    original_native = {
        name: getattr(runtime_state, name)
        for name in (
            "_fstat",
            "_open_child_directory",
            "_open_child_regular",
            "_open_root_directory",
            "_read_snapshot",
            "_statat",
        )
    }
    expected = original_bytes(
        _observe=lambda: original_projection(
            _read_initial=lambda: (release, deadline),
            _read_boot=lambda: boot,
            _wait_ready=lambda _deadline: ready,
            _read_final=lambda: (release, deadline, ready),
        )
    )
    harness = _NativeHarness()
    harness.files["/tmp/decoy"] = (b"decoy", _file_stat(b"decoy", inode=900))

    def reject_relabel(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("selectively relabelled runtime-state global was consulted")

    for name in original_native:
        monkeypatch.setattr(runtime_state, name, reject_relabel)
    for name in (
        "_parse_deadline_marker",
        "_require_boot_id_marker",
        "_require_deadline_marker",
        "_require_fixed_marker",
        "_sha256_hex_bytes",
    ):
        monkeypatch.setattr(runtime_state, name, reject_relabel)
    monkeypatch.setattr(runtime_state.hashlib, "sha256", reject_relabel)
    monkeypatch.setattr(runtime_state.stat, "S_ISDIR", reject_relabel)
    monkeypatch.setattr(runtime_state.stat, "S_ISREG", reject_relabel)
    monkeypatch.setattr(runtime_state.stat, "S_IMODE", reject_relabel)
    monkeypatch.setattr(runtime_state, "_RELEASE_BYTES", b"decoy")
    monkeypatch.setattr(runtime_state, "_READY_BYTES", b"decoy")
    monkeypatch.setattr(runtime_state, "_DEADLINE_PREFIX", b"decoy")
    monkeypatch.setattr(runtime_state, "_DEADLINE_AFTER_BOOT", b"decoy")
    monkeypatch.setattr(runtime_state, "_DEADLINE_BEFORE_ISSUED", b"decoy")
    monkeypatch.setattr(runtime_state, "_DEADLINE_SUFFIX", b"decoy")
    monkeypatch.setattr(runtime_state, "_RUNTIME_STATE_PREFIX", b"decoy")
    monkeypatch.setattr(runtime_state, "_RUNTIME_STATE_SUFFIX", b"decoy")
    monkeypatch.setattr(runtime_state, "_INITIAL_MARKER_COMPONENTS", ("decoy",))
    monkeypatch.setattr(runtime_state, "_FINAL_MARKER_COMPONENTS", ("decoy",))
    monkeypatch.setattr(runtime_state, "_READY_MARKER_COMPONENTS", ("decoy",))
    monkeypatch.setattr(runtime_state, "_ALL_STAGING_COMPONENTS", ("decoy",))
    monkeypatch.setattr(runtime_state, "_READY_STAGING_COMPONENTS", ("decoy",))
    monkeypatch.setattr(runtime_state, "_DEADLINE_COMPONENT", "decoy")
    monkeypatch.setattr(runtime_state, "_RELEASE_COMPONENT", "decoy")

    assert projection_defaults["_require_fixed"] is not reject_relabel
    assert projection_defaults["_require_deadline"] is not reject_relabel
    assert projection_defaults["_require_boot"] is not reject_relabel
    assert projection_defaults["_parse_deadline"] is not reject_relabel
    assert parser_defaults["_prefix"] != b"decoy"
    assert parser_defaults["_after_boot"] != b"decoy"
    assert parser_defaults["_before_issued"] != b"decoy"
    assert parser_defaults["_suffix"] != b"decoy"
    assert bytes_defaults["_prefix"] != b"decoy"
    assert bytes_defaults["_suffix"] != b"decoy"
    assert tmp_defaults["_open_root"] is original_native["_open_root_directory"]
    assert tmp_defaults["_open_directory"] is original_native["_open_child_directory"]
    assert tmp_defaults["_fstat_exact"] is original_native["_fstat"]
    assert tmp_defaults["_statat_exact"] is original_native["_statat"]

    encoded = original_bytes(
        _observe=lambda: original_projection(
            _read_initial=lambda: (release, deadline),
            _read_boot=lambda: boot,
            _wait_ready=lambda _deadline: ready,
            _read_final=lambda: (release, deadline, ready),
        )
    )
    exact_profile = _read_tmp_with_harness(
        harness,
        (
            "post-enrollment-start-release",
            "post-enrollment-start-sequence-two-deadline",
        ),
        (
            ".post-enrollment-start-sequence-two-deadline-staging",
            ".post-enrollment-start-release-staging",
            ".post-enrollment-start-sequence-two-ready-staging",
        ),
        reader=original_tmp_reader,
    )

    assert encoded == expected
    assert len(exact_profile) == 2
    assert not any(path == "/tmp/decoy" for _operation, path in harness.events)


class _Sink:
    def __init__(self) -> None:
        self.values: list[str] = []

    def write(self, value: str) -> int:
        self.values.append(value)
        return len(value)


def test_runtime_state_main_binds_output_streams_before_reentrant_swap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encoded = runtime_state._runtime_state_bytes(
        _observe=lambda: (
            "trusted-time-runtime-state-projection-v1",
            _DEADLINE_NS,
            b"d" * 64,
        )
    )
    stdout_a = _Sink()
    stderr_a = _Sink()
    stdout_b = _Sink()
    stderr_b = _Sink()
    monkeypatch.setattr(sys, "stdout", stdout_a)
    monkeypatch.setattr(sys, "stderr", stderr_a)
    monkeypatch.setattr(sys, "argv", ["post-enrollment-runtime-state"])

    def emit() -> bytes:
        monkeypatch.setattr(sys, "stdout", stdout_b)
        monkeypatch.setattr(sys, "stderr", stderr_b)
        return encoded

    runtime_state.runtime_state_main(_emit=emit)

    assert stdout_a.values == [encoded.decode("ascii")]
    assert stderr_a.values == []
    assert stdout_b.values == []
    assert stderr_b.values == []


def test_runtime_state_main_binds_failure_stream_before_reentrant_swap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stdout_a = _Sink()
    stderr_a = _Sink()
    stdout_b = _Sink()
    stderr_b = _Sink()
    monkeypatch.setattr(sys, "stdout", stdout_a)
    monkeypatch.setattr(sys, "stderr", stderr_a)
    monkeypatch.setattr(sys, "argv", ["post-enrollment-runtime-state"])

    def fail() -> bytes:
        monkeypatch.setattr(sys, "stdout", stdout_b)
        monkeypatch.setattr(sys, "stderr", stderr_b)
        raise OSError("private boot identifier")

    with pytest.raises(SystemExit) as raised:
        runtime_state.runtime_state_main(_emit=fail)

    assert raised.value.code == 2
    assert stdout_a.values == []
    assert stderr_a.values == ["trusted-time post-enrollment runtime state probe failed\n"]
    assert stdout_b.values == []
    assert stderr_b.values == []


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(9)])
def test_runtime_state_main_preserves_async_identity_without_output(
    error: BaseException,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["post-enrollment-runtime-state"])

    with pytest.raises(type(error)) as raised:
        runtime_state.runtime_state_main(
            _emit=lambda: (_ for _ in ()).throw(error),
        )

    assert raised.value is error
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["autoquant-trusted-time-post-enrollment-runtime-state"],
        ["post-enrollment-runtime-state", "extra"],
    ],
)
def test_runtime_state_main_rejects_every_nonexact_argv(
    argv: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", argv)

    with pytest.raises(SystemExit) as raised:
        runtime_state.runtime_state_main(_emit=lambda: b"should-not-run")

    assert raised.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "trusted-time post-enrollment runtime state probe failed\n"


def test_public_dict_is_secondary_and_grants_no_authority() -> None:
    encoded = runtime_state._runtime_state_bytes(
        _observe=lambda: (
            "trusted-time-runtime-state-projection-v1",
            _DEADLINE_NS,
            b"d" * 64,
        )
    )

    payload = runtime_state.read_post_enrollment_runtime_state(_read_bytes=lambda: encoded)

    assert payload["sequence_two_deadline_marker_sha256"] == "d" * 64
    assert payload["status"] == "sequence_two_ready_observed"
    for field_name, value in payload.items():
        if field_name.endswith("authorized"):
            assert value is False


def test_runtime_state_source_has_no_raw_descriptor_json_or_writer_surface() -> None:
    source = runtime_state.__file__
    assert source is not None
    encoded = Path(source).read_text(encoding="utf-8")
    assert "import os" not in encoded
    assert "import json" not in encoded
    assert "import argparse" not in encoded
    assert ".fileno" not in encoded
    assert "print(" not in encoded
    assert "_create_child_regular_exclusive" not in encoded
    assert "_write_all" not in encoded
    assert "_fsync" not in encoded


def test_runtime_state_console_script_is_inspection_only() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert (
        "autoquant-trusted-time-post-enrollment-runtime-state = "
        '"apps.trusted_time_supervisor.post_enrollment_runtime_state:runtime_state_main"'
        in pyproject
    )
    assert "subprocess" not in vars(runtime_state)
    assert "write_post_enrollment_start_release" not in vars(runtime_state)
    assert "write_post_enrollment_start_sequence_two_ready" not in vars(runtime_state)
