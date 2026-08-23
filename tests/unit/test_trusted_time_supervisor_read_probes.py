from __future__ import annotations

import ast
import hashlib
import json
import stat
import sys
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import pytest

from apps.trusted_time_supervisor import image_schema_contract as schema_probe
from apps.trusted_time_supervisor import post_enrollment_read_probes as marker_probes

_DATABASE_BYTES = b"phase6c-database-secret-consumed-v1\n"
_DEADLINE_BYTES = b'{"contract_version":"deadline"}\n'
_RELEASE_BYTES = b"phase6d-post-enrollment-start-release-v1\n"
_READY_BYTES = b"phase6d-post-enrollment-start-sequence-two-ready-v1\n"
_NO_OVERRIDE = object()


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


def _file_stat(payload: bytes, *, inode: int) -> tuple[int, ...]:
    return (
        1,
        inode,
        stat.S_IFREG | 0o400,
        10_001,
        10_001,
        1,
        len(payload),
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


@dataclass
class _FakeOwner:
    label: str
    metadata: tuple[int, ...]
    events: list[tuple[str, str]]
    close_failures: list[BaseException] = field(default_factory=list)
    closed: bool = False

    def close(self) -> None:
        self.events.append(("close", self.label))
        if self.close_failures:
            raise self.close_failures.pop(0)
        self.closed = True


class _NativeHarness:
    def __init__(self, present: dict[str, bytes]) -> None:
        self.present = dict(present)
        self.root_stat = _directory_stat(inode=2)
        self.tmp_stat = _directory_stat(inode=3)
        self.events: list[tuple[str, str]] = []
        self.owners: list[_FakeOwner] = []
        self.file_owners_live = 0
        self.maximum_file_owners_live = 0
        self.read_error: BaseException | None = None
        self.file_close_failures: list[BaseException] = []
        self.failures: dict[tuple[str, str, int], BaseException] = {}
        self.overrides: dict[tuple[str, str, int], object] = {}
        self.call_counts: dict[tuple[str, str], int] = {}
        self.file_metadata: dict[str, tuple[int, ...]] = {}

    def _record(self, operation: str, label: str) -> object:
        self.events.append((operation, label))
        pair = (operation, label)
        call = self.call_counts.get(pair, 0) + 1
        self.call_counts[pair] = call
        key = (operation, label, call)
        failure = self.failures.get(key)
        if failure is not None:
            raise failure
        return self.overrides.get(key, _NO_OVERRIDE)

    def _metadata(self, component: str) -> tuple[int, ...]:
        overridden = self.file_metadata.get(component)
        if overridden is not None:
            return overridden
        return _file_stat(
            self.present[component],
            inode=100 + tuple(self.present).index(component),
        )

    def _new_owner(self, label: str, metadata: tuple[int, ...]) -> _FakeOwner:
        owner = _FakeOwner(
            label,
            metadata,
            self.events,
            list(self.file_close_failures) if label.startswith("file:") else [],
        )
        self.owners.append(owner)
        return owner

    def open_root(self) -> _FakeOwner:
        self._record("open", "/")
        return self._new_owner("root", self.root_stat)

    def open_directory(self, owner: _FakeOwner, component: str) -> _FakeOwner:
        assert owner.label == "root"
        assert component == "tmp"
        self._record("open", component)
        return self._new_owner("tmp", self.tmp_stat)

    def open_regular(self, owner: _FakeOwner, component: str) -> _FakeOwner:
        assert owner.label == "tmp"
        self._record("open", component)
        self.file_owners_live += 1
        self.maximum_file_owners_live = max(
            self.maximum_file_owners_live,
            self.file_owners_live,
        )
        opened = self._new_owner(
            f"file:{component}",
            self._metadata(component),
        )
        real_close = opened.close

        def close() -> None:
            was_closed = opened.closed
            real_close()
            if not was_closed and opened.closed:
                self.file_owners_live -= 1

        opened.close = close  # type: ignore[method-assign]
        return opened

    def fstat(self, owner: _FakeOwner) -> tuple[int, ...]:
        assert not owner.closed
        overridden = self._record("fstat", owner.label)
        if overridden is not _NO_OVERRIDE:
            return cast(tuple[int, ...], overridden)
        return owner.metadata

    def statat(self, owner: _FakeOwner, component: str) -> tuple[int, ...]:
        assert not owner.closed
        overridden = self._record("statat", component)
        if overridden is not _NO_OVERRIDE:
            return cast(tuple[int, ...], overridden)
        if owner.label == "root":
            assert component == "tmp"
            return self.tmp_stat
        if component not in self.present:
            raise FileNotFoundError(component)
        return self._metadata(component)

    def read_snapshot(
        self,
        owner: _FakeOwner,
        maximum_bytes: int,
    ) -> tuple[bytes, tuple[int, ...], tuple[int, ...]]:
        assert maximum_bytes == 4_096
        assert owner.label.startswith("file:")
        overridden = self._record("read", owner.label)
        if overridden is not _NO_OVERRIDE:
            return cast(tuple[bytes, tuple[int, ...], tuple[int, ...]], overridden)
        if self.read_error is not None:
            raise self.read_error
        component = owner.label.removeprefix("file:")
        return self.present[component], owner.metadata, owner.metadata


def _observe_absences_with_harness(
    harness: _NativeHarness,
    tmp_owner: object,
    bindings: object,
) -> tuple[str, ...]:
    return marker_probes._require_absences(
        cast(Any, tmp_owner),
        cast(Any, bindings),
        _fstat_exact=harness.fstat,
        _statat_exact=harness.statat,
    )


def _read_marker_with_harness(
    harness: _NativeHarness,
    tmp_owner: object,
    component: str,
) -> tuple[bytes, tuple[int, int, int, int, int, int, int, int, int]]:
    return marker_probes._read_marker(
        cast(Any, tmp_owner),
        component,
        _fstat_exact=harness.fstat,
        _statat_exact=harness.statat,
        _open_regular_exact=harness.open_regular,
        _read_snapshot_exact=harness.read_snapshot,
    )


def _require_context_with_harness(
    harness: _NativeHarness,
    root_owner: object,
    tmp_owner: object,
    *,
    root_before: tuple[int, ...],
    tmp_before: tuple[int, ...],
) -> None:
    marker_probes._require_open_tmp_context(
        cast(Any, root_owner),
        cast(Any, tmp_owner),
        root_before=cast(Any, root_before),
        tmp_before=cast(Any, tmp_before),
        _fstat_exact=harness.fstat,
        _statat_exact=harness.statat,
    )


def _staged_barrier_bytes_with_harness(
    harness: _NativeHarness,
    *,
    marker_bytes: Callable[..., bytes] | None = None,
    absence_bytes: Callable[..., bytes] | None = None,
) -> bytes:
    def observe_absences(owner: object, bindings: object) -> tuple[str, ...]:
        return _observe_absences_with_harness(harness, owner, bindings)

    def observe_marker(owner: object, component: str) -> object:
        return _read_marker_with_harness(harness, owner, component)

    def require_context(
        root_owner: object,
        tmp_owner: object,
        *,
        root_before: tuple[int, ...],
        tmp_before: tuple[int, ...],
    ) -> None:
        _require_context_with_harness(
            harness,
            root_owner,
            tmp_owner,
            root_before=root_before,
            tmp_before=tmp_before,
        )

    dependencies: dict[str, Any] = {
        "_open_root": harness.open_root,
        "_open_directory": harness.open_directory,
        "_fstat_exact": harness.fstat,
        "_statat_exact": harness.statat,
        "_observe_absences": observe_absences,
        "_observe_marker": observe_marker,
        "_require_context": require_context,
    }
    if (marker_bytes is None) != (absence_bytes is None):
        raise TypeError
    if marker_bytes is not None and absence_bytes is not None:
        dependencies["_marker_bytes"] = marker_bytes
        dependencies["_absence_bytes"] = absence_bytes
    return marker_probes._staged_barrier_bytes(**dependencies)


def _pre_effect_absence_bytes_with_harness(harness: _NativeHarness) -> bytes:
    def observe_absences(owner: object, bindings: object) -> tuple[str, ...]:
        return _observe_absences_with_harness(harness, owner, bindings)

    def require_context(
        root_owner: object,
        tmp_owner: object,
        *,
        root_before: tuple[int, ...],
        tmp_before: tuple[int, ...],
    ) -> None:
        _require_context_with_harness(
            harness,
            root_owner,
            tmp_owner,
            root_before=root_before,
            tmp_before=tmp_before,
        )

    return marker_probes._pre_effect_runtime_absence_bytes(
        _open_root=harness.open_root,
        _open_directory=harness.open_directory,
        _fstat_exact=harness.fstat,
        _statat_exact=harness.statat,
        _observe_absences=observe_absences,
        _require_context=require_context,
    )


def _persistent_barrier_bytes_with_harness(
    harness: _NativeHarness,
    *,
    marker_bytes: Callable[..., bytes] | None = None,
    absence_bytes: Callable[..., bytes] | None = None,
) -> bytes:
    def observe_absences(owner: object, bindings: object) -> tuple[str, ...]:
        return _observe_absences_with_harness(harness, owner, bindings)

    def observe_marker(owner: object, component: str) -> object:
        return _read_marker_with_harness(harness, owner, component)

    def require_context(
        root_owner: object,
        tmp_owner: object,
        *,
        root_before: tuple[int, ...],
        tmp_before: tuple[int, ...],
    ) -> None:
        _require_context_with_harness(
            harness,
            root_owner,
            tmp_owner,
            root_before=root_before,
            tmp_before=tmp_before,
        )

    dependencies: dict[str, Any] = {
        "_open_root": harness.open_root,
        "_open_directory": harness.open_directory,
        "_fstat_exact": harness.fstat,
        "_statat_exact": harness.statat,
        "_observe_absences": observe_absences,
        "_observe_marker": observe_marker,
        "_require_context": require_context,
    }
    if (marker_bytes is None) != (absence_bytes is None):
        raise TypeError
    if marker_bytes is not None and absence_bytes is not None:
        dependencies["_marker_bytes"] = marker_bytes
        dependencies["_absence_bytes"] = absence_bytes
    return marker_probes._persistent_barrier_bytes(**dependencies)


def _present_markers() -> dict[str, bytes]:
    return {
        "database-secret-consumed": _DATABASE_BYTES,
        "post-enrollment-start-sequence-two-deadline": _DEADLINE_BYTES,
        "post-enrollment-start-release": _RELEASE_BYTES,
        "post-enrollment-start-sequence-two-ready": _READY_BYTES,
    }


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _expected_marker(
    path: str,
    payload: bytes,
    *,
    inode: int,
) -> dict[str, object]:
    metadata = _file_stat(payload, inode=inode)
    return {
        "byte_sha256": hashlib.sha256(payload).hexdigest(),
        "changed_time_ns": metadata[8],
        "device": metadata[0],
        "inode": metadata[1],
        "link_count": metadata[5],
        "mode": stat.S_IMODE(metadata[2]),
        "modified_time_ns": metadata[7],
        "owner_gid": metadata[4],
        "owner_uid": metadata[3],
        "path": path,
        "regular": True,
        "size": len(payload),
    }


def test_schema_contract_target_emits_one_exact_canonical_line(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["image-schema-contract"])

    schema_probe.schema_contract_main()

    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {
        "catalog_relations": [
            "phase6_trusted_time_head_anchor_intents",
            "phase6_trusted_time_head_anchor_receipts",
        ],
        "schema_revision": "0036_phase6_time_anchors",
    }
    assert captured.out == schema_probe._schema_contract_bytes().decode("ascii") + "\n"


def test_schema_contract_output_ignores_selective_module_global_relabels(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected = schema_probe._schema_contract_bytes()
    monkeypatch.setattr(schema_probe, "EXPECTED_SCHEMA_REVISION", "relabelled")
    monkeypatch.setattr(schema_probe, "_INSTALLED_RELATION_TUPLE", ("relabelled",))
    monkeypatch.setattr(schema_probe, "metadata", object())
    monkeypatch.setattr(schema_probe, "_schema_contract_bytes", lambda: b"relabelled")
    monkeypatch.setattr(sys, "argv", ["image-schema-contract"])

    schema_probe.schema_contract_main()

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.encode("ascii") == expected + b"\n"


@pytest.mark.parametrize(
    ("main", "expected_stderr"),
    [
        (
            schema_probe.schema_contract_main,
            "trusted-time operational schema contract probe failed\n",
        ),
        (marker_probes.staged_barrier_main, "trusted-time topology probe failed\n"),
        (
            marker_probes.pre_effect_runtime_absence_main,
            "trusted-time pre-effect runtime absence probe failed\n",
        ),
        (
            marker_probes.persistent_barrier_main,
            "trusted-time persistent topology probe failed\n",
        ),
    ],
)
def test_targets_reject_every_nonexact_argv(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    main: Callable[[], None],
    expected_stderr: str,
) -> None:
    monkeypatch.setattr(sys, "argv", ["target", "extra"])

    with pytest.raises(SystemExit) as raised:
        main()

    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert captured.out == ""
    assert captured.err == expected_stderr


def test_staged_barrier_uses_exact_no_filno_owner_path_and_schema(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    harness = _NativeHarness({"database-secret-consumed": _DATABASE_BYTES})
    monkeypatch.setattr(sys, "argv", ["post-enrollment-staged-barrier-read"])

    marker_probes.staged_barrier_main(_emit=lambda: _staged_barrier_bytes_with_harness(harness))

    captured = capsys.readouterr()
    expected = {
        "contract_version": "phase6d-post-enrollment-barrier-read-probe-v1",
        "marker": _expected_marker(
            "/tmp/database-secret-consumed",
            _DATABASE_BYTES,
            inode=100,
        ),
        "release_absences": [
            {"path": "/tmp/.post-enrollment-start-release-staging", "status": "absent"},
            {"path": "/tmp/post-enrollment-start-release", "status": "absent"},
        ],
    }
    payload = cast(dict[str, Any], json.loads(captured.out))
    assert captured.err == ""
    assert payload == expected
    assert captured.out.encode("ascii") == _canonical_bytes(expected) + b"\n"
    assert harness.maximum_file_owners_live == 1
    assert harness.file_owners_live == 0
    assert all(owner.closed for owner in harness.owners)
    assert harness.events[0:2] == [("open", "/"), ("fstat", "root")]
    assert ("open", "tmp") in harness.events
    assert ("open", "/tmp") not in harness.events


def test_pre_effect_absence_uses_only_root_and_tmp_owners() -> None:
    harness = _NativeHarness({})

    encoded = _pre_effect_absence_bytes_with_harness(harness)
    payload = cast(dict[str, Any], json.loads(encoded))

    expected = {
        "absences": [
            {"path": path, "status": "absent"}
            for path in (
                "/tmp/.post-enrollment-start-sequence-two-deadline-staging",
                "/tmp/post-enrollment-start-sequence-two-deadline",
                "/tmp/.post-enrollment-start-release-staging",
                "/tmp/post-enrollment-start-release",
                "/tmp/.post-enrollment-start-sequence-two-ready-staging",
                "/tmp/post-enrollment-start-sequence-two-ready",
            )
        ],
        "contract_version": ("phase6d-post-enrollment-pre-effect-runtime-absence-probe-v1"),
    }
    assert payload == expected
    assert encoded == _canonical_bytes(expected)
    assert [owner.label for owner in harness.owners] == ["root", "tmp"]
    assert all(owner.closed for owner in harness.owners)


def test_persistent_barrier_closes_each_file_before_opening_the_next() -> None:
    harness = _NativeHarness(_present_markers())

    encoded = _persistent_barrier_bytes_with_harness(harness)
    payload = cast(dict[str, Any], json.loads(encoded))

    expected = {
        "contract_version": "phase6d-post-enrollment-persistent-barrier-read-probe-v1",
        "database_marker": _expected_marker(
            "/tmp/database-secret-consumed",
            _DATABASE_BYTES,
            inode=100,
        ),
        "deadline_marker": _expected_marker(
            "/tmp/post-enrollment-start-sequence-two-deadline",
            _DEADLINE_BYTES,
            inode=101,
        ),
        "release_marker": _expected_marker(
            "/tmp/post-enrollment-start-release",
            _RELEASE_BYTES,
            inode=102,
        ),
        "runtime_staging_absences": [
            {
                "path": "/tmp/.post-enrollment-start-sequence-two-deadline-staging",
                "status": "absent",
            },
            {"path": "/tmp/.post-enrollment-start-release-staging", "status": "absent"},
            {
                "path": "/tmp/.post-enrollment-start-sequence-two-ready-staging",
                "status": "absent",
            },
        ],
        "sequence_marker": _expected_marker(
            "/tmp/post-enrollment-start-sequence-two-ready",
            _READY_BYTES,
            inode=103,
        ),
    }
    assert payload == expected
    assert encoded == _canonical_bytes(expected)
    assert harness.maximum_file_owners_live == 1
    assert harness.file_owners_live == 0
    assert all(owner.closed for owner in harness.owners)
    file_events = [event for event in harness.events if event[1].startswith("file:")]
    for index in range(0, len(file_events), 4):
        assert file_events[index][0] == "fstat"
        assert file_events[index + 1][0] == "read"
        assert file_events[index + 2][0] == "fstat"
        assert file_events[index + 3][0] == "close"
    assert harness.events[-2:] == [("close", "tmp"), ("close", "root")]


def test_marker_output_ignores_selective_native_hash_stat_and_path_relabels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = _persistent_barrier_bytes_with_harness(_NativeHarness(_present_markers()))
    persistent_defaults = cast(
        dict[str, object],
        marker_probes._persistent_barrier_bytes.__kwdefaults__,
    )
    marker_reader_defaults = cast(
        dict[str, object],
        marker_probes._read_marker.__kwdefaults__,
    )
    absence_defaults = cast(
        dict[str, object],
        marker_probes._require_absences.__kwdefaults__,
    )
    context_defaults = cast(
        dict[str, object],
        marker_probes._require_open_tmp_context.__kwdefaults__,
    )
    marker_bytes_defaults = cast(
        dict[str, object],
        marker_probes._marker_payload_bytes.__kwdefaults__,
    )
    original_native = {
        name: getattr(marker_probes, name)
        for name in (
            "_fstat",
            "_open_child_directory",
            "_open_child_regular",
            "_open_root_directory",
            "_read_snapshot",
            "_statat",
        )
    }
    original_sha256 = marker_probes.hashlib.sha256
    original_isdir = marker_probes.stat.S_ISDIR
    original_isreg = marker_probes.stat.S_ISREG
    original_imode = marker_probes.stat.S_IMODE

    def reject_relabel(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("selectively relabelled producer global was consulted")

    for name in original_native:
        monkeypatch.setattr(marker_probes, name, reject_relabel)
    for name in (
        "_absence_payload_bytes",
        "_cleanup_native_owners",
        "_decimal_bytes",
        "_json_string_bytes",
        "_marker_payload_bytes",
        "_preferred_cleanup_exception",
        "_preferred_cleanup_exceptions",
        "_require_stat9",
    ):
        monkeypatch.setattr(marker_probes, name, reject_relabel)
    monkeypatch.setattr(marker_probes.hashlib, "sha256", reject_relabel)
    monkeypatch.setattr(marker_probes.stat, "S_ISDIR", reject_relabel)
    monkeypatch.setattr(marker_probes.stat, "S_ISREG", reject_relabel)
    monkeypatch.setattr(marker_probes.stat, "S_IMODE", reject_relabel)
    monkeypatch.setattr(marker_probes, "_TMP_COMPONENT", "relabelled")
    monkeypatch.setattr(marker_probes, "_MAXIMUM_MARKER_BYTES", 1)
    monkeypatch.setattr(marker_probes, "_DATABASE_MARKER", ("relabelled", "/relabelled"))
    monkeypatch.setattr(marker_probes, "_DEADLINE_MARKER", ("relabelled", "/relabelled"))
    monkeypatch.setattr(marker_probes, "_RELEASE_MARKER", ("relabelled", "/relabelled"))
    monkeypatch.setattr(marker_probes, "_READY_MARKER", ("relabelled", "/relabelled"))
    monkeypatch.setattr(marker_probes, "_PERSISTENT_STAGING_ABSENCES", ())

    assert persistent_defaults["_open_root"] is original_native["_open_root_directory"]
    assert persistent_defaults["_open_directory"] is original_native["_open_child_directory"]
    assert persistent_defaults["_fstat_exact"] is original_native["_fstat"]
    assert persistent_defaults["_statat_exact"] is original_native["_statat"]
    assert marker_reader_defaults["_open_regular_exact"] is original_native["_open_child_regular"]
    assert marker_reader_defaults["_read_snapshot_exact"] is original_native["_read_snapshot"]
    assert marker_reader_defaults["_is_directory"] is original_isdir
    assert marker_reader_defaults["_is_regular"] is original_isreg
    assert absence_defaults["_is_directory"] is original_isdir
    assert context_defaults["_is_directory"] is original_isdir
    assert marker_bytes_defaults["_sha256"] is original_sha256
    assert marker_bytes_defaults["_mode_bits"] is original_imode

    encoded = _persistent_barrier_bytes_with_harness(_NativeHarness(_present_markers()))

    assert encoded == expected


def test_marker_projection_serializes_only_immutable_values_after_cleanup() -> None:
    harness = _NativeHarness(_present_markers())
    marker_inputs: list[tuple[str, object]] = []
    absence_inputs: list[object] = []

    def marker_bytes(path: str, observed: object) -> bytes:
        assert harness.owners
        assert all(owner.closed for owner in harness.owners)
        assert type(path) is str
        assert type(observed) is tuple
        assert len(observed) == 2
        assert type(observed[0]) is bytes
        assert type(observed[1]) is tuple
        assert all(type(value) is int for value in observed[1])
        marker_inputs.append((path, observed))
        return marker_probes._marker_payload_bytes(path, cast(Any, observed))

    def absence_bytes(paths: object) -> bytes:
        assert harness.owners
        assert all(owner.closed for owner in harness.owners)
        assert type(paths) is tuple
        assert all(type(path) is str for path in paths)
        absence_inputs.append(paths)
        return marker_probes._absence_payload_bytes(cast(Any, paths))

    _persistent_barrier_bytes_with_harness(
        harness,
        marker_bytes=marker_bytes,
        absence_bytes=absence_bytes,
    )

    assert len(marker_inputs) == 4
    assert len(absence_inputs) == 1


@pytest.mark.parametrize(
    ("operation", "label", "call", "metadata"),
    [
        (
            "fstat",
            "root",
            2,
            _directory_stat(inode=2, modified=12),
        ),
        (
            "statat",
            "tmp",
            2,
            _directory_stat(inode=3, changed=12),
        ),
        (
            "fstat",
            "tmp",
            8,
            _directory_stat(inode=3, modified=12),
        ),
    ],
    ids=("root-fstat", "tmp-named", "tmp-fstat"),
)
def test_staged_barrier_rejects_root_or_tmp_identity_drift_and_closes_all_owners(
    operation: str,
    label: str,
    call: int,
    metadata: tuple[int, ...],
) -> None:
    harness = _NativeHarness({"database-secret-consumed": _DATABASE_BYTES})
    harness.overrides[(operation, label, call)] = metadata

    with pytest.raises(OSError):
        _staged_barrier_bytes_with_harness(harness)

    assert harness.owners
    assert all(owner.closed for owner in harness.owners)
    assert harness.file_owners_live == 0


@pytest.mark.parametrize(
    ("operation", "call", "read_slot"),
    [
        ("statat", 1, None),
        ("fstat", 1, None),
        ("read", 1, 1),
        ("read", 1, 2),
        ("fstat", 2, None),
        ("statat", 2, None),
    ],
    ids=("named-before", "opened", "read-before", "read-after", "opened-final", "named-final"),
)
def test_marker_reader_rejects_every_named_open_read_and_final_identity_drift(
    operation: str,
    call: int,
    read_slot: int | None,
) -> None:
    component = "database-secret-consumed"
    harness = _NativeHarness({component: _DATABASE_BYTES})
    metadata = _file_stat(_DATABASE_BYTES, inode=100)
    changed = _replace_stat_slot(metadata, 8, metadata[8] + 1)
    label = f"file:{component}" if operation in {"fstat", "read"} else component
    if operation == "read":
        before = changed if read_slot == 1 else metadata
        after = changed if read_slot == 2 else metadata
        harness.overrides[(operation, label, call)] = (_DATABASE_BYTES, before, after)
    else:
        harness.overrides[(operation, label, call)] = changed
    tmp_owner = harness._new_owner("tmp", harness.tmp_stat)

    with pytest.raises(OSError):
        _read_marker_with_harness(harness, tmp_owner, component)

    file_owners = [owner for owner in harness.owners if owner.label.startswith("file:")]
    assert len(file_owners) <= 1
    assert all(owner.closed for owner in file_owners)
    assert harness.file_owners_live == 0


@pytest.mark.parametrize("invalid_kind", ["type", "link-count", "size"])
def test_marker_reader_rejects_wrong_type_link_count_or_size(
    invalid_kind: str,
) -> None:
    component = "database-secret-consumed"
    harness = _NativeHarness({component: _DATABASE_BYTES})
    metadata = _file_stat(_DATABASE_BYTES, inode=100)
    index, value = {
        "type": (2, stat.S_IFDIR | 0o400),
        "link-count": (5, 2),
        "size": (6, 4_097),
    }[invalid_kind]
    harness.file_metadata[component] = _replace_stat_slot(metadata, index, value)
    tmp_owner = harness._new_owner("tmp", harness.tmp_stat)

    with pytest.raises(OSError):
        _read_marker_with_harness(harness, tmp_owner, component)

    file_owners = [owner for owner in harness.owners if owner.label.startswith("file:")]
    assert len(file_owners) == 1
    assert file_owners[0].closed
    assert harness.file_owners_live == 0


@pytest.mark.parametrize("absence_pass", [1, 2], ids=("first-pass", "second-pass"))
def test_staged_barrier_rejects_presence_during_either_absence_pass(
    absence_pass: int,
) -> None:
    component = ".post-enrollment-start-release-staging"
    harness = _NativeHarness({"database-secret-consumed": _DATABASE_BYTES})
    harness.overrides[("statat", component, absence_pass)] = _file_stat(b"x", inode=200)

    with pytest.raises(OSError):
        _staged_barrier_bytes_with_harness(harness)

    assert all(owner.closed for owner in harness.owners)
    assert harness.file_owners_live == 0


@pytest.mark.parametrize(
    ("operation", "label", "call"),
    [
        ("open", "/", 1),
        ("fstat", "root", 1),
        ("statat", "tmp", 1),
        ("open", "tmp", 1),
        ("fstat", "tmp", 1),
        ("statat", ".post-enrollment-start-release-staging", 1),
        ("statat", "database-secret-consumed", 1),
        ("open", "database-secret-consumed", 1),
        ("fstat", "file:database-secret-consumed", 1),
        ("read", "file:database-secret-consumed", 1),
        ("fstat", "file:database-secret-consumed", 2),
        ("statat", "database-secret-consumed", 2),
        ("fstat", "tmp", 5),
    ],
)
def test_staged_target_fails_closed_at_each_native_open_stat_and_read_phase(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    operation: str,
    label: str,
    call: int,
) -> None:
    harness = _NativeHarness({"database-secret-consumed": _DATABASE_BYTES})
    harness.failures[(operation, label, call)] = RuntimeError("injected native failure")
    monkeypatch.setattr(sys, "argv", ["post-enrollment-staged-barrier-read"])

    with pytest.raises(SystemExit) as raised:
        marker_probes.staged_barrier_main(_emit=lambda: _staged_barrier_bytes_with_harness(harness))

    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert captured.out == ""
    assert captured.err == "trusted-time topology probe failed\n"
    assert all(owner.closed for owner in harness.owners)
    assert harness.file_owners_live == 0


def test_staged_target_writes_only_after_child_first_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _NativeHarness({"database-secret-consumed": _DATABASE_BYTES})
    monkeypatch.setattr(sys, "argv", ["post-enrollment-staged-barrier-read"])
    writes: list[str] = []

    class _CloseAwareStdout:
        def write(self, value: str) -> int:
            assert harness.owners
            assert all(owner.closed for owner in harness.owners)
            assert harness.events[-2:] == [("close", "tmp"), ("close", "root")]
            writes.append(value)
            return len(value)

    monkeypatch.setattr(sys, "stdout", _CloseAwareStdout())

    marker_probes.staged_barrier_main(_emit=lambda: _staged_barrier_bytes_with_harness(harness))

    assert len(writes) == 1
    assert writes[0].endswith("\n")


@pytest.mark.parametrize(
    ("body_error", "cleanup_error", "expected"),
    [
        (KeyboardInterrupt, ValueError, KeyboardInterrupt),
        (ValueError, KeyboardInterrupt, KeyboardInterrupt),
        (KeyboardInterrupt, SystemExit, KeyboardInterrupt),
    ],
)
def test_marker_reader_closes_owner_and_preserves_async_priority(
    body_error: type[BaseException],
    cleanup_error: type[BaseException],
    expected: type[BaseException],
) -> None:
    harness = _NativeHarness({"database-secret-consumed": _DATABASE_BYTES})
    harness.read_error = body_error()
    harness.file_close_failures = [cleanup_error()]
    tmp_owner = harness._new_owner("tmp", harness.tmp_stat)

    with pytest.raises(expected):
        _read_marker_with_harness(harness, tmp_owner, "database-secret-consumed")

    file_owners = [owner for owner in harness.owners if owner.label.startswith("file:")]
    assert len(file_owners) == 1
    assert file_owners[0].closed is True
    assert [event for event in harness.events if event == ("close", file_owners[0].label)] == [
        ("close", file_owners[0].label),
        ("close", file_owners[0].label),
    ]


def test_marker_target_emits_nothing_when_cleanup_is_unconfirmed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["post-enrollment-staged-barrier-read"])

    with pytest.raises(SystemExit) as raised:
        marker_probes.staged_barrier_main(_emit=lambda: (_ for _ in ()).throw(KeyboardInterrupt()))

    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert captured.out == ""
    assert captured.err == "trusted-time topology probe failed\n"


def test_marker_probe_source_has_no_raw_descriptor_or_writer_surface() -> None:
    source = marker_probes.__file__
    assert source is not None
    encoded = Path(source).read_text(encoding="utf-8")
    assert "import os" not in encoded
    assert "import ctypes" not in encoded
    assert ".fileno" not in encoded
    assert "_create_child_regular_exclusive" not in encoded
    assert "_write_all" not in encoded
    assert "_fsync" not in encoded


def test_schema_contract_module_has_no_native_owner_import_or_call() -> None:
    source = schema_probe.__file__
    assert source is not None
    tree = ast.parse(Path(source).read_text(encoding="utf-8"), filename=source)
    assert not any(
        isinstance(node, ast.ImportFrom)
        and node.module == "packages.adapters.trusted_time._owned_file_descriptor"
        for node in ast.walk(tree)
    )
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id
        in {
            "_fstat",
            "_open_child_directory",
            "_open_child_regular",
            "_open_root_directory",
            "_read_snapshot",
            "_statat",
        }
        for node in ast.walk(tree)
    )


def test_marker_probe_native_calls_satisfy_direct_owner_policy() -> None:
    from scripts.check_architecture import _native_owned_file_descriptor_usage_violations

    source = marker_probes.__file__
    assert source is not None
    root = Path(__file__).resolve().parents[2]
    relative = Path("apps/trusted_time_supervisor/post_enrollment_read_probes.py")
    tree = ast.parse(Path(source).read_text(encoding="utf-8"), filename=source)
    with (root / "infra/architecture-boundaries.toml").open("rb") as stream:
        config = cast(dict[str, Any], tomllib.load(stream)["scan"])
    captured_defaults_by_path = cast(
        dict[str, dict[str, dict[str, str]]],
        config["native_owned_file_descriptor_captured_defaults"],
    )
    captured_call_counts: dict[str, dict[str, int]] = {
        "_require_absences": {"_fstat_exact": 2, "_statat_exact": 1},
        "_read_marker": {
            "_fstat_exact": 4,
            "_statat_exact": 2,
            "_open_regular_exact": 1,
            "_read_snapshot_exact": 1,
        },
        "_require_open_tmp_context": {"_fstat_exact": 2, "_statat_exact": 1},
        "_staged_barrier_bytes": {
            "_open_root": 1,
            "_open_directory": 1,
            "_fstat_exact": 2,
            "_statat_exact": 1,
        },
        "_pre_effect_runtime_absence_bytes": {
            "_open_root": 1,
            "_open_directory": 1,
            "_fstat_exact": 2,
            "_statat_exact": 1,
        },
        "_persistent_barrier_bytes": {
            "_open_root": 1,
            "_open_directory": 1,
            "_fstat_exact": 2,
            "_statat_exact": 1,
        },
    }
    captured_owner_consumers: dict[str, dict[str, tuple[str, int]]] = {
        "_read_marker": {"_cleanup": ("_cleanup_native_owners", 2)},
        "_staged_barrier_bytes": {
            "_observe_absences": ("_require_absences", 2),
            "_observe_marker": ("_read_marker", 1),
            "_require_context": ("_require_open_tmp_context", 1),
            "_cleanup": ("_cleanup_native_owners", 2),
        },
        "_pre_effect_runtime_absence_bytes": {
            "_observe_absences": ("_require_absences", 2),
            "_require_context": ("_require_open_tmp_context", 1),
            "_cleanup": ("_cleanup_native_owners", 2),
        },
        "_persistent_barrier_bytes": {
            "_observe_absences": ("_require_absences", 2),
            "_observe_marker": ("_read_marker", 4),
            "_require_context": ("_require_open_tmp_context", 1),
            "_cleanup": ("_cleanup_native_owners", 2),
        },
    }

    assert (
        _native_owned_file_descriptor_usage_violations(
            tree,
            relative_path=relative,
            module="packages.adapters.trusted_time._owned_file_descriptor",
            captured_defaults=captured_defaults_by_path[relative.as_posix()],
            captured_call_counts=captured_call_counts,
            captured_owner_consumers=captured_owner_consumers,
        )
        == []
    )


def test_runtime_probe_intrinsic_architecture_pins_are_current() -> None:
    from scripts.check_architecture import (
        _canonical_ast_sha256,
        _project_build_bootstrap_manifest_sha256,
    )

    root = Path(__file__).resolve().parents[2]
    with (root / "infra/architecture-boundaries.toml").open("rb") as stream:
        config = cast(dict[str, Any], tomllib.load(stream)["scan"])
    verifier_tree = ast.parse(
        (root / "scripts/verify_trusted_time_images.py").read_text(encoding="utf-8")
    )
    bootstrap_paths = tuple(config["project_build_bootstrap_manifest_paths"])

    assert config["native_owned_file_descriptor_allowed_imports"][
        "apps/trusted_time_supervisor/post_enrollment_read_probes.py"
    ] == [
        ("packages.adapters.trusted_time._owned_file_descriptor:_OwnedFileDescriptor"),
        "packages.adapters.trusted_time._owned_file_descriptor:_fstat",
        ("packages.adapters.trusted_time._owned_file_descriptor:_open_child_directory"),
        ("packages.adapters.trusted_time._owned_file_descriptor:_open_child_regular"),
        ("packages.adapters.trusted_time._owned_file_descriptor:_open_root_directory"),
        "packages.adapters.trusted_time._owned_file_descriptor:_read_snapshot",
        "packages.adapters.trusted_time._owned_file_descriptor:_statat",
    ]
    assert config["native_bounded_process_consumer_module_ast_sha256"] == {
        "scripts/verify_trusted_time_images.py": _canonical_ast_sha256(verifier_tree)
    }
    assert config["project_build_bootstrap_manifest_sha256"] == (
        _project_build_bootstrap_manifest_sha256(root, bootstrap_paths)
    )
