"""Real bounded retained bytes, without typed truth, authentication or publication."""

import copy
import hashlib
import os
import stat
import sys
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta, tzinfo
from types import SimpleNamespace

import pytest

from apps.trader import operational_control_operator_evidence as evidence
from packages.adapters.research_artifacts_v2 import (
    LocalResearchArtifactStore,
    ResearchArtifactError,
)
from packages.domain import operational_control_operator_statement as data
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlBlockingEvent,
    OperationalControlIncidentDisposition,
    OperationalControlState,
)
from packages.domain.research_job_contracts import MAX_OBJECT_BYTES, ObjectRef

_AT = datetime(2026, 10, 28, 14, tzinfo=UTC)
_PAYLOAD = b"\x00synthetic operator evidence\xff\n"
_READER = evidence.OperatorStatementEvidenceReader
_READ_CODE = LocalResearchArtifactStore.read.__code__
_DIRECTORY_CODE = LocalResearchArtifactStore._directory.__code__
_COPY_CODE = data.copy_operational_control_operator_statement.__code__
_PUT_CODE = LocalResearchArtifactStore.put.__code__
_INSTALL_CODE = LocalResearchArtifactStore.install_file.__code__


def _statement(digest):
    event = OperationalControlBlockingEvent(
        scope_id="evidence-component-account",
        sequence_number=1,
        command_id="initial-halted-command",
        command_sha256="a" * 64,
        state=OperationalControlState.HALTED,
        occurred_at=_AT,
    )
    return data.OperationalControlOperatorStatement(
        scope_id=event.scope_id,
        control_transition_id="declared-control-head",
        control_transition_sha256="b" * 64,
        control_sequence_number=1,
        control_state=OperationalControlState.HALTED,
        control_state_epoch_id="declared-control-epoch",
        blocking_event=event,
        actor=OperationalControlActor(
            actor_id="evidence-component-operator",
            kind=OperationalControlActorKind.HUMAN,
            authority_sha256="c" * 64,
            authenticated_at=_AT + timedelta(seconds=1),
        ),
        resolution_claim=OperationalControlIncidentDisposition(
            event_id=event.event_id,
            event_sha256=event.semantic_sha256,
            resolution_code="operator-reviewed",
            resolution_evidence_sha256=digest,
            resolved_at=_AT + timedelta(seconds=1),
        ),
        authentication_checked_at=_AT + timedelta(seconds=1),
        attested_at=_AT + timedelta(seconds=1),
        idempotency_key="evidence-component-0001",
    )


def _case(tmp_path, *, codec="personal-record/1", maximum=None):
    store = LocalResearchArtifactStore(tmp_path / "objects")
    reference = store.put(_PAYLOAD, codec_version=codec)
    return SimpleNamespace(
        store=store,
        reference=reference,
        statement=_statement(reference.object_sha256),
        reader=_READER(store, max_bytes=len(_PAYLOAD) if maximum is None else maximum),
        root=tmp_path / "objects",
        path=tmp_path / "objects" / (reference.object_sha256 + ".json"),
    )


def _inventory(root):
    """Only the known fresh fixture directory; never traverse a retained root."""
    directory = root.lstat()
    rows = []
    for path in sorted(root.iterdir()):
        metadata = path.lstat()
        payload = path.read_bytes() if stat.S_ISREG(metadata.st_mode) else None
        target = os.readlink(path) if stat.S_ISLNK(metadata.st_mode) else None
        rows.append(
            (
                path.name,
                metadata.st_mode,
                metadata.st_uid,
                metadata.st_ino,
                metadata.st_nlink,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
                payload,
                target,
            )
        )
    return directory.st_mode, directory.st_uid, directory.st_ino, tuple(rows)


@contextmanager
def _observe(action=None, *, at=_READ_CODE, returned=False):
    """Finite original-code observation, with no replacement passing read."""
    monitor, tool = sys.monitoring, 3
    codes = (_READ_CODE, _DIRECTORY_CODE, _COPY_CODE, _PUT_CODE, _INSTALL_CODE)
    entries, enabled = [], []
    owned = start_registered = return_registered = False

    def start(code, offset):
        entries.append(code)
        if action is not None and code is at and not returned:
            action()

    def finish(code, offset, result):
        if action is not None and code is at and returned:
            action()

    try:
        assert monitor.get_tool(tool) is None and monitor.get_events(tool) == 0
        monitor.use_tool_id(tool, "aqt-operator-evidence-unit")
        owned = True
        assert monitor.register_callback(tool, monitor.events.PY_START, start) is None
        start_registered = True
        if returned:
            assert monitor.register_callback(tool, monitor.events.PY_RETURN, finish) is None
            return_registered = True
        for code in codes:
            assert monitor.get_local_events(tool, code) == 0
            events = monitor.events.PY_START
            if returned and code is at:
                events |= monitor.events.PY_RETURN
            monitor.set_local_events(tool, code, events)
            enabled.append(code)
        yield entries
    finally:
        try:
            for code in enabled:
                monitor.set_local_events(tool, code, 0)
                assert monitor.get_local_events(tool, code) == 0
        finally:
            try:
                if start_registered:
                    monitor.register_callback(tool, monitor.events.PY_START, None)
                if return_registered:
                    monitor.register_callback(tool, monitor.events.PY_RETURN, None)
            finally:
                if owned:
                    assert monitor.get_events(tool) == 0
                    monitor.free_tool_id(tool)
                    assert monitor.get_tool(tool) is None


def _read(case):
    return case.reader.read(case.statement, case.reference)


def _no_write(entries):
    assert not any(code is _PUT_CODE or code is _INSTALL_CODE for code in entries)


@pytest.mark.parametrize(
    "codec", ["personal-record/1", "personal-research-dataset-v1", "personal-provider-json/1"]
)
def test_real_private_bytes_are_detached_read_only_data_under_each_closed_codec(tmp_path, codec):
    case = _case(tmp_path, codec=codec)
    before = _inventory(case.root)
    with _observe() as entries:
        result = _read(case)
    assert type(result) is tuple and len(result) == 3
    statement, reference, payload = result
    assert type(statement) is data.OperationalControlOperatorStatement
    assert type(reference) is ObjectRef and type(payload) is bytes
    assert statement is not case.statement
    assert reference is not case.reference and reference == case.reference
    for name in ("blocking_event", "actor", "resolution_claim"):
        assert getattr(statement, name) is not getattr(case.statement, name)
    assert statement.canonical_json == case.statement.canonical_json
    assert reference.codec_version == codec
    assert payload == _PAYLOAD
    assert hashlib.sha256(payload).hexdigest() == reference.object_sha256
    assert len(payload) == reference.byte_count == len(_PAYLOAD)
    assert statement.resolution_claim.resolution_evidence_sha256 == reference.object_sha256
    assert statement.control_state is OperationalControlState.HALTED
    assert sum(code is _READ_CODE for code in entries) == 1
    _no_write(entries)
    assert _inventory(case.root) == before
    # The deliberately non-JSON bytes are not decoded or promoted to typed truth.
    assert payload.startswith(b"\x00") and b"\xff" in payload


def test_explicit_reopen_reads_same_fixture_without_a_persistent_owner_token(tmp_path):
    case = _case(tmp_path)
    before = _inventory(case.root)
    reopened = LocalResearchArtifactStore(case.root)
    reader = _READER(reopened, max_bytes=MAX_OBJECT_BYTES)
    with _observe() as entries:
        result = reader.read(case.statement, case.reference)
    assert result[2] == _PAYLOAD
    assert result[0] is not case.statement and result[1] is not case.reference
    assert sum(code is _READ_CODE for code in entries) == 1
    _no_write(entries)
    assert _inventory(case.root) == before


def test_reference_semantic_hash_cannot_substitute_for_the_raw_byte_digest(tmp_path):
    case = _case(tmp_path)
    assert case.reference.semantic_sha256 != case.reference.object_sha256
    case.statement = _statement(case.reference.semantic_sha256)
    before = _inventory(case.root)
    with _observe() as entries, pytest.raises(ValueError):
        _read(case)
    assert not any(code is _READ_CODE for code in entries)
    _no_write(entries)
    assert _inventory(case.root) == before


@pytest.mark.parametrize(
    "fault", ["missing", "length", "hash", "symlink", "directory", "root-mode", "file-mode"]
)
def test_real_original_filesystem_failures_are_preserved_without_repairs(tmp_path, fault):
    case = _case(tmp_path, maximum=len(_PAYLOAD) + 1)
    if fault == "missing":
        case.path.unlink()
    elif fault == "length":
        case.reference = replace(case.reference, byte_count=len(_PAYLOAD) - 1)
    elif fault == "hash":
        case.path.write_bytes(_PAYLOAD[::-1])
    elif fault == "symlink":
        target = tmp_path / "separate-private-fixture"
        target.write_bytes(_PAYLOAD)
        target.chmod(0o600)
        case.path.unlink()
        case.path.symlink_to(target)
    elif fault == "directory":
        case.path.unlink()
        case.path.mkdir(mode=0o700)
    elif fault == "root-mode":
        case.root.chmod(0o755)
    else:
        case.path.chmod(0o640)
    before = _inventory(case.root)
    # Native fdopen may reject a directory before the store's regular-file check.
    expected = (
        (OSError, ResearchArtifactError)
        if fault == "directory"
        else (OSError if fault in ("missing", "symlink") else ResearchArtifactError)
    )
    with _observe() as entries, pytest.raises(expected):
        _read(case)
    assert sum(code is _READ_CODE for code in entries) == 1
    _no_write(entries)
    assert _inventory(case.root) == before


def _poison(kind, calls):
    def forbidden(*args, **kwargs):
        calls.append(kind)
        raise AssertionError("evidence admission dispatched a non-native input hook")

    if kind == "str":

        class PoisonString(str):
            __eq__ = __len__ = __str__ = __repr__ = __hash__ = forbidden
            strip = encode = __add__ = forbidden

        return PoisonString("../outside-fixture")
    if kind == "int":

        class PoisonInteger(int):
            __eq__ = __lt__ = __le__ = __gt__ = __ge__ = forbidden
            __int__ = __index__ = __hash__ = __repr__ = forbidden

        return PoisonInteger(1)
    if kind == "bool":
        return True
    if kind == "timezone":

        class PoisonTimezone(tzinfo):
            utcoffset = dst = tzname = forbidden

        return datetime(2026, 10, 28, 14, tzinfo=PoisonTimezone())
    raise AssertionError("unknown poison kind")


@pytest.mark.parametrize(
    "field,kind",
    [
        ("object_sha256", "str"),
        ("byte_count", "int"),
        ("byte_count", "bool"),
        ("codec_version", "str"),
    ],
)
def test_all_reference_leaves_are_native_before_d_copy_store_or_operator_dispatch(
    tmp_path, field, kind
):
    case = _case(tmp_path)
    calls = []
    object.__setattr__(case.reference, field, _poison(kind, calls))
    with _observe() as entries, pytest.raises(ValueError):
        _read(case)
    assert calls == []
    assert not any(code is _READ_CODE or code is _COPY_CODE for code in entries)
    _no_write(entries)


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("object_sha256", "../outside-fixture"),
        ("object_sha256", "A" * 64),
        ("byte_count", 0),
        ("byte_count", -1),
        ("byte_count", MAX_OBJECT_BYTES + 1),
        ("codec_version", "unsupported-codec"),
    ],
)
def test_malformed_exact_reference_never_supplies_a_filename_or_read(tmp_path, field, replacement):
    case = _case(tmp_path)
    object.__setattr__(case.reference, field, replacement)
    with _observe() as entries, pytest.raises(ValueError):
        _read(case)
    assert not any(code is _READ_CODE for code in entries)
    _no_write(entries)


@pytest.mark.parametrize("kind", ["actor", "custom-utc", "rogue-enum"])
def test_original_d_native_admission_remains_before_the_store(tmp_path, kind):
    case = _case(tmp_path)
    calls = []
    if kind == "actor":
        object.__setattr__(case.statement.actor, "actor_id", _poison("str", calls))
    elif kind == "custom-utc":
        object.__setattr__(case.statement, "attested_at", _poison("timezone", calls))
    else:
        rogue = str.__new__(OperationalControlState, "halted")
        object.__setattr__(rogue, "_value_", "halted")
        object.__setattr__(rogue, "_name_", "HALTED")
        object.__setattr__(case.statement, "control_state", rogue)
    with _observe() as entries, pytest.raises(ValueError):
        _read(case)
    assert calls == []
    assert not any(code is _READ_CODE for code in entries)
    _no_write(entries)


@pytest.mark.parametrize("maximum", [True, 0, -1, MAX_OBJECT_BYTES + 1])
def test_explicit_maximum_keeps_the_existing_native_global_bound(tmp_path, maximum):
    store = LocalResearchArtifactStore(tmp_path / "objects")
    with _observe() as entries, pytest.raises(ValueError):
        _READER(store, max_bytes=maximum)
    assert entries == []


def test_maximum_subclasses_are_rejected_without_comparison_or_coercion(tmp_path):
    store = LocalResearchArtifactStore(tmp_path / "objects")
    calls = []
    maximum = _poison("int", calls)
    with _observe() as entries, pytest.raises(ValueError):
        _READER(store, max_bytes=maximum)
    assert calls == []
    assert entries == []


def test_maximum_is_mandatory_and_reader_construction_performs_no_store_lookup(tmp_path):
    case = _case(tmp_path)
    with _observe() as entries:
        with pytest.raises(TypeError):
            _READER(case.store)
        reader = _READER(case.store, max_bytes=1)
    assert type(reader) is _READER
    assert entries == []
    restricted = _READER(case.store, max_bytes=len(_PAYLOAD) - 1)
    with _observe() as entries, pytest.raises(ValueError):
        restricted.read(case.statement, case.reference)
    assert not any(code is _READ_CODE for code in entries)
    _no_write(entries)


@pytest.mark.parametrize("target", ["statement", "reference", "store", "reader"])
def test_foreign_outer_records_are_denied_before_their_getters(tmp_path, target):
    case = _case(tmp_path)
    original = {
        "statement": data.OperationalControlOperatorStatement,
        "reference": ObjectRef,
        "store": LocalResearchArtifactStore,
        "reader": _READER,
    }[target]
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("getter")
        raise AssertionError("foreign evidence object getter was dispatched")

    foreign_type = type("ForeignEvidenceValue", (original,), {"__getattribute__": forbidden})
    foreign = object.__new__(foreign_type)
    with _observe() as entries, pytest.raises(ValueError):
        if target == "statement":
            case.reader.read(foreign, case.reference)
        elif target == "reference":
            case.reader.read(case.statement, foreign)
        elif target == "store":
            _READER(foreign, max_bytes=len(_PAYLOAD))
        else:
            _READER.read(foreign, case.statement, case.reference)
    assert calls == []
    assert not any(code is _READ_CODE for code in entries)
    _no_write(entries)


@pytest.mark.parametrize("method", ["read", "_directory", "_read", "_limit"])
def test_real_instance_method_shadows_are_denied_without_invoking_substitutes(tmp_path, method):
    case = _case(tmp_path)
    called = []

    def forbidden(*args, **kwargs):
        called.append("substitute")
        raise AssertionError("store instance substitute was dispatched")

    case.store.__dict__[method] = forbidden
    with _observe() as entries, pytest.raises(ValueError):
        _read(case)
    assert called == []
    assert not any(code is _READ_CODE for code in entries)
    _no_write(entries)


@pytest.mark.parametrize("phase", ["constructor", "read"])
@pytest.mark.parametrize("kind", ["hostile-sole-key", "extra-native-attribute"])
def test_original_store_dictionary_shape_is_checked_before_key_lookup_or_io(tmp_path, phase, kind):
    case = _case(tmp_path)
    root = case.store._root
    forged = object.__new__(LocalResearchArtifactStore)
    object.__setattr__(forged, "__dict__", {"_root": root})
    reader = _READER(forged, max_bytes=len(_PAYLOAD)) if phase == "read" else None
    calls = []

    class CollidingRootKey(str):
        __hash__ = str.__hash__

        def __eq__(self, other):
            calls.append("key comparison")
            raise AssertionError("non-native dictionary key comparison was dispatched")

    if kind == "hostile-sole-key":
        attributes = {CollidingRootKey("_root"): root}
    else:
        attributes = {"_root": root, "unrelated_native_attribute": "unexpected"}
    object.__setattr__(forged, "__dict__", attributes)
    before = _inventory(case.root)
    with _observe() as entries, pytest.raises(ValueError):
        if phase == "constructor":
            _READER(forged, max_bytes=len(_PAYLOAD))
        else:
            reader.read(case.statement, case.reference)
    assert calls == []
    assert entries == []
    assert _inventory(case.root) == before


@pytest.mark.parametrize("method", ["read", "_directory", "_read", "_limit"])
def test_original_class_and_static_descriptors_are_compared_without_substitution(tmp_path, method):
    case = _case(tmp_path)
    called = []

    def forbidden(*args, **kwargs):
        called.append("substitute")
        raise AssertionError("store class substitute was dispatched")

    replacement = staticmethod(forbidden) if method in ("_read", "_limit") else forbidden
    with pytest.MonkeyPatch.context() as local:
        local.setattr(LocalResearchArtifactStore, method, replacement)
        with _observe() as entries, pytest.raises(ValueError):
            _read(case)
    assert called == []
    assert not any(code is _READ_CODE for code in entries)
    _no_write(entries)


@pytest.mark.parametrize("kind", ["root", "store", "maximum", "reader-copy"])
def test_configured_owner_and_root_references_are_fixed_without_inode_custody(tmp_path, kind):
    case = _case(tmp_path)
    if kind == "root":
        # Same path text, distinct Path object: this checks metadata identity only.
        case.store._root = type(case.root)(str(case.root))
    elif kind == "store":
        object.__setattr__(case.reader, "_artifacts", LocalResearchArtifactStore(case.root))
    elif kind == "maximum":
        object.__setattr__(case.reader, "_max_bytes", len(_PAYLOAD) + 1)
    else:
        case.reader = copy.copy(case.reader)
    with _observe() as entries, pytest.raises(ValueError):
        _read(case)
    assert not any(code is _READ_CODE for code in entries)
    _no_write(entries)


def test_original_reference_validation_replacement_is_not_borrowed_as_a_passing_proof(tmp_path):
    case = _case(tmp_path)
    called = []

    def forbidden(*args, **kwargs):
        called.append("substitute")
        raise AssertionError("reference validation substitute was dispatched")

    with pytest.MonkeyPatch.context() as local:
        local.setattr(ObjectRef, "__post_init__", forbidden)
        with _observe() as entries, pytest.raises(ValueError):
            _read(case)
    assert called == []
    assert not any(code is _READ_CODE for code in entries)
    _no_write(entries)


def test_reference_snapshot_precedes_original_d_copy_callbacks(tmp_path):
    case = _case(tmp_path)
    expected = case.reference
    original_fields = (expected.object_sha256, expected.byte_count, expected.codec_version)

    def mutate_reference():
        object.__setattr__(case.reference, "object_sha256", "f" * 64)
        object.__setattr__(case.reference, "byte_count", 1)
        object.__setattr__(case.reference, "codec_version", "personal-provider-json/1")

    before = _inventory(case.root)
    with _observe(mutate_reference, at=_COPY_CODE) as entries:
        statement, reference, payload = _read(case)
    assert (
        reference.object_sha256,
        reference.byte_count,
        reference.codec_version,
    ) == original_fields
    assert statement.resolution_claim.resolution_evidence_sha256 == original_fields[0]
    assert payload == _PAYLOAD
    assert sum(code is _READ_CODE for code in entries) == 1
    _no_write(entries)
    assert _inventory(case.root) == before


def test_input_mutation_during_genuine_original_read_cannot_change_detached_output(tmp_path):
    case = _case(tmp_path)
    expected_json = case.statement.canonical_json
    expected_ref = (
        case.reference.object_sha256,
        case.reference.byte_count,
        case.reference.codec_version,
    )

    def mutate_inputs():
        object.__setattr__(case.statement, "control_transition_id", "changed-during-read")
        object.__setattr__(case.statement.actor, "actor_id", "changed-during-read")
        object.__setattr__(
            case.statement.resolution_claim, "resolution_code", "changed-during-read"
        )
        object.__setattr__(case.reference, "object_sha256", "f" * 64)
        object.__setattr__(case.reference, "byte_count", 1)

    before = _inventory(case.root)
    with _observe(mutate_inputs) as entries:
        statement, reference, payload = _read(case)
    assert statement.canonical_json == expected_json
    assert (reference.object_sha256, reference.byte_count, reference.codec_version) == expected_ref
    assert payload == _PAYLOAD
    assert sum(code is _READ_CODE for code in entries) == 1
    _no_write(entries)
    assert _inventory(case.root) == before


@pytest.mark.parametrize("kind", ["root", "store", "maximum", "method"])
def test_binding_changes_after_genuine_original_read_deny_delivery(tmp_path, kind):
    case = _case(tmp_path)
    other = LocalResearchArtifactStore(tmp_path / "other-fresh-objects")
    other.put(_PAYLOAD)
    called = []

    def forbidden(*args, **kwargs):
        called.append("substitute")
        raise AssertionError("substitute reader was dispatched")

    def mutate_binding():
        if kind == "root":
            case.store._root = other._root
        elif kind == "store":
            object.__setattr__(case.reader, "_artifacts", other)
        elif kind == "maximum":
            object.__setattr__(case.reader, "_max_bytes", len(_PAYLOAD) + 1)
        else:
            case.store.__dict__["read"] = forbidden

    before = (_inventory(case.root), _inventory(other._root))
    with _observe(mutate_binding, returned=True) as entries, pytest.raises(ValueError):
        _read(case)
    assert called == []
    assert sum(code is _READ_CODE for code in entries) == 1
    _no_write(entries)
    assert (_inventory(case.root), _inventory(other._root)) == before
