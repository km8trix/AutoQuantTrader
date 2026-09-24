"""Finite fingerprint compatibility; these DTO shells confer no source authority.

The oracle retains the complete original expression. Stable ordinary dataclass
metadata and mapping keys model admitted source shapes; arbitrary Python hooks,
concurrent mutation and resource-limit equivalence are not claimed.
"""

from collections import Counter
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import Enum
from hashlib import sha256
from types import MappingProxyType, SimpleNamespace
from uuid import UUID

import pytest

from packages.domain import personal_contracts
from packages.domain.canonical import canonical_json_bytes
from packages.persistence import continuous_runtime_attempt_sources as attempt_sources
from packages.persistence import detached_journal_capture as detached_capture
from packages.persistence.daily_runtime_risk import ResolvedRuntimeAttemptSources

TRACE = []


@dataclass(frozen=True)
class Record:
    label: str
    payload: object
    children: tuple = ()
    _owner: object = None
    _validated_values: object = None

    def __getattribute__(self, name):
        if name in {"label", "payload", "children", "_owner", "_validated_values"}:
            TRACE.append(("field", name))
        return object.__getattribute__(self, name)


@dataclass(frozen=True)
class InheritedRecord(Record):
    sequence: int = 1


class OrdinaryEnum(Enum):
    OBSERVED = "observed"


class ReadMapping(dict):
    def items(self):
        TRACE.append(("mapping", tuple(self.keys())))
        return super().items()


class ReadItem(SimpleNamespace):
    def __getattribute__(self, name):
        if name != "__class__":
            TRACE.append(("item", name))
        return super().__getattribute__(name)


def unowned_shell(leaf):
    """Only exercise the private pure branch, never any owner/store API."""
    item = ReadItem(
        reference=leaf,
        closure=leaf,
        checkpoint=leaf,
        action=leaf,
        request=leaf,
        dispatches=((leaf, b"original-dispatch"),),
        admission_payloads=(b"original-admission",),
        descriptor=leaf,
        unsent_key_payload=b"original-unsent-key",
    )
    row = ReadMapping(account_id="account", sequence=7, payload=b"original-row")
    table = SimpleNamespace(
        table=SimpleNamespace(name="original_table"),
        account_id="account",
        rows=(row, row),
    )
    state = SimpleNamespace(
        captured=SimpleNamespace(plan=SimpleNamespace(sources=(item,)), provenance=(table,)),
        dispatches=((leaf, b"original-resolved-dispatch"),),
    )
    return ResolvedRuntimeAttemptSources(snapshot=object(), sources=(leaf, leaf), state=state)


def legacy_fingerprint(value):
    """Independent literal legacy body, including its second normalization."""
    state = value.state
    return personal_contracts.content_digest(
        detached_capture.detached_journal_value(
            (
                value.sources,
                tuple(
                    (
                        item.reference,
                        item.closure,
                        item.checkpoint,
                        item.action,
                        item.request,
                        item.dispatches,
                        item.admission_payloads,
                        item.descriptor,
                        item.unsent_key_payload,
                    )
                    for item in state.captured.plan.sources
                ),
                tuple(
                    (str(table.table.name), table.account_id, table.rows)
                    for table in state.captured.provenance
                ),
                state.dispatches,
            )
        )
    )


def captured_call(function, value, monkeypatch):
    """Observe actual final canonical bytes and original read/hash order."""
    encoded = []
    TRACE.clear()

    def encode(material):
        result = canonical_json_bytes(material)
        encoded.append(result)
        return result

    def original_byte_hash(payload):
        TRACE.append(("bytes", payload))
        return sha256(payload)

    with monkeypatch.context() as guard:
        guard.setattr(personal_contracts, "canonical_json_bytes", encode)
        guard.setattr(attempt_sources, "canonical_json_bytes", encode)
        guard.setattr(detached_capture, "sha256", original_byte_hash)
        try:
            result = ("return", function(value))
        except Exception as error:
            cause = error.__cause__
            result = (
                "error",
                type(error),
                str(error),
                None if cause is None else (type(cause), str(cause)),
            )
    return result, tuple(encoded), tuple(TRACE)


def assert_legacy_equivalent(value, monkeypatch):
    old = captured_call(legacy_fingerprint, value, monkeypatch)
    new = captured_call(
        attempt_sources.SqlContinuousRuntimeAttemptSources._fingerprint, value, monkeypatch
    )
    assert new == old
    if new[0][0] == "return":
        assert len(new[1]) == 1
        assert new[0][1] == sha256(new[1][0]).hexdigest()
    return new


def test_full_material_bytes_hash_and_original_read_order(monkeypatch):
    leaf = InheritedRecord(
        "retained-é",
        b"original-leaf",
        (
            None,
            True,
            False,
            0,
            -7,
            "text",
            Decimal("12.3400"),
            datetime(2026, 9, 12, 1, 2, 3, 400, tzinfo=UTC),
            date(2026, 9, 12),
            OrdinaryEnum.OBSERVED,
            UUID(int=7),
        ),
        _owner=object(),
        _validated_values=object(),
    )
    result = assert_legacy_equivalent(unowned_shell(leaf), monkeypatch)
    counts = Counter(result[2])
    # Ten aliases of the original leaf and both row aliases are read in full.
    assert counts[("bytes", b"original-leaf")] == 10
    assert counts[("bytes", b"original-row")] == 2
    assert counts[("field", "payload")] == 10
    assert ("field", "_owner") not in counts
    assert ("field", "_validated_values") not in counts
    assert tuple(event[1] for event in result[2] if event[0] == "item") == (
        "reference",
        "closure",
        "checkpoint",
        "action",
        "request",
        "dispatches",
        "admission_payloads",
        "descriptor",
        "unsent_key_payload",
    )


@pytest.mark.parametrize(
    "value",
    [
        None,
        (),
        MappingProxyType({"a": b"one", "b": (2, b"two")}),
        [None, 1, "list"],
        {1, 2},
        frozenset({"a", "b"}),
    ],
)
def test_normal_and_nonadmitted_container_leaf_compatibility(value, monkeypatch):
    # Non-tuple containers here test the old fingerprint behavior, not admission.
    assert_legacy_equivalent(unowned_shell(value), monkeypatch)


def test_aliases_equal_copies_and_between_call_mutations(monkeypatch):
    leaf = Record("original", b"same", (Decimal("7.00"),))
    value = unowned_shell(leaf)
    original = assert_legacy_equivalent(value, monkeypatch)[0]
    copied = replace(value, sources=(replace(leaf), replace(leaf)))
    assert assert_legacy_equivalent(copied, monkeypatch)[0] == original
    for field, replacement in (
        ("label", "changed"),
        ("payload", b"changed"),
        ("children", (Decimal("8"),)),
    ):
        retained = getattr(leaf, field)
        object.__setattr__(leaf, field, replacement)
        try:
            assert assert_legacy_equivalent(value, monkeypatch)[0] != original
        finally:
            object.__setattr__(leaf, field, retained)
        assert assert_legacy_equivalent(value, monkeypatch)[0] == original
    item = value.state.captured.plan.sources[0]
    for field in vars(item):
        retained = getattr(item, field)
        setattr(item, field, ("changed-retained-material", b"changed"))
        try:
            assert assert_legacy_equivalent(value, monkeypatch)[0] != original
        finally:
            setattr(item, field, retained)
    row = value.state.captured.provenance[0].rows[0]
    row["payload"] = b"changed-row"
    assert assert_legacy_equivalent(value, monkeypatch)[0] != original
    row["payload"] = b"original-row"
    assert assert_legacy_equivalent(value, monkeypatch)[0] == original


class TupleSubclass(tuple):
    pass


class BytesSubclass(bytes):
    pass


@pytest.mark.parametrize(
    "leaf",
    [
        1.5,
        float("nan"),
        object(),
        Record,
        TupleSubclass((1,)),
        BytesSubclass(b"x"),
        memoryview(b"x"),
        Decimal("NaN"),
        Decimal("Infinity"),
        datetime(2026, 9, 12),
        [Record("hidden", b"dataclass")],
    ],
)
def test_ordinary_malformed_leaf_error_and_original_reads_match(leaf, monkeypatch):
    result = assert_legacy_equivalent(unowned_shell(leaf), monkeypatch)
    assert result[0][0] == "error"
    assert result[1] == ()


@pytest.mark.parametrize("error_type", [LookupError, StopIteration])
def test_original_field_failure_order_and_exception_chain_match(error_type, monkeypatch):
    @dataclass
    class FailingRecord:
        payload: bytes

        def __getattribute__(self, name):
            if name == "payload":
                TRACE.append(("failure", name))
                raise error_type("original field failure")
            return object.__getattribute__(self, name)

    result = assert_legacy_equivalent(unowned_shell(FailingRecord(b"x")), monkeypatch)
    assert result[0][0] == "error"
    assert result[2].count(("failure", "payload")) == 1
