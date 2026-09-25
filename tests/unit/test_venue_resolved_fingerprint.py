"""Finite pure compatibility only; unowned shells confer no venue authority.

The literal oracle retains the original expression and complete detachment.
Stable ordinary field/mapping reads and string-valued contract digests are the
admitted profile; arbitrary Python hooks, races and resource parity are excluded.
"""

from collections import Counter
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import Enum
from hashlib import sha256
from types import MappingProxyType
from uuid import UUID

import pytest

from packages.domain import personal_contracts
from packages.domain.canonical import canonical_json_bytes
from packages.persistence import continuous_venue_sources as venue_sources

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


class DigestValue:
    def __init__(self, label, digest):
        self.label, self.digest = label, digest

    @property
    def semantic_sha256(self):
        TRACE.append(("semantic", self.label))
        return self.digest


def unowned_shell(leaf):
    """Exercise only the private pure function; never an owner/store API."""
    row = ReadMapping(sequence=7, payload=b"original-row", account_id="account")
    return venue_sources.ResolvedContinuousVenueSources(
        capture=DigestValue("capture", "a" * 64),
        pages=(DigestValue("page-1", "b" * 64), DigestValue("page-2", "c" * 64)),
        reads=(leaf, row, leaf, row),
        seal=object(),
    )


def legacy_fingerprint(value):
    """Literal old material and digest; the original detacher is unchanged."""
    return personal_contracts.content_digest(
        (
            value.capture.semantic_sha256,
            tuple(page.semantic_sha256 for page in value.pages),
            venue_sources._fingerprint_value(value.reads),
        )
    )


def captured_call(function, value, monkeypatch):
    """Observe final canonical bytes and each original semantic/field/byte read."""
    encoded = []
    TRACE.clear()

    def encode(material):
        result = canonical_json_bytes(material)
        encoded.append(result)
        return result

    def original_byte_hash(payload):
        # The final digest is also in this module now. It is separately checked
        # against encoded bytes; only original retained byte hashing is traced.
        if not any(payload is final for final in encoded):
            TRACE.append(("bytes", payload))
        return sha256(payload)

    with monkeypatch.context() as guard:
        guard.setattr(personal_contracts, "canonical_json_bytes", encode)
        guard.setattr(venue_sources, "canonical_json_bytes", encode)
        guard.setattr(venue_sources, "sha256", original_byte_hash)
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
    new = captured_call(venue_sources._fingerprint, value, monkeypatch)
    assert new == old
    if new[0][0] == "return":
        assert new[1]
        assert new[0][1] == sha256(new[1][-1]).hexdigest()
    return new


def test_full_original_bytes_hash_and_read_order(monkeypatch):
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
    assert len(result[1]) == 1
    counts = Counter(result[2])
    assert result[2][:3] == (
        ("semantic", "capture"),
        ("semantic", "page-1"),
        ("semantic", "page-2"),
    )
    assert counts[("bytes", b"original-leaf")] == 2
    assert counts[("bytes", b"original-row")] == 2
    assert counts[("field", "payload")] == 2
    assert ("field", "_owner") not in counts
    assert ("field", "_validated_values") not in counts


@pytest.mark.parametrize(
    "value",
    [
        None,
        (),
        MappingProxyType({"b": (2, b"two"), "a": b"one"}),
        [None, 1, "list"],
        {1, 2},
        frozenset({"a", "b"}),
    ],
)
def test_normal_and_nonadmitted_container_leaf_compatibility(value, monkeypatch):
    # Non-tuple containers probe legacy behavior; this is not source admission.
    assert_legacy_equivalent(unowned_shell(value), monkeypatch)


def test_aliases_equal_copies_and_each_material_mutation(monkeypatch):
    leaf = Record("original", b"same", (Decimal("7.00"),))
    value = unowned_shell(leaf)
    original = assert_legacy_equivalent(value, monkeypatch)[0]
    copied = replace(value, reads=(replace(leaf), value.reads[1], replace(leaf), value.reads[3]))
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
    for item in (value.capture, *value.pages):
        retained = item.digest
        item.digest = "d" * 64
        try:
            assert assert_legacy_equivalent(value, monkeypatch)[0] != original
        finally:
            item.digest = retained
    row = value.reads[1]
    row["payload"] = b"changed-row"
    assert assert_legacy_equivalent(value, monkeypatch)[0] != original
    row["payload"] = b"original-row"
    assert assert_legacy_equivalent(value, monkeypatch)[0] == original
    assert (
        assert_legacy_equivalent(replace(value, pages=tuple(reversed(value.pages))), monkeypatch)[0]
        != original
    )


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
        {"text-key": 1, 2: "incomparable-key"},
    ],
)
def test_ordinary_malformed_leaf_errors_and_original_reads_match(leaf, monkeypatch):
    result = assert_legacy_equivalent(unowned_shell(leaf), monkeypatch)
    assert result[0][0] == "error"
    assert result[1] == ()


@pytest.mark.parametrize("failure_at", ["capture", "page-1", "field"])
def test_original_error_order_and_exception_chain(failure_at, monkeypatch):
    class FailingDigest(DigestValue):
        @property
        def semantic_sha256(self):
            TRACE.append(("failure", self.label))
            raise LookupError("original semantic failure") from ValueError("original cause")

    @dataclass
    class FailingRecord:
        payload: bytes

        def __getattribute__(self, name):
            if name == "payload":
                TRACE.append(("failure", "field"))
                raise LookupError("original field failure") from ValueError("original cause")
            return object.__getattribute__(self, name)

    value = unowned_shell(FailingRecord(b"x"))
    if failure_at == "capture":
        value = replace(value, capture=FailingDigest("capture", "a" * 64))
    elif failure_at == "page-1":
        value = replace(value, pages=(FailingDigest("page-1", "b" * 64), *value.pages[1:]))
    result = assert_legacy_equivalent(value, monkeypatch)
    assert result[0][0] == "error"
    assert result[2][-1] == ("failure", failure_at)
    assert sum(event[0] == "failure" for event in result[2]) == 1
