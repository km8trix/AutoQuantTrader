"""Pure semantic conversion compatibility; no ownership or performance claims."""

from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime
from decimal import Decimal
from enum import IntEnum, StrEnum
from hashlib import sha256

import pytest

from packages.domain import personal_contracts as contracts
from packages.domain.canonical import canonical_json_bytes
from tests.unit.test_personal_contract_semantics import GOLDENS, record_for


def _legacy_semantic_value(value):
    """Literal pre-change algorithm, recursively independent of the candidate."""
    if is_dataclass(value) and not isinstance(value, type):
        return (
            type(value).__module__ + "." + type(value).__qualname__,
            tuple((f.name, _legacy_semantic_value(getattr(value, f.name))) for f in fields(value)),
        )
    if type(value) is tuple:
        return tuple(_legacy_semantic_value(v) for v in value)
    return value


def _encoded_outcome(convert, value):
    try:
        payload = canonical_json_bytes(convert(value))
        return "return", payload, sha256(payload).hexdigest()
    except Exception as error:
        cause = error.__cause__
        return (
            "error",
            type(error),
            str(error),
            None if cause is None else (type(cause), str(cause)),
        )


class _String(str):
    pass


class _Integer(int):
    pass


class _Bytes(bytes):
    pass


class _Tuple(tuple):
    pass


class _StringEnum(StrEnum):
    VALUE = "fixture"


class _IntegerEnum(IntEnum):
    VALUE = 1


@dataclass(frozen=True)
class _StringRecord(str):
    label: str


@dataclass(frozen=True)
class _TupleRecord(tuple):
    label: str


@pytest.mark.parametrize(
    "value",
    [None, False, True, 0, -1, 2**80, "", "é\n\ud800", b"", b"\x00raw", (), (1, ("x", None), b"y")],
)
def test_exact_builtins_preserve_material_bytes_hash_and_leaf_identity(value):
    old = _legacy_semantic_value(value)
    new = contracts.semantic_value(value)
    assert type(new) is type(old) and new == old
    if type(value) is not tuple:
        assert new is value and old is value
    assert _encoded_outcome(contracts.semantic_value, value) == _encoded_outcome(
        _legacy_semantic_value, value
    )
    assert contracts.content_digest(value) == sha256(canonical_json_bytes(old)).hexdigest()


@pytest.mark.parametrize(
    "kind", ["str", "int", "bytes", "tuple", "str_enum", "int_enum", "str_record", "tuple_record"]
)
def test_nonexact_builtins_and_dataclass_subclasses_keep_original_fallthrough(kind):
    if kind == "str_record":
        value = str.__new__(_StringRecord, "underlying string")
        object.__setattr__(value, "label", "record metadata")
    elif kind == "tuple_record":
        value = tuple.__new__(_TupleRecord, (1, 2))
        object.__setattr__(value, "label", "record metadata")
    else:
        value = {
            "str": _String("fixture"),
            "int": _Integer(7),
            "bytes": _Bytes(b"fixture"),
            "tuple": _Tuple((1, 2)),
            "str_enum": _StringEnum.VALUE,
            "int_enum": _IntegerEnum.VALUE,
        }[kind]
    old, new = _legacy_semantic_value(value), contracts.semantic_value(value)
    assert type(new) is type(old) and new == old
    if is_dataclass(value):
        assert type(new) is tuple and new[1] == (("label", "record metadata"),)
    else:
        assert old is value and new is value
    assert _encoded_outcome(contracts.semantic_value, value) == _encoded_outcome(
        _legacy_semantic_value, value
    )


@pytest.mark.parametrize(
    "kind", ["float", "object", "record_class", "naive_time", "nonfinite", "tuple_subclass"]
)
def test_unsupported_values_keep_original_canonical_error_type_message_and_cause(kind):
    value = {
        "float": 1.25,
        "object": object(),
        "record_class": _StringRecord,
        "naive_time": datetime(2026, 9, 24),
        "nonfinite": Decimal("NaN"),
        "tuple_subclass": _Tuple((1, 2)),
    }[kind]
    expected = _encoded_outcome(_legacy_semantic_value, (None, value, "later"))
    assert expected[0] == "error"
    assert _encoded_outcome(contracts.semantic_value, (None, value, "later")) == expected


@pytest.mark.parametrize("kind", ["pin", "mark", "append", "broker_event", "control"])
def test_actual_contract_records_keep_original_semantic_bytes_and_fixed_goldens(kind):
    record = record_for(kind)
    material = (record.contract_version, record)
    expected = canonical_json_bytes(_legacy_semantic_value(material))
    assert canonical_json_bytes(contracts.semantic_value(material)) == expected
    assert sha256(expected).hexdigest() == record.semantic_sha256 == GOLDENS[kind]
    assert (
        contracts.content_digest(record)
        == sha256(canonical_json_bytes(_legacy_semantic_value(record))).hexdigest()
    )


@pytest.mark.parametrize(
    "fault", ["none", "mutate_later", "fail_first", "fail_second", "invalid_first"]
)
def test_original_mutable_field_reads_and_failures_remain_in_order(fault):
    events = []

    @dataclass(frozen=True)
    class Record:
        first: object
        second: object

        def __getattribute__(self, name):
            if name in ("first", "second"):
                events.append(name)
                if (name == "first" and fault == "fail_first") or (
                    name == "second" and fault == "fail_second"
                ):
                    raise LookupError("original field failure") from ValueError("original cause")
                if name == "first" and fault == "mutate_later":
                    object.__setattr__(self, "second", "changed during first field read")
            return object.__getattribute__(self, name)

    record = Record(object() if fault == "invalid_first" else "first", "second")
    observations = []
    for convert in (_legacy_semantic_value, contracts.semantic_value):
        object.__setattr__(record, "second", "second")
        events.clear()
        result = _encoded_outcome(convert, (record,))
        observations.append((result, tuple(events)))
    assert observations[0] == observations[1]
    expected_reads = ("first",) if fault == "fail_first" else ("first", "second")
    assert observations[0][1] == expected_reads
    if fault in ("fail_first", "fail_second"):
        assert observations[0][0] == (
            "error",
            LookupError,
            "original field failure",
            (ValueError, "original cause"),
        )
    elif fault == "invalid_first":
        assert observations[0][0][0] == "error"
    else:
        assert observations[0][0][0] == "return"


def test_same_nested_instance_is_retraversed_on_every_hash_call():
    record = record_for("append")
    child = record.records[0]
    original = child.payload
    before = record.semantic_sha256
    try:
        object.__setattr__(child, "payload", b"changed original field")
        after = record.semantic_sha256
        expected = canonical_json_bytes(_legacy_semantic_value((record.contract_version, record)))
        assert after != before and after == sha256(expected).hexdigest()
    finally:
        object.__setattr__(child, "payload", original)
    assert record.semantic_sha256 == before


@pytest.mark.parametrize("kind", ["instance", "dataclass_instance", "dataclass_class"])
def test_fallthrough_keeps_metaclass_reflection_without_new_equality_probes(kind):
    events = []

    class Meta(type):
        def __getattribute__(cls, name):
            if name == "__dataclass_fields__":
                events.append("dataclass-fields")
            return super().__getattribute__(name)

        def __eq__(cls, other):
            raise AssertionError("dispatch must not probe metaclass equality")

    class Ordinary(metaclass=Meta):
        pass

    @dataclass(frozen=True)
    class Record(metaclass=Meta):
        field: str

    if kind == "instance":
        value = Ordinary()
    elif kind == "dataclass_class":
        value = Record
    else:
        value = Record("x")
    observations = []
    for convert in (_legacy_semantic_value, contracts.semantic_value):
        events.clear()
        result = convert(value)
        observations.append((result, tuple(events)))
    assert observations[0] == observations[1]
    assert observations[0][1]
    if kind != "dataclass_instance":
        assert observations[0][0] is value and observations[1][0] is value


def test_literal_reference_does_not_call_candidate_converter(monkeypatch):
    record = record_for("append")
    expected = canonical_json_bytes(_legacy_semantic_value((record.contract_version, record)))

    def forbidden(value):
        raise AssertionError("candidate cannot supply reference intermediates")

    monkeypatch.setattr(contracts, "semantic_value", forbidden)
    assert (
        canonical_json_bytes(_legacy_semantic_value((record.contract_version, record))) == expected
    )


def _previous_scalar_dispatch(value):
    """Literal immediately preceding converter; never calls candidate helpers."""
    if type(value) is tuple:
        return tuple(_previous_scalar_dispatch(item) for item in value)
    if (
        value is None
        or type(value) is str
        or type(value) is int
        or type(value) is bool
        or type(value) is bytes
    ):
        return value
    if is_dataclass(value) and not isinstance(value, type):
        return (
            type(value).__module__ + "." + type(value).__qualname__,
            tuple(
                (field.name, _previous_scalar_dispatch(getattr(value, field.name)))
                for field in fields(value)
            ),
        )
    if type(value) is tuple:
        return tuple(_previous_scalar_dispatch(item) for item in value)
    return value


@pytest.mark.parametrize(
    "leaf",
    [None, False, True, 0, -(2**100), "", "é\n\ud800", b"", b"\x00raw"],
)
def test_tuple_scalar_children_keep_identity_bytes_and_hash_at_multiple_depths(leaf):
    value = (leaf, ("label", leaf), (), (((leaf,),),))
    actual = contracts.semantic_value(value)
    expected = _previous_scalar_dispatch(value)
    assert actual == expected == _legacy_semantic_value(value)
    assert type(actual) is tuple and actual is not value
    assert actual[0] is leaf and actual[1][1] is leaf and actual[3][0][0][0] is leaf
    assert _encoded_outcome(contracts.semantic_value, value) == _encoded_outcome(
        _previous_scalar_dispatch, value
    )
    assert contracts.content_digest(value) == sha256(canonical_json_bytes(expected)).hexdigest()


def test_tuple_subclasses_enums_and_dataclass_subclasses_keep_nonexact_dispatch():
    string_record = str.__new__(_StringRecord, "underlying string")
    object.__setattr__(string_record, "label", "string metadata")
    tuple_record = tuple.__new__(_TupleRecord, (1, 2))
    object.__setattr__(tuple_record, "label", "tuple metadata")
    leaves = (
        _String("fixture"),
        _Integer(7),
        _Bytes(b"fixture"),
        _Tuple((1, 2)),
        _StringEnum.VALUE,
        _IntegerEnum.VALUE,
        string_record,
        tuple_record,
    )
    for leaf in leaves:
        value = ("before", ((leaf,),), None, "after")
        actual = contracts.semantic_value(value)
        expected = _previous_scalar_dispatch(value)
        assert actual == expected == _legacy_semantic_value(value)
        assert _encoded_outcome(contracts.semantic_value, value) == _encoded_outcome(
            _previous_scalar_dispatch, value
        )
        if not is_dataclass(leaf):
            assert actual[1][0][0] is leaf


@pytest.mark.parametrize("fault", ["none", "mutate_later", "raise_first", "raise_second"])
def test_nested_tuple_records_preserve_alias_reads_mutation_and_first_error(fault):
    events = []

    @dataclass(frozen=True)
    class Record:
        first: object
        second: object

        def __getattribute__(self, name):
            if name in ("first", "second"):
                events.append(name)
                if (fault == "raise_first" and name == "first") or (
                    fault == "raise_second" and name == "second"
                ):
                    raise LookupError("tuple field failed") from ValueError("tuple cause")
                if fault == "mutate_later" and name == "first":
                    object.__setattr__(self, "second", ("changed", b"value", None))
            return object.__getattribute__(self, name)

    record = Record(("scalar", 7, True), ("original",))
    value = (None, ("first visit", record), b"between", (record, "last"))
    observations = []
    for convert in (_previous_scalar_dispatch, contracts.semantic_value):
        object.__setattr__(record, "second", ("original",))
        events.clear()
        outcome = _encoded_outcome(convert, value)
        observations.append((outcome, tuple(events)))
    assert observations[0] == observations[1]
    if fault == "raise_first":
        assert observations[0][1] == ("first",)
    elif fault == "raise_second":
        assert observations[0][1] == ("first", "second")
    else:
        assert observations[0][1] == ("first", "second", "first", "second")


def test_tuple_fast_path_keeps_reflection_hooks_and_rehashes_same_nested_record():
    events = []

    class Meta(type):
        def __getattribute__(cls, name):
            if name == "__dataclass_fields__":
                events.append("dataclass-fields")
            return super().__getattribute__(name)

        def __eq__(cls, other):
            raise AssertionError("tuple dispatch must not probe metaclass equality")

    @dataclass(frozen=True)
    class Record(metaclass=Meta):
        values: object

    record = Record(("first", 3, None))
    value = (None, (record, b"last"))
    digests = []
    for replacement in (("first", 3, None), ("changed", 4, b"bytes")):
        object.__setattr__(record, "values", replacement)
        observations = []
        for convert in (_previous_scalar_dispatch, contracts.semantic_value):
            events.clear()
            observations.append((_encoded_outcome(convert, value), tuple(events)))
        assert observations[0] == observations[1]
        assert observations[0][1]
        digests.append(contracts.content_digest(value))
    assert digests[0] != digests[1]


@pytest.mark.parametrize(
    "leaf",
    [None, False, True, 0, -(2**100), "", "é\n\ud800", b"", b"\x00raw"],
)
def test_record_scalar_fields_keep_leaf_identity_and_allocate_each_original_visit(leaf):
    @dataclass(frozen=True)
    class Record:
        scalar: object
        nested: object

    record = Record(leaf, (leaf, ("nested", leaf)))
    value = (record, record)
    first = contracts.semantic_value(value)
    second = contracts.semantic_value(value)
    assert first == second == _legacy_semantic_value(value)
    assert _encoded_outcome(contracts.semantic_value, value) == _encoded_outcome(
        _legacy_semantic_value, value
    )
    assert first is not second
    visits = (*first, *second)
    assert len({id(visit) for visit in visits}) == 4
    assert len({id(visit[1]) for visit in visits}) == 4
    assert len({id(visit[1][0]) for visit in visits}) == 4
    assert len({id(visit[1][1][1]) for visit in visits}) == 4
    assert len({id(visit[1][1][1][1]) for visit in visits}) == 4
    for visit in visits:
        assert visit[1][0][1] is leaf
        assert visit[1][1][1][0] is leaf
        assert visit[1][1][1][1][1] is leaf


def test_record_nonexact_fields_keep_subclasses_records_and_canonical_failures():
    @dataclass(frozen=True)
    class Record:
        first: object
        last: str = "after original field"

    string_record = str.__new__(_StringRecord, "underlying string")
    object.__setattr__(string_record, "label", "string metadata")
    tuple_record = tuple.__new__(_TupleRecord, (1, 2))
    object.__setattr__(tuple_record, "label", "tuple metadata")
    values = (
        _String("text"),
        _Integer(7),
        _Bytes(b"raw"),
        _Tuple((1, 2)),
        _StringEnum.VALUE,
        _IntegerEnum.VALUE,
        string_record,
        tuple_record,
        Decimal("1.2500"),
        Decimal("NaN"),
        datetime(2026, 9, 26),
        1.25,
        object(),
        Record,
    )
    for leaf in values:
        value = Record(leaf)
        expected = _legacy_semantic_value(value)
        actual = contracts.semantic_value(value)
        assert actual == expected
        assert _encoded_outcome(contracts.semantic_value, value) == _encoded_outcome(
            _legacy_semantic_value, value
        )
        if not is_dataclass(leaf) or isinstance(leaf, type):
            assert actual[1][0][1] is leaf


@pytest.mark.parametrize(
    "fault",
    [
        "none",
        "first",
        "second",
        "prefix_mutation",
        "__module__",
        "__qualname__",
        "__dataclass_fields__",
    ],
)
def test_record_prefix_reflection_and_field_getters_keep_order_and_first_error(fault):
    events = []
    active = False

    class Meta(type):
        def __getattribute__(cls, name):
            if active and name in ("__module__", "__qualname__", "__dataclass_fields__"):
                events.append("class:" + name)
                if fault == name:
                    raise LookupError("prefix failure") from ValueError("prefix cause")
                if fault == "prefix_mutation" and name == "__module__":
                    object.__setattr__(record, "second", ("prefix changed original", None))
            return super().__getattribute__(name)

        def __eq__(cls, other):
            raise AssertionError("record dispatch must not compare metaclasses")

    @dataclass(frozen=True)
    class Record(metaclass=Meta):
        first: object
        second: object

        def __getattribute__(self, name):
            if active and name in ("first", "second", "__dataclass_fields__"):
                events.append("instance:" + name)
                if name == fault:
                    raise LookupError("field failure") from ValueError("field cause")
            return object.__getattribute__(self, name)

    record = Record("first", "second")
    active = True
    observations = []
    for convert in (_legacy_semantic_value, contracts.semantic_value):
        object.__setattr__(record, "second", "second")
        events.clear()
        observations.append((_encoded_outcome(convert, record), tuple(events)))
    assert observations[0] == observations[1]
    if fault in ("none", "prefix_mutation"):
        assert observations[0][1] == (
            "class:__dataclass_fields__",
            "class:__module__",
            "class:__qualname__",
            "instance:__dataclass_fields__",
            "instance:first",
            "instance:second",
        )


@pytest.mark.parametrize("fail_at", [0, 1, 2])
def test_original_field_name_reads_are_distinct_and_precede_field_value(fail_at):
    events = []

    @dataclass(frozen=True)
    class Record:
        first: str

        def __getattribute__(self, name):
            if name == "first":
                events.append("field-value")
            return object.__getattribute__(self, name)

    original_field = fields(Record)[0]

    class ReflectedField:
        _field_type = original_field._field_type
        reads = 0

        @property
        def name(self):
            self.reads += 1
            events.append("field-name:" + str(self.reads))
            if self.reads == fail_at:
                raise LookupError("field name failed") from ValueError("name cause")
            return "output-label" if self.reads == 1 else "first"

    reflected = ReflectedField()
    Record.__dataclass_fields__ = {"first": reflected}
    record = Record("original")
    observations = []
    for convert in (_legacy_semantic_value, contracts.semantic_value):
        reflected.reads = 0
        events.clear()
        observations.append((_encoded_outcome(convert, record), tuple(events)))
    assert observations[0] == observations[1]
    if fail_at == 0:
        assert observations[0][1] == ("field-name:1", "field-name:2", "field-value")
        reflected.reads = 0
        assert contracts.semantic_value(record)[1] == (("output-label", "original"),)
    else:
        assert observations[0][1] == tuple(f"field-name:{index}" for index in range(1, fail_at + 1))


def test_temporary_nested_record_is_released_before_reading_the_next_field():
    events = []

    @dataclass(frozen=True)
    class Child:
        value: str

        def __del__(self):
            events.append("release-child")
            object.__setattr__(record, "second", "changed by original child release")

    @dataclass(frozen=True)
    class Record:
        first: object
        second: str

        def __getattribute__(self, name):
            if name in ("first", "second"):
                events.append("read:" + name)
            if name == "first":
                return Child("original ephemeral child")
            return object.__getattribute__(self, name)

    record = Record(None, "original second")
    observations = []
    for convert in (_legacy_semantic_value, contracts.semantic_value):
        object.__setattr__(record, "second", "original second")
        events.clear()
        observations.append((_encoded_outcome(convert, record), tuple(events)))
    assert observations[0] == observations[1]
    assert observations[0][1] == ("read:first", "release-child", "read:second")
