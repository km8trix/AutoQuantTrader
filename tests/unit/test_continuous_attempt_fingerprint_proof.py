"""Pure admitted-data proof checks; these helpers confer no factory/source authority."""

import abc
import dataclasses
import gc
import sys
import weakref
from collections.abc import Mapping
from copy import copy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, tzinfo
from decimal import Decimal
from types import MappingProxyType

import pytest
from sqlalchemy.sql.elements import quoted_name

from packages.domain.canonical import canonical_json_bytes
from packages.domain.operational_control import OperationalControlState
from packages.domain.research_job_contracts import ObjectRef
from packages.persistence import _factory_attempt_fingerprint as proof_data
from packages.persistence.detached_journal_capture import detached_journal_value

_QUALIFIED_NATIVE_PROFILE = sys.implementation.name == "cpython" and sys.version_info[:3] == (
    3,
    12,
    13,
)


def require_native_profile():
    if not _QUALIFIED_NATIVE_PROFILE:
        pytest.skip("positive native data proof is qualified only on CPython 3.12.13")


@dataclass(frozen=True, slots=True, weakref_slot=True)
class FixtureRecord:
    child: object
    omitted: object = None


@dataclass(frozen=True)
class DictionaryRecord:
    child: object


@dataclass(frozen=True, slots=True)
class PreexistingMappingRecord:
    child: object


@dataclass(frozen=True, slots=True)
class LaterMappingRecord:
    child: object


class OrdinaryClassBase:
    __slots__ = ()


_class_descriptor_calls = []


class SpoofedClassBase:
    __slots__ = ()

    @property
    def __class__(self):
        _class_descriptor_calls.append("class")
        return dict


@dataclass(frozen=True, slots=True)
class ClassDescriptorRecord(OrdinaryClassBase):
    child: object


def seal(roots, **options):
    return proof_data._try_seal_attempt_data(
        roots,
        selectors=options.pop("selectors", ()),
        allowed_records=options.pop("allowed_records", (FixtureRecord, DictionaryRecord)),
        max_containers=options.pop("max_containers", 2048),
        max_bindings=options.pop("max_bindings", 8192),
        **options,
    )


def original_projection(value):
    return canonical_json_bytes(detached_journal_value(value))


def admit(roots, **options):
    # The real source first completes its unchanged original fingerprint. This
    # pure fixture does the literal projection to establish the same native ABC
    # classification witness; it creates no source/factory authority.
    require_native_profile()
    token = abc.get_cache_token()
    original_projection(roots)
    assert abc.get_cache_token() == token
    return seal(roots, mapping_token=token, **options)


def test_original_domain_data_and_exact_leaves_keep_independent_projection():
    backing = {quoted_name("column", None): (b"payload", Decimal("1.2300"))}
    value = FixtureRecord(
        (
            ObjectRef("a" * 64, 7),
            MappingProxyType(backing),
            datetime(2026, 9, 26, tzinfo=UTC, fold=1),
            OperationalControlState.HALTED,
            True,
            None,
            -(2**80),
        )
    )
    original = original_projection(value)
    binding = admit((value,))
    assert binding is not None and binding.containers > 0 and binding.bindings > 0
    assert binding.require() is None
    assert binding.require() is None
    assert original_projection(value) == original


@pytest.mark.parametrize(
    "kind", ["field", "equal_tuple", "mapping_value", "mapping_order", "proxy"]
)
def test_original_mutable_edges_cannot_be_replaced_or_reordered(kind):
    backing = {"first": ("first",), "second": ("original",)}
    value = FixtureRecord(MappingProxyType(backing))
    binding = admit((value,))
    assert binding is not None
    if kind == "field":
        object.__setattr__(value, "child", {"first": ("changed",)})
    elif kind == "equal_tuple":
        old = backing["first"]
        backing["first"] = tuple(list(old))
        assert backing["first"] == old and backing["first"] is not old
    elif kind == "mapping_value":
        backing["first"] = ("changed",)
    elif kind == "mapping_order":
        backing["first"] = backing.pop("first")
    else:
        object.__setattr__(value, "child", MappingProxyType(dict(backing)))
    with pytest.raises(proof_data._AttemptDataChanged):
        binding.require()


@pytest.mark.parametrize(
    "kind", ["inventory", "definition", "field_name", "field_kind", "module", "qualname"]
)
def test_original_record_schema_and_class_bindings_are_checked(monkeypatch, kind):
    value = FixtureRecord("original")
    binding = admit((value,))
    assert binding is not None
    definitions = FixtureRecord.__dataclass_fields__
    definition = definitions["child"]
    if kind == "inventory":
        monkeypatch.setattr(FixtureRecord, "__dataclass_fields__", dict(definitions))
    elif kind == "definition":
        # copyreg may cache slots on Field itself. Restore that incidental
        # stdlib class mutation so this case isolates definition identity.
        missing = object()
        original_slots = vars(dataclasses.Field).get("__slotnames__", missing)
        try:
            duplicate = copy(definition)
        finally:
            if original_slots is missing and "__slotnames__" in vars(dataclasses.Field):
                delattr(dataclasses.Field, "__slotnames__")
        monkeypatch.setitem(definitions, "child", duplicate)
    elif kind == "field_name":
        monkeypatch.setattr(definition, "name", "omitted")
    elif kind == "field_kind":
        monkeypatch.setattr(definition, "_field_type", object())
    elif kind == "module":
        monkeypatch.setattr(FixtureRecord, "__module__", "changed.original.module")
    else:
        # __qualname__ is a type-managed attribute, absent from this slots class
        # namespace; monkeypatch's delete-based undo cannot restore it.
        original = FixtureRecord.__qualname__
        FixtureRecord.__qualname__ = "ChangedRecord"
        try:
            with pytest.raises(proof_data._AttemptDataChanged):
                binding.require()
        finally:
            FixtureRecord.__qualname__ = original
        return
    with pytest.raises(proof_data._AttemptDataChanged):
        binding.require()


@pytest.mark.parametrize("name", ["child", "__getattribute__"])
def test_changed_record_descriptor_is_rejected_before_the_new_callback(monkeypatch, name):
    value = FixtureRecord("original")
    binding = admit((value,))
    assert binding is not None
    reached = []

    def forbidden(*args):
        reached.append(args)
        raise AssertionError("substituted record callback executed")

    monkeypatch.setattr(FixtureRecord, name, property(forbidden) if name == "child" else forbidden)
    with pytest.raises(proof_data._AttemptDataChanged):
        binding.require()
    assert reached == []


@pytest.mark.parametrize("attribute", ["_name_", "_value_"])
def test_domain_enum_member_mutation_is_rejected(monkeypatch, attribute):
    value = OperationalControlState.HALTED
    binding = admit((value,))
    assert binding is not None
    monkeypatch.setattr(value, attribute, "changed-member")
    with pytest.raises(proof_data._AttemptDataChanged):
        binding.require()


@pytest.mark.parametrize("attribute", ["name", "value", "__getattribute__"])
def test_enum_descriptor_rebinding_does_not_invoke_the_new_behavior(monkeypatch, attribute):
    value = OperationalControlState.HALTED
    binding = admit((value,))
    assert binding is not None
    reached = []

    def forbidden(*args):
        reached.append(args)
        raise AssertionError("substituted enum callback executed")

    replacement = forbidden if attribute == "__getattribute__" else property(forbidden)
    monkeypatch.setattr(OperationalControlState, attribute, replacement, raising=False)
    with pytest.raises(proof_data._AttemptDataChanged):
        binding.require()
    assert reached == []


def test_mutable_timezone_is_unsupported_without_executing_its_methods():
    reached = []

    class MutableZone(tzinfo):
        def utcoffset(self, value):
            reached.append("offset")
            return timedelta(0)

        def dst(self, value):
            reached.append("dst")
            return timedelta(0)

    value = datetime(2026, 9, 26, tzinfo=MutableZone())
    assert seal((value,)) is None
    assert reached == []
    # The unchanged fallback still performs the original timezone conversion.
    assert original_projection(value)
    assert reached


@pytest.mark.parametrize("kind", ["decimal", "fold", "bytes"])
def test_equal_canonical_leaf_replacement_does_not_refresh_original_identity(kind):
    if kind == "decimal":
        before, after = Decimal("1.0"), Decimal("1.00")
    elif kind == "fold":
        before = datetime(2026, 9, 26, tzinfo=UTC, fold=0)
        after = datetime(2026, 9, 26, tzinfo=UTC, fold=1)
    else:
        before = b"original bytes with more than one character"
        after = bytes(bytearray(before))
    assert before is not after and original_projection(before) == original_projection(after)
    value = FixtureRecord(before)
    binding = admit((value,))
    assert binding is not None
    object.__setattr__(value, "child", after)
    with pytest.raises(proof_data._AttemptDataChanged):
        binding.require()


@pytest.mark.parametrize("value", [[], ["ordinary canonical list"], Decimal("NaN"), object()])
def test_unsupported_leaf_profiles_return_no_seal(value):
    assert seal((value,)) is None


def test_unknown_custom_class_is_not_inspected_through_metaclass_hooks():
    reached = []

    class UnknownMeta(type):
        def __eq__(cls, other):
            reached.append("equality")
            raise AssertionError("unknown metaclass equality executed")

        def __hash__(cls):
            reached.append("hash")
            raise AssertionError("unknown metaclass hashing executed")

        def __getattribute__(cls, name):
            reached.append("attribute")
            raise AssertionError("unknown metaclass reflection executed")

    class Unknown(metaclass=UnknownMeta):
        pass

    assert seal((Unknown(),)) is None
    assert reached == []


def test_unslotted_record_uses_full_fallback_instead_of_an_untracked_instance_inventory():
    value = DictionaryRecord("original")
    assert seal((value,)) is None
    assert original_projection(value)


@pytest.mark.parametrize("target", ["field_kind", "field_name_descriptor", "referents"])
def test_changed_reflection_dependency_rejects_without_calling_new_behavior(monkeypatch, target):
    value = FixtureRecord(MappingProxyType({"child": "original"}))
    binding = admit((value,))
    assert binding is not None
    reached = []

    def forbidden(*args):
        reached.append(args)
        raise AssertionError("substituted reflection dependency executed")

    if target == "field_kind":
        monkeypatch.setattr(dataclasses, "_FIELD", object())
    elif target == "field_name_descriptor":
        monkeypatch.setattr(dataclasses.Field, "name", property(forbidden))
    else:
        monkeypatch.setattr(gc, "get_referents", forbidden)
    with pytest.raises(proof_data._AttemptDataChanged):
        binding.require()
    assert reached == []


def test_selectors_do_not_read_unselected_opaque_data():
    require_native_profile()
    value = FixtureRecord("included", object())
    original_projection((value.child,))
    binding = seal((value,), selectors=((FixtureRecord, ("child",)),))
    assert binding is not None
    assert binding.require() is None
    object.__setattr__(value, "child", "changed")
    with pytest.raises(proof_data._AttemptDataChanged):
        binding.require()


def test_unsupported_selected_descriptor_is_not_called_during_admission(monkeypatch):
    value = FixtureRecord("original")
    reached = []

    def forbidden(*args):
        reached.append(args)
        raise StopIteration("original selected getter")

    monkeypatch.setattr(FixtureRecord, "child", property(forbidden))
    assert seal((value,), selectors=((FixtureRecord, ("child",)),)) is None
    assert reached == []
    with pytest.raises(RuntimeError, match="generator raised StopIteration") as error:
        original_projection(value)
    assert type(error.value.__cause__) is StopIteration
    assert len(reached) == 1


def test_aliases_share_charges_but_root_edges_and_descendant_changes_still_count():
    shared = {"value": ("original",)}
    once, twice = admit((shared,)), admit((shared, shared))
    assert once is not None and twice is not None
    assert once.containers == twice.containers
    assert twice.bindings == once.bindings + 1
    shared["value"] = ("changed",)
    with pytest.raises(proof_data._AttemptDataChanged):
        twice.require()


@pytest.mark.parametrize("bound", ["max_containers", "max_bindings"])
def test_exact_resource_boundary_passes_and_one_less_falls_back(bound):
    roots = ({"value": ("original",)},)
    binding = admit(roots)
    assert binding is not None
    limit = binding.containers if bound == "max_containers" else binding.bindings
    assert admit(roots, **{bound: limit}) is not None
    assert admit(roots, **{bound: limit - 1}) is None


def test_cycles_are_unsupported_without_partial_success_or_retained_graph():
    value = FixtureRecord(None)
    backing = {"cycle": value}
    object.__setattr__(value, "child", backing)
    reference = weakref.ref(value)
    assert seal((value,)) is None
    del value, backing
    gc.collect()
    assert reference() is None


def test_releasing_pure_seal_releases_original_graph():
    value = FixtureRecord(("original",))
    reference = weakref.ref(value)
    binding = admit((value,))
    assert binding is not None
    del value
    gc.collect()
    assert reference() is not None
    del binding
    gc.collect()
    assert reference() is None


def test_preexisting_virtual_mapping_registration_uses_the_original_fallback():
    # Registration is irreversible, so this otherwise unused fixture class is
    # isolated from domain types and all other cases in this process.
    Mapping.register(PreexistingMappingRecord)
    value = PreexistingMappingRecord("original")
    assert isinstance(value, Mapping)
    # The old projection treats it as a Mapping before dataclass reflection.
    # Proof admission must not accidentally bless the dataclass interpretation.
    with pytest.raises(AttributeError, match="items"):
        original_projection((value,))
    assert seal((value,), allowed_records=(PreexistingMappingRecord,)) is None


def test_later_virtual_mapping_registration_invalidates_an_existing_seal():
    value = LaterMappingRecord("original")
    binding = admit((value,), allowed_records=(LaterMappingRecord,))
    assert binding is not None
    original_token = abc.get_cache_token()
    Mapping.register(LaterMappingRecord)
    with pytest.raises(proof_data._AttemptDataChanged):
        binding.require()
    assert (
        seal((value,), allowed_records=(LaterMappingRecord,), mapping_token=original_token) is None
    )


def test_cleared_native_mapping_cache_cannot_reuse_an_existing_classification_witness():
    value = FixtureRecord("original")
    binding = admit((value,))
    assert binding is not None
    Mapping._abc_caches_clear()
    with pytest.raises(proof_data._AttemptDataChanged):
        binding.require()
    # An unchanged full projection can establish a new pure inventory. This
    # creates no authority to rescue an already-poisoned source operation.
    replacement = admit((value,))
    assert replacement is not None
    assert replacement is not binding


def test_stale_or_nonexact_mapping_token_cannot_be_used_for_initial_admission():
    require_native_profile()
    roots = (FixtureRecord("original"),)
    original_projection(roots)
    token = abc.get_cache_token()
    assert seal(roots, mapping_token=token) is not None
    assert seal(roots, mapping_token=token - 1) is None
    assert seal(roots, mapping_token=True) is None


@pytest.mark.parametrize("before_admission", [True, False])
def test_custom_class_descriptor_cannot_change_mapping_classification(
    monkeypatch, before_admission
):
    value = ClassDescriptorRecord("original")
    options = {"allowed_records": (ClassDescriptorRecord,)}
    binding = None if before_admission else admit((value,), **options)
    if not before_admission:
        assert binding is not None
    monkeypatch.setattr(sys.modules[__name__], "_class_descriptor_calls", [])
    # Like __qualname__, __bases__ is managed by type and absent from the
    # class namespace. Restore it explicitly instead of monkeypatch's deletion.
    original_bases = ClassDescriptorRecord.__bases__
    try:
        ClassDescriptorRecord.__bases__ = (SpoofedClassBase,)
        if before_admission:
            assert seal((value,), **options) is None
        else:
            with pytest.raises(proof_data._AttemptDataChanged):
                binding.require()
        assert _class_descriptor_calls == []
        assert isinstance(value, Mapping)
        assert _class_descriptor_calls == ["class"]
    finally:
        ClassDescriptorRecord.__bases__ = original_bases


@pytest.mark.parametrize("attribute", ["__code__", "__defaults__", "__kwdefaults__"])
def test_enum_getter_behavior_mutation_is_rejected_without_invocation(monkeypatch, attribute):
    value = OperationalControlState.HALTED
    binding = admit((value,))
    assert binding is not None
    getter = proof_data._ENUM_VALUE_GETTER

    def forbidden(_value):
        raise AssertionError("mutated enum getter executed")

    replacement = {
        "__code__": forbidden.__code__,
        "__defaults__": ("changed default",),
        "__kwdefaults__": {"changed": True},
    }[attribute]
    monkeypatch.setattr(getter, attribute, replacement)
    with pytest.raises(proof_data._AttemptDataChanged):
        binding.require()


def test_rebinding_record_module_export_invalidates_original_type(monkeypatch):
    value = FixtureRecord("original")
    binding = admit((value,))
    assert binding is not None
    monkeypatch.setattr(sys.modules[__name__], "FixtureRecord", object())
    with pytest.raises(proof_data._AttemptDataChanged):
        binding.require()


def test_quoted_name_quote_mutation_is_rejected(monkeypatch):
    name = quoted_name("column", None)
    binding = admit(({name: "original"},))
    assert binding is not None
    monkeypatch.setattr(name, "quote", True)
    with pytest.raises(proof_data._AttemptDataChanged):
        binding.require()


@pytest.mark.parametrize("target", ["abc_token", "int_limit", "field_lookup", "quoted_str"])
def test_pinned_runtime_callback_replacement_is_rejected_before_invocation(monkeypatch, target):
    value = FixtureRecord({quoted_name("column", None): "original"})
    binding = admit((value,))
    assert binding is not None

    def forbidden(*args):
        raise AssertionError("substituted runtime callback executed")

    owner, name = {
        "abc_token": (abc, "get_cache_token"),
        "int_limit": (sys, "get_int_max_str_digits"),
        "field_lookup": (dataclasses.Field, "__getattribute__"),
        "quoted_str": (quoted_name, "__str__"),
    }[target]
    monkeypatch.setattr(owner, name, forbidden)
    with pytest.raises(proof_data._AttemptDataChanged):
        binding.require()
    assert seal((value,)) is None


@pytest.mark.parametrize("target", ["implementation", "version_info", "_FIELDS"])
def test_unsupported_runtime_or_field_inventory_cannot_issue_a_new_seal(monkeypatch, target):
    value = FixtureRecord("original")
    binding = admit((value,))
    assert binding is not None
    owner = dataclasses if target == "_FIELDS" else sys
    with monkeypatch.context() as patch:
        patch.setattr(owner, target, object())
        with pytest.raises(proof_data._AttemptDataChanged):
            binding.require()
        assert seal((value,)) is None


def test_unsupported_scalar_and_container_subclasses_are_not_traversed():
    class CustomTuple(tuple):
        def __iter__(self):
            raise AssertionError("custom tuple iteration executed")

    class CustomDecimal(Decimal):
        def is_finite(self):
            raise AssertionError("custom decimal method executed")

    class CustomString(str):
        def __str__(self):
            raise AssertionError("custom string conversion executed")

        def __lt__(self, other):
            raise AssertionError("custom string comparison executed")

    for value in (CustomTuple(("value",)), CustomDecimal("1"), {CustomString("key"): "value"}):
        assert seal((value,)) is None
