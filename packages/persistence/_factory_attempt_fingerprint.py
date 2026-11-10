"""Bounded raw data bindings for one private factory attempt fingerprint.

This helper grants no ownership or validation authority. Exact, ordinary data is
admitted; unsupported profiles retain the existing full fingerprint path. The
CPython proxy probe observes only an exact proxy's one exact-dict referent.
"""

from __future__ import annotations

import abc
import dataclasses
import gc
import sys
from collections.abc import Mapping
from dataclasses import Field, dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import Enum, EnumType
from types import GetSetDescriptorType, MappingProxyType, MemberDescriptorType, ModuleType
from typing import Any, cast
from weakref import ReferenceType

from sqlalchemy.sql.elements import quoted_name


class _AttemptDataChanged(ValueError):
    """An admitted original data binding or its behavior changed."""


class _NotAdmitted(Exception):
    pass


_TYPE_DICT = vars(type)["__dict__"]
_TYPE_MRO = vars(type)["__mro__"]
_TYPE_NAME = vars(type)["__name__"]
_TYPE_QUALNAME = vars(type)["__qualname__"]
_OBJECT_CLASS = vars(object)["__class__"]
_MAPPING_IMPL = vars(Mapping)["_abc_impl"]
_ABC_STATE_TYPE = type(_MAPPING_IMPL)
_GET_REFERENTS = gc.get_referents
_GET_ABC_TOKEN = abc.get_cache_token
_GET_INT_LIMIT = sys.get_int_max_str_digits
_FIELD_NAME = vars(Field)["name"]
_FIELD_KIND = vars(Field)["_field_type"]
_FIELD_GETATTRIBUTE = Field.__getattribute__
_FIELD = vars(dataclasses)["_FIELD"]
_FIELDS = vars(dataclasses)["_FIELDS"]
_ENUM_NAME: Any = vars(Enum)["name"]
_ENUM_VALUE: Any = vars(Enum)["value"]
_ENUM_GETATTRIBUTE = Enum.__getattribute__
_ENUM_NAME_GETTER = _ENUM_NAME.fget
_ENUM_VALUE_GETTER = _ENUM_VALUE.fget
_ENUM_PROPERTY_GET = type(_ENUM_VALUE).__get__
_ENUM_BEHAVIOR = tuple(
    (function, function.__code__, function.__defaults__, function.__kwdefaults__)
    for function in (_ENUM_NAME_GETTER, _ENUM_VALUE_GETTER, _ENUM_PROPERTY_GET)
)
_QUOTED_GETATTRIBUTE = quoted_name.__getattribute__
_QUOTED_STR = quoted_name.__str__
_QUOTED_QUOTE = vars(quoted_name)["quote"]
_PYTHON_IMPLEMENTATION = sys.implementation
_PYTHON_VERSION = sys.version_info
_KNOWN_DOMAIN_TYPES = tuple(
    value
    for module_name, module in tuple(sys.modules.items())
    if module_name.startswith("packages.domain.") and type(module) is ModuleType
    for value in tuple(vars(module).values())
    if (type(value) is type or type(value) is EnumType)
    and type.__getattribute__(value, "__module__") == module_name
)


def _runtime() -> tuple[int, int]:
    return (cast(int, _GET_ABC_TOKEN()), _GET_INT_LIMIT())


def _supported_runtime() -> bool:
    return (
        sys.implementation is _PYTHON_IMPLEMENTATION
        and sys.implementation.name == "cpython"
        and sys.version_info is _PYTHON_VERSION
        and sys.version_info[:3] == (3, 12, 13)
        and gc.get_referents is _GET_REFERENTS
        and abc.get_cache_token is _GET_ABC_TOKEN
        and sys.get_int_max_str_digits is _GET_INT_LIMIT
        and vars(dataclasses)["_FIELD"] is _FIELD
        and vars(dataclasses)["_FIELDS"] is _FIELDS
        and vars(Field).get("name") is _FIELD_NAME
        and vars(Field).get("_field_type") is _FIELD_KIND
        and Field.__getattribute__ is _FIELD_GETATTRIBUTE
        and vars(Enum)["name"] is _ENUM_NAME
        and vars(Enum)["value"] is _ENUM_VALUE
        and Enum.__getattribute__ is _ENUM_GETATTRIBUTE
        and _ENUM_NAME.fget is _ENUM_NAME_GETTER
        and _ENUM_VALUE.fget is _ENUM_VALUE_GETTER
        and type(_ENUM_VALUE).__get__ is _ENUM_PROPERTY_GET
        and all(
            function.__code__ is code
            and function.__defaults__ is defaults
            and function.__kwdefaults__ is kwdefaults
            for function, code, defaults, kwdefaults in _ENUM_BEHAVIOR
        )
        and quoted_name.__getattribute__ is _QUOTED_GETATTRIBUTE
        and quoted_name.__str__ is _QUOTED_STR
        and vars(quoted_name).get("quote") is _QUOTED_QUOTE
    )


def _class_attribute(kind: type[Any], name: str) -> tuple[object, object]:
    for base in _TYPE_MRO.__get__(kind, type):
        namespace = _TYPE_DICT.__get__(base, type)
        if name in namespace:
            return base, namespace[name]
    return None, None


def _class_metadata(kind: type[Any], name: str) -> object:
    if name == "__mro__":
        return _TYPE_MRO.__get__(kind, type)
    if name == "__name__":
        return _TYPE_NAME.__get__(kind, type)
    if name == "__qualname__":
        return _TYPE_QUALNAME.__get__(kind, type)
    return _TYPE_DICT.__get__(kind, type)[name]


def _same(actual: tuple[object, ...], expected: tuple[object, ...]) -> bool:
    return len(actual) == len(expected) and all(
        left is right for left, right in zip(actual, expected, strict=True)
    )


# tag, original object, original type, raw accessors, original values. One record
# is charged as one container and every retained accessor/value/owner as a binding.
_Binding = tuple[str, Any, type[Any], tuple[Any, ...], tuple[object, ...]]


@dataclass(frozen=True, slots=True)
class _MappingCacheSeal:
    """CPython 3.12.13 native cache witness, never a new classification call.

    The source must first complete the original fingerprint under one unchanged
    ABC token. Its outer exact tuple proves the native negative-cache version was
    current. Cache clearing, registration or missing membership fails closed.
    """

    state: object
    caches: tuple[set[Any], set[Any] | None, set[Any]]
    positive: tuple[type[Any], ...]
    negative: tuple[type[Any], ...]
    token: int
    max_members: int

    def require(self) -> None:
        if (
            vars(Mapping).get("_abc_impl") is not self.state
            or type(self.state) is not _ABC_STATE_TYPE
            or _GET_ABC_TOKEN() != self.token
        ):
            raise _AttemptDataChanged("FACTORY_ATTEMPT_MAPPING_CHANGED")
        parts = _GET_REFERENTS(self.state)
        if (
            len(parts) not in (3, 4)
            or parts[0] is not _ABC_STATE_TYPE
            or any(type(cache) is not set for cache in parts[1:])
            or parts[1] is not self.caches[0]
            or parts[-1] is not self.caches[2]
            or (self.caches[1] is not None and (len(parts) != 4 or parts[2] is not self.caches[1]))
            or sum(len(cache) for cache in parts[1:]) > self.max_members
        ):
            raise _AttemptDataChanged("FACTORY_ATTEMPT_MAPPING_CHANGED")
        # CPython may lazily create the positive set after issuance. The original
        # native state/registry/negative identities remain fixed; no new token or
        # arbitrary private cache manipulation is admitted by this runtime profile.
        positive = None if len(parts) == 3 else parts[2]
        for cache in parts[1:]:
            if any(type(reference) is not ReferenceType for reference in cache):
                raise _AttemptDataChanged("FACTORY_ATTEMPT_MAPPING_CHANGED")
        for kind in self.positive:
            if not any(
                ReferenceType.__call__(reference) is kind for reference in self.caches[0]
            ) and (
                positive is None
                or not any(ReferenceType.__call__(reference) is kind for reference in positive)
            ):
                raise _AttemptDataChanged("FACTORY_ATTEMPT_MAPPING_CHANGED")
        for kind in self.negative:
            if not any(ReferenceType.__call__(reference) is kind for reference in self.caches[2]):
                raise _AttemptDataChanged("FACTORY_ATTEMPT_MAPPING_CHANGED")


@dataclass(frozen=True, slots=True)
class _AttemptDataSeal:
    records: tuple[_Binding, ...]
    runtime: tuple[object, ...]
    mapping: _MappingCacheSeal
    containers: int
    bindings: int

    def require(self) -> None:
        if not _supported_runtime() or _runtime() != self.runtime:
            raise _AttemptDataChanged("FACTORY_ATTEMPT_DATA_RUNTIME_CHANGED")
        self.mapping.require()
        for tag, value, kind, accessors, before in self.records:
            if type(value) is not kind:
                raise _AttemptDataChanged("FACTORY_ATTEMPT_DATA_TYPE_CHANGED")
            if tag == "class":
                actual = tuple(_class_metadata(value, name) for name in accessors)
            elif tag == "lookup":
                actual = tuple(part for name in accessors for part in _class_attribute(value, name))
            elif tag == "slots":
                # Invoke the original C member descriptor directly. A replaced
                # property is detected separately and is never called here.
                actual = tuple(descriptor.__get__(value, kind) for descriptor in accessors)
            elif tag == "attrs":
                descriptor, *names = accessors
                dictionary = descriptor.__get__(value, kind)
                if type(dictionary) is not dict:
                    raise _AttemptDataChanged("FACTORY_ATTEMPT_DATA_DICTIONARY_CHANGED")
                actual = tuple(dict.__getitem__(dictionary, name) for name in names)
            elif tag == "module":
                namespace = ModuleType.__getattribute__(value, "__dict__")
                actual = tuple(dict.__getitem__(namespace, name) for name in accessors)
            elif tag == "tuple":
                actual = value
            elif tag == "dict":
                if len(value) * 2 != len(before):
                    raise _AttemptDataChanged("FACTORY_ATTEMPT_DATA_BINDING_CHANGED")
                actual = tuple(part for pair in dict.items(value) for part in pair)
            elif tag == "proxy":
                actual = tuple(_GET_REFERENTS(value))
            else:
                raise _AttemptDataChanged("FACTORY_ATTEMPT_DATA_RECORD_CHANGED")
            if not _same(actual, before):
                raise _AttemptDataChanged("FACTORY_ATTEMPT_DATA_BINDING_CHANGED")


def _try_seal_attempt_data(
    roots: tuple[object, ...],
    *,
    selectors: tuple[tuple[type[Any], tuple[str, ...]], ...],
    allowed_records: tuple[type[Any], ...],
    selector_objects: tuple[object, ...] = (),
    selector_roles: tuple[tuple[type[Any], tuple[bool, ...]], ...] = (),
    mapping_token: int | None = None,
    max_containers: int,
    max_bindings: int,
) -> _AttemptDataSeal | None:
    """Admit an exact bounded graph; never call an unsupported object's hooks."""
    if (
        type(roots) is not tuple
        or type(max_containers) is not int
        or type(max_bindings) is not int
        or min(max_containers, max_bindings) <= 0
        or len(roots) > max_bindings
        or not _supported_runtime()
    ):
        return None
    runtime = _runtime()
    # The source caller supplies the token captured before its unchanged full
    # fingerprint. Pure helper callers establish that same precondition only;
    # this helper never authenticates a caller or issues source authority.
    if mapping_token is not None and (
        type(mapping_token) is not int or mapping_token != runtime[0]
    ):
        return None
    records: list[_Binding] = []
    containers = 0
    bindings = len(roots) + len(runtime)
    seen: set[tuple[int, bool]] = set()
    active: set[int] = set()
    positive_types: dict[int, type[Any]] = {}
    negative_types: dict[int, type[Any]] = {id(tuple): tuple}
    classes: dict[type[Any], tuple[str, ...]] = {}
    accessors_by_class: dict[tuple[type[Any], tuple[str, ...]], tuple[Any, ...]] = {}
    # Selector definitions are code configuration, never untrusted graph keys.
    if any(type(kind) is not type or type(names) is not tuple for kind, names in selectors):
        return None
    selected = dict(selectors)
    roles = dict(selector_roles)

    def preflight(count: int) -> None:
        if count < 0 or count > max_bindings - bindings or containers >= max_containers:
            raise _NotAdmitted

    def retain(
        tag: str, item: object, accessors: tuple[Any, ...], values: tuple[object, ...]
    ) -> None:
        nonlocal containers, bindings
        charge = 2 + len(accessors) + len(values)
        preflight(charge)
        containers += 1
        bindings += charge
        records.append((tag, item, type(item), accessors, values))

    def known_class(kind: type[Any], *, record: bool) -> tuple[str, ...]:
        if type(kind) is not type or not any(
            kind is original for original in (*_KNOWN_DOMAIN_TYPES, *allowed_records)
        ):
            raise _NotAdmitted
        if kind in classes:
            return classes[kind]
        namespace = _TYPE_DICT.__get__(kind, type)
        definitions = namespace.get("__dataclass_fields__")
        if record and type(definitions) is not dict:
            raise _NotAdmitted
        if (
            _class_attribute(kind, "__getattribute__")[1] is not object.__getattribute__
            or _class_attribute(kind, "__class__")[1] is not _OBJECT_CLASS
        ):
            raise _NotAdmitted
        names = (
            ("__mro__", "__module__", "__qualname__", "__dataclass_fields__")
            if record
            else ("__mro__", "__module__", "__qualname__")
        )
        retain("class", kind, names, tuple(_class_metadata(kind, name) for name in names))
        retain(
            "lookup",
            kind,
            ("__getattribute__", "__class__"),
            (*_class_attribute(kind, "__getattribute__"), *_class_attribute(kind, "__class__")),
        )
        result: list[str] = []
        if record:
            # Reject unslotted/shadowable records rather than guessing which
            # instance or class schema dataclasses.fields would consume.
            if _class_attribute(kind, "__dict__")[1] is not None:
                raise _NotAdmitted
            preflight(2 * len(definitions))
            if any(
                type(name) is not str or type(field) is not Field
                for name, field in dict.items(definitions)
            ):
                raise _NotAdmitted
            inventory = tuple(part for pair in dict.items(definitions) for part in pair)
            retain("dict", definitions, (), inventory)
            for definition in dict.values(definitions):
                name = _FIELD_NAME.__get__(definition, Field)
                field_type = _FIELD_KIND.__get__(definition, Field)
                if type(name) is not str:
                    raise _NotAdmitted
                retain("slots", definition, (_FIELD_NAME, _FIELD_KIND), (name, field_type))
                if field_type is _FIELD:
                    result.append(name)
        module_name = _class_metadata(kind, "__module__")
        export_name = _class_metadata(kind, "__name__")
        if type(module_name) is not str or type(export_name) is not str:
            raise _NotAdmitted
        module = sys.modules.get(module_name)
        if type(module) is not ModuleType or vars(module).get(export_name) is not kind:
            raise _NotAdmitted
        retain("module", module, (export_name,), (kind,))
        classes[kind] = tuple(result)
        return classes[kind]

    def fields_for(
        item: object, names: tuple[str, ...], *, dictionary: bool = False
    ) -> tuple[object, ...]:
        kind = type(item)
        key = (kind, names)
        accessors = accessors_by_class.get(key)
        if accessors is None:
            lookup_names = (*names, "__dict__") if dictionary else names
            lookup = tuple(part for name in lookup_names for part in _class_attribute(kind, name))
            retain("lookup", kind, lookup_names, lookup)
            if dictionary:
                descriptor = _class_attribute(kind, "__dict__")[1]
                if type(descriptor) is not GetSetDescriptorType:
                    raise _NotAdmitted
                # These are the explicit original Table.name / Enum state paths;
                # any custom data descriptor would change normal lookup semantics.
                if any(_class_attribute(kind, name)[1] is not None for name in names):
                    raise _NotAdmitted
                accessors = (descriptor, *names)
            else:
                accessors = tuple(_class_attribute(kind, name)[1] for name in names)
                if any(type(descriptor) is not MemberDescriptorType for descriptor in accessors):
                    raise _NotAdmitted
            accessors_by_class[key] = accessors
        if dictionary:
            descriptor, *keys = accessors
            data = descriptor.__get__(item, kind)
            if type(data) is not dict:
                raise _NotAdmitted
            values = tuple(dict.__getitem__(data, name) for name in keys)
        else:
            values = tuple(descriptor.__get__(item, kind) for descriptor in accessors)
        retain("attrs" if dictionary else "slots", item, accessors, values)
        return values

    try:
        preflight(0)
        pending: list[tuple[Any, bool, bool]] = [
            (root, False, not (type(type(root)) is type and type(root) in selected))
            for root in roots
        ]
        while pending:
            item, leaving, converted = pending.pop()
            identity = id(item)
            if leaving:
                active.remove(identity)
                seen.add((identity, converted))
                continue
            kind = type(item)
            if item is None or any(kind is scalar for scalar in (bool, int, str, bytes, date)):
                if converted and kind is not bytes:
                    negative_types[id(kind)] = kind
                continue
            if kind is datetime:
                if item.tzinfo is not UTC:
                    raise _NotAdmitted
                if converted:
                    negative_types[id(kind)] = kind
                continue
            if kind is Decimal:
                if not item.is_finite():
                    raise _NotAdmitted
                if converted:
                    negative_types[id(kind)] = kind
                continue
            if identity in active:
                raise _NotAdmitted
            if (identity, converted) in seen:
                continue
            children: tuple[object, ...]
            child_roles: tuple[bool, ...] | None = None
            if kind is tuple:
                if converted:
                    negative_types[id(kind)] = kind
                preflight(len(item))
                retain("tuple", item, (), item)
                children = item
            elif kind is dict:
                if converted:
                    positive_types[id(kind)] = kind
                preflight(2 * len(item))
                if any(
                    type(key) is not str and type(key) is not quoted_name for key in dict.keys(item)
                ):
                    raise _NotAdmitted
                children = tuple(part for pair in dict.items(item) for part in pair)
                retain("dict", item, (), children)
                child_roles = tuple(index % 2 == 1 for index in range(len(children)))
            elif kind is MappingProxyType:
                if converted:
                    positive_types[id(kind)] = kind
                referents = _GET_REFERENTS(item)
                if len(referents) != 1 or type(referents[0]) is not dict:
                    raise _NotAdmitted
                children = (referents[0],)
                retain("proxy", item, (), children)
                child_roles = (False,)
            elif kind is quoted_name:
                quote = _QUOTED_QUOTE.__get__(item, quoted_name)
                if not any(quote is allowed for allowed in (None, True, False)):
                    raise _NotAdmitted
                retain("slots", item, (_QUOTED_QUOTE,), (quote,))
                children = ()
            elif type(kind) is EnumType and any(
                kind is original for original in (*_KNOWN_DOMAIN_TYPES, *allowed_records)
            ):
                if (
                    _class_attribute(kind, "__getattribute__")[1] is not _ENUM_GETATTRIBUTE
                    or _class_attribute(kind, "__class__")[1] is not _OBJECT_CLASS
                ):
                    raise _NotAdmitted
                if (
                    _class_attribute(kind, "name")[1] is not _ENUM_NAME
                    or _class_attribute(kind, "value")[1] is not _ENUM_VALUE
                    or _class_attribute(kind, "__dataclass_fields__")[0] is not None
                ):
                    raise _NotAdmitted
                if kind not in classes:
                    classes[kind] = ()
                    names: tuple[str, ...] = ("__mro__", "__module__", "__qualname__")
                    retain(
                        "class",
                        kind,
                        names,
                        tuple(_class_metadata(kind, name) for name in names),
                    )
                    names = (
                        "__getattribute__",
                        "__class__",
                        "name",
                        "value",
                        "__dataclass_fields__",
                    )
                    retain(
                        "lookup",
                        kind,
                        names,
                        tuple(part for name in names for part in _class_attribute(kind, name)),
                    )
                if converted:
                    negative_types[id(kind)] = kind
                values = fields_for(item, ("_name_", "_value_"), dictionary=True)
                if type(values[0]) is not str:
                    raise _NotAdmitted
                children = values
                child_roles = (False, False)
            else:
                if type(kind) is not type:
                    raise _NotAdmitted
                selected_names = None if converted else selected.get(kind)
                dictionary = False
                if selected_names is not None:
                    names = selected_names
                    is_record = "__dataclass_fields__" in _TYPE_DICT.__get__(kind, type)
                    known_class(kind, record=is_record)
                    dictionary = not is_record
                    if dictionary and not any(item is original for original in selector_objects):
                        raise _NotAdmitted
                else:
                    negative_types[id(kind)] = kind
                    names = tuple(
                        name
                        for name in known_class(kind, record=True)
                        if name not in {"_owner", "_validated_values"}
                    )
                children = fields_for(item, names, dictionary=dictionary)
                child_roles = (
                    roles.get(kind, (True,) * len(children))
                    if not converted
                    else (True,) * len(children)
                )
                if len(child_roles) != len(children) or any(
                    type(role) is not bool for role in child_roles
                ):
                    raise _NotAdmitted
            active.add(identity)
            pending.append((item, True, converted))
            pending.extend(
                (child, False, converted if child_roles is None else child_roles[index])
                for index, child in enumerate(children)
            )
        if vars(Mapping).get("_abc_impl") is not _MAPPING_IMPL:
            raise _NotAdmitted
        parts = _GET_REFERENTS(_MAPPING_IMPL)
        if (
            len(parts) not in (3, 4)
            or parts[0] is not _ABC_STATE_TYPE
            or any(type(part) is not set for part in parts[1:])
        ):
            raise _NotAdmitted
        fixed_edges = 6 + len(positive_types) + len(negative_types)
        available_members = min(
            max_containers - containers - 4, (max_bindings - bindings - fixed_edges) // 2
        )
        members = sum(len(part) for part in parts[1:])
        if available_members < 0 or members > available_members:
            raise _NotAdmitted
        mapping = _MappingCacheSeal(
            _MAPPING_IMPL,
            (parts[1], None if len(parts) == 3 else parts[2], parts[-1]),
            tuple(positive_types.values()),
            tuple(negative_types.values()),
            runtime[0],
            available_members,
        )
        mapping.require()
        seal = _AttemptDataSeal(
            tuple(records),
            runtime,
            mapping,
            containers + 4 + members,
            bindings + fixed_edges + 2 * members,
        )
        seal.require()
        return seal
    except (_NotAdmitted, _AttemptDataChanged, AttributeError, KeyError, TypeError):
        return None
