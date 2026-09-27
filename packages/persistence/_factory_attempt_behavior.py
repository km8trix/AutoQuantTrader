"""Finite original behavior bindings for the private factory fingerprint pilot.

This is a checked implementation inventory, not source or factory authority.
Callers supply reviewed functions/classes at their module's completion. Only
those functions' nested code constants are inspected; no module or call graph is
discovered. The ordinary interpreter and this private verifier/baseline remain
trusted, as do imports before the reviewed modules finish initialization.
"""

from __future__ import annotations

import abc
import contextlib
import dataclasses
import dis
import enum
import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from types import CodeType, DynamicClassAttribute, FunctionType, ModuleType
from typing import Any, cast

from sqlalchemy.sql.elements import quoted_name

from packages.domain import canonical
from packages.persistence import detached_journal_capture


class _AttemptBehaviorUnsupported(ValueError):
    """The explicit implementation inventory has an unsupported shape."""


class _AttemptBehaviorChanged(ValueError):
    """An original implementation binding has changed."""


_TYPE = type
_LEN = len
_ENUMERATE = enumerate
_ALL = all
_TUPLE: Any = tuple
_DICT = dict
_STR = str
_GET = dict.get
_ITEMS = dict.items
_OBJECT_ATTRIBUTE = object.__getattribute__
_OBJECT_TYPE = object
_TYPE_NAMESPACE = vars(type)["__dict__"]
_TYPE_MRO = vars(type)["__mro__"]
_MODULE_ATTRIBUTE = ModuleType.__getattribute__
_MISSING = object()
_MODULES = sys.modules
_INSTRUCTIONS = dis.get_instructions
_KNOWN_METATYPES = (type, enum.EnumType, abc.ABCMeta)


def _same(left: tuple[object, ...], right: tuple[object, ...]) -> bool:
    if _LEN(left) != _LEN(right):
        return False
    return _ALL(item is right[index] for index, item in _ENUMERATE(left))


def _flat(value: object, functions: tuple[FunctionType, ...]) -> bool:
    kind = _TYPE(value)
    if value is None or kind is bool or kind is int or kind is str or kind is bytes:
        return True
    if value is _OBJECT_TYPE:
        # The generated frozen dataclass constructor closes over this original
        # immutable builtin to perform its original object.__setattr__ calls.
        return True
    if kind is tuple:
        return all(
            item is None or any(_TYPE(item) is scalar for scalar in (bool, int, str, bytes))
            for item in cast(tuple[object, ...], value)
        )
    return kind is FunctionType and any(value is original for original in functions)


def _global_names(code: CodeType) -> tuple[str, ...]:
    """Read only a supplied function's finite, immutable code-constant tree."""
    names: set[str] = set()
    pending = [code]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        for instruction in _INSTRUCTIONS(current):
            if instruction.opname in ("LOAD_GLOBAL", "LOAD_NAME"):
                if _TYPE(instruction.argval) is not str:
                    raise _AttemptBehaviorUnsupported("FACTORY_BEHAVIOR_NAME_UNSUPPORTED")
                names.add(instruction.argval)
        pending.extend(item for item in current.co_consts if _TYPE(item) is CodeType)
    return tuple(sorted(names))


@dataclass(frozen=True, slots=True)
class _NamespaceKeys:
    namespace: dict[str, Any]
    size: int

    def require(self) -> None:
        # A foreign dictionary key could run equality during a normal lookup.
        # Reject it first, under the original finite module-size bound.
        if _TYPE(self.namespace) is not _DICT or _LEN(self.namespace) != self.size:
            raise _AttemptBehaviorChanged("FACTORY_BEHAVIOR_NAMESPACE_SHAPE_CHANGED")
        for key in self.namespace:
            if _TYPE(key) is not _STR:
                raise _AttemptBehaviorChanged("FACTORY_BEHAVIOR_NAMESPACE_KEY_CHANGED")


@dataclass(frozen=True, slots=True)
class _FunctionBinding:
    function: FunctionType
    metadata: tuple[object, ...]
    defaults: tuple[object, ...]
    keyword_defaults: tuple[object, ...]
    cells: tuple[object, ...]
    names: tuple[tuple[str, object, object], ...]

    def require(self) -> None:
        function = self.function
        actual = (
            function.__code__,
            function.__defaults__,
            function.__kwdefaults__,
            function.__closure__,
            function.__globals__,
            _OBJECT_ATTRIBUTE(function, "__builtins__"),
            function.__dict__,
            _GET(function.__dict__, "__wrapped__", _MISSING),
        )
        if not _same(actual, self.metadata):
            raise _AttemptBehaviorChanged("FACTORY_BEHAVIOR_FUNCTION_CHANGED")
        defaults = function.__defaults__
        if defaults is not None and not _same(defaults, self.defaults):
            raise _AttemptBehaviorChanged("FACTORY_BEHAVIOR_DEFAULTS_CHANGED")
        keywords = function.__kwdefaults__
        if keywords is not None:
            if _TYPE(keywords) is not _DICT or 2 * _LEN(keywords) != _LEN(self.keyword_defaults):
                raise _AttemptBehaviorChanged("FACTORY_BEHAVIOR_KEYWORD_DEFAULTS_CHANGED")
            actual_keywords = _TUPLE(part for pair in _ITEMS(keywords) for part in pair)
            if not _same(actual_keywords, self.keyword_defaults):
                raise _AttemptBehaviorChanged("FACTORY_BEHAVIOR_KEYWORD_DEFAULTS_CHANGED")
        closure = function.__closure__
        if closure is not None:
            try:
                actual_cells = _TUPLE(cell.cell_contents for cell in closure)
            except ValueError:
                raise _AttemptBehaviorChanged("FACTORY_BEHAVIOR_CLOSURE_CHANGED") from None
            if not _same(actual_cells, self.cells):
                raise _AttemptBehaviorChanged("FACTORY_BEHAVIOR_CLOSURE_CHANGED")
        namespace, builtins = function.__globals__, _OBJECT_ATTRIBUTE(function, "__builtins__")
        for name, original_global, original_builtin in self.names:
            if (
                _GET(namespace, name, _MISSING) is not original_global
                or _GET(builtins, name, _MISSING) is not original_builtin
            ):
                raise _AttemptBehaviorChanged("FACTORY_BEHAVIOR_NAME_BINDING_CHANGED")


@dataclass(frozen=True, slots=True)
class _ClassBinding:
    kind: type[Any]
    metatype: type[Any]
    original_mro: tuple[type[Any], ...]
    namespace: tuple[object, ...]

    def require(self) -> None:
        if (
            _TYPE(self.kind) is not self.metatype
            or _TYPE_MRO.__get__(self.kind, _TYPE) is not self.original_mro
        ):
            raise _AttemptBehaviorChanged("FACTORY_BEHAVIOR_CLASS_CHANGED")
        namespace = _TYPE_NAMESPACE.__get__(self.kind, _TYPE)
        if 2 * _LEN(namespace) != _LEN(self.namespace):
            raise _AttemptBehaviorChanged("FACTORY_BEHAVIOR_CLASS_NAMESPACE_CHANGED")
        actual = _TUPLE(part for pair in namespace.items() for part in pair)
        if not _same(actual, self.namespace):
            raise _AttemptBehaviorChanged("FACTORY_BEHAVIOR_CLASS_NAMESPACE_CHANGED")


@dataclass(frozen=True, slots=True)
class _NamespaceBinding:
    owner: ModuleType
    name: str
    namespace: dict[str, Any]
    values: tuple[tuple[str, object], ...]

    def require(self) -> None:
        # The fingerprint uses these retained module globals, not a fresh import
        # registry lookup. Avoid unrelated mutable sys.modules key callbacks.
        if (
            _TYPE(self.owner) is not ModuleType
            or _MODULE_ATTRIBUTE(self.owner, "__dict__") is not self.namespace
        ):
            raise _AttemptBehaviorChanged("FACTORY_BEHAVIOR_MODULE_CHANGED")
        for name, original in self.values:
            if _GET(self.namespace, name, _MISSING) is not original:
                raise _AttemptBehaviorChanged("FACTORY_BEHAVIOR_MODULE_BINDING_CHANGED")


@dataclass(frozen=True, slots=True)
class _DescriptorBinding:
    descriptor: object
    kind: type[Any]
    namespace: dict[str, Any]
    values: tuple[object, ...]

    def require(self) -> None:
        if _TYPE(self.descriptor) is not self.kind:
            raise _AttemptBehaviorChanged("FACTORY_BEHAVIOR_DESCRIPTOR_CHANGED")
        actual = _OBJECT_ATTRIBUTE(self.descriptor, "__dict__")
        if actual is not self.namespace or 2 * _LEN(actual) != _LEN(self.values):
            raise _AttemptBehaviorChanged("FACTORY_BEHAVIOR_DESCRIPTOR_CHANGED")
        if not _same(_TUPLE(part for pair in _ITEMS(actual) for part in pair), self.values):
            raise _AttemptBehaviorChanged("FACTORY_BEHAVIOR_DESCRIPTOR_CHANGED")


@dataclass(frozen=True, slots=True)
class _AttemptBehaviorSeal:
    records: tuple[Any, ...]
    containers: int
    bindings: int

    def require(self) -> None:
        for record in self.records:
            record.require()


def _capture_records(
    *,
    functions: tuple[FunctionType, ...],
    modules: tuple[ModuleType, ...],
    classes: tuple[type[Any], ...],
    descriptors: tuple[object, ...] = (),
) -> _AttemptBehaviorSeal:
    if any(_TYPE(value) is not tuple for value in (functions, modules, classes)):
        raise _AttemptBehaviorUnsupported("FACTORY_BEHAVIOR_INVENTORY_UNSUPPORTED")
    records: list[Any] = []
    bindings = 0
    checked_namespaces: set[int] = set()
    for function in functions:
        if _TYPE(function) is not FunctionType:
            raise _AttemptBehaviorUnsupported("FACTORY_BEHAVIOR_FUNCTION_UNSUPPORTED")
        defaults = function.__defaults__
        keywords = function.__kwdefaults__
        closure = function.__closure__
        if defaults is not None and (
            _TYPE(defaults) is not tuple or not all(_flat(value, functions) for value in defaults)
        ):
            raise _AttemptBehaviorUnsupported("FACTORY_BEHAVIOR_DEFAULTS_UNSUPPORTED")
        if keywords is not None and (
            _TYPE(keywords) is not dict
            or any(
                _TYPE(key) is not str or not _flat(value, functions)
                for key, value in _ITEMS(keywords)
            )
        ):
            raise _AttemptBehaviorUnsupported("FACTORY_BEHAVIOR_KEYWORD_DEFAULTS_UNSUPPORTED")
        try:
            cells = () if closure is None else tuple(cell.cell_contents for cell in closure)
        except ValueError:
            raise _AttemptBehaviorUnsupported("FACTORY_BEHAVIOR_CLOSURE_UNSUPPORTED") from None
        if not all(_flat(value, functions) for value in cells):
            raise _AttemptBehaviorUnsupported("FACTORY_BEHAVIOR_CLOSURE_UNSUPPORTED")
        namespace, builtins = function.__globals__, _OBJECT_ATTRIBUTE(function, "__builtins__")
        if _TYPE(namespace) is not dict or _TYPE(builtins) is not dict:
            raise _AttemptBehaviorUnsupported("FACTORY_BEHAVIOR_NAMESPACE_UNSUPPORTED")
        for mapping in (namespace, builtins, function.__dict__):
            if id(mapping) not in checked_namespaces:
                if any(_TYPE(key) is not str for key in mapping):
                    raise _AttemptBehaviorUnsupported("FACTORY_BEHAVIOR_NAMESPACE_KEY_UNSUPPORTED")
                checked_namespaces.add(id(mapping))
                records.append(_NamespaceKeys(mapping, _LEN(mapping)))
                bindings += 3
        names = tuple(
            (name, _GET(namespace, name, _MISSING), _GET(builtins, name, _MISSING))
            for name in _global_names(function.__code__)
        )
        metadata = (
            function.__code__,
            defaults,
            keywords,
            closure,
            namespace,
            builtins,
            function.__dict__,
            _GET(function.__dict__, "__wrapped__", _MISSING),
        )
        keyword_values = (
            () if keywords is None else tuple(part for pair in _ITEMS(keywords) for part in pair)
        )
        records.append(
            _FunctionBinding(function, metadata, defaults or (), keyword_values, cells, names)
        )
        bindings += (
            8
            + _LEN(metadata)
            + _LEN(defaults or ())
            + _LEN(keyword_values)
            + _LEN(cells)
            + 4 * _LEN(names)
        )
    for kind in classes:
        if not any(_TYPE(kind) is original for original in _KNOWN_METATYPES):
            raise _AttemptBehaviorUnsupported("FACTORY_BEHAVIOR_CLASS_UNSUPPORTED")
        namespace = _TYPE_NAMESPACE.__get__(kind, _TYPE)
        values = tuple(part for pair in namespace.items() for part in pair)
        mro = _TYPE_MRO.__get__(kind, _TYPE)
        records.append(_ClassBinding(kind, _TYPE(kind), mro, values))
        bindings += 8 + _LEN(mro) + _LEN(values)
    for module in modules:
        if _TYPE(module) is not ModuleType:
            raise _AttemptBehaviorUnsupported("FACTORY_BEHAVIOR_MODULE_UNSUPPORTED")
        namespace = _MODULE_ATTRIBUTE(module, "__dict__")
        name = _GET(namespace, "__name__")
        if _TYPE(name) is not str or _GET(_MODULES, name) is not module:
            raise _AttemptBehaviorUnsupported("FACTORY_BEHAVIOR_MODULE_UNREGISTERED")
        # Snapshot only the direct namespace of this explicitly listed module.
        # Native attributes are covered too; mutable registry contents are not
        # traversed or frozen. There is no recursive module/callgraph discovery.
        if id(namespace) not in checked_namespaces:
            if any(_TYPE(key) is not str for key in namespace):
                raise _AttemptBehaviorUnsupported("FACTORY_BEHAVIOR_NAMESPACE_KEY_UNSUPPORTED")
            checked_namespaces.add(id(namespace))
            records.append(_NamespaceKeys(namespace, _LEN(namespace)))
            bindings += 3
        values = tuple(_ITEMS(namespace))
        records.append(_NamespaceBinding(module, name, namespace, values))
        bindings += 8 + 3 * _LEN(values)
    for descriptor in descriptors:
        namespace = _OBJECT_ATTRIBUTE(descriptor, "__dict__")
        if _TYPE(namespace) is not dict:
            raise _AttemptBehaviorUnsupported("FACTORY_BEHAVIOR_DESCRIPTOR_UNSUPPORTED")
        values = tuple(part for pair in _ITEMS(namespace) for part in pair)
        records.append(_DescriptorBinding(descriptor, _TYPE(descriptor), namespace, values))
        bindings += 8 + _LEN(values)
    # Count each retained record/container, nested metadata/name tuples and
    # every owner/name/value edge. The caller also charges its lifecycle state.
    containers = 2 + _LEN(records)
    for record in records:
        if _TYPE(record) is _FunctionBinding:
            containers += 5 + _LEN(record.names)
        elif _TYPE(record) is _NamespaceBinding:
            containers += 1 + _LEN(record.values)
        elif _TYPE(record) is not _NamespaceKeys:
            containers += 1
    result = _AttemptBehaviorSeal(tuple(records), containers, bindings)
    result.require()
    return result


def _build_static_behavior() -> tuple[_AttemptBehaviorSeal, object]:
    if sys.implementation.name != "cpython" or sys.version_info[:3] != (3, 12, 13):
        raise _AttemptBehaviorUnsupported("FACTORY_BEHAVIOR_RUNTIME_UNSUPPORTED")
    for module, names in (
        (contextlib, ("_GeneratorContextManager", "_GeneratorContextManagerBase")),
        (json.encoder, ("c_make_encoder", "encode_basestring_ascii")),
    ):
        namespace = _MODULE_ATTRIBUTE(module, "__dict__")
        if any(name not in namespace for name in names):
            raise _AttemptBehaviorUnsupported("FACTORY_BEHAVIOR_NATIVE_PROFILE_UNSUPPORTED")
    if _GET(vars(json.encoder), "c_make_encoder") is None:
        raise _AttemptBehaviorUnsupported("FACTORY_BEHAVIOR_NATIVE_ENCODER_REQUIRED")
    _ENUM_NAME = vars(enum.Enum)["name"]
    _ENUM_VALUE = vars(enum.Enum)["value"]
    _STATIC_FUNCTIONS = cast(
        tuple[FunctionType, ...],
        (
            canonical.canonical_json_bytes,
            canonical.canonical_json_text,
            canonical._append_typed_text,
            canonical._typed_fragment_text,
            canonical._typed_node,
            canonical._json_text,
            canonical.canonical_decimal_text,
            canonical.canonical_decimal,
            detached_journal_capture.detached_journal_value,
            cast,
            dataclasses.fields,
            dataclasses.is_dataclass,
            json.dumps,
            json.JSONEncoder.__init__,
            json.JSONEncoder.encode,
            json.JSONEncoder.iterencode,
            json.JSONEncoder.default,
            enum.property.__get__,
            _ENUM_NAME.fget,
            _ENUM_VALUE.fget,
            abc.ABCMeta.__instancecheck__,
            abc.ABCMeta.__subclasscheck__,
            contextlib._GeneratorContextManagerBase.__init__,
            contextlib._GeneratorContextManager.__enter__,
            contextlib._GeneratorContextManager.__exit__,
        ),
    )
    _STATIC_CLASSES = (
        json.JSONEncoder,
        dataclasses.Field,
        enum.Enum,
        enum.EnumType,
        enum.property,
        DynamicClassAttribute,
        abc.ABCMeta,
        Mapping,
        quoted_name,
        *_TYPE_MRO.__get__(quoted_name, _TYPE)[2:-1],
        contextlib._GeneratorContextManager,
        contextlib._GeneratorContextManagerBase,
    )
    behavior = _capture_records(
        functions=_STATIC_FUNCTIONS,
        modules=(
            canonical,
            detached_journal_capture,
            dataclasses,
            json,
            json.encoder,
            enum,
            abc,
            contextlib,
        ),
        classes=_STATIC_CLASSES,
        descriptors=(_ENUM_NAME, _ENUM_VALUE),
    )
    return behavior, _GET(vars(json.encoder), "c_make_encoder")


_STATIC_BEHAVIOR: _AttemptBehaviorSeal | None
try:
    _STATIC_BEHAVIOR, _NATIVE_ENCODER = _build_static_behavior()
except _AttemptBehaviorUnsupported:
    # Unsupported profiles disable only this optimization. Ordinary source and
    # factory APIs retain their existing validation and import behavior.
    _STATIC_BEHAVIOR, _NATIVE_ENCODER = None, None


def _capture_attempt_behavior(
    *,
    functions: tuple[FunctionType, ...],
    modules: tuple[ModuleType, ...],
    classes: tuple[type[Any], ...] = (),
) -> _AttemptBehaviorSeal:
    """Capture an explicit original module inventory, never caller authority."""
    if _STATIC_BEHAVIOR is None:
        raise _AttemptBehaviorUnsupported("FACTORY_BEHAVIOR_RUNTIME_UNSUPPORTED")
    _STATIC_BEHAVIOR.require()
    if _NATIVE_ENCODER is None:
        raise _AttemptBehaviorUnsupported("FACTORY_BEHAVIOR_NATIVE_ENCODER_REQUIRED")
    additional = _capture_records(functions=functions, modules=modules, classes=classes)
    return _AttemptBehaviorSeal(
        (*_STATIC_BEHAVIOR.records, *additional.records),
        _STATIC_BEHAVIOR.containers + additional.containers + 1,
        _STATIC_BEHAVIOR.bindings + additional.bindings + 2,
    )
