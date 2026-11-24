"""Independent generator-boundary and failure-lifetime compatibility checks."""

from dataclasses import dataclass, fields, is_dataclass

import pytest

from packages.domain import personal_contracts as contracts


def _original(value):
    if is_dataclass(value) and not isinstance(value, type):
        return (
            type(value).__module__ + "." + type(value).__qualname__,
            tuple((field.name, _original(getattr(value, field.name))) for field in fields(value)),
        )
    if type(value) is tuple:
        return tuple(_original(item) for item in value)
    return value


class _Stop(StopIteration):
    pass


def _exception_summary(error):
    cause = error.__cause__
    return (
        type(error),
        str(error),
        error.args,
        error.__suppress_context__,
        None if cause is None else _exception_summary(cause),
        error.__context__ is cause,
    )


def _failure(convert, factory):
    events = []
    value = factory(events)
    try:
        convert(value)
    except Exception as error:
        # Observe releases while the complete original traceback remains alive.
        return _exception_summary(error), tuple(events)
    raise AssertionError("fixture did not raise")


def _wrap(value, shape):
    if shape == "tuple":
        return (value,)
    if shape == "nested_tuple":
        return ((value,),)
    if shape == "record":

        @dataclass(frozen=True)
        class Outer:
            child: object

        return Outer(value)
    return value


@pytest.mark.parametrize("exception", [StopIteration, _Stop, LookupError, StopAsyncIteration])
@pytest.mark.parametrize("shape", ["root", "tuple", "nested_tuple", "record"])
def test_field_getter_error_keeps_generator_boundary_and_complete_chaining(exception, shape):
    def factory(events):
        @dataclass(frozen=True)
        class Record:
            first: object
            second: object

            def __getattribute__(self, name):
                if name in ("first", "second"):
                    events.append(name)
                if name == "first":
                    raise exception("original getter failure") from ValueError("original cause")
                return object.__getattribute__(self, name)

        return _wrap(Record(None, None), shape)

    expected = _failure(_original, factory)
    actual = _failure(contracts.semantic_value, factory)
    assert actual == expected
    assert actual[0][0] is (RuntimeError if issubclass(exception, StopIteration) else exception)
    assert actual[1] == ("first",)


@pytest.mark.parametrize("fault", ["class_fields", "__module__", "__qualname__", "fields"])
@pytest.mark.parametrize("shape", ["root", "tuple", "record"])
def test_root_reflection_remains_outside_the_child_generator(fault, shape):
    def factory(events):
        active = False

        class Meta(type):
            def __getattribute__(cls, name):
                if active and name in ("__dataclass_fields__", "__module__", "__qualname__"):
                    events.append("class:" + name)
                    if (
                        fault == "class_fields" and name == "__dataclass_fields__"
                    ) or name == fault:
                        raise _Stop("original reflection failure")
                return super().__getattribute__(name)

        @dataclass(frozen=True)
        class Record(metaclass=Meta):
            child: object

            def __getattribute__(self, name):
                if name == "__dataclass_fields__":
                    events.append("instance:fields")
                    if fault == "fields":
                        raise _Stop("original fields failure")
                return object.__getattribute__(self, name)

        value = _wrap(Record(None), shape)
        events.clear()
        active = True
        return value

    expected = _failure(_original, factory)
    actual = _failure(contracts.semantic_value, factory)
    assert actual == expected
    assert actual[0][0] is (_Stop if shape == "root" else RuntimeError)


@pytest.mark.parametrize("read", [1, 2])
@pytest.mark.parametrize("exception", [StopIteration, _Stop, LookupError])
def test_original_field_name_reads_keep_error_boundary_and_order(read, exception):
    def factory(events):
        @dataclass(frozen=True)
        class Record:
            child: object

            def __getattribute__(self, name):
                if name == "child":
                    events.append("get:child")
                return object.__getattribute__(self, name)

        original_field = fields(Record)[0]

        class ReflectedField:
            _field_type = original_field._field_type
            count = 0

            @property
            def name(self):
                self.count += 1
                events.append("name:" + str(self.count))
                if self.count == read:
                    raise exception("original field-name failure")
                return "child"

        Record.__dataclass_fields__ = {"child": ReflectedField()}
        return Record(None)

    expected = _failure(_original, factory)
    actual = _failure(contracts.semantic_value, factory)
    assert actual == expected
    assert actual[1] == tuple("name:" + str(index) for index in range(1, read + 1))


@pytest.mark.parametrize("exception", [StopIteration, _Stop, LookupError])
@pytest.mark.parametrize("shape", ["root", "tuple", "record"])
def test_previous_temporary_result_releases_before_error_handler_with_traceback_alive(
    exception, shape
):
    def factory(events):
        class Temporary:
            def __del__(self):
                events.append("release:temporary")

        @dataclass(frozen=True)
        class Record:
            first: object
            second: object

            def __getattribute__(self, name):
                if name in ("first", "second"):
                    events.append("get:" + name)
                if name == "first":
                    return Temporary()
                if name == "second":
                    raise exception("original later failure")
                return object.__getattribute__(self, name)

        return _wrap(Record(None, None), shape)

    expected = _failure(_original, factory)
    actual = _failure(contracts.semantic_value, factory)
    assert actual == expected
    assert actual[1] == ("get:first", "get:second", "release:temporary")


@pytest.mark.parametrize("exception", [StopIteration, _Stop, LookupError])
def test_failing_temporary_record_remains_owned_by_original_recursive_traceback(exception):
    def factory(events):
        @dataclass(frozen=True)
        class Child:
            child: object

            def __getattribute__(self, name):
                if name == "child":
                    events.append("get:child")
                    raise exception("original recursive failure")
                return object.__getattribute__(self, name)

            def __del__(self):
                events.append("release:child")

        @dataclass(frozen=True)
        class Parent:
            first: object
            second: object

            def __getattribute__(self, name):
                if name in ("first", "second"):
                    events.append("get:" + name)
                if name == "first":
                    return Child(None)
                return object.__getattribute__(self, name)

        return Parent(None, None)

    expected = _failure(_original, factory)
    actual = _failure(contracts.semantic_value, factory)
    assert actual == expected
    assert actual[1] == ("get:first", "get:child")


@pytest.mark.parametrize("exception", [StopIteration, _Stop, LookupError])
def test_transient_field_metadata_remains_owned_by_original_generator_traceback(exception):
    def factory(events):
        @dataclass(frozen=True)
        class Record:
            child: object

            def __getattribute__(self, name):
                if name == "__dataclass_fields__":
                    events.append("get:fields")
                    return {"child": ReflectedField()}
                if name == "child":
                    events.append("get:child")
                    raise exception("original metadata lifetime failure")
                return object.__getattribute__(self, name)

        original_field = fields(Record)[0]

        class ReflectedField:
            _field_type = original_field._field_type

            @property
            def name(self):
                events.append("field:name")
                return "child"

            def __del__(self):
                events.append("release:field")

        return Record(None)

    expected = _failure(_original, factory)
    actual = _failure(contracts.semantic_value, factory)
    assert actual == expected
    assert actual[1] == ("get:fields", "field:name", "field:name", "get:child")
