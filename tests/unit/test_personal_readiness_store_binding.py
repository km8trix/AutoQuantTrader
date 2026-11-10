"""Pure application DTO admission; no wire or store authority is implied."""

import builtins
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path

import pytest

from apps.trader.readiness_store_binding import ReadinessStoreBinding
from tests.unit.test_personal_continuous_readiness_owner import lifecycle as lifecycle


def _values():
    return dict(
        incarnation="original-owner-incarnation",
        account_id="synthetic-account",
        account_binding_sha256="a" * 64,
        stream_id="synthetic-stream",
        database_path="/private/tmp/readiness-binding-native-only.sqlite",
        database_device=0,
        database_inode=1,
        configuration_payload_sha256="b" * 64,
    )


def test_binding_is_flat_frozen_slotted_private_metadata_with_no_filesystem_reads(monkeypatch):
    values = _values()

    def forbidden(*args, **kwargs):
        raise AssertionError("pure DTO must not open, resolve or inspect a path")

    with monkeypatch.context() as local:
        local.setattr(builtins, "open", forbidden)
        local.setattr(Path, "open", forbidden)
        local.setattr(Path, "stat", forbidden)
        local.setattr(Path, "resolve", forbidden)
        binding = ReadinessStoreBinding(**values)
        repeated = ReadinessStoreBinding(**values)
    assert binding == repeated and binding is not repeated
    assert tuple(field.name for field in fields(binding)) == tuple(values)
    assert not hasattr(binding, "__dict__")
    assert values["database_path"] not in repr(binding)
    assert {type(getattr(binding, name)) for name in values} == {str, int}
    with pytest.raises(FrozenInstanceError):
        binding.database_inode = 2


@pytest.mark.parametrize("number", [0, 2**80])
def test_binding_keeps_native_nonnegative_stat_values_without_inventing_a_new_cap(number):
    values = _values()
    values.update(database_device=number, database_inode=number)
    binding = ReadinessStoreBinding(**values)
    assert binding.database_device == binding.database_inode == number
    assert type(binding.database_device) is type(binding.database_inode) is int


@pytest.mark.parametrize("name", ["incarnation", "account_id", "stream_id"])
@pytest.mark.parametrize("bad", [None, True, "", "x" * 129])
def test_binding_requires_original_native_bounded_journal_identifiers(name, bad):
    baseline = ReadinessStoreBinding(**_values())
    with pytest.raises(ValueError, match=r"^READINESS_STORE_BINDING_INVALID$"):
        replace(baseline, **{name: bad})


@pytest.mark.parametrize("name", ["account_binding_sha256", "configuration_payload_sha256"])
@pytest.mark.parametrize("bad", [None, "A" * 64, "g" * 64, "0" * 63])
def test_binding_requires_original_native_lowercase_digest_fields(name, bad):
    baseline = ReadinessStoreBinding(**_values())
    with pytest.raises(ValueError, match=r"^READINESS_STORE_BINDING_INVALID$"):
        replace(baseline, **{name: bad})


@pytest.mark.parametrize("name", ["database_device", "database_inode"])
@pytest.mark.parametrize("bad", [True, -1, 0.0, "1", None])
def test_binding_rejects_nonnative_or_negative_physical_identity(name, bad):
    baseline = ReadinessStoreBinding(**_values())
    with pytest.raises(ValueError, match=r"^READINESS_STORE_BINDING_INVALID$"):
        replace(baseline, **{name: bad})


@pytest.mark.parametrize(
    "bad",
    [
        None,
        Path("/private/tmp/not-a-native-string.sqlite"),
        "relative.sqlite",
        "/private/tmp/../not-canonical.sqlite",
        "/private/tmp/./not-canonical.sqlite",
        "/private/tmp/not\x00a-path.sqlite",
    ],
)
def test_binding_requires_native_absolute_lexically_canonical_path(bad):
    baseline = ReadinessStoreBinding(**_values())
    with pytest.raises(ValueError, match=r"^READINESS_STORE_BINDING_INVALID$"):
        replace(baseline, database_path=bad)


class _HostileText(str):
    def strip(self, *args, **kwargs):
        raise AssertionError("text subclass must be rejected before invoking a method")

    def __str__(self):
        raise AssertionError("text subclass must not be coerced")


class _HostileInteger(int):
    def __lt__(self, other):
        raise AssertionError("integer subclass must be rejected before comparison")

    def __ge__(self, other):
        raise AssertionError("integer subclass must be rejected before comparison")


@pytest.mark.parametrize(
    ("name", "bad"),
    [
        ("account_id", _HostileText("synthetic-account")),
        ("database_path", _HostileText("/private/tmp/native-required.sqlite")),
        ("account_binding_sha256", _HostileText("a" * 64)),
        ("database_inode", _HostileInteger(1)),
    ],
)
def test_binding_rejects_native_subclasses_without_coercion_or_hostile_operations(name, bad):
    baseline = ReadinessStoreBinding(**_values())
    with pytest.raises(ValueError, match=r"^READINESS_STORE_BINDING_INVALID$"):
        replace(baseline, **{name: bad})


def test_original_unconfigured_lifecycle_owner_never_invents_a_store_binding(lifecycle):
    owner = lifecycle.create()
    assert owner.store_binding() is None and lifecycle.calls == []
    assert owner.start().phase == "idle"
    assert owner.store_binding() is None
    assert owner.check("original-unconfigured").status == "ready"
    assert owner.store_binding() is None
    stopped = owner.stop()
    assert stopped.phase == "stopped" and stopped.cleanup_complete is True
    assert owner.store_binding() is None
    assert [name for name, _ in lifecycle.calls] == ["open", "proof", "cleanup"]
    assert lifecycle.proof_count == 1
    # The imported original FakeRuntime qualifies transport compatibility only.
