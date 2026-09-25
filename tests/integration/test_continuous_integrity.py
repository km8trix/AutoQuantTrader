"""Actual offline C/B/A and signed-owner integrity; no connected trading authority."""

from dataclasses import replace
from datetime import timedelta

import pytest
import sqlalchemy as sa

from packages.persistence.continuous_integrity import (
    ContinuousIntegrityError,
    SqlContinuousIntegrityReader,
)
from packages.persistence.daily_runtime_risk_schema import daily_runtime_assignments
from packages.persistence.durable_journal_schema import journal_entries
from packages.persistence.runtime_owner_associations import SqlRuntimeOwnerAssociations
from tests.integration.test_runtime_owner_associations import (
    genuine_empty_b_bootstrap,
    install_initial_signed_assignment,
)
from tests.integration.test_runtime_owner_dependencies import converge


@pytest.fixture
def case(tmp_path, monkeypatch):
    value = genuine_empty_b_bootstrap(tmp_path, monkeypatch)
    install_initial_signed_assignment(value)
    try:
        yield value
    finally:
        value[0].close()


def reader_for(case, *, journals=None):
    pair, owner, producer, *_ = case
    return SqlContinuousIntegrityReader(
        pair.base.engine,
        scope=pair.base.scope,
        reconciliation_scope=pair.scope,
        account=pair.account,
        daily=pair.base.h.store,
        publisher=pair.publisher,
        associations=SqlRuntimeOwnerAssociations(owner_dependencies=owner),
        journals=journals
        if journals is not None
        else (
            pair.account.journal,
            pair.publisher.journal,
            pair.sources.journal,
            pair.base.forward.journal,
            producer.journal,
            producer.operating.journal,
            owner.commands.journal,
        ),
        fence=pair.base.h.lease.fence,
    )


def test_real_genesis_and_signed_initial_assignment_validate_without_new_authority(case):
    reader = reader_for(case)
    snapshot = reader._capture()
    before = case[0].counts()
    assert reader.validate_snapshot(snapshot) is None
    assert case[0].counts() == before
    assert not hasattr(reader, "permit") and not hasattr(reader, "readiness")
    # Repeat validation uses exact retained evidence and changes no original times.
    assert reader.validate_snapshot(snapshot) is None


def test_all_original_applied_pairs_and_current_heads_are_validated(case):
    converge(case)
    reader = reader_for(case)
    snapshot = reader._capture()
    assert len(snapshot.tables["personal_reconciliation_commits"]) == 2
    assert reader.validate_snapshot(snapshot) is None


@pytest.mark.parametrize("change", ["missing_dependency", "stale_rows", "assignment_payload"])
def test_snapshot_input_cannot_replace_actual_retained_rows(case, change):
    pair = case[0]
    reader = reader_for(case)
    snapshot = reader._capture()
    if change == "missing_dependency":
        snapshot = replace(snapshot, dependencies={})
    elif change == "stale_rows":
        with pair.base.engine.begin() as connection:
            connection.execute(sa.update(daily_runtime_assignments).values(command_sha256="9" * 64))
    else:
        with pair.base.engine.begin() as connection:
            connection.execute(sa.update(daily_runtime_assignments).values(command_payload=b"{}"))
        snapshot = reader._capture()
    with pytest.raises((ContinuousIntegrityError, ValueError)):
        reader.validate_snapshot(snapshot)


def test_every_journal_requires_actual_configured_typed_reader(case):
    reader = reader_for(case, journals=(case[0].account.journal,))
    with pytest.raises(ContinuousIntegrityError, match="TYPED_JOURNAL_READER"):
        reader.validate_snapshot(reader._capture())


def test_original_owner_record_corruption_is_rejected_by_actual_journal_replay(case):
    reader = reader_for(case)
    with case[0].base.engine.begin() as connection:
        connection.execute(
            sa.update(journal_entries)
            .where(journal_entries.c.schema_id == next(iter(case[1].commands.journal._types)))
            .values(payload=b"{}")
        )
    with pytest.raises(ValueError):
        reader.validate_snapshot(reader._capture())


def test_expired_current_fence_cannot_be_replaced_by_historical_receipts(case):
    reader = reader_for(case)
    snapshot = reader._capture()
    case[0].base.h.clock.instant += timedelta(days=1)
    with pytest.raises(ValueError):
        reader.validate_snapshot(snapshot)


def test_reconfigured_store_graph_is_rejected(case):
    reader = reader_for(case)
    snapshot = reader._capture()
    reader.journals = tuple(reversed(reader.journals))
    with pytest.raises(ContinuousIntegrityError, match="CONFIGURATION_CHANGED"):
        reader.validate_snapshot(snapshot)


def test_final_coherent_readback_rejects_valid_control_change_during_detached_validation(
    case, monkeypatch
):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from packages.domain.operational_control import (
        OperationalControlCommandKind,
        OperationalControlState,
    )

    reader = reader_for(case)
    snapshot = reader._capture()
    entered, release = Event(), Event()
    original = reader.associations.require_association

    def paused(value):
        original(value)
        entered.set()
        assert release.wait(15)

    monkeypatch.setattr(reader.associations, "require_association", paused)
    h = case[0].base.h
    with ThreadPoolExecutor(max_workers=2) as pool:
        reading = pool.submit(reader.validate_snapshot, snapshot)
        try:
            assert entered.wait(10)
            changed = pool.submit(
                h.controls.apply,
                h.command(
                    OperationalControlCommandKind.HALT,
                    "integrity-concurrent-halt",
                    OperationalControlState.HALTED,
                ),
            ).result(timeout=5)
            assert changed.sequence_number == 2
            assert not reading.done()
        finally:
            release.set()
        with pytest.raises(ContinuousIntegrityError, match="ORIGINAL_ROWS_CHANGED"):
            reading.result(timeout=10)
    monkeypatch.setattr(reader.associations, "require_association", original)
    reader.validate_snapshot(reader._capture())


def test_all_referenced_objects_share_existing_32_mib_bound(case, monkeypatch):
    import packages.persistence.continuous_integrity as integrity

    reader = reader_for(case)
    snapshot = reader._capture()
    monkeypatch.setattr(integrity, "MAX_CONTINUOUS_OBJECT_BYTES", 1)
    with pytest.raises(ContinuousIntegrityError, match="OBJECT_CLOSURE_BOUND"):
        reader.validate_snapshot(snapshot)


def test_expired_original_assignment_remains_historical_under_real_new_fence(case):
    pair = case[0]
    h = pair.base.h
    with h.engine.connect() as connection:
        original = tuple(
            dict(row) for row in connection.execute(sa.select(daily_runtime_assignments)).mappings()
        )
    h.coordinator.release(h.lease.fence)
    h.clock.instant += timedelta(days=1)
    h.lease = h.coordinator.acquire("integrity-restarted-owner")
    pair.composer.fence = h.lease.fence
    reader = reader_for(case)
    reader.validate_snapshot(reader._capture())
    with h.engine.connect() as connection:
        after = tuple(
            dict(row) for row in connection.execute(sa.select(daily_runtime_assignments)).mappings()
        )
    assert after == original


def test_retained_object_failure_is_static_and_never_echoes_payload(case, monkeypatch):
    reader = reader_for(case)
    snapshot = reader._capture()

    def missing(*_args, **_kwargs):
        raise FileNotFoundError("PRIVATE_FIXTURE_OBJECT_SENTINEL")

    monkeypatch.setattr(case[0].account.artifacts, "read", missing)
    with pytest.raises(ContinuousIntegrityError) as error:
        reader.validate_snapshot(snapshot)
    assert "PRIVATE_FIXTURE" not in str(error.value)


def test_original_reference_count_preserves_existing_source_metadata_bound(case, monkeypatch):
    import packages.persistence.continuous_integrity as integrity

    reader = reader_for(case)
    monkeypatch.setattr(integrity, "MAX_ROWS", 1)
    with pytest.raises(ContinuousIntegrityError, match="OBJECT_CLOSURE_BOUND"):
        reader.validate_snapshot(reader._capture())


def test_advancing_clock_preserves_all_rows_except_exact_owned_committed_observations(
    case, monkeypatch
):
    from packages.persistence.schema import phase2_account_lease_heads

    pair = case[0]
    clock = pair.base.h.clock

    def advancing(_self):
        clock.instant += timedelta(microseconds=1)
        return clock.instant

    monkeypatch.setattr(type(clock), "now", advancing)
    reader = reader_for(case)
    snapshot = reader._capture()
    assert reader.validate_snapshot(snapshot) is None
    after = reader._capture()
    assert after.tables == snapshot.tables
    for table, rows in snapshot.dependencies.items():
        if table == phase2_account_lease_heads.name:
            assert len(rows) == len(after.dependencies[table]) == 1
            first, last = rows[0], after.dependencies[table][0]
            assert last["updated_at"] > first["updated_at"]
            assert {k: v for k, v in first.items() if k != "updated_at"} == {
                k: v for k, v in last.items() if k != "updated_at"
            }
        else:
            assert after.dependencies[table] == rows
    assert pair.base.h.coordinator._state.observations is None
    assert reader.validate_snapshot(after) is None


def test_unowned_observation_timestamp_after_detached_validation_is_rejected(case, monkeypatch):
    from packages.persistence.schema import phase2_account_lease_heads

    reader = reader_for(case)
    snapshot = reader._capture()
    original = reader._recheck_final

    def changed(captured, observations):
        with reader.engine.begin() as connection:
            connection.execute(
                sa.update(phase2_account_lease_heads).values(
                    updated_at=case[0].base.h.clock.instant + timedelta(microseconds=1)
                )
            )
        original(captured, observations)

    monkeypatch.setattr(reader, "_recheck_final", changed)
    with pytest.raises(ContinuousIntegrityError):
        reader.validate_snapshot(snapshot)
    assert case[0].base.h.coordinator._state.observations is None
