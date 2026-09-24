"""Real signed HALTED history across the schema/result gap; no provider authority."""

from datetime import UTC, timedelta

import pytest
import sqlalchemy as sa

import packages.persistence.continuous_integrity as integrity_module
from apps.trader.continuous_simulation_factory import (
    ContinuousSimulationFactory,
    ContinuousSimulationFactoryError,
)
from packages.persistence.continuous_account import SqlContinuousAccount
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.daily_runtime_risk_schema import daily_runtime_assignments
from packages.persistence.durable_journal_schema import journal_entries
from packages.persistence.schema import phase2_account_lease_heads, phase2_account_leases
from tests.integration.test_continuous_simulation_factory import (
    configured as configured,
)
from tests.integration.test_continuous_simulation_factory import release
from tests.integration.test_runtime_owner_associations import install_initial_signed_assignment


@pytest.fixture
def transfer_factory(configured):
    fixture, configuration = configured
    _, command, *_ = install_initial_signed_assignment(fixture)
    previous_fence = fixture[0].base.h.lease.fence
    release(fixture)
    factory = ContinuousSimulationFactory(
        configuration,
        account_id=fixture[0].base.scope.account_id,
        stop_requested=lambda: False,
    )
    fence = factory.lease.fence
    assert fence.owner_id != previous_fence.owner_id
    assert fence.fencing_generation == previous_fence.fencing_generation + 1
    try:
        yield factory, command
    finally:
        released = factory.close()
        assert released is not None and released.fence == fence
        assert factory.engine is None and factory.venue_engine is None


def _head(factory):
    with factory.engine.connect() as connection:
        return dict(
            connection.execute(
                sa.select(phase2_account_lease_heads).where(
                    phase2_account_lease_heads.c.account_id == factory.scope.account_id
                )
            )
            .mappings()
            .one()
        )


@pytest.mark.parametrize("row_kind", ["canonical_commit", "signed_assignment", "owner_journal"])
def test_factory_rejects_original_sql_row_changed_after_real_schema_validation(
    transfer_factory, monkeypatch, row_kind
):
    factory, command = transfer_factory
    verifier = integrity_module.verify_operational_schema
    completed = []
    if row_kind == "canonical_commit":
        table, column = continuous_account_commits, "canonical_payload"
        predicate = sa.and_(
            table.c.account_id == factory.scope.account_id,
            table.c.sequence == 1,
        )
    elif row_kind == "signed_assignment":
        table, column = daily_runtime_assignments, "command_payload"
        predicate = sa.and_(
            table.c.account_id == factory.scope.account_id,
            table.c.generation == 1,
            table.c.command_id == command.command_id,
        )
    else:
        table, column = journal_entries, "payload"
        predicate = table.c.record_id == command.command_id

    def verify_then_corrupt(*args, **kwargs):
        result = verifier(*args, **kwargs)
        assert kwargs["continuous_integrity"] is factory.integrity
        with factory.engine.begin() as connection:
            original = connection.execute(sa.select(table).where(predicate)).mappings().one()
            assert original[column] != b"{}"
            changed = connection.execute(sa.update(table).where(predicate).values({column: b"{}"}))
            assert changed.rowcount == 1
        completed.append(row_kind)
        return result

    monkeypatch.setattr(integrity_module, "verify_operational_schema", verify_then_corrupt)
    with pytest.raises(ContinuousSimulationFactoryError, match=r"^OFFLINE_OPERATION_FAILED$"):
        factory.execute(operation_id="reject-original-sql-transfer")
    assert completed == [row_kind], "the actual schema verifier must return before the fault"
    with factory.engine.connect() as connection:
        assert connection.scalar(sa.select(table.c[column]).where(predicate)) == b"{}"
    assert factory.coordinator._state.observations is None


def test_original_coordinator_observation_preserves_exact_transferred_result(
    transfer_factory, monkeypatch
):
    factory, _command = transfer_factory
    verifier = integrity_module.verify_operational_schema
    resolve = SqlContinuousAccount.resolve_snapshot
    resolved = []
    observations = []
    with factory.engine.connect() as connection:
        original_leases = tuple(
            dict(row)
            for row in connection.execute(
                sa.select(phase2_account_leases)
                .where(phase2_account_leases.c.account_id == factory.scope.account_id)
                .order_by(phase2_account_leases.c.fencing_generation)
            ).mappings()
        )

    def observe_resolve(owner, *args, **kwargs):
        value = resolve(owner, *args, **kwargs)
        if owner is factory.account:
            resolved.append(value)
        return value

    def verify_then_observe(*args, **kwargs):
        result = verifier(*args, **kwargs)
        assert kwargs["continuous_integrity"] is factory.integrity
        tracked = factory.coordinator._state.observations
        assert tracked is not None
        original_view, original_count = tracked.view, tracked.count
        before = _head(factory)
        receipt = factory.coordinator.revalidate(factory.lease.fence)
        after = _head(factory)
        assert factory.coordinator._state.observations is tracked
        assert tracked.view is original_view and tracked.count == original_count + 1
        with factory.engine.connect() as connection:
            connection.begin()
            try:
                expected = factory.coordinator.recheck_committed_observations_in_transaction(
                    connection, original_view
                )
            finally:
                connection.rollback()
        assert expected is tracked.expected and dict(expected) == after
        assert receipt.fence == factory.lease.fence
        assert receipt.lease_sha256 == factory.lease.semantic_sha256
        assert receipt.valid_until == factory.lease.expires_at
        assert (
            before["updated_at"].replace(tzinfo=UTC) <= receipt.validated_at < receipt.valid_until
        )
        assert after["updated_at"] > before["updated_at"]
        assert after == {**before, "updated_at": after["updated_at"]}
        # The committed head uses the separate transaction-time trusted sample.
        assert after["updated_at"].replace(tzinfo=UTC) < receipt.valid_until
        observations.append(after)
        return result

    monkeypatch.setattr(SqlContinuousAccount, "resolve_snapshot", observe_resolve)
    monkeypatch.setattr(integrity_module, "verify_operational_schema", verify_then_observe)
    actual = factory.integrity.verify_original_for_factory()
    assert any(actual is value for value in resolved)
    factory.account.require_resolved(actual)
    assert actual.receipt.commit.sequence == 1
    assert len(observations) == 1
    assert _head(factory) == observations[0]
    assert factory.coordinator._state.observations is None
    with factory.engine.connect() as connection:
        current_leases = tuple(
            dict(row)
            for row in connection.execute(
                sa.select(phase2_account_leases)
                .where(phase2_account_leases.c.account_id == factory.scope.account_id)
                .order_by(phase2_account_leases.c.fencing_generation)
            ).mappings()
        )
    assert current_leases == original_leases, "observation cannot renew original lease times"


def test_factory_rejects_unowned_head_timestamp_changed_after_real_schema_validation(
    transfer_factory, monkeypatch
):
    factory, _command = transfer_factory
    verifier = integrity_module.verify_operational_schema
    changed_heads = []

    def verify_then_change_head(*args, **kwargs):
        result = verifier(*args, **kwargs)
        assert kwargs["continuous_integrity"] is factory.integrity
        before = _head(factory)
        changed_at = before["updated_at"] + timedelta(microseconds=1)
        with factory.engine.begin() as connection:
            changed = connection.execute(
                sa.update(phase2_account_lease_heads)
                .where(phase2_account_lease_heads.c.account_id == factory.scope.account_id)
                .values(updated_at=changed_at)
            )
            assert changed.rowcount == 1
        after = _head(factory)
        assert after == {**before, "updated_at": changed_at}
        changed_heads.append(after)
        return result

    monkeypatch.setattr(integrity_module, "verify_operational_schema", verify_then_change_head)
    with pytest.raises(ContinuousSimulationFactoryError, match=r"^OFFLINE_OPERATION_FAILED$"):
        factory.execute(operation_id="reject-unowned-observation-transfer")
    assert len(changed_heads) == 1
    assert _head(factory) == changed_heads[0]
    assert factory.coordinator._state.observations is None
