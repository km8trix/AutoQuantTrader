"""Actual retained pending/C/A fixtures for distinct pending and completed readbacks.

These tests exercise SQL/original-object ownership, not venue delivery permission.
Actual activation/dispatch coverage is shared with the attempt source suite.
"""

from dataclasses import replace

import pytest
import sqlalchemy as sa

from packages.application import personal_codec as codec
from packages.persistence.continuous_account_schema import continuous_account_heads
from packages.persistence.daily_runtime_risk import DailyRuntimeRiskConflict, SqlDailyRuntimeRisk
from packages.persistence.daily_runtime_risk_schema import daily_runtime_attempt_heads
from packages.persistence.schema import phase5_operational_control_heads
from tests.integration.test_continuous_runtime_attempt_sources import (
    attempt_case,  # noqa: F401
    publish_original_pending,
)


def forbidden(*_args, **_kwargs):
    raise AssertionError("detached graph work reached final SQL readback")


def test_pending_c_readback_rejects_copies_late_heads_and_final_deadline(
    attempt_case,  # noqa: F811
    monkeypatch,
):
    case, service, _reader, _previous, _current, _view = attempt_case
    _source, pending_account, _receipt = publish_original_pending(attempt_case)
    paired = case.paired_fixture
    prepared = paired.prepare("original-a-after-pending-readback", previous=paired.restore())
    before = paired.counts()
    original = case.h.store.recheck_snapshot_after_continuous_publication_in_transaction
    source_recheck = service.recheck_attempt_sources_after_publication_in_transaction
    checked = []

    def inspect(connection, snapshot, **kwargs):
        assert snapshot.attempt_sources is not None
        with monkeypatch.context() as patch:
            for name in ("encode_record", "decode_record"):
                patch.setattr(codec, name, forbidden)
            patch.setattr(case.artifacts, "read", forbidden)
            patch.setattr(case.h.store, "resolve_snapshot", forbidden)
            original(connection, snapshot, **kwargs)
        checked.append("original")
        for name in ("prepared_account", "account_receipt"):
            with pytest.raises(ValueError, match=r"OWNED|original|ORIGINAL"):
                original(connection, snapshot, **(kwargs | {name: replace(kwargs[name])}))
            checked.append(name)
        for table, values in (
            (phase5_operational_control_heads, {"canonical_payload": "{}"}),
            (daily_runtime_attempt_heads, {"attempt_sha256": "a" * 64}),
            (continuous_account_heads, {"checkpoint_sha256": "a" * 64}),
        ):
            savepoint = connection.begin_nested()
            try:
                count = connection.execute(
                    sa.update(table)
                    .where(table.c.account_id == case.scope.account_id)
                    .values(**values)
                ).rowcount
                assert count >= 1
                with pytest.raises(ValueError, match=r"changed|CHANGED|differ|DIFFER"):
                    original(connection, snapshot, **kwargs)
                checked.append(table.name)
            finally:
                savepoint.rollback()
        deadline = snapshot.raw.receipt.valid_until

        def expire_after_source(*args, **source_kwargs):
            source_recheck(*args, **source_kwargs)
            case.h.clock.instant = deadline

        with monkeypatch.context() as patch:
            patch.setattr(
                service,
                "recheck_attempt_sources_after_publication_in_transaction",
                expire_after_source,
            )
            with pytest.raises(ValueError, match=r"expired|EXPIRED"):
                original(connection, snapshot, **kwargs)
        checked.append("final_deadline")
        raise DailyRuntimeRiskConflict("fixture requires rollback after final deadline")

    monkeypatch.setattr(
        case.h.store, "recheck_snapshot_after_continuous_publication_in_transaction", inspect
    )
    with pytest.raises(DailyRuntimeRiskConflict, match="fixture requires rollback"):
        paired.publisher.publish(prepared, fence=case.h.lease.fence)
    assert checked == [
        "original",
        "prepared_account",
        "account_receipt",
        phase5_operational_control_heads.name,
        daily_runtime_attempt_heads.name,
        continuous_account_heads.name,
        "final_deadline",
    ]
    assert paired.counts() == before
    with case.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(continuous_account_heads.c.command_id))
            == pending_account.commit.transition.command_id
        )


def test_completed_readback_uses_actual_original_source_without_pending_c_authority(
    attempt_case,  # noqa: F811
    monkeypatch,
):
    case, service, _reader, _previous, _current, _view = attempt_case
    source, prepared_account, _receipt = publish_original_pending(attempt_case)
    prepared = case.store.composer.inspect_prepared_attempt(prepared_account.composition)
    assert prepared.snapshot.attempt_sources is not None
    with case.store.write_transaction() as connection:
        raw = case.store.capture_reference_in_transaction(
            connection,
            scope=case.scope,
            command_id=source.source.coordinator_command_id,
            source_lease_sha256=source.source.fence.lease_sha256,
        )
    publication = case.store.resolve_reference(raw)
    committed = service.resolve_committed_attempt_sources(
        prepared.snapshot.attempt_sources, publication=publication
    )
    case.h.store.require_prepared_attempt(prepared)
    service.require_committed_attempt_sources(committed)
    foreign_store = SqlDailyRuntimeRisk(
        case.engine,
        coordinator=case.h.coordinator,
        codec=codec,
        producers=service,
        accounting=case.h.store.accounting,
    )
    method = case.h.store.recheck_completed_attempt_in_transaction
    source_recheck = service.recheck_committed_attempt_sources_in_transaction
    before = case.paired_fixture.counts()
    with case.store.write_transaction() as connection:
        with monkeypatch.context() as patch:
            for name in ("encode_record", "decode_record"):
                patch.setattr(codec, name, forbidden)
            patch.setattr(case.artifacts, "read", forbidden)
            patch.setattr(case.h.store, "resolve_snapshot", forbidden)
            assert (
                method(connection, prepared, fence=case.h.lease.fence, committed_sources=committed)
                is prepared.result
            )
        for changed in (replace(committed), replace(committed, seal=object())):
            with pytest.raises(ValueError, match=r"OWNED|original|ORIGINAL"):
                method(connection, prepared, fence=case.h.lease.fence, committed_sources=changed)
        with pytest.raises(DailyRuntimeRiskConflict, match="original"):
            foreign_store.recheck_completed_attempt_in_transaction(
                connection, prepared, fence=case.h.lease.fence, committed_sources=committed
            )
        for table, values in (
            (phase5_operational_control_heads, {"canonical_payload": "{}"}),
            (daily_runtime_attempt_heads, {"attempt_sha256": "a" * 64}),
        ):
            savepoint = connection.begin_nested()
            try:
                assert (
                    connection.execute(
                        sa.update(table)
                        .where(table.c.account_id == case.scope.account_id)
                        .values(**values)
                    ).rowcount
                    >= 1
                )
                with pytest.raises(ValueError, match=r"changed|CHANGED|differ|DIFFER"):
                    method(
                        connection, prepared, fence=case.h.lease.fence, committed_sources=committed
                    )
            finally:
                savepoint.rollback()
        assert prepared.valid_until is not None

        def expire_after_source(*args, **kwargs):
            source_recheck(*args, **kwargs)
            case.h.clock.instant = prepared.valid_until

        with monkeypatch.context() as patch:
            patch.setattr(
                service, "recheck_committed_attempt_sources_in_transaction", expire_after_source
            )
            with pytest.raises(DailyRuntimeRiskConflict, match="deadline expired"):
                method(connection, prepared, fence=case.h.lease.fence, committed_sources=committed)
    assert case.paired_fixture.counts() == before
