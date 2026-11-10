"""Exact paired daily readback with real local source owners and synthetic captures."""

from dataclasses import replace

import pytest
import sqlalchemy as sa

from packages.application import personal_codec as codec
from packages.persistence.continuous_account_schema import (
    continuous_account_commits,
    continuous_account_heads,
)
from packages.persistence.continuous_frontier_publication import SqlContinuousFrontierPublication
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_admissions,
    daily_runtime_hold_events,
    daily_runtime_hold_heads,
    daily_runtime_outbound,
)
from packages.persistence.schema import phase5_operational_control_transitions
from tests.integration import test_continuous_runtime_sources as sources

source = sources.source


def preparation(source):
    case, _service, previous, request, descriptor, _resolved, _clock = source
    transition = case.owner.prepare_frontier(
        command_id="paired-actual-daily", checkpoint=previous.checkpoint, frontier=request
    )
    admission = sources.prepare_admission(source)
    prepared = case.store.prepare(
        transition,
        scope=case.scope,
        previous=previous,
        source_evidence=descriptor.descriptor.market_source,
        admissions=(admission,),
    )
    return admission, prepared


def test_actual_daily_poststate_keeps_original_sources_and_restores(source, monkeypatch):
    case, service, previous, _request, descriptor, resolved, _clock = source
    admission, prepared = preparation(source)
    original_bytes = codec.encode_record(descriptor.descriptor)
    publication = SqlContinuousFrontierPublication(account=case.store)

    def forbidden(*args, **kwargs):
        raise AssertionError("heavy work inside post-publication SQL")

    original_recheck = case.composer.recheck_frontier_publication_in_transaction

    def bounded(connection, prepared, receipt, *, fence):
        with monkeypatch.context() as guard:
            guard.setattr(codec, "encode_record", forbidden)
            guard.setattr(codec, "decode_record", forbidden)
            guard.setattr(service.artifacts, "read", forbidden)
            guard.setattr(service.accounting, "advance", forbidden)
            original_recheck(connection, prepared, receipt, fence=fence)

    monkeypatch.setattr(case.composer, "recheck_frontier_publication_in_transaction", bounded)
    receipt = publication.publish(prepared)
    restored = case.store.restore(case.scope)
    assert restored.receipt == receipt
    assert receipt.commit.sequence == previous.receipt.commit.sequence + 1
    assert not admission.result.decision.approved
    assert restored.checkpoint.runtime_decisions[-1].decision == admission.result.decision
    assert codec.encode_record(descriptor.descriptor) == original_bytes
    assert resolved.plan.descriptor is descriptor.descriptor
    with case.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(daily_runtime_admissions)) == 1
        )


@pytest.mark.parametrize(
    "fault", ["written", "extra", "control", "head", "deadline", "nested_current"]
)
def test_post_c_changes_roll_back_exact_daily_and_c_pair(source, monkeypatch, fault):
    case, _service, previous, *_ = source
    admission, prepared = preparation(source)
    with case.engine.connect() as connection:
        before = tuple(
            dict(row)
            for row in connection.execute(sa.select(continuous_account_commits)).mappings()
        )
    original = case.store.commit_in_transaction

    def late(connection, *, prepared, fence):
        receipt = original(connection, prepared=prepared, fence=fence)
        if fault == "written":
            connection.execute(sa.update(daily_runtime_admissions).values(payload=b"changed"))
        elif fault == "extra":
            row = dict(admission.writes[0].values)
            row.update(admission_id="f" * 64, command_id="unrelated-late-admission")
            connection.execute(sa.insert(daily_runtime_admissions).values(**row))
        elif fault == "control":
            connection.execute(
                sa.update(phase5_operational_control_transitions).values(
                    canonical_payload="changed"
                )
            )
        elif fault == "head":
            connection.execute(
                sa.update(continuous_account_heads).values(checkpoint_sha256="f" * 64)
            )
        elif fault == "nested_current":
            current = prepared.composition.state.current
            object.__setattr__(current.raw, "tables", tuple(replace(t) for t in current.raw.tables))
        else:
            case.h.clock.instant = admission.valid_until
        return receipt

    monkeypatch.setattr(case.store, "commit_in_transaction", late)
    with pytest.raises(ValueError):
        SqlContinuousFrontierPublication(account=case.store).publish(prepared)
    with case.engine.connect() as connection:
        after = tuple(
            dict(row)
            for row in connection.execute(sa.select(continuous_account_commits)).mappings()
        )
        assert after == before
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(daily_runtime_admissions)) == 0
        )
        assert connection.scalar(sa.select(continuous_account_heads.c.checkpoint_sha256)) == (
            previous.checkpoint.semantic_sha256
        )


@pytest.mark.parametrize("fault", ["copy", "result", "write"])
def test_original_admission_guard_rejects_copied_or_replaced_preparations(source, fault):
    case, *_ = source
    admission, _prepared = preparation(source)
    if fault == "copy":
        admission = replace(admission)
    elif fault == "result":
        object.__setattr__(admission, "result", replace(admission.result))
    else:
        object.__setattr__(admission.writes[0], "values", dict(admission.writes[0].values))
    with pytest.raises(ValueError):
        case.h.store.require_prepared_admission(admission)


@pytest.mark.parametrize("fault", [None, "hold", "outbound"])
def test_actual_qualified_admission_proves_all_hold_writes(tmp_path, monkeypatch, fault):
    from tests.integration import test_continuous_runtime_attempt_sources as qualified

    original = sources.Case.publish
    checked = []

    def paired(case, transition=None, previous=None, ref=None, admissions=()):
        if not admissions:
            return original(case, transition, previous, ref, admissions)
        assert len(admissions) == 1 and admissions[0].result.decision.approved
        assert admissions[0].writes
        prepared = case.store.prepare(
            transition,
            scope=case.scope,
            previous=previous,
            source_evidence=ref,
            admissions=admissions,
        )
        if fault is None:
            receipt = SqlContinuousFrontierPublication(account=case.store).publish(prepared)
            with case.engine.connect() as connection:
                for table in (
                    daily_runtime_hold_events,
                    daily_runtime_hold_heads,
                    daily_runtime_outbound,
                ):
                    assert connection.scalar(sa.select(sa.func.count()).select_from(table)) > 0
            checked.append(receipt)
            return receipt
        commit = case.store.commit_in_transaction

        def late(connection, *, prepared, fence):
            receipt = commit(connection, prepared=prepared, fence=fence)
            if fault == "hold":
                connection.execute(sa.update(daily_runtime_hold_events).values(payload=b"changed"))
            else:
                connection.execute(
                    sa.update(daily_runtime_outbound).values(binding_sha256="f" * 64)
                )
            return receipt

        monkeypatch.setattr(case.store, "commit_in_transaction", late)
        with pytest.raises(ValueError):
            SqlContinuousFrontierPublication(account=case.store).publish(prepared)
        with case.engine.connect() as connection:
            for table in (
                daily_runtime_admissions,
                daily_runtime_hold_events,
                daily_runtime_hold_heads,
                daily_runtime_outbound,
            ):
                assert connection.scalar(sa.select(sa.func.count()).select_from(table)) == 0
            assert connection.scalar(sa.select(continuous_account_heads.c.checkpoint_sha256)) == (
                previous.checkpoint.semantic_sha256
            )
        checked.append(fault)
        raise ValueError("injected qualified publication rolled back")

    monkeypatch.setattr(sources.Case, "publish", paired)
    fixture = qualified.attempt_case.__wrapped__(tmp_path, monkeypatch)
    try:
        if fault is None:
            next(fixture)
        else:
            with pytest.raises(ValueError, match="injected qualified publication rolled back"):
                next(fixture)
        assert len(checked) == 1
    finally:
        fixture.close()


@pytest.mark.parametrize("fault", ["late_control", "late_clock"])
def test_changes_during_original_source_readback_are_checked_afterward(source, monkeypatch, fault):
    case, service, previous, _request, _descriptor, _resolved, clock = source
    _admission, prepared = preparation(source)
    original = service.recheck_admission_sources_after_publication_in_transaction

    def late(connection, *args, **kwargs):
        original(connection, *args, **kwargs)
        if fault == "late_control":
            connection.execute(
                sa.update(phase5_operational_control_transitions).values(
                    canonical_payload="changed-after-source-readback"
                )
            )
        else:
            clock.advance(31)

    monkeypatch.setattr(service, "recheck_admission_sources_after_publication_in_transaction", late)
    with pytest.raises(ValueError):
        SqlContinuousFrontierPublication(account=case.store).publish(prepared)
    with case.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(sa.func.count()).select_from(daily_runtime_admissions)) == 0
        )
        assert connection.scalar(sa.select(continuous_account_heads.c.checkpoint_sha256)) == (
            previous.checkpoint.semantic_sha256
        )
