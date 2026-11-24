"""Actual B/C/journal stores; the retained clock and market sources are simulation fixtures."""

import threading
import weakref
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta

import pytest

from packages.application import personal_codec as codec
from packages.domain.durable_journal_contracts import empty_head
from packages.domain.runtime_operating_contracts import CLOCK_SCHEMA, RuntimeClockObservation
from packages.persistence.daily_runtime_risk import RuntimeProducerRawSnapshot, RuntimeReadBudget
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.runtime_operating_evidence import SqlRuntimeOperatingEvidence
from tests.integration.test_continuous_composition import Case
from tests.integration.test_sql_daily_runtime_risk import _write_transaction
from tests.unit.test_daily_attempt import reference
from tests.unit.test_runtime_operating_evidence import healthy_sampler
from tests.unit.test_stateful_venue import model


@pytest.fixture
def operating(tmp_path):
    case = Case(tmp_path)
    case.publish()
    old, transition, ref, admissions = case.next()
    case.publish(transition, old, ref, admissions)
    previous = case.store.restore(case.scope)
    daily = case.h.resolved()
    clock, sampler, sample = healthy_sampler(case.scope, at=previous.checkpoint.now)
    journal = SqlDurableJournal(
        case.engine, codec=codec, record_types={CLOCK_SCHEMA: RuntimeClockObservation}
    )
    service = SqlRuntimeOperatingEvidence(
        case.engine,
        journal=journal,
        artifacts=case.artifacts,
        codec=codec,
        clock_sampler=sampler,
    )
    prepared = service.prepare_clock_append(sample, expected_head=empty_head(service.clock_key()))
    with _write_transaction(case.engine) as connection:
        clock_ref = service.append_clock_in_transaction(connection, prepared)
    venue = model()
    plan = service.prepare(
        clock_reference=clock_ref,
        accounts=case.store,
        daily=case.h.store,
        previous=previous,
        daily_snapshot=daily,
        original_checked_at=previous.checkpoint.now,
        venue_account_id=venue.account_id,
        venue_model=reference(venue),
    )
    with _repeatable_read_transaction(case.engine) as connection:
        raw = service.capture_in_transaction(connection, plan, budget=RuntimeReadBudget())
    resolved = service.resolve(raw)
    yield case, service, clock, plan, raw, resolved
    case.engine.dispose()


def evaluate(service, plan, resolved, **kwargs):
    args = dict(
        batch=plan.previous.checkpoint.runtime_decisions[-1].batch,
        phase="decision",
        evaluated_at=plan.original_checked_at,
        request_rows=plan.previous.checkpoint.request_rows,
    )
    args.update(kwargs)
    return {v.role: v for v in service.evaluate(resolved, **args)}


def test_actual_retained_clock_calendar_and_empty_local_dispatch_history(operating):
    case, service, _clock, plan, _raw, resolved = operating
    facts = evaluate(service, plan, resolved)
    assert set(facts) == {"clock", "session", "request_budget"}
    assert all(fact.status == "available" for fact in facts.values())
    assert all(fact.clock_profile == "explicit_simulation_time_model" for fact in facts.values())
    assert all(fact.budget_scope == "local_stateful_venue_only" for fact in facts.values())
    assert facts["clock"].source_at == plan.clock.observed_at_utc
    assert facts["clock"].clock_epoch == plan.clock.epoch
    assert facts["clock"].valid_until == plan.original_checked_at + timedelta(seconds=30)
    service.require_current_clock(resolved)
    with _write_transaction(case.engine) as connection:
        service.recheck_in_transaction(connection, resolved, require_current=True)


@pytest.mark.parametrize("kind", ["plan", "raw", "resolved", "daily", "previous"])
def test_copied_operating_context_never_becomes_owned_evidence(operating, kind):
    case, service, _clock, plan, raw, resolved = operating
    with pytest.raises(ValueError):
        if kind == "plan":
            with _repeatable_read_transaction(case.engine) as connection:
                service.capture_in_transaction(
                    connection, replace(plan), budget=RuntimeReadBudget()
                )
        elif kind == "raw":
            service.resolve(replace(raw))
        elif kind == "resolved":
            service.require_resolved(replace(resolved))
        elif kind == "daily":
            case.h.store.require_resolved_snapshot(replace(plan.daily_snapshot))
        else:
            case.store.require_resolved(replace(plan.previous))


def test_fixed_table_capture_reuses_original_shared_budget_footprint(operating):
    case, service, _clock, plan, _raw, _resolved = operating
    budget = RuntimeReadBudget()
    budget.captured.extend(plan.daily_snapshot.raw.tables)
    original = tuple(budget.captured)
    with _repeatable_read_transaction(case.engine) as connection:
        raw = service.capture_in_transaction(connection, plan, budget=budget)
    assert len(budget.captured) == len(original)
    assert all(a is b for a, b in zip(raw.daily_tables, original, strict=True))
    assert budget.rows > 0 and budget.payload_bytes > 0  # journal and account auxiliary rows


def test_physical_auxiliary_rows_are_charged_once_across_shared_account_capture(operating):
    from packages.persistence.continuous_account_schema import continuous_account_commits
    from packages.persistence.daily_runtime_risk import capture_runtime_table

    case, service, _clock, plan, _raw, _resolved = operating
    budget = RuntimeReadBudget()
    budget.captured.extend(plan.daily_snapshot.raw.tables)
    with _repeatable_read_transaction(case.engine) as connection:
        capture_runtime_table(
            connection,
            continuous_account_commits,
            account_id=case.scope.account_id,
            budget=budget,
        )
        before = budget.rows
        service.capture_in_transaction(connection, plan, budget=budget)
    # One clock stream, one append, one entry. The account row was already
    # transferred, and the head/receipt views refer to the same physical entry.
    assert budget.rows - before == 3


def test_original_history_allows_later_heads_but_current_check_rejects_later_clock(operating):
    case, service, clock, plan, _raw, resolved = operating
    clock.epoch = "changed-epoch"
    sample = service.clock_sampler.sample()
    assert sample.observation.status == "blocked"
    next_append = service.prepare_clock_append(
        sample, expected_head=plan.clock_reference.receipt.committed_head
    )
    with _write_transaction(case.engine) as connection:
        service.append_clock_in_transaction(connection, next_append)
    with _write_transaction(case.engine) as connection:
        service.recheck_in_transaction(connection, resolved, require_current=False)
    with pytest.raises(ValueError), _write_transaction(case.engine) as connection:
        service.recheck_in_transaction(connection, resolved, require_current=True)
    with pytest.raises(ValueError, match="epoch"):
        service.require_current_clock(resolved)


def test_unknown_local_request_rows_and_changed_window_remain_unavailable(operating):
    _case, service, _clock, plan, _raw, resolved = operating
    rows = ((plan.original_checked_at, True),) * 10
    facts = evaluate(service, plan, resolved, request_rows=rows)
    assert facts["request_budget"].status == "unavailable"
    assert "LOCAL_FIRST_SEND_HISTORY_AND_ENGINE_ROWS_DIFFER" in facts["request_budget"].reasons
    batch = plan.previous.checkpoint.runtime_decisions[-1].batch
    batch = replace(
        batch,
        target=replace(batch.target, not_before=batch.target.not_before + timedelta(seconds=1)),
    )
    assert evaluate(service, plan, resolved, batch=batch)["session"].status == "unavailable"
    with pytest.raises(ValueError, match="refresh"):
        evaluate(
            service,
            plan,
            resolved,
            evaluated_at=plan.original_checked_at + timedelta(microseconds=1),
        )


def test_capture_and_final_recheck_do_no_codec_or_object_reads(operating, monkeypatch):
    case, service, _clock, plan, _raw, resolved = operating

    def forbidden(*args, **kwargs):
        raise AssertionError("decode or object I/O inside SQL")

    with monkeypatch.context() as patch:
        patch.setattr(codec, "encode_record", forbidden)
        patch.setattr(codec, "decode_record", forbidden)
        patch.setattr(case.artifacts, "read", forbidden)
        patch.setattr(service, "_fingerprint", forbidden)
        patch.setattr(case.store, "require_resolved", forbidden)
        patch.setattr(case.h.store, "require_resolved_snapshot", forbidden)
        with _repeatable_read_transaction(case.engine) as connection:
            service.capture_in_transaction(connection, plan, budget=RuntimeReadBudget())
        with _write_transaction(case.engine) as connection:
            service.recheck_in_transaction(connection, resolved, require_current=True)
            service.require_current_clock(resolved)


def test_same_instance_operating_tokens_and_clock_fields_remain_original(operating):
    case, service, _clock, plan, raw, resolved = operating
    mutations = (
        (plan, "original_checked_at", plan.original_checked_at + timedelta(microseconds=1)),
        (plan.clock, "observed_at_utc", plan.clock.observed_at_utc + timedelta(seconds=1)),
        (plan.clock.scope, "account_id", "changed-account"),
        (plan.clock_reference.record, "semantic_sha256", "f" * 64),
        (raw, "daily_tables", ()),
        (raw.clock, "command_id", "changed-command"),
        (raw.account, "row", {}),
        (resolved.clock, "receipt", None),
    )
    for target, name, replacement in mutations:
        original = getattr(target, name)
        try:
            object.__setattr__(target, name, replacement)
            with pytest.raises(ValueError, match="original operating"):
                service.require_resolved(resolved)
            with (
                pytest.raises(ValueError, match="original operating"),
                _write_transaction(case.engine) as connection,
            ):
                service.recheck_in_transaction(connection, resolved, require_current=True)
        finally:
            object.__setattr__(target, name, original)
    service.require_resolved(resolved)


def test_detached_revalidation_detects_nested_checkpoint_mutation(operating):
    _case, service, _clock, plan, _raw, resolved = operating
    checkpoint = plan.previous.checkpoint
    original = checkpoint.request_rows
    try:
        object.__setattr__(checkpoint, "request_rows", ((plan.original_checked_at, True),))
        with pytest.raises(ValueError):
            evaluate(service, plan, resolved)
    finally:
        object.__setattr__(checkpoint, "request_rows", original)


def test_detached_revalidation_detects_nested_daily_hold_mutation(operating):
    _case, service, _clock, plan, _raw, resolved = operating
    commitment = plan.daily_snapshot.obligations.bindings[0].commitment
    original = commitment.reserved_cash
    try:
        object.__setattr__(commitment, "reserved_cash", original + 1)
        with pytest.raises(
            ValueError,
            match=(
                r"original operating token content|original resolved daily snapshot fields changed"
            ),
        ):
            evaluate(service, plan, resolved)
    finally:
        object.__setattr__(commitment, "reserved_cash", original)


def test_same_prepared_clock_cannot_change_nested_record_before_sql(operating):
    case, service, clock, plan, _raw, _resolved = operating
    clock.advance(1)
    prepared = service.prepare_clock_append(
        service.clock_sampler.sample(), expected_head=plan.clock_reference.receipt.committed_head
    )
    object.__setattr__(prepared.reference.record.object_ref, "object_sha256", "e" * 64)
    with (
        pytest.raises(ValueError, match="original operating"),
        _write_transaction(case.engine) as connection,
    ):
        service.append_clock_in_transaction(connection, prepared)
    assert (
        service.journal.read_head(service.clock_key())
        == plan.clock_reference.receipt.committed_head
    )


def test_original_lowercase_clock_fault_maps_to_valid_source_condition(operating):
    from packages.application.continuous_runtime_evidence import RuntimeSourceCondition

    case, service, clock, plan, _raw, _resolved = operating
    clock.epoch = "changed-epoch"
    sample = service.clock_sampler.sample()
    assert "epoch_changed" in sample.observation.reasons
    prepared = service.prepare_clock_append(
        sample, expected_head=plan.clock_reference.receipt.committed_head
    )
    with _write_transaction(case.engine) as connection:
        reference = service.append_clock_in_transaction(connection, prepared)
    blocked = service.prepare(
        clock_reference=reference,
        accounts=plan.accounts,
        daily=plan.daily,
        previous=plan.previous,
        daily_snapshot=plan.daily_snapshot,
        original_checked_at=plan.original_checked_at,
        venue_account_id=plan.venue_account_id,
        venue_model=plan.venue_model,
    )
    with _repeatable_read_transaction(case.engine) as connection:
        raw = service.capture_in_transaction(connection, blocked, budget=RuntimeReadBudget())
    fact = evaluate(service, blocked, service.resolve(raw))["clock"]
    assert fact.status == "unavailable"
    assert "STANDARD_CLOCK_EPOCH_CHANGED" in fact.reasons
    assert "epoch_changed" in blocked.clock.reasons  # original retained observation unchanged
    condition = RuntimeSourceCondition(
        fact.role,
        fact.source_at,
        fact.received_at,
        fact.valid_until,
        fact.revision,
        fact.status,
        fact.reasons,
    )
    assert condition.reasons == fact.reasons


def test_raw_producer_weak_lifetime_and_exact_daily_ownership(operating):
    case, _service, _clock, plan, _raw, _resolved = operating
    original = RuntimeProducerRawSnapshot(())
    assert weakref.ref(original)() is original
    case.h.store.require_resolved_snapshot(plan.daily_snapshot)


def test_stalled_clock_decoder_does_not_hold_sql_and_current_control_change_rejects(
    operating,
    monkeypatch,
):
    from packages.domain.operational_control import (
        OperationalControlCommandKind,
        OperationalControlState,
    )

    case, service, _clock, _plan, raw, _resolved = operating
    entered, release = threading.Event(), threading.Event()
    original = codec.decode_record

    def paused(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return original(*args, **kwargs)

    monkeypatch.setattr(codec, "decode_record", paused)
    with ThreadPoolExecutor(max_workers=2) as pool:
        read = pool.submit(service.resolve, raw)
        try:
            assert entered.wait(5)
            write = pool.submit(
                case.h.controls.apply,
                case.h.command(
                    OperationalControlCommandKind.PAUSE,
                    "operating-decoder-pause",
                    OperationalControlState.PAUSED,
                ),
            )
            assert write.result(timeout=5).effective_state is OperationalControlState.PAUSED
            assert not release.is_set() and not read.done()
        finally:
            release.set()
        resolved = read.result(timeout=5)
    with _write_transaction(case.engine) as connection:
        service.recheck_in_transaction(connection, resolved, require_current=False)
    with (
        pytest.raises(ValueError, match="inventory changed"),
        _write_transaction(case.engine) as connection,
    ):
        service.recheck_in_transaction(connection, resolved, require_current=True)


def test_clock_auxiliary_records_share_the_same_global_capture_bound(operating):
    from packages.persistence.daily_runtime_risk import MAX_TOTAL_BYTES

    case, service, _clock, plan, _raw, _resolved = operating
    budget = RuntimeReadBudget(payload_bytes=MAX_TOTAL_BYTES)
    with (
        pytest.raises(ValueError, match="aggregate capture"),
        _repeatable_read_transaction(case.engine) as connection,
    ):
        service.capture_in_transaction(connection, plan, budget=budget)


def test_actual_sql_first_send_is_counted_once_through_unknown_and_resolution(tmp_path):
    from packages.domain.submission_attempt import SubmissionAttemptState
    from packages.persistence.database import create_database_engine
    from packages.persistence.runtime_operating_evidence import _local_budget_reasons
    from tests.integration.test_sql_daily_runtime_risk import (
        activation_fixture,
        commit_attempt,
        envelope_for,
        later_attempt_source,
        pending_fixture,
        prepare_attempt,
        retain_attempt_source,
    )
    from tests.unit.test_daily_attempt import event_after, observed_outcome

    engine = create_database_engine(f"sqlite+pysqlite:///{tmp_path}/attempt.sqlite")
    try:
        h, source, envelopes, preparations = pending_fixture(engine)
        pending = commit_attempt(h, source, prepare_attempt(h, envelopes, preparations))
        source, sent, journal, appends = activation_fixture(h, source, pending)
        current = commit_attempt(
            h, source, prepare_attempt(h, sent, dispatch_journal=journal, dispatch_appends=appends)
        )
        sent_at = current.attempts[0].events[1].dispatch.record.dispatched_at
        rows = ((sent_at, True),)
        for state in (SubmissionAttemptState.UNKNOWN, SubmissionAttemptState.RESOLVED):
            source = later_attempt_source(h, source, current, command="state-" + state.value)
            payload = (
                dict(reason="ambiguous")
                if state is SubmissionAttemptState.UNKNOWN
                else dict(outcome=observed_outcome(current.attempts[0], source.checked_at))
            )
            event = event_after(current.attempts[0], state, source.checked_at, **payload)
            envelope = envelope_for(source, retain_attempt_source(h, source), event)
            current = commit_attempt(h, source, prepare_attempt(h, (envelope,)))
            restored = h.resolved()
            assert restored.attempts == current.attempts
            assert (
                _local_budget_reasons(
                    attempts=restored.attempts,
                    checkpoint_rows=rows,
                    request_rows=rows,
                    evaluated_at=source.checked_at,
                    requested_count=9,
                )
                == []
            )
            assert "LOCAL_MODELED_REQUEST_BUDGET_EXHAUSTED" in _local_budget_reasons(
                attempts=restored.attempts,
                checkpoint_rows=rows,
                request_rows=rows,
                evaluated_at=source.checked_at,
                requested_count=10,
            )
            assert "LOCAL_FIRST_SEND_HISTORY_AND_ENGINE_ROWS_DIFFER" in _local_budget_reasons(
                attempts=restored.attempts,
                checkpoint_rows=rows,
                request_rows=(),
                evaluated_at=source.checked_at,
                requested_count=1,
            )
        assert (
            _local_budget_reasons(
                attempts=current.attempts,
                checkpoint_rows=rows,
                request_rows=(),
                evaluated_at=sent_at + timedelta(seconds=60),
                requested_count=10,
            )
            == []
        )
        assert len(current.attempts[0].events) == 4
    finally:
        engine.dispose()
