"""Actual signed owner requests plus C/B/A stores; all venue data is synthetic."""

from dataclasses import replace
from datetime import timedelta

import pytest
import sqlalchemy as sa

from apps.api.runtime_owner_authentication import LocalRuntimeOwnerAuthenticator
from packages.application import personal_codec as codec
from packages.domain.continuous_runtime_source_contracts import (
    RUNTIME_SOURCE_SCHEMA,
    ContinuousRuntimeSourceDescriptor,
)
from packages.domain.durable_journal_contracts import empty_head
from packages.domain.runtime_operating_contracts import CLOCK_SCHEMA, RuntimeClockObservation
from packages.domain.runtime_owner_dependency_contracts import RuntimeOwnerDependencies
from packages.domain.stateful_venue_contracts import VenueSourceReference
from packages.persistence.continuous_account_schema import continuous_account_commits
from packages.persistence.continuous_runtime_sources import SqlContinuousRuntimeSources
from packages.persistence.daily_runtime_risk import RuntimeAssignmentCommand, RuntimeReadBudget
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_assignment_heads,
    daily_runtime_assignments,
)
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.durable_journal_schema import journal_entries
from packages.persistence.runtime_operating_evidence import SqlRuntimeOperatingEvidence
from packages.persistence.runtime_owner_commands import SqlRuntimeOwnerCommands, journal_key
from packages.persistence.runtime_owner_dependencies import (
    RuntimeOwnerDependencyError,
    SqlRuntimeOwnerDependencies,
)
from tests.integration.test_continuous_reconciliation_publication import PublicationCase
from tests.integration.test_continuous_runtime_sources import install_producers
from tests.unit.test_runtime_operating_evidence import healthy_sampler
from tests.unit.test_runtime_owner_authentication import _session


def attach(pair):
    case = pair.base
    _, sampler, _ = healthy_sampler(case.scope, at=case.h.clock.instant)
    operating = SqlRuntimeOperatingEvidence(
        case.engine,
        journal=SqlDurableJournal(
            case.engine, codec=codec, record_types={CLOCK_SCHEMA: RuntimeClockObservation}
        ),
        artifacts=case.artifacts,
        codec=codec,
        clock_sampler=sampler,
    )
    model_ref = VenueSourceReference(
        pair.model.producer,
        pair.model.semantic_sha256,
        case.artifacts.put(codec.encode_record(pair.model)),
    )
    producer = SqlContinuousRuntimeSources(
        case.engine,
        coordinator=case.h.coordinator,
        journal=SqlDurableJournal(
            case.engine,
            codec=codec,
            record_types={RUNTIME_SOURCE_SCHEMA: ContinuousRuntimeSourceDescriptor},
        ),
        artifacts=case.artifacts,
        codec=codec,
        forward_sources=case.forward,
        operating=operating,
        accounting=case.owner.accounting,
        strategy=case.owner.strategy,
        venue_model=pair.model,
        venue_reference=model_ref,
        producer_map=case.h.producer_map,
        benchmark_instrument_id=case.inputs.spec.instruments[0][0],
        current_fence=lambda: case.h.lease.fence,
    )
    case.h.store.producers = producer
    case.reader = producer
    case.owner.runtime_evidence = producer
    pair.restart()
    case.store = pair.account
    producer.bind_stores(accounts=pair.account, daily=case.h.store)
    producer.bind_reconciliation(pair.publisher)
    security, cookie, csrf = _session(issued_at=case.h.clock.instant)
    authenticator = LocalRuntimeOwnerAuthenticator(security)
    requests = SqlRuntimeOwnerCommands(case.engine, codec=codec, authenticator=authenticator)
    reader = SqlRuntimeOwnerDependencies(
        case.engine,
        accounts=pair.account,
        daily=case.h.store,
        publisher=pair.publisher,
        commands=requests,
        artifacts=case.artifacts,
        codec=codec,
    )
    producer.bind_owner_dependencies(reader)
    return reader, producer, authenticator, cookie, csrf


@pytest.fixture
def case(tmp_path):
    pair = PublicationCase(tmp_path)
    install_producers(pair.base, pair.model)
    reader, producer, auth, cookie, csrf = attach(pair)
    yield pair, reader, producer, auth, cookie, csrf
    pair.base.engine.dispose()
    pair.venue_engine.dispose()


def proposed(case, *, enabled=False, **changes):
    pair, _reader, *_ = case
    h = pair.base.h
    current = h.store.resolve_snapshot(
        h.store.read_snapshot(account_id=h.account, fence=h.lease.fence)
    ).assignment
    return replace(
        current,
        generation=current.generation + 1,
        previous_assignment_sha256=current.semantic_sha256,
        effective_at=h.clock.instant,
        enabled_for_new_exposure=enabled,
        **changes,
    )


def dependencies(case, assignment=None):
    pair, reader, *_ = case
    return reader.prepare_dependencies(
        previous=pair.account.restore(pair.base.scope),
        proposed=assignment or proposed(case),
        fence=pair.base.h.lease.fence,
    )


def retained_request(case, dep=None, *, name="signed-owner-selection"):
    pair, reader, _producer, auth, cookie, csrf = case
    dep = dep or dependencies(case)
    h = pair.base.h
    command = RuntimeAssignmentCommand(
        name,
        "simulation-owner",
        h.account,
        dep.record.previous_assignment_sha256,
        dep.record.proposed.semantic_sha256,
        dep.record.heads,
        dep.record.semantic_sha256,
        h.clock.instant,
        min(h.clock.instant + timedelta(seconds=60), dep.record.valid_until),
    )
    authenticated = auth.authenticate(
        command, session_cookie=cookie, csrf_token=csrf, now=command.requested_at
    )
    prepared = reader.commands.prepare(
        dep.record.scope,
        command=command,
        authenticated=authenticated,
        dependencies=dep.reference,
        expected_head=empty_head(journal_key(dep.record.scope)),
    )
    reader.commands.require_prepared(prepared)
    with pair.account.write_transaction() as connection:
        receipt = reader.commands.append_in_transaction(connection, prepared)
    return dep, command, receipt


def assignment_preparation(case, dep=None):
    pair, reader, *_ = case
    dep, command, receipt = retained_request(case, dep)
    plan = reader.prepare_owner_command_read(
        previous=dep.previous, original_receipt=receipt, fence=pair.base.h.lease.fence
    )
    h = pair.base.h
    raw = h.store.read_snapshot(
        account_id=h.account, fence=h.lease.fence, owner_command_ref=receipt
    )
    resolved = h.store.resolve_snapshot(raw)
    prepared = h.store.prepare_assignment(
        resolved,
        assignment=dep.record.proposed,
        expected_previous_sha256=dep.record.previous_assignment_sha256,
        owner_command_ref=receipt,
    )
    return dep, command, receipt, plan, prepared


def test_actual_signed_request_prepares_and_installs_disabled_selection(case):
    pair, reader, producer, *_ = case
    dep, command, receipt, plan, prepared = assignment_preparation(case)
    assert receipt.command_sha256 == command.semantic_sha256
    assert plan.dependencies.record == dep.record
    assert producer.owner_dependencies is reader
    assert (
        codec.decode_record(codec.encode_record(dep.record), RuntimeOwnerDependencies) == dep.record
    )
    assert dep.record.reconciliation is None
    before_control = prepared.snapshot.control
    with pair.account.write_transaction() as connection:
        result = pair.base.h.store.install_prepared_in_transaction(
            connection, prepared, fence=pair.base.h.lease.fence
        )
    actual = pair.base.h.store.resolve_snapshot(
        pair.base.h.store.read_snapshot(account_id=result.account_id, fence=pair.base.h.lease.fence)
    )
    assert actual.assignment == dep.record.proposed and actual.control == before_control
    assert actual.obligations == prepared.snapshot.obligations
    assert actual.attempts == prepared.snapshot.attempts
    assert not result.enabled_for_new_exposure and not result.live_authorized


def test_enable_without_actual_reconciliation_fails_closed(case):
    with pytest.raises(RuntimeOwnerDependencyError, match="RECONCILIATION"):
        dependencies(case, proposed(case, enabled=True))


def converge(case):
    pair = case[0]
    prior = None
    for i in range(2):
        prep = pair.prepare(f"owner-cash-round-{i}", previous=prior)
        pair.publisher.publish(prep, fence=pair.base.h.lease.fence)
        prior = pair.restore()
    assert prior.reconciliation.resolved.result.status == "converged"
    return prior


def test_enable_uses_actual_original_converged_heads_and_signed_request(case):
    prior = converge(case)
    pair = case[0]
    dep = dependencies(case, proposed(case, enabled=True))
    assert dep.record.reconciliation == prior.reconciliation.receipt
    assert dep.record.heads == prior.reconciliation.resolved.result.heads
    assert (
        dep.record.valid_until
        <= prior.reconciliation.resolved.result.observation_started_at + timedelta(seconds=60)
    )
    _dep, _command, _receipt, plan, prepared = assignment_preparation(case, dep)
    assert plan.dependencies.reconciliation.reconciliation.receipt == prior.reconciliation.receipt
    with pair.account.write_transaction() as connection:
        installed = pair.base.h.store.install_prepared_in_transaction(
            connection, prepared, fence=pair.base.h.lease.fence
        )
    assert installed.enabled_for_new_exposure and not installed.live_authorized


@pytest.mark.parametrize("change", ["strategy", "configuration", "policy"])
def test_policy_or_strategy_cutover_requires_an_actual_engine_transition(case, change):
    current = proposed(case)
    updates = {
        "strategy": replace(current.strategy, version="different"),
        "configuration": "9" * 64,
        "policy": replace(
            current.policy, daily_loss_boundary=current.policy.daily_loss_boundary / 2
        ),
    }
    field = {"configuration": "configuration_sha256"}.get(change, change)
    with pytest.raises(RuntimeOwnerDependencyError, match="CUTOVER_UNSUPPORTED"):
        dependencies(case, replace(current, **{field: updates[change]}))


def test_current_owner_request_requires_exact_producer_plan_before_capture(case):
    pair = case[0]
    _, _, receipt = retained_request(case)
    with pytest.raises(RuntimeOwnerDependencyError, match="BEFORE_CAPTURE"):
        pair.base.h.store.read_snapshot(
            account_id=pair.base.h.account, fence=pair.base.h.lease.fence, owner_command_ref=receipt
        )


def test_cloned_or_nested_mutated_dependency_preparation_is_rejected(case):
    reader = case[1]
    dep = dependencies(case)
    with pytest.raises(RuntimeOwnerDependencyError, match="OWNED"):
        reader.require_prepared(replace(dep))
    object.__setattr__(dep.record.heads, "capacity_sha256", "9" * 64)
    with pytest.raises(RuntimeOwnerDependencyError, match=r"FIELDS|CONTENT"):
        reader.require_prepared(dep)


def test_request_restart_preserves_original_source_times_without_session_reauthentication(
    case, monkeypatch
):
    pair, reader, *_ = case
    dep, _, receipt = retained_request(case)

    def forbidden(*args, **kwargs):
        raise AssertionError("historical retained request must not be reauthenticated")

    monkeypatch.setattr(reader.commands.authenticator, "require_authenticated", forbidden)
    restarted = SqlRuntimeOwnerDependencies(
        pair.base.engine,
        accounts=pair.account,
        daily=pair.base.h.store,
        publisher=pair.publisher,
        commands=reader.commands,
        artifacts=pair.base.artifacts,
        codec=codec,
    )
    pair.base.h.clock.instant += timedelta(seconds=1)
    plan = restarted.prepare_owner_command_read(
        previous=dep.previous, original_receipt=receipt, fence=pair.base.h.lease.fence
    )
    assert plan.dependencies.record == dep.record
    assert plan.request.record.command.requested_at == dep.record.checked_at
    with pytest.raises(ValueError):
        case[2].bind_owner_dependencies(restarted)


def test_original_deadline_expiry_does_not_refresh_request(case):
    pair, reader, *_ = case
    dep, _, receipt = retained_request(case)
    pair.base.h.clock.instant = dep.record.valid_until
    with pytest.raises(ValueError):
        reader.prepare_owner_command_read(
            previous=dep.previous, original_receipt=receipt, fence=pair.base.h.lease.fence
        )
    original = reader.commands.read(
        dep.record.scope, command_id=receipt.command_id, budget=RuntimeReadBudget()
    )
    assert original.record.dependencies == dep.reference


def test_expiry_after_preparation_rolls_back_assignment(case):
    pair = case[0]
    dep, _, _, _plan, prepared = assignment_preparation(case)
    before = prepared.snapshot.assignment
    pair.base.h.clock.instant = prepared.valid_until
    with pytest.raises(ValueError), pair.account.write_transaction() as connection:
        pair.base.h.store.install_prepared_in_transaction(
            connection, prepared, fence=pair.base.h.lease.fence
        )
    with pair.base.engine.connect() as connection:
        head = connection.execute(sa.select(daily_runtime_assignment_heads)).mappings().one()
    assert head["semantic_sha256"] == before.semantic_sha256
    assert dep.record.valid_until == prepared.valid_until


def test_changed_current_control_rejects_the_prepared_owner_request(case):
    from packages.domain.operational_control import (
        OperationalControlCommandKind,
        OperationalControlState,
    )

    pair = case[0]
    _, _, _, _plan, prepared = assignment_preparation(case)
    pair.base.h.controls.apply(
        pair.base.h.command(
            OperationalControlCommandKind.PAUSE, "owner-pause", OperationalControlState.PAUSED
        )
    )
    with pytest.raises(ValueError), pair.account.write_transaction() as connection:
        pair.base.h.store.install_prepared_in_transaction(
            connection, prepared, fence=pair.base.h.lease.fence
        )


@pytest.mark.parametrize("enabled", [False, True])
def test_sql_recheck_and_assignment_write_never_decode_read_objects_or_reduce(
    case, monkeypatch, enabled
):
    pair, reader, *_ = case
    if enabled:
        converge(case)
    dep = dependencies(case, proposed(case, enabled=enabled))
    _, _, _, _plan, prepared = assignment_preparation(case, dep)

    def forbidden(*args, **kwargs):
        raise AssertionError("heavy owner resolution under SQL")

    monkeypatch.setattr(codec, "decode_record", forbidden)
    monkeypatch.setattr(codec, "encode_record", forbidden)
    monkeypatch.setattr(pair.base.artifacts, "read", forbidden)
    monkeypatch.setattr(reader, "_fingerprint", forbidden)
    monkeypatch.setattr(reader, "_quiescent", forbidden)
    with pair.account.write_transaction() as connection:
        pair.base.h.store.install_prepared_in_transaction(
            connection, prepared, fence=pair.base.h.lease.fence
        )


@pytest.mark.parametrize("target", ["canonical", "request"])
def test_original_source_tamper_before_assignment_rolls_back(case, target):
    pair = case[0]
    _, command, _, _plan, prepared = assignment_preparation(case)
    with pair.base.engine.begin() as connection:
        if target == "canonical":
            connection.execute(
                sa.update(continuous_account_commits).values(canonical_payload=b"{}")
            )
        else:
            connection.execute(
                sa.update(journal_entries)
                .where(journal_entries.c.record_id == command.command_id)
                .values(payload=b"{}")
            )
    with pytest.raises(ValueError), pair.account.write_transaction() as connection:
        pair.base.h.store.install_prepared_in_transaction(
            connection, prepared, fence=pair.base.h.lease.fence
        )


def test_initial_disabled_assignment_requires_actual_genesis_and_no_existing_assignment(case):
    pair, _reader, *_ = case
    # Remove only fixture-created assignments before the actual tested initial
    # installation. The C genesis remains real and its immutable rows are intact.
    after = replace(proposed(case), generation=1, previous_assignment_sha256=None)
    with pair.base.engine.begin() as connection:
        connection.execute(sa.delete(daily_runtime_assignment_heads))
        connection.execute(sa.delete(daily_runtime_assignments))
    dep = dependencies(case, after)
    assert dep.record.previous.commit.sequence == 1
    assert dep.record.previous_assignment_sha256 is None
    _, _, _, _plan, prepared = assignment_preparation(case, dep)
    with pair.account.write_transaction() as connection:
        pair.base.h.store.install_prepared_in_transaction(
            connection, prepared, fence=pair.base.h.lease.fence
        )
    assert prepared.result.generation == 1 and not prepared.result.enabled_for_new_exposure


def test_dependency_object_is_source_only_and_bounds_complete_unique_object_graph(
    case, monkeypatch
):
    import packages.persistence.runtime_owner_dependencies as implementation

    dep = dependencies(case)
    assert not any(
        name in dep.record.__dataclass_fields__
        for name in ("command", "authentication", "owner", "verified", "quiescent")
    )
    monkeypatch.setattr(
        implementation,
        "MAX_TOTAL_BYTES",
        dep.record.previous.commit.transition.checkpoint.byte_count,
    )
    with pytest.raises(RuntimeOwnerDependencyError, match="SOURCE_OBJECT_BOUND"):
        case[1]._object_bound(dep)


def test_capture_reuses_complete_daily_tables_and_charges_aggregate_before_owner_reads(case):
    pair, reader, *_ = case
    dep, _, receipt = retained_request(case)
    plan = reader.prepare_owner_command_read(
        previous=dep.previous, original_receipt=receipt, fence=pair.base.h.lease.fence
    )
    budget = RuntimeReadBudget(
        payload_bytes=32 * 1024 * 1024, captured=list(plan.dependencies.daily.raw.tables)
    )
    with (
        pytest.raises(ValueError, match="aggregate"),
        pair.account.write_transaction() as connection,
    ):
        reader.capture_in_transaction(
            connection, account_id=pair.base.h.account, owner_command_ref=receipt, budget=budget
        )


def test_retained_request_cannot_outlive_original_dependency_deadline(case):
    pair, reader, _producer, auth, cookie, csrf = case
    dep = dependencies(case)
    pair.base.h.clock.instant += timedelta(seconds=1)
    at = pair.base.h.clock.instant
    # The actual session permits this 60-second command, but its source closure
    # expires one second earlier. The reader must retain that earlier boundary.
    command = RuntimeAssignmentCommand(
        "overlong-source-request",
        "simulation-owner",
        pair.base.h.account,
        dep.record.previous_assignment_sha256,
        dep.record.proposed.semantic_sha256,
        dep.record.heads,
        dep.record.semantic_sha256,
        at,
        at + timedelta(seconds=60),
    )
    authenticated = auth.authenticate(command, session_cookie=cookie, csrf_token=csrf, now=at)
    prepared = reader.commands.prepare(
        dep.record.scope,
        command=command,
        authenticated=authenticated,
        dependencies=dep.reference,
        expected_head=empty_head(journal_key(dep.record.scope)),
    )
    with pair.account.write_transaction() as connection:
        receipt = reader.commands.append_in_transaction(connection, prepared)
    with pytest.raises(RuntimeOwnerDependencyError, match="EXPIRED"):
        reader.prepare_owner_command_read(
            previous=dep.previous, original_receipt=receipt, fence=pair.base.h.lease.fence
        )


def test_later_control_does_not_rewrite_original_converged_heads(case):
    from packages.domain.operational_control import (
        OperationalControlCommandKind,
        OperationalControlState,
    )

    prior = converge(case)
    pair = case[0]
    pair.base.h.controls.apply(
        pair.base.h.command(
            OperationalControlCommandKind.PAUSE,
            "pause-after-convergence",
            OperationalControlState.PAUSED,
        )
    )
    with pytest.raises(RuntimeOwnerDependencyError, match="RECONCILIATION_HEADS_DIFFER"):
        dependencies(case, proposed(case, enabled=True))
    assert (
        prior.reconciliation.resolved.result.heads.control_revision
        == prior.continuous.receipt.commit.transition.resulting_heads.control_revision
    )


def test_original_requested_authentication_times_cannot_be_refreshed_under_same_command(case):
    pair, reader, _producer, auth, cookie, csrf = case
    dep, original, receipt = retained_request(case)
    at = original.requested_at + timedelta(seconds=1)
    changed = replace(original, requested_at=at)
    authenticated = auth.authenticate(changed, session_cookie=cookie, csrf_token=csrf, now=at)
    retry = reader.commands.prepare(
        dep.record.scope,
        command=changed,
        authenticated=authenticated,
        dependencies=dep.reference,
        expected_head=receipt.previous_head,
    )
    with pytest.raises(ValueError), pair.account.write_transaction() as connection:
        reader.commands.append_in_transaction(connection, retry)
    restored = reader.commands.read(
        dep.record.scope, command_id=original.command_id, budget=RuntimeReadBudget()
    )
    assert restored.record.command == original


def test_fresh_reconciliation_cannot_authorize_a_silent_engine_policy_change(case):
    converge(case)
    after = proposed(case, enabled=True)
    after = replace(
        after,
        policy=replace(after.policy, daily_loss_boundary=after.policy.daily_loss_boundary / 2),
    )
    with pytest.raises(RuntimeOwnerDependencyError, match="CUTOVER_UNSUPPORTED"):
        dependencies(case, after)


@pytest.mark.parametrize("enabled", [False, True])
def test_actual_post_install_source_and_full_b_readback_accept_only_own_write(
    case, monkeypatch, enabled
):
    pair = case[0]
    if enabled:
        converge(case)
    dep = dependencies(case, proposed(case, enabled=enabled))
    _, _, _, _plan, prepared = assignment_preparation(case, dep)
    pair.base.h.store.require_prepared_assignment(prepared)

    def forbidden(*args, **kwargs):
        raise AssertionError("no heavy resolution in assignment readback")

    with pair.account.write_transaction() as connection:
        pair.base.h.store.install_prepared_in_transaction(
            connection, prepared, fence=pair.base.h.lease.fence
        )
        with monkeypatch.context() as patch:
            patch.setattr(codec, "encode_record", forbidden)
            patch.setattr(codec, "decode_record", forbidden)
            patch.setattr(pair.base.artifacts, "read", forbidden)
            patch.setattr(case[1], "_fingerprint", forbidden)
            result = pair.base.h.store.recheck_installed_assignment_in_transaction(
                connection, prepared, fence=pair.base.h.lease.fence
            )
        assert result == dep.record.proposed


@pytest.mark.parametrize("change", ["deadline", "request", "assignment"])
def test_post_install_changed_state_or_source_deadline_rolls_back_own_assignment(case, change):
    pair = case[0]
    _, command, _, _plan, prepared = assignment_preparation(case)
    with pytest.raises(ValueError), pair.account.write_transaction() as connection:
        pair.base.h.store.install_prepared_in_transaction(
            connection, prepared, fence=pair.base.h.lease.fence
        )
        if change == "deadline":
            pair.base.h.clock.instant = prepared.valid_until
        elif change == "request":
            connection.execute(
                sa.update(journal_entries)
                .where(journal_entries.c.record_id == command.command_id)
                .values(payload=b"{}")
            )
        else:
            connection.execute(
                sa.update(daily_runtime_assignments)
                .where(daily_runtime_assignments.c.generation == prepared.result.generation)
                .values(command_payload=b"{}")
            )
        pair.base.h.store.recheck_installed_assignment_in_transaction(
            connection, prepared, fence=pair.base.h.lease.fence
        )
    with pair.base.engine.connect() as connection:
        head = connection.execute(sa.select(daily_runtime_assignment_heads)).mappings().one()
    assert head["semantic_sha256"] == prepared.snapshot.assignment.semantic_sha256
