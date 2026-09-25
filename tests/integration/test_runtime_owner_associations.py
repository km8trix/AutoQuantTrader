"""Original signed assignment evidence after expiry; no renewed owner authority."""

from dataclasses import replace
from datetime import timedelta

import pytest
import sqlalchemy as sa

from packages.application import personal_codec as codec
from packages.domain.continuous_runtime_source_contracts import runtime_producer_map
from packages.domain.daily_runtime_contracts import RuntimeProducerSpec
from packages.domain.operational_control import (
    OperationalControlCommandKind,
    OperationalControlState,
)
from packages.domain.personal_contracts import content_digest
from packages.persistence.daily_runtime_risk import RuntimeReadBudget
from packages.persistence.daily_runtime_risk_schema import daily_runtime_assignments
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.durable_journal_schema import journal_entries
from packages.persistence.runtime_owner_associations import SqlRuntimeOwnerAssociations
from packages.persistence.runtime_owner_dependencies import RuntimeOwnerDependencyError
from tests.integration.test_continuous_composition import ActualDailyHarness
from tests.integration.test_continuous_reconciliation_publication import PublicationCase
from tests.integration.test_runtime_owner_dependencies import (
    assignment_preparation,
    attach,
    converge,
    dependencies,
    proposed,
)
from tests.integration.test_runtime_owner_dependencies import (
    case as case,
)


def genuine_empty_b_bootstrap(tmp_path, monkeypatch):
    """Create a real C genesis while B has never received a fixture assignment.

    Only setup configuration normalization is retained; fixture assignment and
    enable helpers are suppressed before C genesis is prepared and committed.
    """

    def configure_without_assignment(harness, assignment):
        spec = harness.inputs.spec
        harness.assignment = replace(
            assignment,
            account_binding_sha256=spec.account_binding_sha256,
            policy=spec.risk_policy,
            strategy=spec.strategy,
            configuration_sha256=content_digest(spec.strategy_configuration),
            effective_at=spec.initialized_at,
            instrument_symbols=spec.instruments,
        )

    with monkeypatch.context() as patch:
        patch.setattr(ActualDailyHarness, "install", configure_without_assignment)
        patch.setattr(ActualDailyHarness, "enable", lambda _self: None)
        pair = PublicationCase(tmp_path)
    case = pair.base
    daily = case.template
    case.h.producer_map = runtime_producer_map(
        account_id=case.h.account,
        venue_model=pair.model,
        daily=RuntimeProducerSpec(
            role="daily_inputs",
            producer=daily.producer,
            provider_id=daily.source.provider,
            source_environment=daily.source.environment,
            account_scope=case.h.account,
        ),
        quotes=RuntimeProducerSpec(
            role="quotes",
            producer=daily.producer,
            provider_id="etrade",
            source_environment="production",
            account_scope=case.h.account,
        ),
    )
    case.h.assignment = replace(
        case.h.assignment, producer_map_sha256=case.h.producer_map.semantic_sha256
    )
    reader, producer, auth, cookie, csrf = attach(pair)
    current = case.h.store.resolve_snapshot(
        case.h.store.read_snapshot(account_id=case.h.account, fence=case.h.lease.fence)
    )
    assert current.assignment is None and not current.assignment_rows
    return pair, reader, producer, auth, cookie, csrf


def install_initial_signed_assignment(case):
    pair = case[0]
    initial = replace(
        pair.base.h.assignment,
        generation=1,
        previous_assignment_sha256=None,
        enabled_for_new_exposure=False,
    )
    dep = dependencies(case, initial)
    values = assignment_preparation(case, dep)
    prepared = values[-1]
    pair.base.h.store.require_prepared_assignment(prepared)
    with pair.account.write_transaction() as connection:
        pair.base.h.store.install_prepared_in_transaction(
            connection, prepared, fence=pair.base.h.lease.fence
        )
        pair.base.h.store.recheck_installed_assignment_in_transaction(
            connection, prepared, fence=pair.base.h.lease.fence
        )
    return values


def current(case):
    pair = case[0]
    return pair.base.h.store.resolve_snapshot(
        pair.base.h.store.read_snapshot(
            account_id=pair.base.h.account, fence=pair.base.h.lease.fence
        )
    )


def install(case, dep=None):
    values = assignment_preparation(case, dep)
    prepared = values[-1]
    pair = case[0]
    with pair.account.write_transaction() as connection:
        pair.base.h.store.install_prepared_in_transaction(
            connection, prepared, fence=pair.base.h.lease.fence
        )
        pair.base.h.store.recheck_installed_assignment_in_transaction(
            connection, prepared, fence=pair.base.h.lease.fence
        )
    return values


def association(case, generation, snapshot=None):
    reader = SqlRuntimeOwnerAssociations(owner_dependencies=case[1])
    value = reader.read(
        case[0].base.scope, current=snapshot or current(case), assignment_generation=generation
    )
    return reader, value


def test_genuine_initial_assignment_binds_prior_real_genesis_without_fixture_owner_journal(
    tmp_path, monkeypatch
):
    fixture = genuine_empty_b_bootstrap(tmp_path, monkeypatch)
    pair = fixture[0]
    try:
        dep, command, receipt, _plan, prepared = install_initial_signed_assignment(fixture)
        reader, value = association(fixture, 1)
        assert value.dependencies == dep.record
        assert value.request.record.command == command
        assert value.request.read.receipt == receipt
        assert value.canonical.receipt.commit.sequence == 1
        assert value.prefix.before_assignment is None
        assert value.prefix.after_assignment == prepared.result
        assert value.reconciliation is None
        reader.require_association(value)
        with _repeatable_read_transaction(pair.base.engine) as connection:
            reader.recheck_in_transaction(connection, value)
    finally:
        pair.close()


def test_applied_owner_association_preserves_expired_original_times_and_never_restores_account(
    case, monkeypatch
):
    dep, command, _, _plan, prepared = install(case)
    pair = case[0]
    pair.base.h.coordinator.release(pair.base.h.lease.fence)
    pair.base.h.clock.instant = command.expires_at + timedelta(days=1)
    pair.base.h.lease = pair.base.h.coordinator.acquire("owner")
    snapshot = current(case)

    def forbidden(*args, **kwargs):
        raise AssertionError("historical owner evidence must not renew or restore current state")

    monkeypatch.setattr(pair.account, "restore", forbidden)
    monkeypatch.setattr(pair.base.h.store, "read_snapshot", forbidden)
    monkeypatch.setattr(pair.base.h.store, "resolve_snapshot", forbidden)
    monkeypatch.setattr(case[1].commands.authenticator, "require_authenticated", forbidden)
    reader, value = association(case, prepared.result.generation, snapshot)
    reader.require_owned(value)
    assert value.dependencies == dep.record
    assert value.request.record.command.requested_at == command.requested_at
    assert value.request.record.command.expires_at == command.expires_at
    assert not hasattr(value, "current_heads") and not hasattr(value, "verified")


def test_enabled_assignment_authenticates_original_a_comparison_after_expiry(case):
    prior = converge(case)
    dep = dependencies(case, proposed(case, enabled=True))
    _, command, _, _plan, prepared = install(case, dep)
    pair = case[0]
    pair.base.h.coordinator.release(pair.base.h.lease.fence)
    pair.base.h.clock.instant = command.expires_at + timedelta(days=1)
    pair.base.h.lease = pair.base.h.coordinator.acquire("owner")
    reader, value = association(case, prepared.result.generation)
    assert value.reconciliation.receipt == prior.reconciliation.receipt
    assert (
        value.reconciliation.resolved.result.completed_at
        == prior.reconciliation.resolved.result.completed_at
    )
    reader.require_association(value)
    with _repeatable_read_transaction(pair.base.engine) as connection:
        reader.recheck_in_transaction(connection, value)


def test_fixture_assignment_rows_are_not_relabelled_as_real_owner_requests(case):
    with pytest.raises(RuntimeOwnerDependencyError, match="ACTUAL_REQUEST_REQUIRED"):
        association(case, 1)


@pytest.mark.parametrize("kind", ["clone", "nested"])
def test_historical_association_rejects_forged_or_mutated_original_ownership(case, kind):
    *_, prepared = install(case)
    reader, value = association(case, prepared.result.generation)
    if kind == "clone":
        value = replace(value)
    else:
        object.__setattr__(value.dependencies.heads, "capacity_sha256", "9" * 64)
    with pytest.raises(RuntimeOwnerDependencyError):
        reader.require_association(value)


def test_historical_recheck_is_sql_only_and_does_not_require_current_authority(case, monkeypatch):
    *_, prepared = install(case)
    reader, value = association(case, prepared.result.generation)
    reader.require_association(value)

    def forbidden(*args, **kwargs):
        raise AssertionError("historical SQL recheck cannot decode, replay or renew")

    monkeypatch.setattr(codec, "encode_record", forbidden)
    monkeypatch.setattr(codec, "decode_record", forbidden)
    monkeypatch.setattr(case[0].base.artifacts, "read", forbidden)
    monkeypatch.setattr(
        type(case[0].base.h.coordinator), "revalidate_for_commit_in_transaction", forbidden
    )
    monkeypatch.setattr(reader, "_fingerprint", forbidden)
    with _repeatable_read_transaction(case[0].base.engine) as connection:
        reader.recheck_in_transaction(connection, value)


@pytest.mark.parametrize("kind", ["request", "assignment"])
def test_original_request_or_assignment_tamper_invalidates_historical_association(case, kind):
    _, command, _, _plan, prepared = install(case)
    reader, value = association(case, prepared.result.generation)
    with case[0].base.engine.begin() as connection:
        if kind == "request":
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
    with pytest.raises(ValueError), _repeatable_read_transaction(case[0].base.engine) as connection:
        reader.recheck_in_transaction(connection, value)


def test_historical_source_sql_capture_respects_the_shared_budget(case):
    *_, prepared = install(case)
    reader = SqlRuntimeOwnerAssociations(owner_dependencies=case[1])
    with pytest.raises(ValueError):
        reader.read(
            case[0].base.scope,
            current=current(case),
            assignment_generation=prepared.result.generation,
            budget=RuntimeReadBudget(payload_bytes=32 * 1024 * 1024),
        )


def test_later_independent_stop_preserves_original_assignment_association(case):
    *_, prepared = install(case)
    reader, original = association(case, prepared.result.generation)
    harness = case[0].base.h
    harness.controls.apply(
        harness.command(
            OperationalControlCommandKind.HALT,
            "later-owner-audit-stop",
            OperationalControlState.HALTED,
        )
    )
    later = reader.read(
        case[0].base.scope, current=current(case), assignment_generation=prepared.result.generation
    )
    assert later.dependencies == original.dependencies
    assert later.prefix.control == original.prefix.control
    with _repeatable_read_transaction(case[0].base.engine) as connection:
        reader.recheck_in_transaction(connection, original)
        reader.recheck_in_transaction(connection, later)
