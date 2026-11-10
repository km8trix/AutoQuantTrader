"""Reconstruct disabled selections as historical evidence, never renewed authority."""

from dataclasses import replace
from datetime import timedelta
from threading import Event
from types import SimpleNamespace

import pytest
import sqlalchemy as sa

from apps.api.runtime_owner_authentication import LocalRuntimeOwnerAuthenticator
from apps.trader.synthetic_initial_selection import prepare_synthetic_initial_selection
from apps.trader.synthetic_session_genesis import (
    initialize_synthetic_session,
    reconstruct_selected_synthetic_session_owners,
    reconstruct_synthetic_session_owners,
)
from apps.trader.synthetic_session_graph import build_synthetic_session_graph
from packages.application import personal_codec as codec
from packages.domain.account_coordinator import AccountCoordinatorError, AccountLeasePolicy
from packages.domain.operational_control import (
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlCommand,
    OperationalControlCommandKind,
    OperationalControlState,
)
from packages.domain.personal_contracts import content_digest
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.continuous_account_schema import continuous_account_heads
from packages.persistence.daily_runtime_risk_schema import (
    daily_runtime_assignment_heads,
    daily_runtime_assignments,
)
from packages.persistence.durable_journal_schema import journal_entries
from packages.persistence.operational_control import SqlOperationalControlRepository
from packages.persistence.runtime_assignment_publication import SqlRuntimeAssignmentPublication
from packages.persistence.runtime_owner_associations import SqlRuntimeOwnerAssociations
from packages.persistence.runtime_owner_commands import journal_key
from packages.persistence.runtime_owner_dependencies import (
    RuntimeOwnerDependencyError,
    SqlRuntimeOwnerDependencies,
)
from packages.persistence.schema import phase2_account_lease_heads
from packages.persistence.stateful_venue import SqlStatefulVenue
from tests.integration.test_continuous_synthetic_initial_selection import _facts, _publish, _request
from tests.integration.test_continuous_synthetic_session_genesis import captured as captured


@pytest.fixture
def selected(captured):
    bootstrap, ports = captured
    genesis = initialize_synthetic_session(bootstrap, **ports)
    coordinator = genesis.account.coordinator
    study = SimpleNamespace(
        bootstrap=bootstrap,
        genesis=genesis,
        ports=ports,
        lease=coordinator.acquire("synthetic-selected-owner-test"),
    )
    try:
        study.owners = reconstruct_synthetic_session_owners(genesis, lease=study.lease)
        study.dependencies = prepare_synthetic_initial_selection(
            genesis, owners=study.owners, lease=study.lease
        )
        # The separate fixture API performs actual session/CSRF authentication.
        # The worker still has its original disabled authenticator.
        study.request = _request(study, lifetime=1)
        study.assignment = _publish(study, study.request)
        yield study
    finally:
        current = coordinator.current()
        if current is not None:
            assert current.fence == study.lease.fence
            coordinator.release(study.lease.fence)
        assert coordinator.current() is None


def _continue(study, **changes):
    return reconstruct_selected_synthetic_session_owners(
        study.genesis, **{"lease": study.lease, **changes}
    )


def _inventory(study, owners):
    return owners.daily.resolve_snapshot(
        owners.daily.read_snapshot(
            account_id=study.genesis.scope.account_id, fence=study.lease.fence
        )
    )


def _head(study):
    with study.ports["account_engine"].connect() as connection:
        return dict(connection.execute(sa.select(phase2_account_lease_heads)).mappings().one())


def _halt(study, name):
    return SqlOperationalControlRepository(
        engine=study.ports["account_engine"], clock=study.ports["clock"]
    ).apply(
        OperationalControlCommand(
            study.genesis.scope.account_id,
            name,
            OperationalControlCommandKind.HALT,
            OperationalControlState.HALTED,
            OperationalControlActor(
                "synthetic-test-system",
                OperationalControlActorKind.SYSTEM,
                content_digest(name),
                None,
            ),
            "TEST_SELECTED_OWNER_LATER_HALT",
            content_digest(name),
            study.ports["clock"].now(),
        )
    )


def _assert_unchanged(study, facts):
    assert _facts(study) == facts
    assert study.genesis.account.coordinator.current() == study.lease
    assert study.genesis.runtime_sources.attempt_sources is None
    assert study.genesis.runtime_sources.observed_hold_sources is None
    assert not study.genesis.owners.commands.authenticator.security._enabled


def _forbid_new_authority(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("historical continuation attempted new authority or publication")

    monkeypatch.setattr(SqlRuntimeOwnerDependencies, "prepare_owner_command_read", forbidden)
    monkeypatch.setattr(LocalRuntimeOwnerAuthenticator, "authenticate", forbidden)
    monkeypatch.setattr(LocalRuntimeOwnerAuthenticator, "require_authenticated", forbidden)
    monkeypatch.setattr(SqlRuntimeAssignmentPublication, "publish", forbidden)
    monkeypatch.setattr(SqlAccountCoordinator, "acquire", forbidden)
    monkeypatch.setattr(SqlAccountCoordinator, "renew", forbidden)
    monkeypatch.setattr(SqlAccountCoordinator, "release", forbidden)
    monkeypatch.setattr(SqlStatefulVenue, "initialize", forbidden)
    monkeypatch.setattr(SqlStatefulVenue, "execute", forbidden)


def test_actual_selected_halted_owners_reconstruct_without_new_authority_or_fact_changes(
    selected, monkeypatch
):
    study = selected
    original, old = study.owners, study.genesis.runtime_sources
    before, head_before = _facts(study), _head(study)
    study.ports["clock"].advance_to(study.lease.acquired_at + timedelta(milliseconds=500))
    with monkeypatch.context() as operation:
        _forbid_new_authority(operation)
        current = _continue(study)
        assert (
            current.account is not original.account and current.account is not study.genesis.account
        )
        assert current.runtime is not original.runtime and current.runtime is not old
        assert current.daily is not original.daily and current.owners is not original.owners
        assert (
            current.runtime.accounts is current.account and current.runtime.daily is current.daily
        )
        assert current.daily.producers is current.runtime
        assert current.owners.commands is study.genesis.owners.commands
        assert current.runtime.current_fence() == study.lease.fence
        assert current.account.composer.fence == study.lease.fence
        assert (
            current.runtime.attempt_sources is None
            and current.runtime.observed_hold_sources is None
        )
        assert (
            old.accounts is study.genesis.account
            and old.current_fence() == study.genesis.lease.fence
        )
        restored = current.account.restore(study.genesis.scope)
        assert restored.receipt == study.genesis.restored.receipt
        assert restored.checkpoint == study.genesis.restored.checkpoint
        inventory = _inventory(study, current)
        assert inventory.assignment == study.assignment
        assert inventory.assignment_rows == (study.assignment,)
        assert inventory.assignment.generation == 1
        assert (
            not inventory.assignment.enabled_for_new_exposure
            and not inventory.assignment.live_authorized
        )
        assert inventory.control == study.genesis.control
        assert inventory.control.effective_state is OperationalControlState.HALTED
        assert not inventory.admissions and not inventory.obligations.bindings
        assert (
            not inventory.attempts
            and not inventory.attempt_envelopes
            and not inventory.observed_groups
        )
        _assert_unchanged(study, before)
        head_after = _head(study)
        assert {key: value for key, value in head_after.items() if key != "updated_at"} == {
            key: value for key, value in head_before.items() if key != "updated_at"
        }
        assert head_after["updated_at"] >= head_before["updated_at"]


def test_expired_original_request_is_only_historical_evidence_under_fresh_caller_lease(
    selected, monkeypatch
):
    study = selected
    coordinator = study.genesis.account.coordinator
    prior = study.lease
    coordinator.release(prior.fence)
    study.ports["clock"].advance_to(study.request.command.expires_at + timedelta(days=1))
    study.lease = coordinator.acquire("synthetic-later-selected-owner")
    assert study.lease.fence.fencing_generation > prior.fence.fencing_generation
    assert study.ports["clock"].now() > study.request.command.expires_at
    before = _facts(study)
    with monkeypatch.context() as operation:
        _forbid_new_authority(operation)
        current = _continue(study)
        inventory = _inventory(study, current)
        reader = SqlRuntimeOwnerAssociations(owner_dependencies=current.owners)
        association = reader.read(study.genesis.scope, current=inventory, assignment_generation=1)
        reader.require_association(association)
        assert association.dependencies == study.dependencies.record
        assert association.dependencies.fence.fence == prior.fence
        assert association.request.read.receipt == study.request.receipt
        assert association.request.record.command == study.request.command
        assert association.request.record.command.requested_at == study.request.command.requested_at
        assert association.request.record.command.expires_at == study.request.command.expires_at
        assert association.prefix.recorded_at < study.request.command.expires_at
        assert association.canonical.receipt == study.genesis.restored.receipt
        assert association.dependencies.proposed == study.assignment
        assert association.reconciliation is None
        assert not hasattr(association, "verified") and not hasattr(association, "current_heads")
        _assert_unchanged(study, before)


def test_empty_b_api_remains_closed_after_selection(selected):
    before = _facts(selected)
    with pytest.raises(ValueError, match="CURRENT_HALTED_EMPTY_SYNTHETIC_GENESIS_REQUIRED"):
        reconstruct_synthetic_session_owners(selected.genesis, lease=selected.lease)
    _assert_unchanged(selected, before)


@pytest.mark.parametrize("request_retained", [False, True])
def test_selected_api_requires_actual_installed_selection_not_empty_b(captured, request_retained):
    bootstrap, ports = captured
    genesis = initialize_synthetic_session(bootstrap, **ports)
    lease = genesis.account.coordinator.acquire("synthetic-empty-selection-denial")
    study = SimpleNamespace(genesis=genesis, ports=ports, lease=lease)
    try:
        if request_retained:
            study.owners = reconstruct_synthetic_session_owners(genesis, lease=lease)
            study.dependencies = prepare_synthetic_initial_selection(
                genesis, owners=study.owners, lease=lease
            )
            study.request = _request(study)
        before = _facts(study)
        with pytest.raises(
            ValueError, match="CURRENT_HALTED_DISABLED_INITIAL_SYNTHETIC_SELECTION_REQUIRED"
        ):
            _continue(study)
        _assert_unchanged(study, before)
    finally:
        genesis.account.coordinator.release(lease.fence)


def test_selected_owners_feed_original_halted_session_graph_without_send(selected):
    current = _continue(selected)
    before = _facts(selected)
    session = build_synthetic_session_graph(
        account=current.account,
        runtime=current.runtime,
        daily=current.daily,
        venue_sources=current.venue_sources,
        venue_engine=selected.ports["venue_engine"],
        venue_artifacts=selected.ports["venue_artifacts"],
        codec=codec,
        capture_clock=selected.ports["clock"].now,
        stop_event=Event(),
    )
    assert session.account is current.account and session.runtime is current.runtime
    assert session.delivery.venue.verified_sources is session.delivery
    assert not session.delivery.venue.read().state.commands
    assert not session.delivery.venue.read().state.accounting.submissions
    assert _inventory(selected, current).assignment == selected.assignment
    _assert_unchanged(selected, before)


@pytest.mark.parametrize("kind", ["copied", "foreign"])
def test_association_must_belong_to_actual_historical_reader(selected, monkeypatch, kind):
    original = SqlRuntimeOwnerAssociations.read

    def unowned(reader, *args, **kwargs):
        if kind == "copied":
            return replace(original(reader, *args, **kwargs))
        other = SqlRuntimeOwnerAssociations(owner_dependencies=reader.owner_dependencies)
        return original(other, *args, **kwargs)

    monkeypatch.setattr(SqlRuntimeOwnerAssociations, "read", unowned)
    before = _facts(selected)
    with pytest.raises(
        RuntimeOwnerDependencyError, match="OWNED_HISTORICAL_OWNER_ASSOCIATION_REQUIRED"
    ):
        _continue(selected)
    _assert_unchanged(selected, before)


@pytest.mark.parametrize("kind", ["request", "assignment", "dependencies", "capture_source"])
def test_tampered_original_history_is_not_adopted_or_repaired(selected, kind):
    study = selected
    if kind in ("request", "assignment"):
        with study.ports["account_engine"].begin() as connection:
            if kind == "request":
                result = connection.execute(
                    sa.update(journal_entries)
                    .where(
                        journal_entries.c.key_sha256
                        == journal_key(study.genesis.scope).semantic_sha256
                    )
                    .values(payload=b"{}")
                )
            else:
                result = connection.execute(
                    sa.update(daily_runtime_assignments)
                    .where(daily_runtime_assignments.c.account_id == study.genesis.scope.account_id)
                    .values(command_payload=b"{}")
                )
            assert result.rowcount == 1
    else:
        reference = (
            study.dependencies.reference.object_ref
            if kind == "dependencies"
            else study.genesis.restored.receipt.commit.source_evidence.object_ref
        )
        path = study.ports["account_artifacts"]._root / (reference.object_sha256 + ".json")
        original = path.read_bytes()
        path.write_bytes(b"X" * len(original))
    before = _facts(study)
    with pytest.raises(ValueError):
        _continue(study)
    _assert_unchanged(study, before)


@pytest.mark.parametrize("kind", ["control", "canonical_head", "assignment_head"])
def test_changed_current_heads_before_capture_are_not_selected(selected, kind):
    if kind == "control":
        changed = _halt(selected, "before-selected-continuation-halt")
        assert changed != selected.genesis.control
    else:
        with selected.ports["account_engine"].begin() as connection:
            if kind == "canonical_head":
                connection.execute(
                    sa.update(continuous_account_heads).values(
                        checkpoint_sha256=content_digest("changed-head")
                    )
                )
            else:
                connection.execute(sa.delete(daily_runtime_assignment_heads))
    before = _facts(selected)
    with pytest.raises(ValueError):
        _continue(selected)
    _assert_unchanged(selected, before)


@pytest.mark.parametrize(
    "kind", ["control", "canonical_head", "assignment_head", "request", "lease_revision"]
)
def test_changes_after_owned_historical_capture_fail_terminal_current_rechecks(
    selected, monkeypatch, kind
):
    original = SqlRuntimeOwnerAssociations.require_association
    changes = []

    def change_after_capture(reader, association):
        original(reader, association)
        if changes:
            return
        if kind == "control":
            _halt(selected, "after-selected-capture-halt")
        elif kind == "lease_revision":
            selected.ports["clock"].advance_to(
                selected.lease.acquired_at + timedelta(milliseconds=500)
            )
            renewed = selected.genesis.account.coordinator.renew(selected.lease.fence)
            assert renewed != selected.lease and renewed.fence == selected.lease.fence
        else:
            with selected.ports["account_engine"].begin() as connection:
                if kind == "canonical_head":
                    connection.execute(
                        sa.update(continuous_account_heads).values(
                            checkpoint_sha256=content_digest("after-capture-head")
                        )
                    )
                elif kind == "assignment_head":
                    connection.execute(sa.delete(daily_runtime_assignment_heads))
                else:
                    connection.execute(
                        sa.update(journal_entries)
                        .where(
                            journal_entries.c.key_sha256
                            == journal_key(selected.genesis.scope).semantic_sha256
                        )
                        .values(payload=b"{}")
                    )
        changes.append(_facts(selected))

    monkeypatch.setattr(SqlRuntimeOwnerAssociations, "require_association", change_after_capture)
    with pytest.raises(ValueError):
        _continue(selected)
    assert len(changes) == 1
    assert _facts(selected) == changes[0]
    current = selected.genesis.account.coordinator.current()
    if kind == "lease_revision":
        assert current != selected.lease and current.fence == selected.lease.fence
    else:
        assert current == selected.lease
    assert not selected.genesis.owners.commands.authenticator.security._enabled


def test_released_startup_fence_cannot_continue_selected_owners(selected):
    before = _facts(selected)
    with pytest.raises(AccountCoordinatorError, match="account fence is no longer current"):
        _continue(selected, lease=selected.genesis.lease)
    _assert_unchanged(selected, before)


def test_same_fence_stale_lease_revision_cannot_continue_selected_owners(selected):
    selected.ports["clock"].advance_to(selected.lease.acquired_at + timedelta(milliseconds=500))
    renewed = selected.genesis.account.coordinator.renew(selected.lease.fence)
    before = _facts(selected)
    with pytest.raises(ValueError, match="CURRENT_SYNTHETIC_LEASE_REVISION_REQUIRED"):
        _continue(selected)
    assert _facts(selected) == before
    assert selected.genesis.account.coordinator.current() == renewed


def test_actual_other_account_fence_cannot_continue_this_selection(selected):
    clock = selected.ports["clock"]
    coordinator = SqlAccountCoordinator(
        account_id="another-synthetic-selected-account",
        authority=SqlAccountCoordinatorAuthority(
            engine=selected.ports["account_engine"],
            clock=clock,
            policy=AccountLeasePolicy(
                "another-synthetic-lease",
                "1",
                timedelta(seconds=60),
                timedelta(seconds=5),
                timedelta(seconds=10),
            ),
        ),
    )
    other = coordinator.acquire("another-synthetic-owner")
    try:
        before = _facts(selected)
        with pytest.raises(ValueError, match="EXACT_SYNTHETIC_ACCOUNT_LEASE_REQUIRED"):
            _continue(selected, lease=other)
        _assert_unchanged(selected, before)
        assert coordinator.current() == other
    finally:
        coordinator.release(other.fence)
