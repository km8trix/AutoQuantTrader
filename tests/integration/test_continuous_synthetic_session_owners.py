"""Same-process reconstruction uses original current leases and real stored genesis."""

from dataclasses import replace
from datetime import timedelta
from threading import Event

import pytest
import sqlalchemy as sa

from apps.trader.synthetic_session_genesis import (
    initialize_synthetic_session,
    reconstruct_synthetic_session_owners,
)
from apps.trader.synthetic_session_graph import build_synthetic_session_graph
from packages.application import personal_codec as codec
from packages.domain.account_coordinator import AccountCoordinatorError, AccountLeasePolicy
from packages.domain.continuous_forward_contracts import ContinuousForwardClosure
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
from packages.persistence.continuous_account import ContinuousAccountConflict
from packages.persistence.continuous_account_schema import CONTINUOUS_ACCOUNT_TABLES
from packages.persistence.daily_runtime_risk_schema import DAILY_RUNTIME_TABLES
from packages.persistence.durable_journal_schema import JOURNAL_TABLES
from packages.persistence.operational_control import SqlOperationalControlRepository
from packages.persistence.schema import (
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
    phase5_operational_control_completions,
    phase5_operational_control_heads,
    phase5_operational_control_transitions,
)
from tests.integration.test_continuous_synthetic_session_genesis import captured as captured


@pytest.fixture
def active_genesis(captured):
    bootstrap, ports = captured
    genesis = initialize_synthetic_session(bootstrap, **ports)
    coordinator = genesis.account.coordinator
    lease = coordinator.acquire("synthetic-owner-reconstruction")
    try:
        yield genesis, ports, lease
    finally:
        # Reconstruction never assumes this lifecycle, including its failures.
        coordinator.release(lease.fence)
        assert coordinator.current() is None


def _rows(engine, tables):
    with engine.connect() as connection:
        return tuple(
            tuple(dict(row) for row in connection.execute(sa.select(table)).mappings())
            for table in tables
        )


def _facts(ports):
    account_tables = (
        *CONTINUOUS_ACCOUNT_TABLES,
        *DAILY_RUNTIME_TABLES,
        *JOURNAL_TABLES,
        phase5_operational_control_transitions,
        phase5_operational_control_heads,
        phase5_operational_control_completions,
        phase2_account_leases,
        phase2_account_lease_releases,
    )
    return (
        _rows(ports["account_engine"], account_tables),
        _rows(ports["venue_engine"], JOURNAL_TABLES),
        tuple(
            tuple(sorted((path.name, path.read_bytes()) for path in store._root.iterdir()))
            for store in (ports["account_artifacts"], ports["venue_artifacts"])
        ),
    )


def _head(engine):
    with engine.connect() as connection:
        return dict(connection.execute(sa.select(phase2_account_lease_heads)).mappings().one())


def test_reconstruction_authenticates_current_genesis_and_retains_callers_lease(active_genesis):
    genesis, ports, lease = active_genesis
    original = genesis.runtime_sources
    before = _facts(ports)
    head_before = _head(ports["account_engine"])
    ports["clock"].advance_to(lease.acquired_at + timedelta(seconds=1))

    current = reconstruct_synthetic_session_owners(genesis, lease=lease)

    assert current.account is not genesis.account
    assert current.daily is not genesis.daily
    assert current.runtime is not original
    assert current.owners is not genesis.owners
    assert current.account.preparer is not genesis.account.preparer
    assert current.account.composer is not genesis.account.composer
    assert current.owners.publisher is not genesis.owners.publisher
    assert current.account.coordinator is genesis.account.coordinator
    assert current.runtime.accounts is current.account
    assert current.runtime.daily is current.daily
    assert current.daily.producers is current.runtime
    assert current.account.composer.producer_history is current.runtime
    assert current.account.composer.venue_sources is current.venue_sources
    assert current.venue_sources is genesis.owners.publisher.sources
    assert current.owners.commands is genesis.owners.commands
    assert current.runtime.operating is original.operating
    assert current.runtime.forward_sources is original.forward_sources
    assert current.runtime.accounting is original.accounting
    assert current.runtime.strategy is original.strategy
    assert current.runtime.current_fence() == lease.fence
    assert current.account.composer.fence == lease.fence
    assert current.runtime.attempt_sources is None
    assert current.runtime.observed_hold_sources is None
    assert original.accounts is genesis.account and original.daily is genesis.daily
    assert original.owner_dependencies is genesis.owners
    assert original.attempt_sources is None and original.observed_hold_sources is None
    assert original.current_fence() == genesis.lease.fence
    assert genesis.account.composer.fence == genesis.lease.fence
    assert not genesis.owners.commands.authenticator.security._enabled
    assert not genesis.owners.commands.authenticator._owned
    restored = current.account.restore(genesis.scope)
    assert restored is not None
    assert restored.receipt == genesis.restored.receipt
    assert restored.checkpoint == genesis.restored.checkpoint
    current.account.require_resolved(restored)
    inventory = current.daily.resolve_snapshot(
        current.daily.read_snapshot(account_id=genesis.scope.account_id, fence=lease.fence)
    )
    assert inventory.assignment is None and not inventory.assignment_rows
    assert not inventory.admissions and not inventory.obligations.bindings
    assert not inventory.attempts and not inventory.observed_groups
    assert inventory.control == genesis.control
    assert inventory.control.effective_state is OperationalControlState.HALTED
    assert _facts(ports) == before
    head_after = _head(ports["account_engine"])
    assert {key: value for key, value in head_before.items() if key != "updated_at"} == {
        key: value for key, value in head_after.items() if key != "updated_at"
    }
    assert head_after["updated_at"] >= head_before["updated_at"]
    assert genesis.account.coordinator.current() == lease
    assert ports["clock"].now() == lease.acquired_at + timedelta(seconds=1)
    with pytest.raises(ContinuousAccountConflict, match=r"^CONTINUOUS_RETAINED_INDEX_INVALID$"):
        genesis.account.restore(genesis.scope)
    assert _facts(ports) == before


def test_reconstructed_owners_feed_original_session_graph_without_sending(active_genesis):
    genesis, ports, lease = active_genesis
    current = reconstruct_synthetic_session_owners(genesis, lease=lease)
    before = _facts(ports)
    stop = Event()
    session = build_synthetic_session_graph(
        account=current.account,
        runtime=current.runtime,
        daily=current.daily,
        venue_sources=current.venue_sources,
        venue_engine=ports["venue_engine"],
        venue_artifacts=ports["venue_artifacts"],
        codec=codec,
        capture_clock=ports["clock"].now,
        stop_event=stop,
    )
    assert session.account is current.account
    assert session.runtime is current.runtime
    assert session.stop_event is stop
    assert session.delivery.venue.verified_sources is session.delivery
    assert current.runtime.attempt_sources is session.attempts
    assert current.runtime.observed_hold_sources is not None
    assert not session.delivery.venue.read().state.commands
    assert _facts(ports) == before
    assert genesis.account.coordinator.current() == lease
    assert genesis.runtime_sources.attempt_sources is None
    assert genesis.runtime_sources.observed_hold_sources is None


def test_released_startup_lease_cannot_reconstruct_current_owners(active_genesis):
    genesis, ports, lease = active_genesis
    before = _facts(ports)
    with pytest.raises(AccountCoordinatorError, match="account fence is no longer current"):
        reconstruct_synthetic_session_owners(genesis, lease=genesis.lease)
    assert _facts(ports) == before
    assert genesis.account.coordinator.current() == lease
    assert genesis.runtime_sources.attempt_sources is None


def test_renewed_fence_requires_actual_current_revision_not_stale_lease_value(active_genesis):
    genesis, ports, lease = active_genesis
    coordinator = genesis.account.coordinator
    ports["clock"].advance_to(lease.acquired_at + timedelta(seconds=1))
    renewed = coordinator.renew(lease.fence)
    assert renewed.fence == lease.fence and renewed != lease
    before = _facts(ports)
    with pytest.raises(ValueError, match=r"^CURRENT_SYNTHETIC_LEASE_REVISION_REQUIRED$"):
        reconstruct_synthetic_session_owners(genesis, lease=lease)
    assert _facts(ports) == before
    assert coordinator.current() == renewed
    current = reconstruct_synthetic_session_owners(genesis, lease=renewed)
    assert current.runtime.current_fence() == renewed.fence
    assert coordinator.current() == renewed
    assert _facts(ports) == before


def test_genuine_other_account_lease_cannot_reconstruct_this_genesis(active_genesis):
    genesis, ports, lease = active_genesis
    other = SqlAccountCoordinator(
        account_id="different-synthetic-account",
        authority=SqlAccountCoordinatorAuthority(
            engine=ports["account_engine"],
            clock=ports["clock"],
            policy=AccountLeasePolicy(
                "synthetic-session-account-lease/1",
                "1",
                timedelta(seconds=60),
                timedelta(seconds=5),
                timedelta(seconds=10),
            ),
        ),
    )
    foreign = other.acquire("different-owner")
    try:
        before = _facts(ports)
        with pytest.raises(ValueError, match=r"^EXACT_SYNTHETIC_ACCOUNT_LEASE_REQUIRED$"):
            reconstruct_synthetic_session_owners(genesis, lease=foreign)
        assert _facts(ports) == before
        assert other.current() == foreign
        assert genesis.account.coordinator.current() == lease
    finally:
        other.release(foreign.fence)


@pytest.mark.parametrize("field", ["daily", "scope", "restored", "inventory"])
def test_reconstruction_rejects_replaced_original_owner_or_owned_value(active_genesis, field):
    genesis, ports, lease = active_genesis
    if field == "daily":
        current = reconstruct_synthetic_session_owners(genesis, lease=lease)
        changed = replace(genesis, daily=current.daily)
    elif field == "scope":
        changed = replace(genesis, scope=replace(genesis.scope, stream_id="another-stream"))
    elif field == "restored":
        changed = replace(genesis, restored=replace(genesis.restored))
    else:
        changed = replace(genesis, inventory=replace(genesis.inventory))
    before = _facts(ports)
    with pytest.raises(ValueError):
        reconstruct_synthetic_session_owners(changed, lease=lease)
    assert _facts(ports) == before
    assert genesis.account.coordinator.current() == lease
    assert genesis.runtime_sources.accounts is genesis.account
    assert genesis.runtime_sources.daily is genesis.daily
    genesis.account.require_resolved(genesis.restored)
    genesis.daily.require_resolved_snapshot(genesis.inventory)


def test_reconstruction_reads_real_capture_bytes_instead_of_reusing_old_success(active_genesis):
    genesis, ports, lease = active_genesis
    source = genesis.restored.receipt.commit.source_evidence
    closure = codec.decode_record(
        ports["account_artifacts"].read(source.object_ref), ContinuousForwardClosure
    )
    assert closure.semantic_sha256 == source.semantic_sha256
    publication = closure.publications[0]
    reference = publication.record.raw_object
    path = ports["account_artifacts"]._root / (reference.object_sha256 + ".json")
    original = path.read_bytes()
    path.write_bytes(b"x" * len(original))
    before = _facts(ports)
    with pytest.raises(ContinuousAccountConflict, match=r"^CONTINUOUS_RETAINED_INDEX_INVALID$"):
        reconstruct_synthetic_session_owners(genesis, lease=lease)
    assert _facts(ports) == before
    assert path.read_bytes() == b"x" * len(original)
    assert genesis.account.coordinator.current() == lease
    assert genesis.runtime_sources.attempt_sources is None


def test_reconstruction_does_not_adopt_later_control_transition(active_genesis):
    genesis, ports, lease = active_genesis
    controls = SqlOperationalControlRepository(engine=ports["account_engine"], clock=ports["clock"])
    changed = controls.apply(
        OperationalControlCommand(
            genesis.scope.account_id,
            "later-halt-command",
            OperationalControlCommandKind.HALT,
            OperationalControlState.HALTED,
            OperationalControlActor(
                "system", OperationalControlActorKind.SYSTEM, content_digest("halt"), None
            ),
            "TEST_LATER_HALT",
            content_digest("later-halt"),
            ports["clock"].now(),
        )
    )
    assert changed != genesis.control
    before = _facts(ports)
    with pytest.raises(ValueError):
        reconstruct_synthetic_session_owners(genesis, lease=lease)
    assert controls.load(genesis.scope.account_id) == changed
    assert _facts(ports) == before
    assert genesis.account.coordinator.current() == lease
