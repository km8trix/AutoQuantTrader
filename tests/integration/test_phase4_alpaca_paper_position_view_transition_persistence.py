from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from threading import Barrier
from typing import Any, cast
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from sqlalchemy.engine import Connection, Engine

from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperCredentialReference,
)
from packages.adapters.broker.alpaca_paper_position_snapshot_runtime import (
    AlpacaPaperAuthenticatedPositionSnapshotEvidence,
    AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    AlpacaPaperPositionSnapshotPreparationReceipt,
    AlpacaPaperPositionSnapshotRuntimePlan,
    create_alpaca_paper_position_snapshot_runtime_plan,
)
from packages.adapters.broker.alpaca_paper_positions import (
    create_alpaca_paper_position_snapshot_description,
)
from packages.application.alpaca_paper_position_view_transition import (
    AlpacaPaperPositionViewTransitionConflict,
    AlpacaPaperPositionViewTransitionPlan,
    AlpacaPaperPositionViewTransitionRole,
    create_alpaca_paper_position_view_transition_plan,
)
from packages.domain.account_coordinator import (
    AccountFence,
    AccountFenceReceipt,
    AccountLeasePolicy,
    _account_fence_receipt,
)
from packages.domain.clock import FixedClock
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
    account_lease_from_row,
)
from packages.persistence.alpaca_paper_account_binding import (
    SqlAlpacaPaperAccountBindingRepository,
)
from packages.persistence.alpaca_paper_position_snapshot import (
    AlpacaPaperPositionSnapshotPersistenceConflict,
    SqlAlpacaPaperPositionSnapshotRepository,
)
from packages.persistence.alpaca_paper_position_view_transition import (
    AlpacaPaperPositionViewTransitionPersistenceConflict,
    SqlAlpacaPaperPositionViewTransitionRepository,
    verify_alpaca_paper_position_view_transition_integrity,
)
from packages.persistence.database import DatabaseSchemaNotReady, verify_operational_schema
from packages.persistence.schema import (
    phase2_account_lease_heads,
    phase2_account_leases,
    phase4_alpaca_paper_position_snapshot_plans,
    phase4_alpaca_paper_position_transition_claims,
    phase4_alpaca_paper_position_transition_consumptions,
    phase4_alpaca_paper_position_transition_members,
)
from tests.integration.test_phase4_alpaca_paper_account_binding_persistence import (
    _prepare_concurrent_postgres_evidence,
)
from tests.integration.test_phase4_alpaca_paper_position_snapshot_persistence import (
    Phase4PositionSnapshotSystem,
    _alembic_config,
    _lease_policy,
    _system,
    phase4u_postgres_engine,  # noqa: F401
)


def _later_plan(
    system: Phase4PositionSnapshotSystem,
    suffix: str,
) -> AlpacaPaperPositionSnapshotRuntimePlan:
    return create_alpaca_paper_position_snapshot_runtime_plan(
        description=create_alpaca_paper_position_snapshot_description(
            account_id=system.plan.description.account_id,
            capture_idempotency_key=f"phase4x-position-{suffix}",
        ),
        reference=system.plan.reference,
        account_binding=system.plan.account_binding,
    )


def _transition(
    system: Phase4PositionSnapshotSystem,
    suffix: str,
) -> AlpacaPaperPositionViewTransitionPlan:
    return create_alpaca_paper_position_view_transition_plan(
        earlier_plan=system.plan,
        later_plan=_later_plan(system, suffix),
    )


def _coordinator(
    system: Phase4PositionSnapshotSystem,
    instant: datetime,
) -> SqlAccountCoordinator:
    return SqlAccountCoordinator(
        account_id=system.plan.description.account_id,
        authority=SqlAccountCoordinatorAuthority(
            engine=system.account.engine,
            policy=_lease_policy(),
            clock=FixedClock(instant),
        ),
    )


def _repository(
    system: Phase4PositionSnapshotSystem,
    instant: datetime,
) -> SqlAlpacaPaperPositionViewTransitionRepository:
    return SqlAlpacaPaperPositionViewTransitionRepository(
        engine=system.account.engine,
        coordinator=_coordinator(system, instant),
    )


class _ChangedOnSecondFence:
    def __init__(self, delegate: SqlAccountCoordinator) -> None:
        self.delegate = delegate
        self.calls = 0

    def revalidate_for_commit_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
    ) -> AccountFenceReceipt:
        self.calls += 1
        receipt = self.delegate.revalidate_for_commit_in_transaction(
            connection,
            fence,
        )
        if self.calls == 1:
            return receipt
        return _account_fence_receipt(
            fence=receipt.fence,
            validated_at=receipt.validated_at,
            valid_until=receipt.valid_until,
            policy_sha256=receipt.policy_sha256,
            lease_sha256="f" * 64,
        )


class _PreparedRuntime:
    def __init__(
        self,
        system: Phase4PositionSnapshotSystem,
        preparation: AlpacaPaperPositionSnapshotPreparationReceipt,
    ) -> None:
        self.system = system
        self.delegate = system.repository
        self.preparation = preparation
        self.prepare_calls = 0

    def prepare(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
        *,
        checked_at: datetime,
    ) -> AlpacaPaperPositionSnapshotPreparationReceipt:
        self.prepare_calls += 1
        assert plan == self.preparation.plan
        assert checked_at == self.preparation.prepared_at
        return self.preparation

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedPositionSnapshotEvidence,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
        return self.delegate.record(evidence)

    def load(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt | None:
        return self.delegate.load(plan)


def test_claim_retry_unscoped_rejection_and_atomic_consumption(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4x-claim-consume.sqlite")
    transition = _transition(system, "claim-consume-later")
    selected_at = system.capture_base - timedelta(milliseconds=10)
    claim = _repository(system, selected_at).claim(
        transition,
        selected_role=AlpacaPaperPositionViewTransitionRole.EARLIER,
        fence=system.account.fence,
    )

    retry = _repository(
        system,
        selected_at + timedelta(milliseconds=1),
    ).claim(
        transition,
        selected_role=AlpacaPaperPositionViewTransitionRole.EARLIER,
        fence=system.account.fence,
    )
    assert retry == claim
    assert retry.selected_at == selected_at
    with pytest.raises(
        AlpacaPaperPositionSnapshotPersistenceConflict,
        match="pair-aware preparation",
    ):
        system.repository.prepare(
            transition.earlier_plan,
            checked_at=system.capture_base,
        )

    consumption = _repository(system, system.capture_base).prepare_claimed(
        claim,
        checked_at=system.capture_base,
        fence=system.account.fence,
    )
    assert consumption.claim == claim
    assert consumption.preparation.plan == transition.earlier_plan
    loader = _repository(system, system.capture_base)
    assert loader.load_claim(claim.claim_id) == claim
    assert loader.load_consumption(consumption.consumption_id) == consumption
    assert loader.load_consumption_for_claim(claim.claim_id) == consumption
    with pytest.raises(
        AlpacaPaperPositionViewTransitionPersistenceConflict,
        match="already consumed",
    ):
        _repository(
            system,
            system.capture_base + timedelta(milliseconds=1),
        ).prepare_claimed(
            claim,
            checked_at=system.capture_base + timedelta(milliseconds=1),
            fence=system.account.fence,
        )

    with system.account.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(
                    phase4_alpaca_paper_position_transition_members
                )
            )
            == 2
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(
                    phase4_alpaca_paper_position_transition_claims
                )
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(
                    phase4_alpaca_paper_position_transition_consumptions
                )
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_alpaca_paper_position_snapshot_plans)
            )
            == 1
        )
    verify_alpaca_paper_position_view_transition_integrity(system.account.engine)


def test_direct_prepare_wins_before_pair_claim_without_registration(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4x-direct-first.sqlite")
    transition = _transition(system, "direct-first-later")
    system.repository.prepare(
        transition.earlier_plan,
        checked_at=system.capture_base,
    )

    with pytest.raises(
        AlpacaPaperPositionViewTransitionPersistenceConflict,
        match="existing stalled or complete",
    ):
        _repository(
            system,
            system.capture_base + timedelta(milliseconds=1),
        ).claim(
            transition,
            selected_role=AlpacaPaperPositionViewTransitionRole.EARLIER,
            fence=system.account.fence,
        )
    with system.account.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(
                    phase4_alpaca_paper_position_transition_members
                )
            )
            == 0
        )


def test_opposite_role_reuse_across_rounds_rolls_back_new_members(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4x-opposite-role-reuse.sqlite")
    first = _transition(system, "first-later")
    _repository(
        system,
        system.capture_base - timedelta(milliseconds=2),
    ).claim(
        first,
        selected_role=AlpacaPaperPositionViewTransitionRole.EARLIER,
        fence=system.account.fence,
    )
    second = create_alpaca_paper_position_view_transition_plan(
        earlier_plan=_later_plan(system, "second-earlier"),
        later_plan=first.earlier_plan,
    )

    with pytest.raises(
        AlpacaPaperPositionViewTransitionPersistenceConflict,
        match="membership conflicts with durable history",
    ):
        _repository(
            system,
            system.capture_base - timedelta(milliseconds=1),
        ).claim(
            second,
            selected_role=AlpacaPaperPositionViewTransitionRole.EARLIER,
            fence=system.account.fence,
        )
    with system.account.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(
                    phase4_alpaca_paper_position_transition_members
                )
            )
            == 2
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(
                    phase4_alpaca_paper_position_transition_claims
                )
            )
            == 1
        )


def test_changed_final_fence_rolls_back_members_and_claim(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4x-claim-final-fence-rollback.sqlite")
    transition = _transition(system, "claim-final-fence-later")
    selected_at = system.capture_base - timedelta(milliseconds=1)
    changed = _ChangedOnSecondFence(_coordinator(system, selected_at))
    repository = SqlAlpacaPaperPositionViewTransitionRepository(
        engine=system.account.engine,
        coordinator=changed,
    )

    with pytest.raises(
        AlpacaPaperPositionViewTransitionPersistenceConflict,
        match="fence changed before claim commit",
    ):
        repository.claim(
            transition,
            selected_role=AlpacaPaperPositionViewTransitionRole.EARLIER,
            fence=system.account.fence,
        )
    assert changed.calls == 2
    with system.account.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(
                    phase4_alpaca_paper_position_transition_members
                )
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(
                    phase4_alpaca_paper_position_transition_claims
                )
            )
            == 0
        )
    verify_alpaca_paper_position_view_transition_integrity(system.account.engine)


def test_changed_final_fence_rolls_back_u_plan_and_consumption(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4x-final-fence-rollback.sqlite")
    transition = _transition(system, "final-fence-later")
    claim = _repository(
        system,
        system.capture_base - timedelta(milliseconds=1),
    ).claim(
        transition,
        selected_role=AlpacaPaperPositionViewTransitionRole.EARLIER,
        fence=system.account.fence,
    )
    changed = _ChangedOnSecondFence(_coordinator(system, system.capture_base))
    repository = SqlAlpacaPaperPositionViewTransitionRepository(
        engine=system.account.engine,
        coordinator=changed,
    )

    with pytest.raises(
        AlpacaPaperPositionViewTransitionPersistenceConflict,
        match="fence changed before consumption commit",
    ):
        repository.prepare_claimed(
            claim,
            checked_at=system.capture_base,
            fence=system.account.fence,
        )
    assert changed.calls == 2
    with system.account.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_alpaca_paper_position_snapshot_plans)
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(
                    phase4_alpaca_paper_position_transition_consumptions
                )
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(
                    phase4_alpaca_paper_position_transition_claims
                )
            )
            == 1
        )
    verify_alpaca_paper_position_view_transition_integrity(system.account.engine)


def test_later_claim_is_eligible_only_after_exact_complete_earlier_source(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4x-later-eligibility.sqlite")
    transition = _transition(system, "eligible-later")
    claim = _repository(
        system,
        system.capture_base - timedelta(milliseconds=1),
    ).claim(
        transition,
        selected_role=AlpacaPaperPositionViewTransitionRole.EARLIER,
        fence=system.account.fence,
    )
    consumption = _repository(system, system.capture_base).prepare_claimed(
        claim,
        checked_at=system.capture_base,
        fence=system.account.fence,
    )

    prepared_runtime = _PreparedRuntime(system, consumption.preparation)
    original_repository = system.repository
    system.repository = cast(Any, prepared_runtime)
    try:
        earlier_receipt = system.observe()
    finally:
        system.repository = original_repository
    assert prepared_runtime.prepare_calls == 1

    eligible_at = earlier_receipt.persisted_snapshot.observation.received_at + timedelta(seconds=2)
    with pytest.raises(
        AlpacaPaperPositionViewTransitionConflict,
        match="receive-time boundary",
    ):
        _repository(
            system,
            eligible_at - timedelta(microseconds=1),
        ).claim(
            transition,
            selected_role=AlpacaPaperPositionViewTransitionRole.LATER,
            fence=system.account.fence,
        )

    later_claim = _repository(system, eligible_at).claim(
        transition,
        selected_role=AlpacaPaperPositionViewTransitionRole.LATER,
        fence=system.account.fence,
    )
    assert later_claim.prior_earlier_receipt == earlier_receipt
    assert later_claim.eligible_at == eligible_at
    verify_alpaca_paper_position_view_transition_integrity(system.account.engine)


def test_integrity_and_readiness_reject_member_payload_tampering(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4x-member-tamper.sqlite")
    transition = _transition(system, "tamper-later")
    _repository(
        system,
        system.capture_base - timedelta(milliseconds=1),
    ).claim(
        transition,
        selected_role=AlpacaPaperPositionViewTransitionRole.EARLIER,
        fence=system.account.fence,
    )
    with system.account.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_position_transition_members).values(
                canonical_payload="[]"
            )
        )

    with pytest.raises(
        AlpacaPaperPositionViewTransitionPersistenceConflict,
        match="failed exact reconstruction",
    ):
        verify_alpaca_paper_position_view_transition_integrity(system.account.engine)
    with pytest.raises(
        DatabaseSchemaNotReady,
        match="position-transition integrity",
    ):
        verify_operational_schema(
            system.account.engine,
            require_phase_zero_facts=False,
        )


def test_nonempty_transition_history_refuses_0023_downgrade(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase4x-downgrade.sqlite"
    system = _system(database_path)
    transition = _transition(system, "downgrade-later")
    _repository(
        system,
        system.capture_base - timedelta(milliseconds=1),
    ).claim(
        transition,
        selected_role=AlpacaPaperPositionViewTransitionRole.EARLIER,
        fence=system.account.fence,
    )
    system.account.engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="refusing to downgrade nonempty position-view transition history",
    ):
        command.downgrade(
            _alembic_config(database_path),
            "0022_phase4_position_view_cmp",
        )


def test_postgresql_direct_prepare_and_pair_claim_are_serialized(
    phase4u_postgres_engine: Engine,  # noqa: F811
) -> None:
    engine = phase4u_postgres_engine
    account_id = f"phase4x-pg-race-{uuid4().hex[:20]}"
    evidence, _ = _prepare_concurrent_postgres_evidence(engine, account_id)
    binding = SqlAlpacaPaperAccountBindingRepository(engine).record(evidence)
    reference = AlpacaPaperCredentialReference(
        account_id=account_id,
        expected_provider_account_id=binding.expected_provider_account_id,
        secret_ref=binding.secret_ref,
        secret_version=binding.secret_version,
    )
    earlier = create_alpaca_paper_position_snapshot_runtime_plan(
        description=create_alpaca_paper_position_snapshot_description(
            account_id=account_id,
            capture_idempotency_key=f"phase4x-pg-earlier-{uuid4()}",
        ),
        reference=reference,
        account_binding=binding,
    )
    later = create_alpaca_paper_position_snapshot_runtime_plan(
        description=create_alpaca_paper_position_snapshot_description(
            account_id=account_id,
            capture_idempotency_key=f"phase4x-pg-later-{uuid4()}",
        ),
        reference=reference,
        account_binding=binding,
    )
    transition = create_alpaca_paper_position_view_transition_plan(
        earlier_plan=earlier,
        later_plan=later,
    )
    with engine.connect() as connection:
        lease_sha256 = connection.scalar(
            sa.select(phase2_account_lease_heads.c.current_lease_sha256).where(
                phase2_account_lease_heads.c.account_id == account_id
            )
        )
        lease_row = (
            connection.execute(
                sa.select(phase2_account_leases).where(
                    phase2_account_leases.c.lease_sha256 == lease_sha256
                )
            )
            .mappings()
            .one()
        )
    lease = account_lease_from_row(lease_row)
    instant = binding.qualified_at + timedelta(microseconds=1)
    policy = AccountLeasePolicy(
        policy_id="phase4g-postgres-binding-lock",
        policy_version="1.0.0",
        lease_ttl=timedelta(minutes=5),
        maximum_in_flight_duration=timedelta(seconds=5),
        takeover_safety_interval=timedelta(seconds=10),
    )
    coordinator = SqlAccountCoordinator(
        account_id=account_id,
        authority=SqlAccountCoordinatorAuthority(
            engine=engine,
            policy=policy,
            clock=FixedClock(instant),
        ),
    )
    direct = SqlAlpacaPaperPositionSnapshotRepository(
        engine=engine,
        coordinator=coordinator,
    )
    pair = SqlAlpacaPaperPositionViewTransitionRepository(
        engine=engine,
        coordinator=coordinator,
    )
    barrier = Barrier(2)

    def prepare_direct() -> str:
        barrier.wait(timeout=10)
        try:
            direct.prepare(earlier, checked_at=instant)
            return "direct"
        except AlpacaPaperPositionSnapshotPersistenceConflict:
            return "direct_rejected"

    def claim_pair() -> str:
        barrier.wait(timeout=10)
        try:
            pair.claim(
                transition,
                selected_role=AlpacaPaperPositionViewTransitionRole.EARLIER,
                fence=lease.fence,
            )
            return "claim"
        except AlpacaPaperPositionViewTransitionPersistenceConflict:
            return "claim_rejected"

    with ThreadPoolExecutor(max_workers=2) as executor:
        direct_future = executor.submit(prepare_direct)
        claim_future = executor.submit(claim_pair)
        results = {
            direct_future.result(timeout=20),
            claim_future.result(timeout=20),
        }

    assert results in (
        {"direct", "claim_rejected"},
        {"direct_rejected", "claim"},
    )
    with engine.connect() as connection:
        member_count = connection.scalar(
            sa.select(sa.func.count())
            .select_from(phase4_alpaca_paper_position_transition_members)
            .where(
                phase4_alpaca_paper_position_transition_members.c.round_id == transition.round_id
            )
        )
        plan_count = connection.scalar(
            sa.select(sa.func.count())
            .select_from(phase4_alpaca_paper_position_snapshot_plans)
            .where(phase4_alpaca_paper_position_snapshot_plans.c.plan_id == earlier.plan_id)
        )
    assert (member_count, plan_count) in ((0, 1), (2, 0))
