from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
import sqlalchemy as sa
from alembic import command
from sqlalchemy.engine import Connection

from packages.adapters.broker.alpaca_paper_order_snapshot_runtime import (
    AlpacaPaperAuthenticatedOrderSnapshotPageEvidence,
    AlpacaPaperAuthenticatedOrderSnapshotPageReceipt,
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    AlpacaPaperOrderSnapshotPagePreparationReceipt,
)
from packages.adapters.broker.alpaca_paper_order_snapshots import (
    AlpacaPaperOrderSnapshotPageDescription,
    AlpacaPaperOrderSnapshotPlan,
    create_alpaca_paper_order_snapshot_plan,
)
from packages.application.alpaca_paper_order_view_transition import (
    AlpacaPaperOrderViewTransitionClaim,
    AlpacaPaperOrderViewTransitionConflict,
    AlpacaPaperOrderViewTransitionPlan,
    AlpacaPaperOrderViewTransitionRole,
    create_alpaca_paper_order_view_transition_plan,
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
)
from packages.persistence.alpaca_paper_order_snapshot import (
    AlpacaPaperOrderSnapshotPersistenceConflict,
    SqlAlpacaPaperOrderSnapshotRepository,
    verify_alpaca_paper_order_snapshot_integrity,
)
from packages.persistence.alpaca_paper_order_view_transition import (
    AlpacaPaperOrderViewTransitionPersistenceConflict,
    SqlAlpacaPaperOrderViewTransitionRepository,
    verify_alpaca_paper_order_view_transition_integrity,
)
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.schema import (
    phase4_alpaca_paper_order_snapshot_plans,
    phase4_alpaca_paper_order_transition_claims,
    phase4_alpaca_paper_order_transition_consumptions,
    phase4_alpaca_paper_order_transition_members,
)
from tests.integration.test_phase4_alpaca_paper_account_binding_persistence import (
    BASE,
)
from tests.integration.test_phase4_alpaca_paper_order_snapshot_persistence import (
    Phase4OrderSnapshotSystem,
    _alembic_config,
    _first_page_runtime_instants,
    _second_page_runtime_instants,
    _system,
)
from tests.unit.test_alpaca_paper_order_snapshots import _body, _order


def _lease_policy() -> AccountLeasePolicy:
    return AccountLeasePolicy(
        policy_id="phase4g-binding-integration",
        policy_version="1.0.0",
        lease_ttl=timedelta(minutes=5),
        maximum_in_flight_duration=timedelta(seconds=5),
        takeover_safety_interval=timedelta(seconds=10),
    )


def _transition(
    system: Phase4OrderSnapshotSystem,
    suffix: str,
) -> AlpacaPaperOrderViewTransitionPlan:
    later = create_alpaca_paper_order_snapshot_plan(
        account_id=system.plan.account_id,
        capture_idempotency_key=f"phase4aa-order-{suffix}",
        page_limit=system.plan.page_limit,
        maximum_pages=system.plan.maximum_pages,
    )
    return create_alpaca_paper_order_view_transition_plan(
        earlier_plan=system.plan,
        later_plan=later,
    )


def _coordinator(
    system: Phase4OrderSnapshotSystem,
    instant: datetime,
) -> SqlAccountCoordinator:
    return SqlAccountCoordinator(
        account_id=system.plan.account_id,
        authority=SqlAccountCoordinatorAuthority(
            engine=system.account.engine,
            policy=_lease_policy(),
            clock=FixedClock(instant),
        ),
    )


def _repository(
    system: Phase4OrderSnapshotSystem,
    instant: datetime,
) -> SqlAlpacaPaperOrderViewTransitionRepository:
    return SqlAlpacaPaperOrderViewTransitionRepository(
        engine=system.account.engine,
        coordinator=_coordinator(system, instant),
    )


def _claim_current(
    system: Phase4OrderSnapshotSystem,
    repository: SqlAlpacaPaperOrderViewTransitionRepository,
    transition: AlpacaPaperOrderViewTransitionPlan,
    role: AlpacaPaperOrderViewTransitionRole,
) -> AlpacaPaperOrderViewTransitionClaim:
    state = system.repository.load_state(transition.selected_plan(role))
    return repository.claim(
        transition,
        selected_role=role,
        selected_prefix=state.prefix,
        selected_source_head_sha256=state.source_head_sha256,
        fence=system.account.fence,
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


class _PreparedPageRuntime:
    def __init__(
        self,
        delegate: SqlAlpacaPaperOrderSnapshotRepository,
        preparation: AlpacaPaperOrderSnapshotPagePreparationReceipt,
    ) -> None:
        self.delegate = delegate
        self.preparation = preparation
        self.prepare_calls = 0

    def prepare_next(
        self,
        description: AlpacaPaperOrderSnapshotPageDescription,
        *,
        checked_at: datetime,
    ) -> AlpacaPaperOrderSnapshotPagePreparationReceipt:
        self.prepare_calls += 1
        assert description == self.preparation.description
        assert checked_at == self.preparation.prepared_at
        return self.preparation

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedOrderSnapshotPageEvidence,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
        return self.delegate.record(evidence)

    def load_prefix(
        self,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix:
        return self.delegate.load_prefix(plan)


def _observe_consumed(
    system: Phase4OrderSnapshotSystem,
    preparation: AlpacaPaperOrderSnapshotPagePreparationReceipt,
    *,
    response_body: bytes,
    runtime_instants: list[datetime],
    budget_instants: list[datetime],
) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
    proxy = _PreparedPageRuntime(system.repository, preparation)
    original = system.repository
    system.repository = cast(Any, proxy)
    try:
        receipt = system.observe(
            preparation.description,
            response_body=response_body,
            runtime_instants=runtime_instants,
            budget_instants=budget_instants,
        )
    finally:
        system.repository = original
    assert proxy.prepare_calls == 1
    return receipt


def test_claim_retry_unscoped_rejection_and_atomic_consumption(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4aa-order-claim.sqlite")
    transition = _transition(system, "atomic-later")
    selected_at = BASE + timedelta(milliseconds=900)
    claim = _claim_current(
        system,
        _repository(system, selected_at),
        transition,
        AlpacaPaperOrderViewTransitionRole.EARLIER,
    )

    retry = _claim_current(
        system,
        _repository(
            system,
            selected_at + timedelta(microseconds=1),
        ),
        transition,
        AlpacaPaperOrderViewTransitionRole.EARLIER,
    )
    assert retry == claim
    assert retry.selected_at == selected_at
    with pytest.raises(
        AlpacaPaperOrderSnapshotPersistenceConflict,
        match="pair-aware preparation",
    ):
        system.repository.prepare_next(
            claim.description,
            checked_at=BASE + timedelta(seconds=1),
        )

    consumed_at = BASE + timedelta(seconds=1)
    consumption = _repository(system, consumed_at).prepare_claimed(
        claim,
        checked_at=consumed_at,
        fence=system.account.fence,
    )
    assert consumption.claim == claim
    assert consumption.preparation.description == claim.description
    loader = _repository(system, consumed_at)
    assert loader.load_claim(claim.claim_id) == claim
    assert loader.load_consumption(consumption.consumption_id) == consumption
    assert loader.load_consumption_for_claim(claim.claim_id) == consumption
    with pytest.raises(
        AlpacaPaperOrderViewTransitionPersistenceConflict,
        match="already consumed",
    ):
        _repository(
            system,
            consumed_at + timedelta(microseconds=1),
        ).prepare_claimed(
            claim,
            checked_at=consumed_at + timedelta(microseconds=1),
            fence=system.account.fence,
        )

    with system.account.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_alpaca_paper_order_transition_members)
            )
            == 2
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_alpaca_paper_order_transition_claims)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(
                    phase4_alpaca_paper_order_transition_consumptions
                )
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_alpaca_paper_order_snapshot_plans)
            )
            == 1
        )
    verify_alpaca_paper_order_snapshot_integrity(system.account.engine)
    verify_alpaca_paper_order_view_transition_integrity(system.account.engine)


def test_changed_final_fence_rolls_back_members_and_claim(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4aa-order-fence.sqlite")
    transition = _transition(system, "fence-later")
    selected_at = BASE + timedelta(milliseconds=900)
    changed = _ChangedOnSecondFence(_coordinator(system, selected_at))
    repository = SqlAlpacaPaperOrderViewTransitionRepository(
        engine=system.account.engine,
        coordinator=changed,
    )

    with pytest.raises(
        AlpacaPaperOrderViewTransitionPersistenceConflict,
        match="fence changed before claim commit",
    ):
        _claim_current(
            system,
            repository,
            transition,
            AlpacaPaperOrderViewTransitionRole.EARLIER,
        )
    assert changed.calls == 2
    with system.account.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_alpaca_paper_order_transition_members)
            )
            == 0
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_alpaca_paper_order_transition_claims)
            )
            == 0
        )
    verify_alpaca_paper_order_view_transition_integrity(system.account.engine)


def test_continued_earlier_pages_and_later_timing_gate(
    tmp_path: Path,
) -> None:
    system = _system(
        tmp_path / "phase4aa-order-pages.sqlite",
        page_limit=1,
    )
    transition = _transition(system, "pages-later")

    first_claim = _claim_current(
        system,
        _repository(
            system,
            BASE + timedelta(milliseconds=900),
        ),
        transition,
        AlpacaPaperOrderViewTransitionRole.EARLIER,
    )
    first_consumption = _repository(
        system,
        BASE + timedelta(seconds=1),
    ).prepare_claimed(
        first_claim,
        checked_at=BASE + timedelta(seconds=1),
        fence=system.account.fence,
    )
    first_page = _observe_consumed(
        system,
        first_consumption.preparation,
        response_body=_body(
            _order(
                1,
                submitted_at="2026-07-27T13:59:00.123456789Z",
            )
        ),
        runtime_instants=_first_page_runtime_instants(),
        budget_instants=[
            BASE + timedelta(seconds=1, milliseconds=40),
            BASE + timedelta(seconds=2, milliseconds=10),
        ],
    )

    second_claim = _claim_current(
        system,
        _repository(
            system,
            BASE + timedelta(seconds=2, milliseconds=500),
        ),
        transition,
        AlpacaPaperOrderViewTransitionRole.EARLIER,
    )
    assert second_claim.previous_claim == first_claim
    assert second_claim.previous_page_receipt_id == first_page.receipt_id
    second_consumption = _repository(
        system,
        BASE + timedelta(seconds=2, milliseconds=510),
    ).prepare_claimed(
        second_claim,
        checked_at=BASE + timedelta(seconds=2, milliseconds=510),
        fence=system.account.fence,
    )
    terminal_page = _observe_consumed(
        system,
        second_consumption.preparation,
        response_body=b"[]",
        runtime_instants=_second_page_runtime_instants(),
        budget_instants=[
            BASE + timedelta(seconds=2, milliseconds=550),
            BASE + timedelta(seconds=2, milliseconds=750),
        ],
    )
    eligible_at = terminal_page.persisted_page.observation.received_at + timedelta(seconds=2)

    with pytest.raises(
        AlpacaPaperOrderViewTransitionConflict,
        match="boundary",
    ):
        _claim_current(
            system,
            _repository(
                system,
                eligible_at - timedelta(microseconds=1),
            ),
            transition,
            AlpacaPaperOrderViewTransitionRole.LATER,
        )
    later_claim = _claim_current(
        system,
        _repository(system, eligible_at),
        transition,
        AlpacaPaperOrderViewTransitionRole.LATER,
    )
    assert later_claim.eligible_at == eligible_at
    assert later_claim.prior_earlier_prefix is not None
    assert later_claim.prior_earlier_prefix.page_receipts == (
        first_page,
        terminal_page,
    )
    verify_alpaca_paper_order_snapshot_integrity(system.account.engine)
    verify_alpaca_paper_order_view_transition_integrity(system.account.engine)


def test_readiness_rejects_removed_registered_consumption(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4aa-order-readiness.sqlite")
    transition = _transition(system, "readiness-later")
    claim = _claim_current(
        system,
        _repository(
            system,
            BASE + timedelta(milliseconds=900),
        ),
        transition,
        AlpacaPaperOrderViewTransitionRole.EARLIER,
    )
    _repository(system, BASE + timedelta(seconds=1)).prepare_claimed(
        claim,
        checked_at=BASE + timedelta(seconds=1),
        fence=system.account.fence,
    )
    with system.account.engine.begin() as connection:
        connection.execute(
            sa.delete(phase4_alpaca_paper_order_transition_consumptions).where(
                phase4_alpaca_paper_order_transition_consumptions.c.claim_id == claim.claim_id
            )
        )

    with pytest.raises(
        AlpacaPaperOrderViewTransitionPersistenceConflict,
        match="lacks atomic claim consumption",
    ):
        verify_alpaca_paper_order_view_transition_integrity(system.account.engine)
    with pytest.raises(
        DatabaseSchemaNotReady,
        match="order-snapshot integrity",
    ):
        verify_operational_schema(
            system.account.engine,
            require_phase_zero_facts=False,
        )


def test_phase4o_read_rejects_corrupted_registered_consumption(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4aa-order-consumption-corruption.sqlite")
    transition = _transition(system, "consumption-corruption-later")
    claim = _claim_current(
        system,
        _repository(
            system,
            BASE + timedelta(milliseconds=900),
        ),
        transition,
        AlpacaPaperOrderViewTransitionRole.EARLIER,
    )
    consumption = _repository(system, BASE + timedelta(seconds=1)).prepare_claimed(
        claim,
        checked_at=BASE + timedelta(seconds=1),
        fence=system.account.fence,
    )
    with system.account.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_order_transition_consumptions)
            .where(
                phase4_alpaca_paper_order_transition_consumptions.c.consumption_id
                == consumption.consumption_id
            )
            .values(
                canonical_payload="{}",
                semantic_sha256="f" * 64,
            )
        )

    with pytest.raises(
        AlpacaPaperOrderSnapshotPersistenceConflict,
        match="failed exact reconstruction",
    ):
        system.repository.load_state(transition.earlier_plan)
    with pytest.raises(
        AlpacaPaperOrderSnapshotPersistenceConflict,
        match="failed exact reconstruction",
    ):
        verify_alpaca_paper_order_snapshot_integrity(system.account.engine)


def test_nonempty_transition_history_refuses_downgrade_and_is_preserved(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase4aa-order-downgrade.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    system = _system(database_path)
    transition = _transition(system, "downgrade-later")
    _claim_current(
        system,
        _repository(
            system,
            BASE + timedelta(milliseconds=900),
        ),
        transition,
        AlpacaPaperOrderViewTransitionRole.EARLIER,
    )
    system.account.engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="refusing to downgrade nonempty order-view transition history",
    ):
        command.downgrade(
            _alembic_config(database_url),
            "0023_phase4_position_transition",
        )

    engine = create_database_engine(database_url)
    try:
        assert phase4_alpaca_paper_order_transition_members.name in (
            sa.inspect(engine).get_table_names()
        )
        with engine.connect() as connection:
            assert (
                connection.scalar(
                    sa.select(sa.func.count()).select_from(
                        phase4_alpaca_paper_order_transition_members
                    )
                )
                == 2
            )
            assert (
                connection.scalar(
                    sa.select(sa.func.count()).select_from(
                        phase4_alpaca_paper_order_transition_claims
                    )
                )
                == 1
            )
    finally:
        engine.dispose()


def test_direct_prepare_wins_and_stale_selection_creates_no_pair(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4aa-order-direct.sqlite")
    transition = _transition(system, "direct-later")
    selected = system.repository.load_state(transition.earlier_plan)
    description = selected.prefix.next_page_description
    assert description is not None
    system.repository.prepare_next(
        description,
        checked_at=BASE + timedelta(milliseconds=900),
    )

    with pytest.raises(
        AlpacaPaperOrderViewTransitionPersistenceConflict,
        match="selected source changed before admission",
    ):
        _repository(system, BASE + timedelta(seconds=1)).claim(
            transition,
            selected_role=AlpacaPaperOrderViewTransitionRole.EARLIER,
            selected_prefix=selected.prefix,
            selected_source_head_sha256=selected.source_head_sha256,
            fence=system.account.fence,
        )
    with system.account.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_alpaca_paper_order_transition_members)
            )
            == 0
        )


def test_stale_selected_state_cannot_claim_the_following_page(
    tmp_path: Path,
) -> None:
    system = _system(
        tmp_path / "phase4aa-order-stale-page.sqlite",
        page_limit=1,
    )
    transition = _transition(system, "stale-page-later")
    stale_state = system.repository.load_state(transition.earlier_plan)
    repository = _repository(
        system,
        BASE + timedelta(milliseconds=900),
    )
    first_claim = repository.claim(
        transition,
        selected_role=AlpacaPaperOrderViewTransitionRole.EARLIER,
        selected_prefix=stale_state.prefix,
        selected_source_head_sha256=stale_state.source_head_sha256,
        fence=system.account.fence,
    )
    first_consumption = _repository(
        system,
        BASE + timedelta(seconds=1),
    ).prepare_claimed(
        first_claim,
        checked_at=BASE + timedelta(seconds=1),
        fence=system.account.fence,
    )
    _observe_consumed(
        system,
        first_consumption.preparation,
        response_body=_body(
            _order(
                1,
                submitted_at="2026-07-27T13:59:00.123456789Z",
            )
        ),
        runtime_instants=_first_page_runtime_instants(),
        budget_instants=[
            BASE + timedelta(seconds=1, milliseconds=40),
            BASE + timedelta(seconds=2, milliseconds=10),
        ],
    )

    with pytest.raises(
        AlpacaPaperOrderViewTransitionPersistenceConflict,
        match="selected source changed before admission",
    ):
        _repository(
            system,
            BASE + timedelta(seconds=2, milliseconds=500),
        ).claim(
            transition,
            selected_role=AlpacaPaperOrderViewTransitionRole.EARLIER,
            selected_prefix=stale_state.prefix,
            selected_source_head_sha256=stale_state.source_head_sha256,
            fence=system.account.fence,
        )
    with system.account.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_alpaca_paper_order_transition_claims)
            )
            == 1
        )
