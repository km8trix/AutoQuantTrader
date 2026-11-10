from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, make_url

from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperCredentialReference,
    _AlpacaPaperAuthenticationHeaders,
    _AlpacaPaperCredentialMaterial,
    create_alpaca_paper_credential_envelope,
)
from packages.adapters.broker.alpaca_paper_order_snapshot_runtime import (
    ALPACA_PAPER_ORDER_SNAPSHOT_ACCEPT_MEDIA_TYPE,
    ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_ID,
    ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_VERSION,
    AlpacaPaperAuthenticatedOrderSnapshotPageReceipt,
    AlpacaPaperOrderSnapshotTransportRequest,
    AlpacaPaperOrderSnapshotTransportResponse,
    _observe_authenticated_alpaca_paper_order_snapshot_page_with_transport,
)
from packages.adapters.broker.alpaca_paper_order_snapshots import (
    AlpacaPaperOrderSnapshotPageDescription,
    AlpacaPaperOrderSnapshotPlan,
    create_alpaca_paper_order_snapshot_plan,
    start_alpaca_paper_order_snapshot,
)
from packages.application.alpaca_paper_order_view_supervisor import (
    AlpacaPaperOrderSnapshotSupervisorSourceStage,
)
from packages.domain.account_coordinator import (
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
    AlpacaPaperOrderSnapshotPersistenceError,
    SqlAlpacaPaperOrderSnapshotRepository,
    _head_from_row,
    verify_alpaca_paper_order_snapshot_integrity,
)
from packages.persistence.broker_ingress import SqlBrokerIngressRepository
from packages.persistence.broker_request_budget import (
    SqlBrokerRequestBudgetRepository,
)
from packages.persistence.database import (
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.schema import (
    phase4_alpaca_paper_order_snapshot_heads,
    phase4_alpaca_paper_order_snapshot_pages,
    phase4_alpaca_paper_order_snapshot_plans,
    phase4_alpaca_paper_order_snapshot_preparations,
)
from tests.integration.phase4_postgres_cleanup import (
    delete_phase4_postgres_account_facts,
)
from tests.integration.test_phase4_alpaca_paper_account_binding_persistence import (
    ACCOUNT_ID,
    API_KEY_ID,
    BASE,
    PROVIDER_ACCOUNT_ID,
    SECRET_KEY,
    RuntimeSystem,
    SequenceClock,
)
from tests.integration.test_phase4_alpaca_paper_account_binding_persistence import (
    _system as _account_system,
)
from tests.unit.test_alpaca_paper_order_snapshots import _body, _order

ROOT = Path(__file__).resolve().parents[2]
TEST_DATABASE_ENV = "AQT_TEST_POSTGRES_URL"


class OrderSnapshotCredentialResolver:
    resolver_id = "phase4o-integration-secret-store"
    resolver_version = "v1"

    def __init__(self) -> None:
        self.materials: list[_AlpacaPaperCredentialMaterial] = []

    def _resolve_for_order_snapshot_page(
        self,
        reference: AlpacaPaperCredentialReference,
    ) -> object:
        del reference
        envelope = create_alpaca_paper_credential_envelope(
            api_key_id=API_KEY_ID,
            secret_key=SECRET_KEY,
        )
        assert type(envelope) is _AlpacaPaperCredentialMaterial
        self.materials.append(envelope)
        return envelope


class OrderSnapshotTransport:
    transport_id = ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_ID
    transport_version = ALPACA_PAPER_ORDER_SNAPSHOT_TRANSPORT_VERSION

    def __init__(self, response_body: bytes) -> None:
        self.response_body = response_body
        self.calls = 0

    def execute(
        self,
        request: AlpacaPaperOrderSnapshotTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperOrderSnapshotTransportResponse:
        self.calls += 1
        assert tuple(headers)
        return AlpacaPaperOrderSnapshotTransportResponse(
            request_sha256=request.semantic_sha256,
            transport_id=self.transport_id,
            transport_version=self.transport_version,
            http_status=200,
            provider_request_id=f"phase4o-integration-request-{self.calls:03d}",
            media_type=ALPACA_PAPER_ORDER_SNAPSHOT_ACCEPT_MEDIA_TYPE,
            response_body=self.response_body,
        )


@dataclass(slots=True)
class Phase4OrderSnapshotSystem:
    account: RuntimeSystem
    binding: object
    reference: AlpacaPaperCredentialReference
    plan: AlpacaPaperOrderSnapshotPlan
    repository: SqlAlpacaPaperOrderSnapshotRepository
    resolver: OrderSnapshotCredentialResolver
    ingress: SqlBrokerIngressRepository

    def observe(
        self,
        description: AlpacaPaperOrderSnapshotPageDescription,
        *,
        response_body: bytes,
        runtime_instants: list[datetime],
        budget_instants: list[datetime],
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
        return _observe_authenticated_alpaca_paper_order_snapshot_page_with_transport(
            reference=self.reference,
            account_binding=self.binding,  # type: ignore[arg-type]
            description=description,
            credential_resolver=self.resolver,
            transport=OrderSnapshotTransport(response_body),
            budget=SqlBrokerRequestBudgetRepository(
                engine=self.account.engine,
                clock=SequenceClock(budget_instants),
            ),
            account_bindings=self.account.bindings,
            coordinator=self.account.coordinator,
            fence=self.account.fence,
            ingress_recorder=self.ingress,
            page_runtime=self.repository,
            clock=SequenceClock(runtime_instants),
        )


def _first_page_runtime_instants() -> list[datetime]:
    return [
        BASE + timedelta(seconds=1),
        BASE + timedelta(seconds=1, milliseconds=10),
        BASE + timedelta(seconds=1, milliseconds=20),
        BASE + timedelta(seconds=1, milliseconds=30),
        BASE + timedelta(seconds=2, milliseconds=20),
        BASE + timedelta(seconds=2, milliseconds=30),
        BASE + timedelta(seconds=2, milliseconds=40),
        BASE + timedelta(seconds=2, milliseconds=50),
        BASE + timedelta(seconds=2, milliseconds=210),
        BASE + timedelta(seconds=2, milliseconds=220),
    ]


def _second_page_runtime_instants() -> list[datetime]:
    return [
        BASE + timedelta(seconds=2, milliseconds=510),
        BASE + timedelta(seconds=2, milliseconds=520),
        BASE + timedelta(seconds=2, milliseconds=530),
        BASE + timedelta(seconds=2, milliseconds=540),
        BASE + timedelta(seconds=2, milliseconds=760),
        BASE + timedelta(seconds=2, milliseconds=770),
        BASE + timedelta(seconds=2, milliseconds=780),
        BASE + timedelta(seconds=2, milliseconds=790),
        BASE + timedelta(seconds=2, milliseconds=810),
        BASE + timedelta(seconds=2, milliseconds=820),
    ]


def _system(
    database_path: Path,
    *,
    page_limit: int = 2,
    maximum_pages: int = 3,
    migrated: bool = True,
) -> Phase4OrderSnapshotSystem:
    account = _account_system(
        database_path,
        run_count=3,
        migrated=migrated,
    )
    binding = account.observe("phase4o-source")
    reference = AlpacaPaperCredentialReference(
        account_id=ACCOUNT_ID,
        expected_provider_account_id=PROVIDER_ACCOUNT_ID,
        secret_ref="secret://paper/alpaca/trading",
        secret_version="version-001",
    )
    plan = create_alpaca_paper_order_snapshot_plan(
        account_id=ACCOUNT_ID,
        capture_idempotency_key="phase4o-integration-capture-0001",
        page_limit=page_limit,
        maximum_pages=maximum_pages,
    )
    return Phase4OrderSnapshotSystem(
        account=account,
        binding=binding,
        reference=reference,
        plan=plan,
        repository=SqlAlpacaPaperOrderSnapshotRepository(
            engine=account.engine,
            coordinator=account.coordinator,
        ),
        resolver=OrderSnapshotCredentialResolver(),
        ingress=SqlBrokerIngressRepository(account.engine),
    )


def test_prepare_claim_is_single_use_and_restart_refuses_a_stalled_page(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4o-preparation.sqlite")
    description = start_alpaca_paper_order_snapshot(system.plan).next_page_description
    assert description is not None
    assert system.repository.runtime_store_identity == id(system.account.engine)
    absent = system.repository.load_state(system.plan)

    assert absent.stage is AlpacaPaperOrderSnapshotSupervisorSourceStage.ABSENT
    assert absent.prefix.page_receipts == ()
    assert absent.preparation is None
    assert absent.source_head_sha256 is None

    first = system.repository.prepare_next(
        description,
        checked_at=BASE + timedelta(seconds=1),
    )
    restarted = SqlAlpacaPaperOrderSnapshotRepository(
        engine=system.account.engine,
        coordinator=system.account.coordinator,
    )
    assert restarted.runtime_store_identity == system.repository.runtime_store_identity
    with pytest.raises(
        AlpacaPaperOrderSnapshotPersistenceConflict,
        match="unresolved single-use claim",
    ):
        restarted.prepare_next(
            description,
            checked_at=BASE + timedelta(seconds=1, milliseconds=1),
        )

    assert restarted.load_prefix(system.plan).page_count == 0
    stalled = restarted.load_state(system.plan)
    assert stalled.stage is AlpacaPaperOrderSnapshotSupervisorSourceStage.STALLED
    assert stalled.prefix.page_receipts == ()
    assert stalled.preparation == first
    assert stalled.source_head_sha256 is not None
    with system.account.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(phase4_alpaca_paper_order_snapshot_heads.c.state))
            == "stalled"
        )
        assert (
            connection.scalar(
                sa.select(phase4_alpaca_paper_order_snapshot_heads.c.preparation_sha256)
            )
            == first.semantic_sha256
        )


def test_authenticated_page_round_trips_from_exact_durable_sources(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4o-round-trip.sqlite")
    description = start_alpaca_paper_order_snapshot(system.plan).next_page_description
    assert description is not None

    receipt = system.observe(
        description,
        response_body=b"[]",
        runtime_instants=_first_page_runtime_instants(),
        budget_instants=[
            BASE + timedelta(seconds=1, milliseconds=40),
            BASE + timedelta(seconds=2, milliseconds=10),
        ],
    )
    restarted = SqlAlpacaPaperOrderSnapshotRepository(
        engine=system.account.engine,
        coordinator=system.account.coordinator,
    )
    prefix = restarted.load_prefix(system.plan)
    state = restarted.load_state(system.plan)

    assert prefix.page_receipts == (receipt,)
    assert state.stage is (AlpacaPaperOrderSnapshotSupervisorSourceStage.CURSOR_EXHAUSTED)
    assert state.prefix == prefix
    assert state.preparation is None
    assert state.source_head_sha256 is not None
    assert restarted.record(receipt.evidence) == receipt
    assert prefix.capture.pagination_exhausted is True
    assert prefix.next_page_description is None
    assert receipt.evidence.persisted_page.receipt.delivery.body == b"[]"
    assert receipt.evidence.request_budget_enforced is True
    assert receipt.committed_prefix_established is True
    assert all(material.closed for material in system.resolver.materials)
    with system.account.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_alpaca_paper_order_snapshot_plans)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_alpaca_paper_order_snapshot_pages)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(
                    phase4_alpaca_paper_order_snapshot_preparations
                )
            )
            == 1
        )
        assert (
            connection.scalar(sa.select(phase4_alpaca_paper_order_snapshot_heads.c.state))
            == "cursor_exhausted_unisolated"
        )
    verify_alpaca_paper_order_snapshot_integrity(system.account.engine)
    verify_operational_schema(
        system.account.engine,
        require_phase_zero_facts=False,
    )


def test_load_state_reports_bounded_truncation_without_resume_authority(
    tmp_path: Path,
) -> None:
    system = _system(
        tmp_path / "phase4q-bounded-state.sqlite",
        page_limit=1,
        maximum_pages=1,
    )
    description = system.repository.load_state(system.plan).prefix.next_page_description
    assert description is not None
    receipt = system.observe(
        description,
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

    state = system.repository.load_state(system.plan)

    assert state.stage is (AlpacaPaperOrderSnapshotSupervisorSourceStage.BOUNDED_TRUNCATED)
    assert state.prefix.page_receipts == (receipt,)
    assert state.prefix.capture.bounded_truncation is True
    assert state.preparation is None
    assert state.source_head_sha256 is not None


def test_two_page_prefix_binds_runtime_and_phase4m_predecessors(
    tmp_path: Path,
) -> None:
    system = _system(
        tmp_path / "phase4o-two-pages.sqlite",
        page_limit=1,
    )
    first_description = start_alpaca_paper_order_snapshot(system.plan).next_page_description
    assert first_description is not None
    first = system.observe(
        first_description,
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
    active = system.repository.load_state(system.plan)
    assert active.stage is AlpacaPaperOrderSnapshotSupervisorSourceStage.ACTIVE
    assert active.prefix.page_receipts == (first,)
    assert active.preparation is None
    assert active.source_head_sha256 is not None
    second_description = active.prefix.next_page_description
    assert second_description is not None

    second = system.observe(
        second_description,
        response_body=b"[]",
        runtime_instants=_second_page_runtime_instants(),
        budget_instants=[
            BASE + timedelta(seconds=2, milliseconds=550),
            BASE + timedelta(seconds=2, milliseconds=750),
        ],
    )
    prefix = system.repository.load_prefix(system.plan)

    assert prefix.page_receipts == (first, second)
    assert second.previous_page_receipt_sha256 == first.semantic_sha256
    assert second.description.previous_page_sha256 == (first.persisted_page.semantic_sha256)
    assert second.evidence.preparation.previous_page_receipt_id == first.receipt_id
    assert prefix.capture.pagination_exhausted is True
    verify_alpaca_paper_order_snapshot_integrity(system.account.engine)


def test_load_prefix_rejects_tampered_canonical_page_payload(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4o-tamper.sqlite")
    description = start_alpaca_paper_order_snapshot(system.plan).next_page_description
    assert description is not None
    system.observe(
        description,
        response_body=b"[]",
        runtime_instants=_first_page_runtime_instants(),
        budget_instants=[
            BASE + timedelta(seconds=1, milliseconds=40),
            BASE + timedelta(seconds=2, milliseconds=10),
        ],
    )
    with system.account.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_order_snapshot_pages).values(
                canonical_payload='{"tampered":true}'
            )
        )

    with pytest.raises(
        AlpacaPaperOrderSnapshotPersistenceConflict,
        match="reconstruction",
    ):
        system.repository.load_prefix(system.plan)
    with pytest.raises(AlpacaPaperOrderSnapshotPersistenceConflict):
        verify_alpaca_paper_order_snapshot_integrity(system.account.engine)


def test_load_prefix_requires_fence_expiry_from_the_exact_lease(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4o-fence-expiry.sqlite")
    description = start_alpaca_paper_order_snapshot(system.plan).next_page_description
    assert description is not None
    receipt = system.observe(
        description,
        response_body=b"[]",
        runtime_instants=_first_page_runtime_instants(),
        budget_instants=[
            BASE + timedelta(seconds=1, milliseconds=40),
            BASE + timedelta(seconds=2, milliseconds=10),
        ],
    )
    pre_fence = receipt.evidence.pre_fence_receipt
    tampered_fence = _account_fence_receipt(
        fence=pre_fence.fence,
        validated_at=pre_fence.validated_at,
        valid_until=pre_fence.valid_until - timedelta(seconds=1),
        policy_sha256=pre_fence.policy_sha256,
        lease_sha256=pre_fence.lease_sha256,
    )
    with system.account.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_order_snapshot_pages).values(
                pre_fence_valid_until=tampered_fence.valid_until,
                pre_fence_receipt_sha256=tampered_fence.semantic_sha256,
            )
        )

    with pytest.raises(
        AlpacaPaperOrderSnapshotPersistenceConflict,
        match="pre fence conflicts with its lease source",
    ):
        system.repository.load_prefix(system.plan)


def test_load_rejects_a_missing_immutable_preparation_fact(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4o-missing-preparation.sqlite")
    description = start_alpaca_paper_order_snapshot(system.plan).next_page_description
    assert description is not None
    preparation = system.repository.prepare_next(
        description,
        checked_at=BASE + timedelta(seconds=1),
    )
    with system.account.engine.begin() as connection:
        connection.execute(
            sa.delete(phase4_alpaca_paper_order_snapshot_preparations).where(
                phase4_alpaca_paper_order_snapshot_preparations.c.preparation_sha256
                == preparation.semantic_sha256
            )
        )

    with pytest.raises(
        AlpacaPaperOrderSnapshotPersistenceConflict,
        match="lacks its immutable fact",
    ):
        system.repository.load_state(system.plan)
    with pytest.raises(
        AlpacaPaperOrderSnapshotPersistenceConflict,
        match="lacks its immutable fact",
    ):
        verify_alpaca_paper_order_snapshot_integrity(system.account.engine)


@pytest.mark.parametrize("completed", [False, True])
def test_0024_upgrade_backfills_existing_preparation_history(
    tmp_path: Path,
    completed: bool,
) -> None:
    database_path = tmp_path / f"phase4o-preparation-backfill-{completed}.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    system = _system(database_path)
    description = start_alpaca_paper_order_snapshot(system.plan).next_page_description
    assert description is not None
    if completed:
        system.observe(
            description,
            response_body=b"[]",
            runtime_instants=_first_page_runtime_instants(),
            budget_instants=[
                BASE + timedelta(seconds=1, milliseconds=40),
                BASE + timedelta(seconds=2, milliseconds=10),
            ],
        )
    else:
        system.repository.prepare_next(
            description,
            checked_at=BASE + timedelta(seconds=1),
        )
    system.account.engine.dispose()

    config = _alembic_config(database_url)
    command.downgrade(config, "0023_phase4_position_transition")
    legacy_engine = create_database_engine(database_url)
    try:
        assert (
            phase4_alpaca_paper_order_snapshot_preparations.name
            not in sa.inspect(legacy_engine).get_table_names()
        )
    finally:
        legacy_engine.dispose()

    command.upgrade(config, "head")
    upgraded_engine = create_database_engine(database_url)
    try:
        restarted = SqlAlpacaPaperOrderSnapshotRepository(
            engine=upgraded_engine,
            coordinator=system.account.coordinator,
        )
        state = restarted.load_state(system.plan)
        assert state.page_count == (1 if completed else 0)
        expected_stage = (
            AlpacaPaperOrderSnapshotSupervisorSourceStage.CURSOR_EXHAUSTED
            if completed
            else AlpacaPaperOrderSnapshotSupervisorSourceStage.STALLED
        )
        assert state.stage is expected_stage
        with upgraded_engine.connect() as connection:
            assert (
                connection.scalar(
                    sa.select(sa.func.count()).select_from(
                        phase4_alpaca_paper_order_snapshot_preparations
                    )
                )
                == 1
            )
        verify_alpaca_paper_order_snapshot_integrity(upgraded_engine)
    finally:
        upgraded_engine.dispose()


def test_0024_upgrade_backfills_committed_page_and_stalled_successor(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase4o-preparation-backfill-page2.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    system = _system(database_path, page_limit=1)
    first_description = start_alpaca_paper_order_snapshot(system.plan).next_page_description
    assert first_description is not None
    first = system.observe(
        first_description,
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
    active = system.repository.load_state(system.plan)
    second_description = active.prefix.next_page_description
    assert second_description is not None
    second_preparation = system.repository.prepare_next(
        second_description,
        checked_at=BASE + timedelta(seconds=2, milliseconds=500),
    )
    system.account.engine.dispose()

    config = _alembic_config(database_url)
    command.downgrade(config, "0023_phase4_position_transition")
    command.upgrade(config, "head")
    upgraded_engine = create_database_engine(database_url)
    try:
        restarted = SqlAlpacaPaperOrderSnapshotRepository(
            engine=upgraded_engine,
            coordinator=system.account.coordinator,
        )
        state = restarted.load_state(system.plan)
        assert state.stage is AlpacaPaperOrderSnapshotSupervisorSourceStage.STALLED
        assert state.prefix.page_receipts == (first,)
        assert state.preparation == second_preparation
        with upgraded_engine.connect() as connection:
            facts = (
                connection.execute(
                    sa.select(phase4_alpaca_paper_order_snapshot_preparations).order_by(
                        phase4_alpaca_paper_order_snapshot_preparations.c.page_number
                    )
                )
                .mappings()
                .all()
            )
        assert [row["page_number"] for row in facts] == [1, 2]
        assert facts[0]["preparation_sha256"] == (first.evidence.preparation.semantic_sha256)
        assert facts[1]["preparation_sha256"] == second_preparation.semantic_sha256
        assert facts[1]["previous_page_receipt_id"] == first.receipt_id
        assert facts[1]["previous_page_receipt_sha256"] == first.semantic_sha256
        assert facts[1]["previous_persisted_page_sha256"] == (first.persisted_page.semantic_sha256)
        verify_alpaca_paper_order_snapshot_integrity(upgraded_engine)
    finally:
        upgraded_engine.dispose()


def test_startup_integrity_rejects_a_head_without_its_plan(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4o-orphan-head.sqlite")
    description = start_alpaca_paper_order_snapshot(system.plan).next_page_description
    assert description is not None
    system.repository.prepare_next(
        description,
        checked_at=BASE + timedelta(seconds=1),
    )

    raw_connection = system.account.engine.raw_connection()
    try:
        raw_connection.execute("PRAGMA foreign_keys=OFF")
        raw_connection.execute("DELETE FROM phase4_alpaca_paper_order_snapshot_plans")
        raw_connection.commit()
        raw_connection.execute("PRAGMA foreign_keys=ON")
    finally:
        raw_connection.close()

    with pytest.raises(
        AlpacaPaperOrderSnapshotPersistenceConflict,
        match="orphaned durable state",
    ):
        system.repository.load_state(system.plan)
    with pytest.raises(
        AlpacaPaperOrderSnapshotPersistenceConflict,
        match="heads exist without durable plans",
    ):
        verify_alpaca_paper_order_snapshot_integrity(system.account.engine)


def test_load_prefix_binds_plan_time_to_the_first_preparation(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4o-plan-time.sqlite")
    description = start_alpaca_paper_order_snapshot(system.plan).next_page_description
    assert description is not None
    system.repository.prepare_next(
        description,
        checked_at=BASE + timedelta(seconds=1),
    )
    with system.account.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_order_snapshot_plans).values(
                prepared_at=BASE + timedelta(seconds=2)
            )
        )

    with pytest.raises(
        AlpacaPaperOrderSnapshotPersistenceConflict,
        match="plan preparation time conflicts with its first claim",
    ):
        system.repository.load_prefix(system.plan)


def test_load_prefix_rejects_a_resealed_head_time_without_its_source(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4o-head-time.sqlite")
    description = start_alpaca_paper_order_snapshot(system.plan).next_page_description
    assert description is not None
    system.repository.prepare_next(
        description,
        checked_at=BASE + timedelta(seconds=1),
    )
    with system.account.engine.begin() as connection:
        row = (
            connection.execute(sa.select(phase4_alpaca_paper_order_snapshot_heads)).mappings().one()
        )
        head = _head_from_row(row)
        tampered_head = replace(
            head,
            updated_at=head.updated_at + timedelta(milliseconds=1),
        )
        connection.execute(
            sa.update(phase4_alpaca_paper_order_snapshot_heads).values(
                updated_at=tampered_head.updated_at,
                canonical_payload=tampered_head.canonical_json,
                semantic_sha256=tampered_head.semantic_sha256,
            )
        )

    with pytest.raises(
        AlpacaPaperOrderSnapshotPersistenceConflict,
        match="head conflicts with its authenticated prefix",
    ):
        system.repository.load_prefix(system.plan)


def test_record_rejects_noncanonical_evidence_before_durable_mutation(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4o-preparation-required.sqlite")
    description = start_alpaca_paper_order_snapshot(system.plan).next_page_description
    assert description is not None
    isolated_repository = SqlAlpacaPaperOrderSnapshotRepository(
        engine=system.account.engine,
        coordinator=system.account.coordinator,
    )

    assert isolated_repository.load_prefix(system.plan).page_count == 0
    with pytest.raises(
        AlpacaPaperOrderSnapshotPersistenceError,
        match="exact authenticated evidence",
    ):
        isolated_repository.record(object())  # type: ignore[arg-type]


def test_migration_refuses_to_drop_a_durable_preparation(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase4o-downgrade.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    system = _system(database_path)
    description = start_alpaca_paper_order_snapshot(system.plan).next_page_description
    assert description is not None
    system.repository.prepare_next(
        description,
        checked_at=BASE + timedelta(seconds=1),
    )
    system.account.engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="refusing to downgrade nonempty authenticated order snapshot history",
    ):
        command.downgrade(
            _alembic_config(database_url),
            "0018_phase4_broker_inbox",
        )

    preserved_engine = create_database_engine(database_url)
    try:
        with preserved_engine.connect() as connection:
            assert (
                connection.scalar(sa.text("SELECT version_num FROM alembic_version"))
                == "0019_phase4_order_snapshots"
            )
            assert (
                connection.scalar(
                    sa.select(sa.func.count()).select_from(phase4_alpaca_paper_order_snapshot_plans)
                )
                == 1
            )
    finally:
        preserved_engine.dispose()


def _alembic_config(database_url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


@pytest.fixture
def phase4o_postgres_engine() -> Iterator[Engine]:
    database_url = os.getenv(TEST_DATABASE_ENV)
    if database_url is None:
        pytest.skip(f"set {TEST_DATABASE_ENV} to run PostgreSQL Phase 4O tests")
    if make_url(database_url).get_backend_name() != "postgresql":
        pytest.fail(f"{TEST_DATABASE_ENV} must select a PostgreSQL test database")
    config = _alembic_config(database_url)
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    with patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}):
        command.upgrade(config, "head")
    engine = create_database_engine(database_url)
    try:
        yield engine
    finally:
        engine.dispose()


def test_postgresql_concurrent_prepare_allows_only_the_claim_winner(
    phase4o_postgres_engine: Engine,
    request: pytest.FixtureRequest,
) -> None:
    engine = phase4o_postgres_engine
    account_id = f"phase4o-pg-{uuid4()}"
    request.addfinalizer(lambda: delete_phase4_postgres_account_facts(engine, account_id))
    instant = datetime.now(tz=UTC)
    coordinator = SqlAccountCoordinator(
        account_id=account_id,
        authority=SqlAccountCoordinatorAuthority(
            engine=engine,
            policy=AccountLeasePolicy(
                policy_id="phase4o-postgres-preparation",
                policy_version="1.0.0",
                lease_ttl=timedelta(minutes=5),
                maximum_in_flight_duration=timedelta(seconds=5),
                takeover_safety_interval=timedelta(seconds=10),
            ),
            clock=FixedClock(instant),
        ),
    )
    coordinator.acquire("phase4o-postgres-worker")
    plan = create_alpaca_paper_order_snapshot_plan(
        account_id=account_id,
        capture_idempotency_key=f"phase4o-pg-capture-{uuid4()}",
        page_limit=2,
        maximum_pages=3,
    )
    description = start_alpaca_paper_order_snapshot(plan).next_page_description
    assert description is not None

    def prepare() -> tuple[str, object]:
        try:
            receipt = SqlAlpacaPaperOrderSnapshotRepository(
                engine=engine,
                coordinator=coordinator,
            ).prepare_next(description, checked_at=instant)
            return ("claimed", receipt)
        except AlpacaPaperOrderSnapshotPersistenceConflict as error:
            return ("rejected", str(error))

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(lambda _: prepare(), range(2)))

    assert sorted(status for status, _ in results) == ["claimed", "rejected"]
    assert "unresolved single-use claim" in next(
        str(value) for status, value in results if status == "rejected"
    )
    with engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase4_alpaca_paper_order_snapshot_plans)
                .where(phase4_alpaca_paper_order_snapshot_plans.c.snapshot_id == plan.snapshot_id)
            )
            == 1
        )
