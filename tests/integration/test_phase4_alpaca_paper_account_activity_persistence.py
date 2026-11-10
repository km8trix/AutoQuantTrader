from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config

from packages.adapters.broker.alpaca_paper_account_activities import (
    AlpacaPaperAccountActivityPageDescription,
    AlpacaPaperAccountActivityPlan,
    create_alpaca_paper_account_activity_plan,
    start_alpaca_paper_account_activity_capture,
)
from packages.adapters.broker.alpaca_paper_account_activity_runtime import (
    ALPACA_PAPER_ACCOUNT_ACTIVITY_ACCEPT_MEDIA_TYPE,
    ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_ID,
    ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_VERSION,
    AlpacaPaperAccountActivityTransportRequest,
    AlpacaPaperAccountActivityTransportResponse,
    AlpacaPaperAccountActivityTraversalStage,
    AlpacaPaperAuthenticatedAccountActivityPageReceipt,
    _observe_authenticated_alpaca_paper_account_activity_page_with_transport,
)
from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperCredentialReference,
    _AlpacaPaperAuthenticationHeaders,
    _AlpacaPaperCredentialMaterial,
    create_alpaca_paper_credential_envelope,
)
from packages.domain.account_coordinator import (
    _account_fence_receipt,
)
from packages.persistence.alpaca_paper_account_activity import (
    AlpacaPaperAccountActivityPersistenceConflict,
    SqlAlpacaPaperAccountActivityRepository,
    verify_alpaca_paper_account_activity_integrity,
)
from packages.persistence.broker_ingress import SqlBrokerIngressRepository
from packages.persistence.broker_request_budget import (
    SqlBrokerRequestBudgetRepository,
)
from packages.persistence.database import (
    verify_operational_schema,
)
from packages.persistence.schema import (
    phase4_alpaca_paper_account_activity_heads,
    phase4_alpaca_paper_account_activity_pages,
    phase4_alpaca_paper_account_activity_plans,
    phase4_alpaca_paper_account_activity_preparations,
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
from tests.unit.test_alpaca_paper_account_activities import _activity, _body

ROOT = Path(__file__).resolve().parents[2]
TEST_DATABASE_ENV = "AQT_TEST_POSTGRES_URL"
ACTIVITY_TABLES = (
    phase4_alpaca_paper_account_activity_plans,
    phase4_alpaca_paper_account_activity_pages,
    phase4_alpaca_paper_account_activity_preparations,
    phase4_alpaca_paper_account_activity_heads,
)


class AccountActivityCredentialResolver:
    resolver_id = "phase4ae-integration-secret-store"
    resolver_version = "v1"

    def __init__(self) -> None:
        self.materials: list[_AlpacaPaperCredentialMaterial] = []

    def _resolve_for_account_activity_page(
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


class AccountActivityTransport:
    transport_id = ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_ID
    transport_version = ALPACA_PAPER_ACCOUNT_ACTIVITY_TRANSPORT_VERSION

    def __init__(self, response_body: bytes) -> None:
        self.response_body = response_body
        self.calls = 0

    def execute(
        self,
        request: AlpacaPaperAccountActivityTransportRequest,
        headers: _AlpacaPaperAuthenticationHeaders,
    ) -> AlpacaPaperAccountActivityTransportResponse:
        self.calls += 1
        assert tuple(headers)
        return AlpacaPaperAccountActivityTransportResponse(
            request_sha256=request.semantic_sha256,
            transport_id=self.transport_id,
            transport_version=self.transport_version,
            http_status=200,
            provider_request_id=f"phase4ae-integration-request-{self.calls:03d}",
            media_type=ALPACA_PAPER_ACCOUNT_ACTIVITY_ACCEPT_MEDIA_TYPE,
            response_body=self.response_body,
        )


@dataclass(slots=True)
class Phase4AccountActivitySystem:
    account: RuntimeSystem
    binding: object
    reference: AlpacaPaperCredentialReference
    plan: AlpacaPaperAccountActivityPlan
    repository: SqlAlpacaPaperAccountActivityRepository
    resolver: AccountActivityCredentialResolver
    ingress: SqlBrokerIngressRepository

    def observe(
        self,
        description: AlpacaPaperAccountActivityPageDescription,
        *,
        response_body: bytes,
        runtime_instants: list[datetime],
        budget_instants: list[datetime],
    ) -> AlpacaPaperAuthenticatedAccountActivityPageReceipt:
        return _observe_authenticated_alpaca_paper_account_activity_page_with_transport(
            reference=self.reference,
            account_binding=self.binding,  # type: ignore[arg-type]
            description=description,
            credential_resolver=self.resolver,
            transport=AccountActivityTransport(response_body),
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
    page_size: int = 2,
    maximum_pages: int = 3,
    maximum_items: int = 6,
    migrated: bool = True,
) -> Phase4AccountActivitySystem:
    account = _account_system(
        database_path,
        run_count=3,
        migrated=migrated,
    )
    binding = account.observe("phase4ae-source")
    reference = AlpacaPaperCredentialReference(
        account_id=ACCOUNT_ID,
        expected_provider_account_id=PROVIDER_ACCOUNT_ID,
        secret_ref="secret://paper/alpaca/trading",
        secret_version="version-001",
    )
    plan = create_alpaca_paper_account_activity_plan(
        account_id=ACCOUNT_ID,
        capture_idempotency_key="phase4ae-integration-capture-0001",
        page_size=page_size,
        maximum_pages=maximum_pages,
        maximum_items=maximum_items,
    )
    return Phase4AccountActivitySystem(
        account=account,
        binding=binding,
        reference=reference,
        plan=plan,
        repository=SqlAlpacaPaperAccountActivityRepository(
            engine=account.engine,
            coordinator=account.coordinator,
        ),
        resolver=AccountActivityCredentialResolver(),
        ingress=SqlBrokerIngressRepository(account.engine),
    )


def test_0029_migration_is_additive_schema_exact_and_reversible(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase4ae-migration.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)

    command.upgrade(config, "0028_phase5_strategy_supervision")
    engine = sa.create_engine(database_url)
    prior_tables = set(sa.inspect(engine).get_table_names())

    command.upgrade(config, "0029_phase4_account_activities")

    assert set(sa.inspect(engine).get_table_names()) == prior_tables | {
        table.name for table in ACTIVITY_TABLES
    }
    for table in ACTIVITY_TABLES:
        assert tuple(
            column["name"] for column in sa.inspect(engine).get_columns(table.name)
        ) == tuple(table.c.keys())

    engine.dispose()
    command.downgrade(config, "0028_phase5_strategy_supervision")
    downgraded = sa.create_engine(database_url)
    assert set(sa.inspect(downgraded).get_table_names()) == prior_tables
    downgraded.dispose()


def test_prepare_claim_is_single_use_and_restart_refuses_a_stalled_page(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4ae-preparation.sqlite")
    description = start_alpaca_paper_account_activity_capture(system.plan).next_page_description
    assert description is not None
    assert system.repository.runtime_store_identity == id(system.account.engine)
    absent = system.repository.load_state(system.plan)

    assert absent.stage is AlpacaPaperAccountActivityTraversalStage.ABSENT
    assert absent.prefix.page_receipts == ()
    assert absent.preparation is None
    assert absent.source_head_sha256 is None

    first = system.repository.prepare_next(
        description,
        checked_at=BASE + timedelta(seconds=1),
    )
    restarted = SqlAlpacaPaperAccountActivityRepository(
        engine=system.account.engine,
        coordinator=system.account.coordinator,
    )
    assert restarted.runtime_store_identity == system.repository.runtime_store_identity
    with pytest.raises(
        AlpacaPaperAccountActivityPersistenceConflict,
        match="unresolved single-use claim",
    ):
        restarted.prepare_next(
            description,
            checked_at=BASE + timedelta(seconds=1, milliseconds=1),
        )

    assert restarted.load_prefix(system.plan).page_count == 0
    stalled = restarted.load_state(system.plan)
    assert stalled.stage is AlpacaPaperAccountActivityTraversalStage.STALLED
    assert stalled.prefix.page_receipts == ()
    assert stalled.preparation == first
    assert stalled.source_head_sha256 is not None
    with system.account.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(phase4_alpaca_paper_account_activity_heads.c.state))
            == "stalled"
        )
        assert (
            connection.scalar(
                sa.select(phase4_alpaca_paper_account_activity_heads.c.preparation_sha256)
            )
            == first.semantic_sha256
        )


def test_authenticated_page_round_trips_from_exact_durable_sources(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4ae-round-trip.sqlite")
    description = start_alpaca_paper_account_activity_capture(system.plan).next_page_description
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
    restarted = SqlAlpacaPaperAccountActivityRepository(
        engine=system.account.engine,
        coordinator=system.account.coordinator,
    )
    prefix = restarted.load_prefix(system.plan)
    state = restarted.load_state(system.plan)

    assert prefix.page_receipts == (receipt,)
    assert state.stage is (AlpacaPaperAccountActivityTraversalStage.CURSOR_EXHAUSTED)
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
                sa.select(sa.func.count()).select_from(phase4_alpaca_paper_account_activity_plans)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_alpaca_paper_account_activity_pages)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(
                    phase4_alpaca_paper_account_activity_preparations
                )
            )
            == 1
        )
        assert (
            connection.scalar(sa.select(phase4_alpaca_paper_account_activity_heads.c.state))
            == "cursor_exhausted_unisolated"
        )
    verify_alpaca_paper_account_activity_integrity(system.account.engine)
    verify_operational_schema(
        system.account.engine,
        require_phase_zero_facts=False,
    )


def test_load_state_reports_bounded_truncation_without_resume_authority(
    tmp_path: Path,
) -> None:
    system = _system(
        tmp_path / "phase4ae-bounded-state.sqlite",
        page_size=1,
        maximum_pages=1,
    )
    description = system.repository.load_state(system.plan).prefix.next_page_description
    assert description is not None
    receipt = system.observe(
        description,
        response_body=_body(
            _activity(
                1,
                transaction_time="2026-07-27T13:59:00.123456789Z",
            )
        ),
        runtime_instants=_first_page_runtime_instants(),
        budget_instants=[
            BASE + timedelta(seconds=1, milliseconds=40),
            BASE + timedelta(seconds=2, milliseconds=10),
        ],
    )

    state = system.repository.load_state(system.plan)

    assert state.stage is (AlpacaPaperAccountActivityTraversalStage.BOUNDED_TRUNCATED)
    assert state.prefix.page_receipts == (receipt,)
    assert state.prefix.capture.bounded_truncation is True
    assert state.preparation is None
    assert state.source_head_sha256 is not None


def test_two_page_prefix_binds_runtime_and_phase4ad_predecessors(
    tmp_path: Path,
) -> None:
    system = _system(
        tmp_path / "phase4ae-two-pages.sqlite",
        page_size=1,
    )
    first_description = start_alpaca_paper_account_activity_capture(
        system.plan
    ).next_page_description
    assert first_description is not None
    first = system.observe(
        first_description,
        response_body=_body(
            _activity(
                1,
                transaction_time="2026-07-27T13:59:00.123456789Z",
            )
        ),
        runtime_instants=_first_page_runtime_instants(),
        budget_instants=[
            BASE + timedelta(seconds=1, milliseconds=40),
            BASE + timedelta(seconds=2, milliseconds=10),
        ],
    )
    active = system.repository.load_state(system.plan)
    assert active.stage is AlpacaPaperAccountActivityTraversalStage.ACTIVE
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
    verify_alpaca_paper_account_activity_integrity(system.account.engine)


def test_item_bound_reduces_the_exact_next_page_and_stops_full_page(
    tmp_path: Path,
) -> None:
    system = _system(
        tmp_path / "phase4ae-item-bound.sqlite",
        page_size=2,
        maximum_pages=3,
        maximum_items=3,
    )
    first_description = system.repository.load_state(system.plan).prefix.next_page_description
    assert first_description is not None
    first = system.observe(
        first_description,
        response_body=_body(_activity(1), _activity(2)),
        runtime_instants=_first_page_runtime_instants(),
        budget_instants=[
            BASE + timedelta(seconds=1, milliseconds=40),
            BASE + timedelta(seconds=2, milliseconds=10),
        ],
    )
    next_description = system.repository.load_prefix(system.plan).next_page_description
    assert next_description is not None
    assert next_description.page_number == 2
    assert next_description.page_size == 1
    assert next_description.page_token == (first.persisted_page.observation.next_page_token)

    second = system.observe(
        next_description,
        response_body=_body(_activity(3)),
        runtime_instants=_second_page_runtime_instants(),
        budget_instants=[
            BASE + timedelta(seconds=2, milliseconds=550),
            BASE + timedelta(seconds=2, milliseconds=750),
        ],
    )
    state = system.repository.load_state(system.plan)

    assert state.stage is AlpacaPaperAccountActivityTraversalStage.BOUNDED_TRUNCATED
    assert state.prefix.page_receipts == (first, second)
    assert state.prefix.capture.activity_count == 3
    assert state.prefix.next_page_description is None
    with system.account.engine.connect() as connection:
        head = (
            connection.execute(sa.select(phase4_alpaca_paper_account_activity_heads))
            .mappings()
            .one()
        )
    assert head["committed_activity_count"] == 3
    assert head["next_page_size"] is None


def test_load_prefix_rejects_tampered_canonical_page_payload(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4ae-tamper.sqlite")
    description = start_alpaca_paper_account_activity_capture(system.plan).next_page_description
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
            sa.update(phase4_alpaca_paper_account_activity_pages).values(
                canonical_payload='{"tampered":true}'
            )
        )

    with pytest.raises(
        AlpacaPaperAccountActivityPersistenceConflict,
        match="reconstruction",
    ):
        system.repository.load_prefix(system.plan)
    with pytest.raises(AlpacaPaperAccountActivityPersistenceConflict):
        verify_alpaca_paper_account_activity_integrity(system.account.engine)


def test_load_prefix_requires_fence_expiry_from_the_exact_lease(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4ae-fence-expiry.sqlite")
    description = start_alpaca_paper_account_activity_capture(system.plan).next_page_description
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
            sa.update(phase4_alpaca_paper_account_activity_pages).values(
                pre_fence_valid_until=tampered_fence.valid_until,
                pre_fence_receipt_sha256=tampered_fence.semantic_sha256,
            )
        )

    with pytest.raises(
        AlpacaPaperAccountActivityPersistenceConflict,
        match="pre fence conflicts with its lease source",
    ):
        system.repository.load_prefix(system.plan)


def test_load_rejects_a_missing_immutable_preparation_fact(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4ae-missing-preparation.sqlite")
    description = start_alpaca_paper_account_activity_capture(system.plan).next_page_description
    assert description is not None
    preparation = system.repository.prepare_next(
        description,
        checked_at=BASE + timedelta(seconds=1),
    )
    with system.account.engine.begin() as connection:
        connection.execute(
            sa.delete(phase4_alpaca_paper_account_activity_preparations).where(
                phase4_alpaca_paper_account_activity_preparations.c.preparation_sha256
                == preparation.semantic_sha256
            )
        )

    with pytest.raises(
        AlpacaPaperAccountActivityPersistenceConflict,
        match="lacks its immutable fact",
    ):
        system.repository.load_state(system.plan)
    with pytest.raises(
        AlpacaPaperAccountActivityPersistenceConflict,
        match="lacks its immutable fact",
    ):
        verify_alpaca_paper_account_activity_integrity(system.account.engine)


@pytest.mark.parametrize(
    ("table", "expected_message"),
    (
        (
            phase4_alpaca_paper_account_activity_plans,
            "plan conflicts with its canonical value",
        ),
        (
            phase4_alpaca_paper_account_activity_heads,
            "head conflicts with its canonical value",
        ),
    ),
)
def test_load_state_rejects_resealed_plan_or_head_corruption(
    tmp_path: Path,
    table: sa.Table,
    expected_message: str,
) -> None:
    system = _system(tmp_path / f"phase4ae-{table.name}-corrupt.sqlite")
    description = start_alpaca_paper_account_activity_capture(system.plan).next_page_description
    assert description is not None
    system.repository.prepare_next(
        description,
        checked_at=BASE + timedelta(seconds=1),
    )
    with system.account.engine.begin() as connection:
        connection.execute(sa.update(table).values(canonical_payload='{"tampered":true}'))

    with pytest.raises(
        AlpacaPaperAccountActivityPersistenceConflict,
        match=expected_message,
    ):
        system.repository.load_state(system.plan)
    with pytest.raises(AlpacaPaperAccountActivityPersistenceConflict):
        verify_alpaca_paper_account_activity_integrity(system.account.engine)
