from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from threading import Barrier
from unittest.mock import patch
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, event, make_url
from sqlalchemy.engine import Connection

from packages.adapters.broker.alpaca_paper import (
    create_alpaca_paper_submission_description,
)
from packages.adapters.broker.alpaca_paper_asset_runtime import (
    AlpacaPaperSecurityReference,
)
from packages.adapters.broker.alpaca_paper_lookup_runtime import (
    AlpacaPaperAuthenticatedLookupOutcome,
    AlpacaPaperAuthenticatedLookupReceipt,
    _observe_authenticated_alpaca_paper_unknown_lookup_with_transport,
    alpaca_paper_unknown_lookup_correlation_sha256,
)
from packages.adapters.broker.alpaca_paper_observations import (
    create_alpaca_client_order_lookup_description,
)
from packages.application.alpaca_paper_unknown_recovery import (
    run_alpaca_paper_unknown_recovery_once,
)
from packages.domain.account_coordinator import (
    AccountFence,
    AccountFenceReceipt,
    _account_fence_receipt,
)
from packages.domain.submission_attempt import (
    UnknownSubmissionResolution,
    resolve_unknown_submission,
)
from packages.domain.unknown_submission_recovery import (
    UnknownSubmissionRecoveryPlan,
    create_unknown_submission_recovery_plan,
)
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.alpaca_paper_account_binding import (
    SqlAlpacaPaperAccountBindingRepository,
)
from packages.persistence.alpaca_paper_lookup_observation import (
    SqlAlpacaPaperLookupObservationRepository,
)
from packages.persistence.batch_risk import account_observation_watermark
from packages.persistence.broker_ingress import SqlBrokerIngressRepository
from packages.persistence.broker_request_budget import (
    SqlBrokerRequestBudgetRepository,
)
from packages.persistence.database import (
    DatabaseSchemaNotReady,
    create_database_engine,
    verify_operational_schema,
)
from packages.persistence.schema import (
    instruments,
    metadata,
    phase2_account_lease_heads,
    phase2_submission_attempt_events,
    phase4_alpaca_paper_lookup_observations,
    phase4_unknown_lookup_recovery_events,
    phase4_unknown_lookup_recovery_heads,
    phase4_unknown_lookup_recovery_plans,
)
from packages.persistence.submission_attempt import _event_values
from packages.persistence.unknown_submission_recovery import (
    RecoveryClaimOutcome,
    SqlUnknownSubmissionRecoveryRepository,
    UnknownSubmissionRecoveryPersistenceConflict,
    UnknownSubmissionRecoveryPersistenceError,
    UnknownSubmissionRecoveryScheduleDecision,
    verify_unknown_submission_recovery_integrity,
)
from tests.integration.test_phase2_submission_attempt_persistence import (
    _system as _submission_system,
)
from tests.integration.test_phase4_alpaca_paper_lookup_observation_persistence import (
    CapturingLookupRecorder,
    PreparedLookupPersistenceSystem,
    _account_binding,
    _prepared_system,
    _run_lookup,
)
from tests.unit.test_alpaca_paper_lookup_runtime import (
    PROVIDER_ASSET_ID,
    LookupResolver,
    LookupTransport,
)
from tests.unit.test_batch_risk import EVALUATED_AT

ROOT = Path(__file__).resolve().parents[2]
TEST_DATABASE_ENV = "AQT_TEST_POSTGRES_URL"
PHASE4J_TABLE_NAMES = frozenset(
    {
        "phase4_unknown_lookup_recovery_events",
        "phase4_unknown_lookup_recovery_heads",
        "phase4_unknown_lookup_recovery_plans",
    }
)


def _alembic_config(database_url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def _phase4j_schema_signature(engine: Engine) -> dict[str, object]:
    inspector = sa.inspect(engine)
    signature: dict[str, object] = {}
    for table_name in sorted(PHASE4J_TABLE_NAMES):
        signature[table_name] = {
            "columns": tuple(
                (
                    column["name"],
                    str(column["type"]),
                    column["nullable"],
                    column.get("default"),
                )
                for column in inspector.get_columns(table_name)
            ),
            "primary_key": (
                str(inspector.get_pk_constraint(table_name)["name"]),
                tuple(inspector.get_pk_constraint(table_name)["constrained_columns"]),
            ),
            "indexes": tuple(
                sorted(
                    (
                        str(index["name"]),
                        tuple(index["column_names"]),
                        bool(index["unique"]),
                    )
                    for index in inspector.get_indexes(table_name)
                )
            ),
            "unique_constraints": tuple(
                sorted(
                    (
                        str(constraint["name"]),
                        tuple(constraint["column_names"]),
                    )
                    for constraint in inspector.get_unique_constraints(table_name)
                )
            ),
            "foreign_keys": tuple(
                sorted(
                    (
                        str(foreign_key["name"]),
                        tuple(foreign_key["constrained_columns"]),
                        str(foreign_key["referred_table"]),
                        tuple(foreign_key["referred_columns"]),
                    )
                    for foreign_key in inspector.get_foreign_keys(table_name)
                )
            ),
            "checks": tuple(
                sorted(
                    (
                        str(constraint["name"]),
                        " ".join(str(constraint["sqltext"]).split()),
                    )
                    for constraint in inspector.get_check_constraints(table_name)
                )
            ),
        }
    signature["source_indexes"] = {
        "phase2_submission_attempts": tuple(
            sorted(
                (
                    str(index["name"]),
                    tuple(index["column_names"]),
                    bool(index["unique"]),
                )
                for index in inspector.get_indexes("phase2_submission_attempts")
            )
        ),
        "phase4_alpaca_paper_lookup_observations": tuple(
            sorted(
                (
                    str(index["name"]),
                    tuple(index["column_names"]),
                    bool(index["unique"]),
                )
                for index in inspector.get_indexes("phase4_alpaca_paper_lookup_observations")
            )
        ),
    }
    return signature


def _set_postgresql_search_path(
    schema_name: str,
) -> Callable[[Connection], None]:
    def set_search_path(
        connection: Connection,
    ) -> None:
        connection.execute(
            sa.text("SELECT pg_catalog.set_config('search_path', :schema_name, true)"),
            {"schema_name": schema_name},
        )

    return set_search_path


@pytest.fixture
def phase4j_postgres_engine() -> Iterator[Engine]:
    """Create an isolated PostgreSQL schema in the explicit test database."""

    database_url = os.getenv(TEST_DATABASE_ENV)
    if database_url is None:
        pytest.skip(f"set {TEST_DATABASE_ENV} to run PostgreSQL Phase 4J tests")
    if make_url(database_url).get_backend_name() != "postgresql":
        pytest.fail(f"{TEST_DATABASE_ENV} must select a PostgreSQL test database")

    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    with patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}):
        command.upgrade(config, "head")

    schema_name = f"aqt_phase4j_{uuid4().hex}"
    database_engine = create_database_engine(database_url)
    isolated_engine: Engine | None = None
    schema_created = False
    try:
        with database_engine.begin() as connection:
            connection.execute(sa.schema.CreateSchema(schema_name))
        schema_created = True
        isolated_engine = create_database_engine(database_url)
        event.listen(
            isolated_engine,
            "begin",
            _set_postgresql_search_path(schema_name),
        )
        with isolated_engine.connect() as connection:
            if connection.scalar(sa.text("SELECT current_schema()")) != schema_name:
                raise RuntimeError("PostgreSQL test schema isolation was not established")
        metadata.create_all(isolated_engine)
        yield isolated_engine
    finally:
        if isolated_engine is not None:
            isolated_engine.dispose()
        if schema_created:
            with database_engine.begin() as connection:
                connection.execute(sa.schema.DropSchema(schema_name, cascade=True))
        database_engine.dispose()


def _copy_operational_facts(source: Engine, target: Engine) -> None:
    with source.connect() as source_connection, target.begin() as target_connection:
        for table in metadata.sorted_tables:
            rows = tuple(source_connection.execute(sa.select(table)).mappings())
            if rows:
                target_connection.execute(
                    sa.insert(table),
                    [dict(row) for row in rows],
                )


def _schedule(
    prepared: PreparedLookupPersistenceSystem,
) -> tuple[
    SqlUnknownSubmissionRecoveryRepository,
    UnknownSubmissionRecoveryPlan,
]:
    attempt = prepared.attempt
    submission = create_alpaca_paper_submission_description(attempt.preparation.intent)
    description = create_alpaca_client_order_lookup_description(
        account_id=attempt.preparation.account_id,
        submission=submission,
    )
    security_reference = AlpacaPaperSecurityReference(
        credential_reference=prepared.reference,
        instrument_id=attempt.preparation.intent.instrument_id,
        symbol=attempt.preparation.intent.symbol,
        expected_provider_asset_id=PROVIDER_ASSET_ID,
    )
    correlation = alpaca_paper_unknown_lookup_correlation_sha256(
        security_reference=security_reference,
        account_binding=prepared.account_binding,
        attempt=attempt,
        description=description,
    )
    plan = create_unknown_submission_recovery_plan(
        account_id=attempt.preparation.account_id,
        client_order_id=attempt.preparation.client_order_id,
        attempt_sha256=attempt.semantic_sha256,
        in_flight_event=attempt.events[1],
        unknown_event=attempt.events[2],
        lookup_correlation_sha256=correlation,
    )
    return (
        SqlUnknownSubmissionRecoveryRepository(
            engine=prepared.submission.engine,
            coordinator=prepared.submission.coordinator,
        ),
        plan,
    )


def _run_not_visible_lookup(
    prepared: PreparedLookupPersistenceSystem,
    *,
    lookup_at: datetime,
    request_idempotency_key: str,
    delivery_idempotency_key: str,
) -> AlpacaPaperAuthenticatedLookupReceipt:
    system = prepared.submission
    system.coordinator_clock.instant = lookup_at
    submission = create_alpaca_paper_submission_description(prepared.attempt.preparation.intent)
    description = create_alpaca_client_order_lookup_description(
        account_id=system.lease.account_id,
        submission=submission,
    )
    security_reference = AlpacaPaperSecurityReference(
        credential_reference=prepared.reference,
        instrument_id=prepared.attempt.preparation.intent.instrument_id,
        symbol=prepared.attempt.preparation.intent.symbol,
        expected_provider_asset_id=PROVIDER_ASSET_ID,
    )
    return _observe_authenticated_alpaca_paper_unknown_lookup_with_transport(
        security_reference=security_reference,
        account_binding=prepared.account_binding,
        attempt=prepared.attempt,
        description=description,
        credential_resolver=LookupResolver(),
        transport=LookupTransport(
            status=404,
            body=b'{"code":40410000,"message":"order not found"}',
            request_id="phase4j-not-visible",
        ),
        budget=SqlBrokerRequestBudgetRepository(
            engine=system.engine,
            clock=system.coordinator_clock,
        ),
        unknown_attempts=system.repository,
        account_bindings=SqlAlpacaPaperAccountBindingRepository(system.engine),
        coordinator=system.coordinator,
        fence=system.lease.fence,
        ingress_recorder=SqlBrokerIngressRepository(system.engine),
        lookup_recorder=prepared.capture,
        clock=system.coordinator_clock,
        request_idempotency_key=request_idempotency_key,
        delivery_idempotency_key=delivery_idempotency_key,
    )


def _late_recorded_unknown(
    database_path: Path,
) -> PreparedLookupPersistenceSystem:
    system = _submission_system(database_path)
    intent = next(intent for intent in system.intents if intent.symbol == "SPY")
    with system.engine.begin() as connection:
        connection.execute(
            sa.insert(instruments).values(
                instrument_id=intent.instrument_id,
                name="SPY zero-slot recovery instrument",
                asset_class="etf",
                currency="USD",
                created_at=EVALUATED_AT,
            )
        )
    submission = create_alpaca_paper_submission_description(intent)
    prepared_at = EVALUATED_AT + timedelta(seconds=1)
    system.coordinator_clock.instant = prepared_at
    attempt = system.repository.prepare(
        intent=intent,
        risk_decision=system.decision,
        fence=system.lease.fence,
        request=submission.request,
        prepared_at=prepared_at,
        recorded_at=prepared_at,
    )
    in_flight_at = EVALUATED_AT + timedelta(seconds=2)
    system.coordinator_clock.instant = in_flight_at
    attempt = system.repository.mark_in_flight(
        attempt.attempt_id,
        fence=system.lease.fence,
        occurred_at=in_flight_at,
        recorded_at=in_flight_at,
    )
    deadline_at = in_flight_at + timedelta(seconds=60)
    attempt = system.repository.mark_unknown(
        attempt.attempt_id,
        occurred_at=EVALUATED_AT + timedelta(seconds=3),
        recorded_at=deadline_at,
        error_class="LateRecordedUnknown",
    )
    account_binding, reference = _account_binding(system)
    repository = SqlAlpacaPaperLookupObservationRepository(
        engine=system.engine,
        coordinator=system.coordinator,
    )
    return PreparedLookupPersistenceSystem(
        submission=system,
        attempt=attempt,
        account_binding=account_binding,
        reference=reference,
        repository=repository,
        capture=CapturingLookupRecorder(delegate=repository, evidence=[]),
    )


@dataclass(frozen=True, slots=True)
class _FoundLookupExecutor:
    prepared: PreparedLookupPersistenceSystem
    lookup_at: datetime

    def execute(
        self,
        *,
        request_idempotency_key: str,
        delivery_idempotency_key: str,
    ) -> AlpacaPaperAuthenticatedLookupReceipt:
        return _run_lookup(
            self.prepared,
            lookup_at=self.lookup_at,
            request_idempotency_key=request_idempotency_key,
            delivery_idempotency_key=delivery_idempotency_key,
        )


@dataclass(frozen=True, slots=True)
class _RegressingCommitFenceValidator:
    delegate: SqlAccountCoordinator
    validated_at: datetime

    def revalidate_for_commit_in_transaction(
        self,
        connection: sa.Connection,
        fence: AccountFence,
    ) -> AccountFenceReceipt:
        current = self.delegate.revalidate_for_commit_in_transaction(
            connection,
            fence,
        )
        return _account_fence_receipt(
            fence=current.fence,
            validated_at=self.validated_at,
            valid_until=current.valid_until,
            policy_sha256=current.policy_sha256,
            lease_sha256=current.lease_sha256,
        )


def test_sql_schedule_claim_is_one_shot_active_then_coalesces_without_burst(
    tmp_path: Path,
) -> None:
    prepared = _prepared_system(tmp_path / "phase4j-claim.sqlite")
    repository, plan = _schedule(prepared)
    first_due = plan.slots[0].scheduled_at

    prepared.submission.coordinator_clock.instant = first_due
    first = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert first.outcome is RecoveryClaimOutcome.DUE
    assert first.newly_issued
    assert first.claim is not None
    assert first.claim.ticket.slot_id == plan.slots[0].slot_id
    assert first.claim.valid_until == first_due + timedelta(seconds=3)

    prepared.submission.coordinator_clock.instant = first_due + timedelta(seconds=1)
    active = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert active.outcome is RecoveryClaimOutcome.ACTIVE
    assert not active.newly_issued
    assert active.claim == first.claim

    prepared.submission.coordinator_clock.instant = first_due + timedelta(seconds=4)
    next_claim = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert next_claim.outcome is RecoveryClaimOutcome.DUE
    assert next_claim.claim is not None
    assert next_claim.claim.ticket.slot_id == plan.slots[2].slot_id
    assert next_claim.evaluation.coalesced_slot_ids == (plan.slots[1].slot_id,)
    progress = repository.load_progress(plan.plan_id)
    assert progress is not None
    assert tuple(dispatch.claim for dispatch in progress.dispatches) == (
        first.claim,
        next_claim.claim,
    )
    assert all(dispatch.lookup_receipt is None for dispatch in progress.dispatches)
    assert progress.consumed_slot_ids == tuple(slot.slot_id for slot in plan.slots[:3])
    assert progress.issuance_status is RecoveryClaimOutcome.ACTIVE

    with prepared.submission.engine.connect() as connection:
        dispatch_rows = tuple(
            connection.execute(
                sa.select(phase4_unknown_lookup_recovery_events)
                .where(phase4_unknown_lookup_recovery_events.c.kind == "dispatch")
                .order_by(phase4_unknown_lookup_recovery_events.c.sequence_number)
            ).mappings()
        )
    assert len(dispatch_rows) == 2
    assert dispatch_rows[0]["selected_slot_ordinal"] == 1
    assert dispatch_rows[1]["selected_slot_ordinal"] == 3
    assert dispatch_rows[1]["coalesced_slot_ids_payload"] == (f'["{plan.slots[1].slot_id}"]')
    verify_unknown_submission_recovery_integrity(prepared.submission.engine)


def test_authenticated_progress_projects_claims_and_attached_receipts_for_restart(
    tmp_path: Path,
) -> None:
    prepared = _prepared_system(tmp_path / "phase4j-progress.sqlite")
    repository, plan = _schedule(prepared)

    assert repository.runtime_store_identity == id(prepared.submission.engine)
    assert repository.load_progress("0" * 64) is None
    for invalid in ("", "0" * 63, "G" * 64):
        with pytest.raises(
            UnknownSubmissionRecoveryPersistenceError,
            match="lowercase SHA-256 digest",
        ):
            repository.load_progress(invalid)

    lookup_at = EVALUATED_AT + timedelta(seconds=20)
    prepared.submission.coordinator_clock.instant = lookup_at
    decision = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert decision.claim is not None
    before_attachment = repository.load_progress(plan.plan_id)
    assert before_attachment is not None
    assert len(before_attachment.dispatches) == 1
    dispatch = before_attachment.dispatches[0]
    assert dispatch.claim == decision.claim
    assert dispatch.lookup_receipt is None
    assert dispatch.lookup_receipt_id is None
    assert dispatch.lookup_receipt_sha256 is None

    ticket = decision.claim.ticket
    receipt = _run_lookup(
        prepared,
        lookup_at=lookup_at,
        request_idempotency_key=ticket.demand_idempotency_key,
        delivery_idempotency_key=ticket.delivery_idempotency_key,
    )
    after_lookup_crash = repository.load_progress(plan.plan_id)
    assert after_lookup_crash is not None
    assert after_lookup_crash.dispatches[0].lookup_receipt is None
    assert prepared.repository.load_by_ingress_receipt_id(ticket.delivery_id) == receipt
    repository.record_observation(
        plan_id=plan.plan_id,
        claim=decision.claim,
        receipt=receipt,
        fence=prepared.submission.lease.fence,
    )

    progress = repository.load_progress(plan.plan_id)
    assert progress is not None
    assert progress == repository.load_progress(plan.plan_id)
    assert progress.plan == plan
    assert len(progress.dispatches) == 1
    attached = progress.dispatches[0]
    assert attached.claim == decision.claim
    assert attached.lookup_receipt == receipt
    assert attached.lookup_receipt_id == receipt.receipt_id
    assert attached.lookup_receipt_sha256 == receipt.semantic_sha256
    assert attached.transport_authorized is False
    assert attached.lookup_authorized is False
    assert attached.attempt_resolution_authorized is False
    assert progress.transport_authorized is False
    assert progress.lookup_authorized is False
    assert progress.attempt_resolution_authorized is False
    assert progress.consumed_slot_ids == tuple(slot.slot_id for slot in plan.slots[:5])
    assert progress.issuance_status is RecoveryClaimOutcome.RECONCILIATION_REQUIRED


def test_sql_schedule_exhaustion_consumes_remaining_and_never_reopens(
    tmp_path: Path,
) -> None:
    prepared = _prepared_system(tmp_path / "phase4j-exhausted.sqlite")
    repository, plan = _schedule(prepared)
    prepared.submission.coordinator_clock.instant = plan.recovery_deadline_at

    exhausted = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert exhausted.outcome is RecoveryClaimOutcome.EXHAUSTED
    assert exhausted.claim is None
    assert exhausted.evaluation.coalesced_slot_ids == tuple(slot.slot_id for slot in plan.slots)

    prepared.submission.coordinator_clock.instant += timedelta(seconds=1)
    replay = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert replay.outcome is RecoveryClaimOutcome.EXHAUSTED
    with prepared.submission.engine.connect() as connection:
        kinds = tuple(connection.scalars(sa.select(phase4_unknown_lookup_recovery_events.c.kind)))
        status = connection.scalar(
            sa.select(phase4_unknown_lookup_recovery_heads.c.issuance_status)
        )
    assert kinds == ("exhausted",)
    assert status == "exhausted"
    verify_unknown_submission_recovery_integrity(prepared.submission.engine)


def test_typed_observation_can_append_after_exhaustion_without_reopening(
    tmp_path: Path,
) -> None:
    prepared = _prepared_system(tmp_path / "phase4j-late-observation.sqlite")
    repository, plan = _schedule(prepared)
    lookup_at = EVALUATED_AT + timedelta(seconds=20)
    prepared.submission.coordinator_clock.instant = lookup_at
    dispatch = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert dispatch.outcome is RecoveryClaimOutcome.DUE
    assert dispatch.claim is not None
    ticket = dispatch.claim.ticket

    receipt = _run_lookup(
        prepared,
        lookup_at=lookup_at,
        request_idempotency_key=ticket.demand_idempotency_key,
        delivery_idempotency_key=ticket.delivery_idempotency_key,
    )
    prepared.submission.coordinator_clock.instant = plan.recovery_deadline_at
    exhausted = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert exhausted.outcome is RecoveryClaimOutcome.EXHAUSTED

    prepared.submission.coordinator_clock.instant += timedelta(seconds=1)
    assert (
        repository.record_observation(
            plan_id=plan.plan_id,
            claim=dispatch.claim,
            receipt=receipt,
            fence=prepared.submission.lease.fence,
        )
        == receipt
    )
    assert (
        repository.record_observation(
            plan_id=plan.plan_id,
            claim=dispatch.claim,
            receipt=receipt,
            fence=prepared.submission.lease.fence,
        )
        == receipt
    )
    with prepared.submission.engine.connect() as connection:
        kinds = tuple(
            connection.scalars(
                sa.select(phase4_unknown_lookup_recovery_events.c.kind).order_by(
                    phase4_unknown_lookup_recovery_events.c.sequence_number
                )
            )
        )
        status = connection.scalar(
            sa.select(phase4_unknown_lookup_recovery_heads.c.issuance_status)
        )
    assert kinds == ("dispatch", "exhausted", "observation")
    assert status == "exhausted"
    verify_unknown_submission_recovery_integrity(prepared.submission.engine)


def test_found_match_requires_reconciliation_and_stops_additional_dispatch(
    tmp_path: Path,
) -> None:
    prepared = _prepared_system(tmp_path / "phase4j-found-match.sqlite")
    repository, plan = _schedule(prepared)
    lookup_at = EVALUATED_AT + timedelta(seconds=20)
    prepared.submission.coordinator_clock.instant = lookup_at
    result = run_alpaca_paper_unknown_recovery_once(
        plan=plan,
        schedule=repository,
        executor=_FoundLookupExecutor(prepared=prepared, lookup_at=lookup_at),
        fence=prepared.submission.lease.fence,
    )
    assert result.newly_issued
    receipt = result.lookup_receipt
    assert receipt is not None
    assert receipt.outcome is AlpacaPaperAuthenticatedLookupOutcome.FOUND_MATCHED

    prepared.submission.coordinator_clock.instant = plan.slots[-1].scheduled_at
    terminal = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert terminal.outcome is RecoveryClaimOutcome.RECONCILIATION_REQUIRED
    assert terminal.claim is None
    assert not terminal.newly_issued
    with prepared.submission.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase4_unknown_lookup_recovery_events)
                .where(phase4_unknown_lookup_recovery_events.c.kind == "dispatch")
            )
            == 1
        )
        assert (
            connection.scalar(sa.select(phase4_unknown_lookup_recovery_heads.c.issuance_status))
            == "reconciliation_required"
        )
    verify_unknown_submission_recovery_integrity(prepared.submission.engine)


def test_security_identity_mismatch_blocks_additional_dispatch(
    tmp_path: Path,
) -> None:
    prepared = _prepared_system(tmp_path / "phase4j-security-mismatch.sqlite")
    repository, plan = _schedule(prepared)
    lookup_at = EVALUATED_AT + timedelta(seconds=20)
    prepared.submission.coordinator_clock.instant = lookup_at
    dispatch = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert dispatch.claim is not None
    receipt = _run_lookup(
        prepared,
        lookup_at=lookup_at,
        asset_id=None,
        provider_request_id="phase4j-security-mismatch",
        request_idempotency_key=dispatch.claim.ticket.demand_idempotency_key,
        delivery_idempotency_key=dispatch.claim.ticket.delivery_idempotency_key,
    )
    assert receipt.outcome is AlpacaPaperAuthenticatedLookupOutcome.SECURITY_IDENTITY_MISMATCH
    repository.record_observation(
        plan_id=plan.plan_id,
        claim=dispatch.claim,
        receipt=receipt,
        fence=prepared.submission.lease.fence,
    )

    prepared.submission.coordinator_clock.instant = plan.slots[-1].scheduled_at
    terminal = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert terminal.outcome is RecoveryClaimOutcome.BLOCKED_MISMATCH
    assert terminal.claim is None
    with prepared.submission.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(phase4_unknown_lookup_recovery_heads.c.issuance_status))
            == "blocked_mismatch"
        )
    verify_unknown_submission_recovery_integrity(prepared.submission.engine)


def test_observation_receipt_must_use_exact_claim_issuing_fence(
    tmp_path: Path,
) -> None:
    prepared = _prepared_system(tmp_path / "phase4j-dispatch-fence.sqlite")
    repository, plan = _schedule(prepared)
    lookup_at = EVALUATED_AT + timedelta(seconds=20)
    prepared.submission.coordinator_clock.instant = lookup_at
    dispatch = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert dispatch.claim is not None

    prepared.submission.coordinator.release(prepared.submission.lease.fence)
    replacement_lease = prepared.submission.coordinator.acquire("phase4j-replacement-owner")
    replacement_system = replace(
        prepared.submission,
        lease=replacement_lease,
    )
    replacement_prepared = replace(
        prepared,
        submission=replacement_system,
    )
    receipt = _run_lookup(
        replacement_prepared,
        lookup_at=lookup_at,
        provider_request_id="phase4j-replacement-fence",
        request_idempotency_key=dispatch.claim.ticket.demand_idempotency_key,
        delivery_idempotency_key=dispatch.claim.ticket.delivery_idempotency_key,
    )

    with pytest.raises(
        UnknownSubmissionRecoveryPersistenceConflict,
        match="plan or one-shot claim",
    ):
        repository.record_observation(
            plan_id=plan.plan_id,
            claim=dispatch.claim,
            receipt=receipt,
            fence=replacement_lease.fence,
        )
    verify_unknown_submission_recovery_integrity(prepared.submission.engine)


def test_not_visible_observation_remains_active_and_allows_next_due_slot(
    tmp_path: Path,
) -> None:
    prepared = _prepared_system(tmp_path / "phase4j-not-visible.sqlite")
    repository, plan = _schedule(prepared)
    lookup_at = EVALUATED_AT + timedelta(seconds=20)
    prepared.submission.coordinator_clock.instant = lookup_at
    dispatch = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert dispatch.claim is not None
    receipt = _run_not_visible_lookup(
        prepared,
        lookup_at=lookup_at,
        request_idempotency_key=dispatch.claim.ticket.demand_idempotency_key,
        delivery_idempotency_key=dispatch.claim.ticket.delivery_idempotency_key,
    )
    assert receipt.outcome is AlpacaPaperAuthenticatedLookupOutcome.NOT_VISIBLE_INCONCLUSIVE
    repository.record_observation(
        plan_id=plan.plan_id,
        claim=dispatch.claim,
        receipt=receipt,
        fence=prepared.submission.lease.fence,
    )

    prepared.submission.coordinator_clock.instant = plan.slots[-1].scheduled_at
    next_due = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert next_due.outcome is RecoveryClaimOutcome.DUE
    assert next_due.claim is not None
    assert next_due.claim.ticket.slot_id == plan.slots[-1].slot_id
    with prepared.submission.engine.connect() as connection:
        assert (
            connection.scalar(sa.select(phase4_unknown_lookup_recovery_heads.c.issuance_status))
            == "active"
        )
    verify_unknown_submission_recovery_integrity(prepared.submission.engine)


def test_zero_slot_plan_persists_as_immediately_exhausted(
    tmp_path: Path,
) -> None:
    prepared = _late_recorded_unknown(tmp_path / "phase4j-zero-slot.sqlite")
    repository, plan = _schedule(prepared)
    assert plan.slots == ()
    assert plan.unknown_recorded_at == plan.recovery_deadline_at

    prepared.submission.coordinator_clock.instant = plan.recovery_deadline_at
    exhausted = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert exhausted.outcome is RecoveryClaimOutcome.EXHAUSTED
    assert exhausted.evaluation.coalesced_slot_ids == ()
    assert repository.load_plan(plan.plan_id) == plan
    progress = repository.load_progress(plan.plan_id)
    assert progress is not None
    assert progress.plan == plan
    assert progress.dispatches == ()
    assert progress.consumed_slot_ids == ()
    assert progress.issuance_status is RecoveryClaimOutcome.EXHAUSTED
    verify_unknown_submission_recovery_integrity(prepared.submission.engine)


def test_plan_authenticates_historical_unknown_prefix_after_later_resolution(
    tmp_path: Path,
) -> None:
    prepared = _prepared_system(tmp_path / "phase4j-historical-prefix.sqlite")
    repository, plan = _schedule(prepared)
    prepared.submission.coordinator_clock.instant = EVALUATED_AT + timedelta(seconds=20)
    decision = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert decision.outcome is RecoveryClaimOutcome.DUE

    resolved = resolve_unknown_submission(
        prepared.attempt,
        occurred_at=EVALUATED_AT + timedelta(seconds=21),
        recorded_at=EVALUATED_AT + timedelta(seconds=21),
        resolution=UnknownSubmissionResolution.NOT_SUBMITTED,
        reconciliation_sha256="a" * 64,
    )
    with prepared.submission.engine.begin() as connection:
        visibility_watermark = account_observation_watermark(
            connection,
            prepared.attempt.preparation.account_id,
        )
        connection.execute(
            sa.insert(phase2_submission_attempt_events).values(
                **_event_values(
                    resolved.events[-1],
                    account_id=prepared.attempt.preparation.account_id,
                    visible_after_observation_sequence=visibility_watermark,
                )
            )
        )

    assert repository.load_plan(plan.plan_id) == plan
    verify_unknown_submission_recovery_integrity(prepared.submission.engine)


def test_postgresql_concurrent_same_plan_evaluation_issues_one_dispatch(
    tmp_path: Path,
    phase4j_postgres_engine: Engine,
) -> None:
    prepared = _prepared_system(tmp_path / "phase4j-postgres-source.sqlite")
    _, plan = _schedule(prepared)
    _copy_operational_facts(
        prepared.submission.engine,
        phase4j_postgres_engine,
    )
    prepared.submission.coordinator_clock.instant = plan.slots[0].scheduled_at
    coordinator = SqlAccountCoordinator(
        account_id=plan.account_id,
        authority=SqlAccountCoordinatorAuthority(
            engine=phase4j_postgres_engine,
            policy=prepared.submission.coordinator._authority.policy,
            clock=prepared.submission.coordinator_clock,
        ),
    )
    repositories = tuple(
        SqlUnknownSubmissionRecoveryRepository(
            engine=phase4j_postgres_engine,
            coordinator=coordinator,
        )
        for _ in range(2)
    )
    start = Barrier(3)

    def evaluate(index: int) -> UnknownSubmissionRecoveryScheduleDecision:
        start.wait(timeout=10)
        return repositories[index].evaluate(
            plan,
            fence=prepared.submission.lease.fence,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = tuple(executor.submit(evaluate, index) for index in range(2))
        start.wait(timeout=10)
        decisions = tuple(future.result(timeout=20) for future in futures)

    assert {decision.outcome for decision in decisions} == {
        RecoveryClaimOutcome.DUE,
        RecoveryClaimOutcome.ACTIVE,
    }
    due = next(decision for decision in decisions if decision.outcome is RecoveryClaimOutcome.DUE)
    active = next(
        decision for decision in decisions if decision.outcome is RecoveryClaimOutcome.ACTIVE
    )
    assert due.claim is not None
    assert active.claim == due.claim
    with phase4j_postgres_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase4_unknown_lookup_recovery_events)
                .where(
                    phase4_unknown_lookup_recovery_events.c.plan_id == plan.plan_id,
                    phase4_unknown_lookup_recovery_events.c.kind == "dispatch",
                )
            )
            == 1
        )
    verify_unknown_submission_recovery_integrity(phase4j_postgres_engine)


def test_schedule_verifier_rejects_head_rollback(
    tmp_path: Path,
) -> None:
    prepared = _prepared_system(tmp_path / "phase4j-head-tamper.sqlite")
    repository, plan = _schedule(prepared)
    prepared.submission.coordinator_clock.instant = plan.slots[0].scheduled_at
    decision = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert decision.outcome is RecoveryClaimOutcome.DUE

    with prepared.submission.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_unknown_lookup_recovery_heads).values(
                consumed_slot_ids_payload="[]",
                consumed_slot_count=0,
            )
        )
    with pytest.raises(
        UnknownSubmissionRecoveryPersistenceConflict,
        match="head conflicts",
    ):
        verify_unknown_submission_recovery_integrity(prepared.submission.engine)
    with pytest.raises(
        UnknownSubmissionRecoveryPersistenceConflict,
        match="head conflicts",
    ):
        repository.load_progress(plan.plan_id)


def test_progress_rejects_corrupted_attached_lookup_source(
    tmp_path: Path,
) -> None:
    prepared = _prepared_system(tmp_path / "phase4j-progress-source-tamper.sqlite")
    repository, plan = _schedule(prepared)
    lookup_at = EVALUATED_AT + timedelta(seconds=20)
    prepared.submission.coordinator_clock.instant = lookup_at
    decision = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert decision.claim is not None
    receipt = _run_lookup(
        prepared,
        lookup_at=lookup_at,
        request_idempotency_key=decision.claim.ticket.demand_idempotency_key,
        delivery_idempotency_key=decision.claim.ticket.delivery_idempotency_key,
    )
    repository.record_observation(
        plan_id=plan.plan_id,
        claim=decision.claim,
        receipt=receipt,
        fence=prepared.submission.lease.fence,
    )
    with prepared.submission.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_lookup_observations)
            .where(phase4_alpaca_paper_lookup_observations.c.receipt_id == receipt.receipt_id)
            .values(canonical_payload="[]")
        )

    with pytest.raises(
        UnknownSubmissionRecoveryPersistenceConflict,
        match="progress authentication failed",
    ):
        repository.load_progress(plan.plan_id)


def test_regressing_structural_fence_time_rejects_evaluation_and_observation_without_rows(
    tmp_path: Path,
) -> None:
    prepared = _prepared_system(tmp_path / "phase4j-regressing-time.sqlite")
    repository, plan = _schedule(prepared)
    lookup_at = EVALUATED_AT + timedelta(seconds=20)
    prepared.submission.coordinator_clock.instant = lookup_at
    dispatch = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert dispatch.claim is not None
    receipt = _run_lookup(
        prepared,
        lookup_at=lookup_at,
        request_idempotency_key=dispatch.claim.ticket.demand_idempotency_key,
        delivery_idempotency_key=dispatch.claim.ticket.delivery_idempotency_key,
    )
    with prepared.submission.engine.connect() as connection:
        event_count_before = connection.scalar(
            sa.select(sa.func.count())
            .select_from(phase4_unknown_lookup_recovery_events)
            .where(phase4_unknown_lookup_recovery_events.c.plan_id == plan.plan_id)
        )
        head_before = dict(
            connection.execute(
                sa.select(phase4_unknown_lookup_recovery_heads).where(
                    phase4_unknown_lookup_recovery_heads.c.plan_id == plan.plan_id
                )
            )
            .mappings()
            .one()
        )

    regressing_repository = SqlUnknownSubmissionRecoveryRepository(
        engine=prepared.submission.engine,
        coordinator=_RegressingCommitFenceValidator(
            delegate=prepared.submission.coordinator,
            validated_at=lookup_at - timedelta(milliseconds=1),
        ),
    )
    with pytest.raises(
        UnknownSubmissionRecoveryPersistenceConflict,
        match="trusted recovery schedule time regresses",
    ):
        regressing_repository.evaluate(
            plan,
            fence=prepared.submission.lease.fence,
        )
    with pytest.raises(
        UnknownSubmissionRecoveryPersistenceConflict,
        match="trusted recovery schedule time regresses",
    ):
        regressing_repository.record_observation(
            plan_id=plan.plan_id,
            claim=dispatch.claim,
            receipt=receipt,
            fence=prepared.submission.lease.fence,
        )

    with prepared.submission.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase4_unknown_lookup_recovery_events)
                .where(phase4_unknown_lookup_recovery_events.c.plan_id == plan.plan_id)
            )
            == event_count_before
        )
        assert (
            dict(
                connection.execute(
                    sa.select(phase4_unknown_lookup_recovery_heads).where(
                        phase4_unknown_lookup_recovery_heads.c.plan_id == plan.plan_id
                    )
                )
                .mappings()
                .one()
            )
            == head_before
        )
    verify_unknown_submission_recovery_integrity(prepared.submission.engine)


def test_0016_upgrade_is_additive_and_preserves_prior_rows(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase4j-additive.sqlite'}"
    config = _alembic_config(database_url)
    with patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}):
        command.upgrade(config, "0015_phase4_lookup_observation")
    engine = create_database_engine(database_url)
    inspector = sa.inspect(engine)
    prior_tables = set(inspector.get_table_names())
    prior_columns = {
        table_name: tuple(column["name"] for column in inspector.get_columns(table_name))
        for table_name in prior_tables
    }
    marker_account_id = "phase4j-additive-marker"
    with engine.begin() as connection:
        connection.execute(
            sa.insert(phase2_account_lease_heads).values(
                account_id=marker_account_id,
                last_fencing_generation=0,
                current_fencing_generation=None,
                current_lease_sha256=None,
                updated_at=EVALUATED_AT,
            )
        )
    engine.dispose()

    with patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}):
        command.upgrade(config, "0016_phase4_unknown_schedule")
    upgraded_engine = create_database_engine(database_url)
    upgraded_inspector = sa.inspect(upgraded_engine)
    assert set(upgraded_inspector.get_table_names()) == prior_tables | PHASE4J_TABLE_NAMES
    assert {
        table_name: tuple(column["name"] for column in upgraded_inspector.get_columns(table_name))
        for table_name in prior_tables
    } == prior_columns
    with upgraded_engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(phase2_account_lease_heads.c.account_id).where(
                    phase2_account_lease_heads.c.account_id == marker_account_id
                )
            )
            == marker_account_id
        )
    attempt_indexes = {
        str(index["name"]): (
            tuple(index["column_names"]),
            bool(index["unique"]),
        )
        for index in upgraded_inspector.get_indexes("phase2_submission_attempts")
    }
    lookup_indexes = {
        str(index["name"]): (
            tuple(index["column_names"]),
            bool(index["unique"]),
        )
        for index in upgraded_inspector.get_indexes("phase4_alpaca_paper_lookup_observations")
    }
    assert attempt_indexes["ux_phase2_submission_attempt_recovery_source"] == (
        ("account_id", "attempt_id", "client_order_id"),
        True,
    )
    assert lookup_indexes["ux_phase4_lookup_observation_recovery_exact"] == (
        ("account_id", "attempt_id", "receipt_id", "semantic_sha256"),
        True,
    )
    upgraded_engine.dispose()


def test_0016_empty_downgrade_and_reupgrade_restore_exact_schema(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase4j-round-trip.sqlite'}"
    config = _alembic_config(database_url)
    with patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}):
        command.upgrade(config, "0016_phase4_unknown_schedule")
    engine = create_database_engine(database_url)
    expected_signature = _phase4j_schema_signature(engine)
    engine.dispose()

    with patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}):
        command.downgrade(config, "0015_phase4_lookup_observation")
    downgraded_engine = create_database_engine(database_url)
    downgraded_inspector = sa.inspect(downgraded_engine)
    assert not PHASE4J_TABLE_NAMES.intersection(downgraded_inspector.get_table_names())
    assert "ux_phase2_submission_attempt_recovery_source" not in {
        index["name"] for index in downgraded_inspector.get_indexes("phase2_submission_attempts")
    }
    assert "ux_phase4_lookup_observation_recovery_exact" not in {
        index["name"]
        for index in downgraded_inspector.get_indexes("phase4_alpaca_paper_lookup_observations")
    }
    downgraded_engine.dispose()

    with patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}):
        command.upgrade(config, "0016_phase4_unknown_schedule")
    reupgraded_engine = create_database_engine(database_url)
    assert _phase4j_schema_signature(reupgraded_engine) == expected_signature
    reupgraded_engine.dispose()


def test_0016_downgrade_refuses_nonempty_real_schedule_history(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase4j-nonempty-downgrade.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = _alembic_config(database_url)
    with patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}):
        command.upgrade(config, "0016_phase4_unknown_schedule")
    prepared = _prepared_system(database_path)
    repository, plan = _schedule(prepared)
    prepared.submission.coordinator_clock.instant = plan.slots[0].scheduled_at
    decision = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert decision.outcome is RecoveryClaimOutcome.DUE
    prepared.submission.engine.dispose()

    with (
        patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}),
        pytest.raises(
            RuntimeError,
            match="refusing to downgrade nonempty UNKNOWN lookup recovery schedule history",
        ),
    ):
        command.downgrade(config, "0015_phase4_lookup_observation")

    preserved_engine = create_database_engine(database_url)
    with preserved_engine.connect() as connection:
        assert connection.scalar(sa.text("SELECT version_num FROM alembic_version")) == (
            "0016_phase4_unknown_schedule"
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_unknown_lookup_recovery_plans)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_unknown_lookup_recovery_events)
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_unknown_lookup_recovery_heads)
            )
            == 1
        )
    preserved_engine.dispose()


def test_operational_readiness_wraps_phase4j_head_projection_corruption(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "phase4j-readiness.sqlite"
    database_url = f"sqlite+pysqlite:///{database_path}"
    config = _alembic_config(database_url)
    with patch.dict(os.environ, {"AQT_DATABASE_URL": database_url}):
        command.upgrade(config, "head")
    prepared = _prepared_system(database_path)
    repository, plan = _schedule(prepared)
    prepared.submission.coordinator_clock.instant = plan.slots[0].scheduled_at
    decision = repository.evaluate(
        plan,
        fence=prepared.submission.lease.fence,
    )
    assert decision.outcome is RecoveryClaimOutcome.DUE
    verify_operational_schema(
        prepared.submission.engine,
        require_phase_zero_facts=False,
    )

    with prepared.submission.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_unknown_lookup_recovery_heads)
            .where(phase4_unknown_lookup_recovery_heads.c.plan_id == plan.plan_id)
            .values(
                consumed_slot_ids_payload="[]",
                consumed_slot_count=0,
            )
        )
    with pytest.raises(
        DatabaseSchemaNotReady,
        match="Phase 4 UNKNOWN lookup-schedule integrity verification failed",
    ):
        verify_operational_schema(
            prepared.submission.engine,
            require_phase_zero_facts=False,
        )
