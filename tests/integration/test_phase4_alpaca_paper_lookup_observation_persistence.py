from __future__ import annotations

import json
from dataclasses import dataclass, fields
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, inspect

import packages.persistence.alpaca_paper_lookup_observation as lookup_persistence
from packages.adapters.broker.alpaca_paper import (
    create_alpaca_paper_submission_description,
)
from packages.adapters.broker.alpaca_paper_account_assets import (
    create_alpaca_account_observation_description,
)
from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperAuthenticatedAccountBinding,
    AlpacaPaperCredentialReference,
    _observe_authenticated_alpaca_paper_account_with_transport,
)
from packages.adapters.broker.alpaca_paper_asset_runtime import (
    AlpacaPaperSecurityReference,
)
from packages.adapters.broker.alpaca_paper_lookup_runtime import (
    AlpacaPaperAuthenticatedLookupEvidence,
    AlpacaPaperAuthenticatedLookupOutcome,
    AlpacaPaperAuthenticatedLookupReceipt,
    AlpacaPaperLookupConflict,
    _observe_authenticated_alpaca_paper_unknown_lookup_with_transport,
)
from packages.adapters.broker.alpaca_paper_observations import (
    create_alpaca_client_order_lookup_description,
)
from packages.domain.account_coordinator import (
    AccountFence,
    AccountFenceReceipt,
    _account_fence_receipt,
)
from packages.domain.clock import Clock
from packages.domain.submission_attempt import (
    CanonicalSubmissionAttempt,
    SubmissionAttemptState,
    UnknownSubmissionResolution,
    resolve_unknown_submission,
)
from packages.persistence.account_coordinator import SqlAccountCoordinator
from packages.persistence.alpaca_paper_account_binding import (
    SqlAlpacaPaperAccountBindingRepository,
)
from packages.persistence.alpaca_paper_lookup_observation import (
    SqlAlpacaPaperLookupObservationRepository,
    _authenticate_durable_sources,
    _authenticate_fence_position_at,
    _fence_receipt,
    immutable_alpaca_paper_lookup_observation_values,
    verify_alpaca_paper_lookup_observation_integrity,
)
from packages.persistence.broker_ingress import SqlBrokerIngressRepository
from packages.persistence.broker_request_budget import (
    SqlBrokerRequestBudgetRepository,
)
from packages.persistence.database import create_database_engine
from packages.persistence.schema import (
    instruments,
    phase2_submission_attempt_events,
    phase4_alpaca_paper_lookup_observation_heads,
    phase4_alpaca_paper_lookup_observations,
    phase4_broker_ingress_receipts,
)
from packages.persistence.submission_attempt import _event_values
from tests.integration.test_phase2_submission_attempt_persistence import (
    SubmissionSystem,
)
from tests.integration.test_phase2_submission_attempt_persistence import (
    _system as _submission_system,
)
from tests.integration.test_phase4_alpaca_paper_account_binding_persistence import (
    ACCOUNT_FIXTURE,
    PROVIDER_ACCOUNT_ID,
    FixedCredentialResolver,
    FixtureTransport,
)
from tests.unit.test_alpaca_paper_account_runtime import SequenceClock
from tests.unit.test_alpaca_paper_lookup_runtime import (
    PROVIDER_ASSET_ID,
    LookupResolver,
    LookupTransport,
)
from tests.unit.test_batch_risk import EVALUATED_AT, MutableClock

ROOT = Path(__file__).resolve().parents[2]
LOOKUP_FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures/broker/alpaca_paper/lookup_found.json"
)


@dataclass(slots=True)
class CapturingLookupRecorder:
    delegate: SqlAlpacaPaperLookupObservationRepository
    evidence: list[AlpacaPaperAuthenticatedLookupEvidence]

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedLookupEvidence,
    ) -> AlpacaPaperAuthenticatedLookupReceipt:
        self.evidence.append(evidence)
        return self.delegate.record(evidence)


@dataclass(slots=True)
class FinalFenceValidator:
    delegate: SqlAccountCoordinator
    clock: MutableClock
    expires_at: datetime
    mode: str
    calls: int = 0

    def revalidate_for_commit_in_transaction(
        self,
        connection: sa.Connection,
        fence: AccountFence,
    ) -> AccountFenceReceipt:
        self.calls += 1
        if self.mode == "expire" and self.calls == 2:
            self.clock.instant = self.expires_at
        current = self.delegate.revalidate_for_commit_in_transaction(
            connection,
            fence,
        )
        if self.mode != "replace" or self.calls != 2:
            return current
        replacement = AccountFence(
            account_id=fence.account_id,
            owner_id="replacement-owner",
            lease_id="replacement-lease",
            fencing_generation=fence.fencing_generation + 1,
        )
        return _account_fence_receipt(
            fence=replacement,
            validated_at=current.validated_at,
            valid_until=current.valid_until,
            policy_sha256=current.policy_sha256,
            lease_sha256="f" * 64,
        )


@dataclass(slots=True)
class FailingCommitFenceValidator:
    detail: str

    def revalidate_for_commit_in_transaction(
        self,
        connection: sa.Connection,
        fence: AccountFence,
    ) -> AccountFenceReceipt:
        del connection, fence
        raise RuntimeError(self.detail)


@dataclass(slots=True)
class SequencedCommitFenceValidator:
    delegate: SqlAccountCoordinator
    validated_ats: list[datetime]

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
            validated_at=self.validated_ats.pop(0),
            valid_until=current.valid_until,
            policy_sha256=current.policy_sha256,
            lease_sha256=current.lease_sha256,
        )


@dataclass(frozen=True, slots=True)
class PreparedLookupPersistenceSystem:
    submission: SubmissionSystem
    attempt: CanonicalSubmissionAttempt
    account_binding: AlpacaPaperAuthenticatedAccountBinding
    reference: AlpacaPaperCredentialReference
    repository: SqlAlpacaPaperLookupObservationRepository
    capture: CapturingLookupRecorder


@dataclass(frozen=True, slots=True)
class LookupPersistenceSystem:
    submission: SubmissionSystem
    attempt: CanonicalSubmissionAttempt
    account_binding: AlpacaPaperAuthenticatedAccountBinding
    repository: SqlAlpacaPaperLookupObservationRepository
    capture: CapturingLookupRecorder
    receipt: AlpacaPaperAuthenticatedLookupReceipt


def _alembic_config(database_url: str) -> Config:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def _lookup_body(
    attempt: CanonicalSubmissionAttempt,
    *,
    asset_id: str | None = PROVIDER_ASSET_ID,
) -> bytes:
    submission = create_alpaca_paper_submission_description(attempt.preparation.intent)
    value = json.loads(LOOKUP_FIXTURE.read_text())
    assert type(value) is dict
    value.update(
        {
            "asset_id": asset_id,
            "client_order_id": attempt.preparation.client_order_id,
            "extended_hours": submission.body["extended_hours"],
            "qty": submission.body["qty"],
            "side": submission.body["side"],
            "symbol": submission.body["symbol"],
            "time_in_force": submission.body["time_in_force"],
            "type": submission.body["type"],
        }
    )
    return json.dumps(value, separators=(",", ":")).encode()


def _account_binding(
    system: SubmissionSystem,
    *,
    observed_at: datetime = EVALUATED_AT + timedelta(seconds=4),
    idempotency_suffix: str = "",
) -> tuple[AlpacaPaperAuthenticatedAccountBinding, AlpacaPaperCredentialReference]:
    system.coordinator_clock.instant = observed_at
    reference = AlpacaPaperCredentialReference(
        account_id=system.lease.account_id,
        expected_provider_account_id=PROVIDER_ACCOUNT_ID,
        secret_ref="secret://paper/alpaca/trading",
        secret_version="version-001",
    )
    repository = SqlAlpacaPaperAccountBindingRepository(system.engine)
    clock = system.coordinator_clock
    binding = _observe_authenticated_alpaca_paper_account_with_transport(
        reference=reference,
        description=create_alpaca_account_observation_description(
            account_id=system.lease.account_id,
        ),
        credential_resolver=FixedCredentialResolver(),
        transport=FixtureTransport(ACCOUNT_FIXTURE.read_bytes()),
        budget=SqlBrokerRequestBudgetRepository(
            engine=system.engine,
            clock=clock,
        ),
        coordinator=system.coordinator,
        fence=system.lease.fence,
        ingress_recorder=SqlBrokerIngressRepository(system.engine),
        binding_recorder=repository,
        clock=clock,
        request_idempotency_key=f"phase4i-account-demand{idempotency_suffix}",
        delivery_idempotency_key=f"phase4i-account-delivery{idempotency_suffix}",
    )
    return binding, reference


def _system(
    database_path: Path,
    *,
    asset_id: str | None = PROVIDER_ASSET_ID,
    provider_request_id: str = "phase4i-persistence-request",
) -> LookupPersistenceSystem:
    prepared = _prepared_system(database_path)
    receipt = _run_lookup(
        prepared,
        asset_id=asset_id,
        provider_request_id=provider_request_id,
    )
    return LookupPersistenceSystem(
        submission=prepared.submission,
        attempt=prepared.attempt,
        account_binding=prepared.account_binding,
        repository=prepared.repository,
        capture=prepared.capture,
        receipt=receipt,
    )


def _prepared_system(
    database_path: Path,
    *,
    commit_guard_mode: str | None = None,
    commit_validator: object | None = None,
    commit_validated_ats: list[datetime] | None = None,
) -> PreparedLookupPersistenceSystem:
    system = _submission_system(database_path)
    intent = next(intent for intent in system.intents if intent.symbol == "SPY")
    with system.engine.begin() as connection:
        connection.execute(
            sa.insert(instruments).values(
                instrument_id=intent.instrument_id,
                name="SPY lookup persistence instrument",
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
    unknown_at = EVALUATED_AT + timedelta(seconds=3)
    attempt = system.repository.mark_unknown(
        attempt.attempt_id,
        occurred_at=unknown_at,
        recorded_at=unknown_at,
        error_class="LookupPersistenceTimeout",
    )
    account_binding, reference = _account_binding(system)
    lookup_at = EVALUATED_AT + timedelta(seconds=20)
    system.coordinator_clock.instant = lookup_at
    validator: object = commit_validator or system.coordinator
    if commit_validated_ats is not None:
        validator = SequencedCommitFenceValidator(
            delegate=system.coordinator,
            validated_ats=commit_validated_ats,
        )
    if commit_guard_mode is not None:
        validator = FinalFenceValidator(
            delegate=system.coordinator,
            clock=system.coordinator_clock,
            expires_at=system.lease.expires_at,
            mode=commit_guard_mode,
        )
    repository = SqlAlpacaPaperLookupObservationRepository(
        engine=system.engine,
        coordinator=validator,  # type: ignore[arg-type]
    )
    return PreparedLookupPersistenceSystem(
        submission=system,
        attempt=attempt,
        account_binding=account_binding,
        reference=reference,
        repository=repository,
        capture=CapturingLookupRecorder(delegate=repository, evidence=[]),
    )


def _run_lookup(
    prepared: PreparedLookupPersistenceSystem,
    *,
    asset_id: str | None = PROVIDER_ASSET_ID,
    provider_request_id: str = "phase4i-persistence-request",
    request_idempotency_key: str = "phase4i-lookup-demand",
    delivery_idempotency_key: str = "phase4i-lookup-delivery",
    lookup_at: datetime | None = None,
    runtime_clock: Clock | None = None,
) -> AlpacaPaperAuthenticatedLookupReceipt:
    system = prepared.submission
    attempt = prepared.attempt
    instant = EVALUATED_AT + timedelta(seconds=20) if lookup_at is None else lookup_at
    system.coordinator_clock.instant = instant
    submission = create_alpaca_paper_submission_description(attempt.preparation.intent)
    description = create_alpaca_client_order_lookup_description(
        account_id=system.lease.account_id,
        submission=submission,
    )
    security_reference = AlpacaPaperSecurityReference(
        credential_reference=prepared.reference,
        instrument_id=attempt.preparation.intent.instrument_id,
        symbol=attempt.preparation.intent.symbol,
        expected_provider_asset_id=PROVIDER_ASSET_ID,
    )
    return _observe_authenticated_alpaca_paper_unknown_lookup_with_transport(
        security_reference=security_reference,
        account_binding=prepared.account_binding,
        attempt=attempt,
        description=description,
        credential_resolver=LookupResolver(),
        transport=LookupTransport(
            body=_lookup_body(attempt, asset_id=asset_id),
            request_id=provider_request_id,
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
        clock=runtime_clock or system.coordinator_clock,
        request_idempotency_key=request_idempotency_key,
        delivery_idempotency_key=delivery_idempotency_key,
    )


def _lookup_runtime_clock(at: datetime) -> SequenceClock:
    return SequenceClock(
        at - timedelta(milliseconds=300),
        at - timedelta(milliseconds=200),
        at - timedelta(milliseconds=100),
        at,
        at,
        at,
        at,
        at,
        at,
        at,
    )


def _receipt_with(
    receipt: AlpacaPaperAuthenticatedLookupReceipt,
    **updates: object,
) -> AlpacaPaperAuthenticatedLookupReceipt:
    forged = object.__new__(AlpacaPaperAuthenticatedLookupReceipt)
    for receipt_field in fields(receipt):
        object.__setattr__(
            forged,
            receipt_field.name,
            updates.get(receipt_field.name, getattr(receipt, receipt_field.name)),
        )
    forged._validate()
    return forged


def _replace_persisted_receipt(
    engine: Engine,
    original: AlpacaPaperAuthenticatedLookupReceipt,
    forged: AlpacaPaperAuthenticatedLookupReceipt,
) -> None:
    values = immutable_alpaca_paper_lookup_observation_values(forged)
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.execute(
            sa.update(phase4_alpaca_paper_lookup_observations)
            .where(phase4_alpaca_paper_lookup_observations.c.receipt_id == original.receipt_id)
            .values(**values)
        )
        connection.execute(
            sa.update(phase4_alpaca_paper_lookup_observation_heads)
            .where(
                phase4_alpaca_paper_lookup_observation_heads.c.account_id == original.account_id,
                phase4_alpaca_paper_lookup_observation_heads.c.attempt_id == original.attempt_id,
                phase4_alpaca_paper_lookup_observation_heads.c.last_receipt_sha256
                == original.semantic_sha256,
            )
            .values(
                last_receipt_sha256=forged.semantic_sha256,
                last_sequence_number=forged.sequence_number,
                last_authenticated_at=forged.authenticated_at,
            )
        )
        connection.commit()
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")


def _lookup_row_counts(engine: Engine) -> tuple[int, int]:
    with engine.connect() as connection:
        observations = connection.scalar(
            sa.select(sa.func.count()).select_from(phase4_alpaca_paper_lookup_observations)
        )
        heads = connection.scalar(
            sa.select(sa.func.count()).select_from(phase4_alpaca_paper_lookup_observation_heads)
        )
    assert isinstance(observations, int)
    assert isinstance(heads, int)
    return observations, heads


def test_authenticated_lookup_round_trips_and_exact_replay_is_idempotent(
    tmp_path: Path,
) -> None:
    system = _system(
        tmp_path / "phase4i-lookup.sqlite",
        provider_request_id="r" * 256,
    )

    assert system.receipt.outcome is AlpacaPaperAuthenticatedLookupOutcome.FOUND_MATCHED
    assert system.receipt.provider_request_id == "r" * 256
    assert system.repository.runtime_store_identity == id(system.submission.engine)
    assert system.repository.load(system.receipt.receipt_id) == system.receipt
    assert (
        system.repository.load_by_ingress_receipt_id(
            system.receipt.ingress_receipt_id,
        )
        == system.receipt
    )
    assert (
        system.repository.load_by_ingress_receipt_id(
            system.receipt.ingress_receipt_id,
        )
        == system.receipt
    )
    assert system.repository.history(
        system.receipt.account_id,
        system.receipt.attempt_id,
    ) == (system.receipt,)
    assert system.repository.record(system.capture.evidence[0]) == system.receipt
    assert system.submission.repository.get(system.attempt.attempt_id) == system.attempt
    assert system.attempt.state is SubmissionAttemptState.UNKNOWN
    verify_alpaca_paper_lookup_observation_integrity(system.submission.engine)


def test_lookup_ingress_source_read_validates_exact_key_and_not_found(
    tmp_path: Path,
) -> None:
    prepared = _prepared_system(tmp_path / "phase4i-ingress-source-empty.sqlite")

    assert prepared.repository.load_by_ingress_receipt_id("0" * 64) is None
    for invalid in ("", "0" * 63, "G" * 64, "  " + ("0" * 62)):
        with pytest.raises(
            AlpacaPaperLookupConflict,
            match="lowercase SHA-256 digest",
        ):
            prepared.repository.load_by_ingress_receipt_id(invalid)


def test_null_provider_asset_id_is_retained_as_security_identity_mismatch(
    tmp_path: Path,
) -> None:
    system = _system(
        tmp_path / "phase4i-null-asset.sqlite",
        asset_id=None,
    )

    assert (
        system.receipt.outcome is AlpacaPaperAuthenticatedLookupOutcome.SECURITY_IDENTITY_MISMATCH
    )
    assert system.receipt.observed_provider_asset_id is None
    assert system.repository.load(system.receipt.receipt_id) == system.receipt


def test_lookup_reads_and_integrity_reject_receipt_corruption(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4i-corruption.sqlite")
    with system.submission.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_lookup_observations)
            .where(
                phase4_alpaca_paper_lookup_observations.c.receipt_id == system.receipt.receipt_id
            )
            .values(canonical_payload="[]")
        )

    with pytest.raises(
        AlpacaPaperLookupConflict,
        match="canonical_payload",
    ):
        system.repository.load(system.receipt.receipt_id)
    with pytest.raises(
        AlpacaPaperLookupConflict,
        match="canonical_payload",
    ):
        system.repository.load_by_ingress_receipt_id(
            system.receipt.ingress_receipt_id,
        )
    with pytest.raises(AlpacaPaperLookupConflict, match="canonical_payload"):
        verify_alpaca_paper_lookup_observation_integrity(system.submission.engine)


@pytest.mark.parametrize("mode", ("expire", "replace"))
def test_final_commit_fence_rejection_rolls_back_typed_lookup(
    tmp_path: Path,
    mode: str,
) -> None:
    prepared = _prepared_system(
        tmp_path / f"phase4i-final-fence-{mode}.sqlite",
        commit_guard_mode=mode,
    )

    with pytest.raises(AlpacaPaperLookupConflict):
        _run_lookup(prepared)

    assert len(prepared.capture.evidence) == 1
    assert _lookup_row_counts(prepared.submission.engine) == (0, 0)
    with prepared.submission.engine.connect() as connection:
        assert (
            connection.scalar(
                sa.select(sa.func.count()).select_from(phase4_broker_ingress_receipts)
            )
            == 2
        )
    assert prepared.submission.repository.get(prepared.attempt.attempt_id) == (prepared.attempt)


def test_commit_fence_failure_is_sanitized_and_rolls_back_lookup(
    tmp_path: Path,
) -> None:
    secret_detail = "unsafe commit fence secret"
    prepared = _prepared_system(
        tmp_path / "phase4i-commit-fence-failure.sqlite",
        commit_validator=FailingCommitFenceValidator(secret_detail),
    )

    with pytest.raises(
        AlpacaPaperLookupConflict,
        match="commit fence validation failed",
    ) as raised:
        _run_lookup(prepared)

    assert secret_detail not in str(raised.value)
    assert raised.value.__cause__ is None
    assert _lookup_row_counts(prepared.submission.engine) == (0, 0)


@pytest.mark.parametrize(
    "tamper",
    ("credential_started_at", "credential_valid_until", "credential_digest"),
)
def test_lookup_replay_reconstructs_exact_credential_resolution(
    tmp_path: Path,
    tamper: str,
) -> None:
    lookup_at = EVALUATED_AT + timedelta(seconds=20)
    prepared = _prepared_system(tmp_path / f"phase4i-credential-{tamper}.sqlite")
    original = _run_lookup(
        prepared,
        lookup_at=lookup_at,
        runtime_clock=_lookup_runtime_clock(lookup_at),
    )
    if tamper == "credential_started_at":
        forged = _receipt_with(
            original,
            credential_resolution_started_at=(
                original.credential_resolution_started_at + timedelta(milliseconds=50)
            ),
        )
    elif tamper == "credential_valid_until":
        forged = _receipt_with(
            original,
            credential_resolution_valid_until=(
                original.credential_resolution_valid_until + timedelta(milliseconds=1)
            ),
        )
    else:
        forged = _receipt_with(
            original,
            credential_resolution_sha256="f" * 64,
        )
    _replace_persisted_receipt(
        prepared.submission.engine,
        original,
        forged,
    )

    with pytest.raises(AlpacaPaperLookupConflict):
        prepared.repository.load(forged.receipt_id)


def test_lookup_replay_binds_permit_issue_between_resolution_and_fence(
    tmp_path: Path,
) -> None:
    lookup_at = EVALUATED_AT + timedelta(seconds=20)
    prepared = _prepared_system(tmp_path / "phase4i-permit-fence-order.sqlite")
    original = _run_lookup(
        prepared,
        lookup_at=lookup_at,
        runtime_clock=_lookup_runtime_clock(lookup_at),
    )
    forged = _receipt_with(
        original,
        pre_fence_validated_at=lookup_at - timedelta(milliseconds=50),
    )
    _replace_persisted_receipt(
        prepared.submission.engine,
        original,
        forged,
    )

    with pytest.raises(
        AlpacaPaperLookupConflict,
        match="protected request admission",
    ):
        prepared.repository.load(forged.receipt_id)


def test_lookup_replay_rejects_forged_fence_expiry(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4i-forged-fence-expiry.sqlite")
    forged = _receipt_with(
        system.receipt,
        post_fence_valid_until=(system.receipt.post_fence_valid_until + timedelta(seconds=1)),
    )
    _replace_persisted_receipt(
        system.submission.engine,
        system.receipt,
        forged,
    )

    with pytest.raises(
        AlpacaPaperLookupConflict,
        match="fence conflicts with its lease source",
    ):
        system.repository.load(forged.receipt_id)


def test_same_instant_renewal_is_later_history_but_old_revision_cannot_be_backdated(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4i-same-instant-renewal.sqlite")
    system.submission.coordinator_clock.instant = system.receipt.commit_checked_at
    renewed = system.submission.coordinator.renew(system.submission.lease.fence)

    assert renewed.revision_number == 2
    assert renewed.heartbeat_at == system.receipt.commit_checked_at
    assert system.repository.load(system.receipt.receipt_id) == system.receipt
    with system.submission.engine.connect() as connection:
        historical = _fence_receipt(connection, system.receipt, phase="post")
        with pytest.raises(
            AlpacaPaperLookupConflict,
            match="not current at its retained check time",
        ):
            _authenticate_fence_position_at(
                connection,
                historical,
                checked_at=renewed.heartbeat_at + timedelta(microseconds=1),
            )


def test_forged_fence_check_before_lease_heartbeat_is_rejected(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4i-forged-fence-heartbeat.sqlite")
    system.submission.coordinator_clock.instant = system.receipt.commit_checked_at + timedelta(
        seconds=1
    )
    renewed = system.submission.coordinator.renew(system.submission.lease.fence)
    forged_source = _account_fence_receipt(
        fence=renewed.fence,
        validated_at=system.receipt.post_fence_validated_at,
        valid_until=renewed.expires_at,
        policy_sha256=renewed.policy_sha256,
        lease_sha256=renewed.semantic_sha256,
    )
    forged = _receipt_with(
        system.receipt,
        post_fence_lease_sha256=renewed.semantic_sha256,
        post_fence_valid_until=renewed.expires_at,
        post_fence_receipt_sha256=forged_source.semantic_sha256,
    )

    with (
        system.submission.engine.connect() as connection,
        pytest.raises(
            AlpacaPaperLookupConflict,
            match="fence conflicts with its lease source",
        ),
    ):
        _fence_receipt(connection, forged, phase="post")


@pytest.mark.parametrize("handoff_offset", (timedelta(0), timedelta(seconds=1)))
def test_same_or_later_takeover_does_not_invalidate_historical_lookup(
    tmp_path: Path,
    handoff_offset: timedelta,
) -> None:
    system = _system(tmp_path / f"phase4i-takeover-{int(handoff_offset.total_seconds())}.sqlite")
    handoff_at = system.receipt.commit_checked_at + handoff_offset
    system.submission.coordinator_clock.instant = handoff_at
    system.submission.coordinator.release(system.submission.lease.fence)
    system.submission.coordinator_clock.instant = handoff_at
    replacement = system.submission.coordinator.acquire("worker-b")

    assert replacement.fencing_generation == (system.submission.lease.fencing_generation + 1)
    assert system.repository.load(system.receipt.receipt_id) == system.receipt


def test_same_instant_account_binding_successor_is_later_history_only(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4i-binding-successor.sqlite")
    successor, _reference = _account_binding(
        system.submission,
        observed_at=system.receipt.commit_checked_at,
        idempotency_suffix="-successor",
    )

    assert successor.sequence_number == system.account_binding.sequence_number + 1
    assert successor.qualified_at == system.receipt.commit_checked_at
    assert system.repository.load(system.receipt.receipt_id) == system.receipt
    forged = _receipt_with(
        system.receipt,
        commit_checked_at=(system.receipt.commit_checked_at + timedelta(microseconds=1)),
    )
    with (
        system.submission.engine.connect() as connection,
        pytest.raises(
            AlpacaPaperLookupConflict,
            match="account identity was not terminal",
        ),
    ):
        _authenticate_durable_sources(connection, forged)


def test_same_instant_attempt_successor_is_later_history_only(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4i-attempt-successor.sqlite")
    resolved = resolve_unknown_submission(
        system.attempt,
        occurred_at=system.receipt.commit_checked_at,
        recorded_at=system.receipt.commit_checked_at,
        resolution=UnknownSubmissionResolution.NOT_SUBMITTED,
        reconciliation_sha256="a" * 64,
    )
    successor = resolved.events[-1]
    with system.submission.engine.begin() as connection:
        visibility_sequence = connection.scalar(
            sa.select(phase2_submission_attempt_events.c.visible_after_observation_sequence).where(
                phase2_submission_attempt_events.c.event_id == system.attempt.events[-1].event_id
            )
        )
        assert isinstance(visibility_sequence, int)
        connection.execute(
            sa.insert(phase2_submission_attempt_events).values(
                **_event_values(
                    successor,
                    account_id=system.receipt.account_id,
                    visible_after_observation_sequence=visibility_sequence,
                )
            )
        )

    assert successor.recorded_at == system.receipt.commit_checked_at
    assert system.repository.load(system.receipt.receipt_id) == system.receipt
    forged = _receipt_with(
        system.receipt,
        commit_checked_at=(system.receipt.commit_checked_at + timedelta(microseconds=1)),
    )
    with (
        system.submission.engine.connect() as connection,
        pytest.raises(
            AlpacaPaperLookupConflict,
            match="later recorded attempt event",
        ),
    ):
        _authenticate_durable_sources(connection, forged)


def test_cross_account_lookup_source_is_rejected(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4i-cross-account.sqlite")
    forged = _receipt_with(system.receipt, account_id="foreign-account")

    with (
        system.submission.engine.connect() as connection,
        pytest.raises(
            AlpacaPaperLookupConflict,
            match="historical UNKNOWN source",
        ),
    ):
        _authenticate_durable_sources(connection, forged)


def test_unexpected_source_exception_is_sanitized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    system = _system(tmp_path / "phase4i-source-exception.sqlite")
    unsafe_detail = "unsafe durable source secret"

    def fail_source(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError(unsafe_detail)

    monkeypatch.setattr(
        lookup_persistence,
        "_authenticate_account_binding_sources",
        fail_source,
    )
    with pytest.raises(
        AlpacaPaperLookupConflict,
        match="sanitized diagnostics",
    ) as raised:
        system.repository.load(system.receipt.receipt_id)

    assert unsafe_detail not in str(raised.value)
    assert raised.value.__cause__ is None


def test_sql_found_outcome_requires_observed_asset_identity(
    tmp_path: Path,
) -> None:
    system = _system(tmp_path / "phase4i-found-null-check.sqlite")

    with pytest.raises(sa.exc.IntegrityError), system.submission.engine.begin() as connection:
        connection.execute(
            sa.update(phase4_alpaca_paper_lookup_observations)
            .where(
                phase4_alpaca_paper_lookup_observations.c.receipt_id == system.receipt.receipt_id
            )
            .values(observed_provider_asset_id=None)
        )

    assert system.repository.load(system.receipt.receipt_id) == system.receipt


@pytest.mark.parametrize("corruption", ("head_rollback", "sequence_gap"))
def test_lookup_stream_rejects_head_rollback_and_sequence_gaps(
    tmp_path: Path,
    corruption: str,
) -> None:
    prepared = _prepared_system(tmp_path / f"phase4i-stream-{corruption}.sqlite")
    first = _run_lookup(prepared)
    second = _run_lookup(
        prepared,
        lookup_at=EVALUATED_AT + timedelta(seconds=21),
        provider_request_id="phase4i-second-request",
        request_idempotency_key="phase4i-second-demand",
        delivery_idempotency_key="phase4i-second-delivery",
    )
    if corruption == "head_rollback":
        with prepared.submission.engine.begin() as connection:
            connection.execute(
                sa.update(phase4_alpaca_paper_lookup_observation_heads)
                .where(
                    phase4_alpaca_paper_lookup_observation_heads.c.account_id == first.account_id,
                    phase4_alpaca_paper_lookup_observation_heads.c.attempt_id == first.attempt_id,
                )
                .values(
                    last_sequence_number=first.sequence_number,
                    last_receipt_sha256=first.semantic_sha256,
                    last_authenticated_at=first.authenticated_at,
                )
            )
    else:
        with prepared.submission.engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            connection.execute(
                sa.delete(phase4_alpaca_paper_lookup_observations).where(
                    phase4_alpaca_paper_lookup_observations.c.receipt_id == first.receipt_id
                )
            )
            connection.commit()
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")

    with pytest.raises(AlpacaPaperLookupConflict):
        prepared.repository.load(second.receipt_id)
    with pytest.raises(AlpacaPaperLookupConflict):
        prepared.repository.load_by_ingress_receipt_id(
            second.ingress_receipt_id,
        )


def test_lookup_stream_rejects_wrong_predecessor(
    tmp_path: Path,
) -> None:
    prepared = _prepared_system(tmp_path / "phase4i-wrong-predecessor.sqlite")
    first = _run_lookup(prepared)
    _run_lookup(
        prepared,
        lookup_at=EVALUATED_AT + timedelta(seconds=21),
        provider_request_id="phase4i-second-request",
        request_idempotency_key="phase4i-second-demand",
        delivery_idempotency_key="phase4i-second-delivery",
    )
    third = _run_lookup(
        prepared,
        lookup_at=EVALUATED_AT + timedelta(seconds=22),
        provider_request_id="phase4i-third-request",
        request_idempotency_key="phase4i-third-demand",
        delivery_idempotency_key="phase4i-third-delivery",
    )
    forged = _receipt_with(
        third,
        previous_receipt_sha256=first.semantic_sha256,
    )
    _replace_persisted_receipt(
        prepared.submission.engine,
        third,
        forged,
    )

    with pytest.raises(
        AlpacaPaperLookupConflict,
        match="predecessor chain",
    ):
        prepared.repository.load(forged.receipt_id)


def test_lookup_append_rejects_commit_clock_regression_and_keeps_prior_head(
    tmp_path: Path,
) -> None:
    first_at = EVALUATED_AT + timedelta(seconds=20)
    prepared = _prepared_system(
        tmp_path / "phase4i-commit-regression.sqlite",
        commit_validated_ats=[
            first_at + timedelta(seconds=2),
            first_at + timedelta(seconds=2),
            first_at + timedelta(seconds=1, milliseconds=500),
        ],
    )
    first = _run_lookup(prepared, lookup_at=first_at)

    with pytest.raises(
        AlpacaPaperLookupConflict,
        match="history regressed",
    ):
        _run_lookup(
            prepared,
            lookup_at=first_at + timedelta(seconds=1),
            provider_request_id="phase4i-regressed-request",
            request_idempotency_key="phase4i-regressed-demand",
            delivery_idempotency_key="phase4i-regressed-delivery",
        )

    assert prepared.repository.history(first.account_id, first.attempt_id) == (first,)
    assert _lookup_row_counts(prepared.submission.engine) == (1, 1)


def test_phase4i_migration_is_additive_and_empty_downgrade_is_reversible(
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'lookup-migration.sqlite'}"
    config = _alembic_config(database_url)
    command.upgrade(config, "0014_phase4_asset_binding")
    engine = create_database_engine(database_url)
    prior_tables = set(inspect(engine).get_table_names())
    prior_attempt_event_indexes = {
        index["name"] for index in inspect(engine).get_indexes("phase2_submission_attempt_events")
    }
    engine.dispose()

    command.upgrade(config, "0015_phase4_lookup_observation")
    upgraded = create_database_engine(database_url)
    assert set(inspect(upgraded).get_table_names()) == prior_tables | {
        phase4_alpaca_paper_lookup_observation_heads.name,
        phase4_alpaca_paper_lookup_observations.name,
    }
    assert tuple(
        column["name"]
        for column in inspect(upgraded).get_columns(phase4_alpaca_paper_lookup_observations.name)
    ) == tuple(phase4_alpaca_paper_lookup_observations.c.keys())
    exact_event_index = next(
        index
        for index in inspect(upgraded).get_indexes("phase2_submission_attempt_events")
        if index["name"] == "ux_phase2_submission_attempt_event_exact"
    )
    assert exact_event_index["unique"] == 1
    assert exact_event_index["column_names"] == [
        "attempt_id",
        "event_id",
        "semantic_sha256",
    ]
    upgraded.dispose()

    command.downgrade(config, "0014_phase4_asset_binding")
    downgraded = create_database_engine(database_url)
    assert set(inspect(downgraded).get_table_names()) == prior_tables
    assert {
        index["name"]
        for index in inspect(downgraded).get_indexes("phase2_submission_attempt_events")
    } == prior_attempt_event_indexes
    downgraded.dispose()


def test_phase4i_migration_refuses_nonempty_downgrade(tmp_path: Path) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'lookup-nonempty.sqlite'}"
    config = _alembic_config(database_url)
    command.upgrade(config, "0015_phase4_lookup_observation")
    engine: Engine = create_database_engine(database_url)
    # The downgrade guard must run before FK enforcement becomes relevant.
    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.execute(
            sa.insert(phase4_alpaca_paper_lookup_observation_heads).values(
                account_id="downgrade-account",
                attempt_id="downgrade-attempt",
                terminal_event_id="downgrade-event",
                terminal_event_sha256="a" * 64,
                last_sequence_number=1,
                last_receipt_sha256="b" * 64,
                last_authenticated_at=EVALUATED_AT,
            )
        )
        connection.commit()
    engine.dispose()

    with pytest.raises(
        RuntimeError,
        match="refusing to downgrade nonempty",
    ):
        command.downgrade(config, "0014_phase4_asset_binding")
