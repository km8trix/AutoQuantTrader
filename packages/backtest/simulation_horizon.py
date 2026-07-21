"""Authenticated proof that one simulated order reached a sealed replay horizon."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

from packages.backtest.simulated_broker import (
    SIMULATED_BROKER_CONTRACT_VERSION,
    SimulatedBrokerOutcome,
    SimulatedBrokerResult,
    SimulatedBrokerSession,
    SimulatedMarketOrderModel,
    SimulatedRiskExecutionCaps,
)
from packages.domain.batch_risk import BatchRiskAuthorization, BatchRiskReservation
from packages.domain.canonical import canonical_json_bytes
from packages.domain.identifiers import canonical_id
from packages.domain.models import OrderIntent, require_utc
from packages.domain.order_reducer import (
    BrokerOrderEventKind,
    CanonicalOrderStatus,
)
from packages.domain.replay import ReplayResult
from packages.domain.replay_manifest import ReplayRunManifest
from packages.domain.submission_attempt import (
    BrokerSubmissionRequest,
    CanonicalSubmissionAttempt,
    SubmissionAttemptState,
    UnknownSubmissionResolution,
    create_broker_submission_request,
    reduce_submission_attempt,
)

SIMULATION_HORIZON_CONTRACT_VERSION = "phase2-simulation-horizon-v1"
CONSERVATIVE_SIMULATION_REQUEST_CONTRACT_VERSION = "phase2-conservative-simulation-request-v1"
CONSERVATIVE_SIMULATOR_ADAPTER_ID = "conservative-simulated-broker"
CONSERVATIVE_SIMULATOR_ADAPTER_VERSION = "1.0.0"
CONSERVATIVE_SIMULATOR_OPERATION = "submit_order"


class SimulationHorizonError(ValueError):
    """The supplied facts cannot prove a complete simulation horizon."""


class SimulationHorizonConflict(SimulationHorizonError):
    """Supposedly identical simulation facts disagree across a proof boundary."""


def create_conservative_simulation_request(
    *,
    intent: OrderIntent,
    manifest: ReplayRunManifest,
    session: SimulatedBrokerSession,
    model: SimulatedMarketOrderModel,
) -> BrokerSubmissionRequest:
    """Commit dispatch to one sealed replay and exact deterministic simulator."""

    for value, expected_type, field_name in (
        (intent, OrderIntent, "order intent"),
        (manifest, ReplayRunManifest, "replay manifest"),
        (session, SimulatedBrokerSession, "simulator session"),
        (model, SimulatedMarketOrderModel, "simulator model"),
    ):
        if type(value) is not expected_type:
            raise SimulationHorizonError(
                f"conservative simulation request {field_name} must be exact"
            )
    return create_broker_submission_request(
        intent=intent,
        adapter_id=CONSERVATIVE_SIMULATOR_ADAPTER_ID,
        adapter_version=CONSERVATIVE_SIMULATOR_ADAPTER_VERSION,
        operation=CONSERVATIVE_SIMULATOR_OPERATION,
        payload={
            "request_contract_version": CONSERVATIVE_SIMULATION_REQUEST_CONTRACT_VERSION,
            "simulation_horizon_contract_version": SIMULATION_HORIZON_CONTRACT_VERSION,
            "simulated_broker_contract_version": SIMULATED_BROKER_CONTRACT_VERSION,
            "order_type": "market",
            "quantity": intent.quantity,
            "side": intent.side.value,
            "symbol": intent.symbol,
            "replay_run_id": manifest.run_id,
            "replay_manifest_sha256": manifest.manifest_sha256,
            "simulation_session_sha256": session.semantic_sha256,
            "simulation_model_sha256": model.semantic_sha256,
        },
    )


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or any(ord(character) < 32 for character in value)
    ):
        raise SimulationHorizonError(f"{field_name} must be non-empty, trimmed text")
    return value


def _require_sha256(value: object, field_name: str) -> str:
    digest = _require_text(value, field_name)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise SimulationHorizonError(f"{field_name} must be a lowercase SHA-256 digest")
    return digest


def _require_utc(value: object, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise SimulationHorizonError(f"{field_name} must be a datetime")
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise SimulationHorizonError(str(error)) from error
    return value.astimezone(UTC)


def _watermarks_sha256(replay: ReplayResult) -> str:
    return _sha256(
        tuple(
            (
                batch.watermark.watermark_id,
                batch.watermark.event_time_through,
                batch.watermark.closed_at,
                batch.watermark.expected_instrument_ids,
                batch.watermark.revision_policy,
                batch.watermark.missing_data_policy,
                batch.watermark.late_event_policy,
            )
            for batch in replay.batches
        )
    )


def _source_sha256(
    *,
    manifest_sha256: str,
    replay_semantic_sha256: str,
    replay_tape_sha256: str,
    final_batch_sha256: str,
    simulation_result_sha256: str,
    order_submission_sha256: str,
    order_state_sha256: str,
    final_order_event_sha256: str,
) -> str:
    return _sha256(
        (
            SIMULATION_HORIZON_CONTRACT_VERSION,
            "authenticated_horizon_source",
            manifest_sha256,
            replay_semantic_sha256,
            replay_tape_sha256,
            final_batch_sha256,
            simulation_result_sha256,
            order_submission_sha256,
            order_state_sha256,
            final_order_event_sha256,
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class SimulationHorizonFact:
    """Content-bound release evidence produced only from complete canonical proofs."""

    horizon_id: str
    horizon_reference: str
    horizon_source_sha256: str
    horizon_at: datetime

    reservation_id: str
    parent_decision_id: str
    authorization_id: str
    attempt_id: str
    order_id: str
    client_order_id: str
    broker_order_id: str
    intent_id: str
    intent_payload_sha256: str
    reservation_sha256: str
    authorization_sha256: str
    attempt_sha256: str
    attempt_state: SubmissionAttemptState
    attempt_resolution: UnknownSubmissionResolution | None
    attempt_response_sha256: str
    attempt_as_of: datetime
    dispatch_event_id: str
    dispatch_event_sha256: str
    dispatch_at: datetime

    replay_run_id: str
    replay_manifest_sha256: str
    replay_input_sha256: str
    replay_semantic_sha256: str
    replay_tape_sha256: str
    replay_started_at: datetime
    replay_completed_at: datetime
    replay_coverage_start: datetime
    replay_coverage_end: datetime
    replay_batch_count: int
    final_batch_id: str
    final_batch_sha256: str

    simulation_result_id: str
    simulation_result_sha256: str
    simulation_outcome: SimulatedBrokerOutcome
    simulation_session_sha256: str
    simulation_model_sha256: str
    risk_execution_caps_sha256: str
    result_completed_at: datetime

    order_submission_sha256: str
    order_state_sha256: str
    order_status: CanonicalOrderStatus
    order_as_of: datetime
    accepted_order_event_id: str
    accepted_order_event_sha256: str
    final_order_event_id: str
    final_order_event_sha256: str
    final_broker_sequence: int

    semantic_sha256: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("SimulationHorizonFact must be produced by its proof factory")

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            SIMULATION_HORIZON_CONTRACT_VERSION,
            "simulation_horizon_fact",
            self.horizon_reference,
            self.horizon_source_sha256,
            self.horizon_at,
            self.reservation_id,
            self.parent_decision_id,
            self.authorization_id,
            self.attempt_id,
            self.order_id,
            self.client_order_id,
            self.broker_order_id,
            self.intent_id,
            self.intent_payload_sha256,
            self.reservation_sha256,
            self.authorization_sha256,
            self.attempt_sha256,
            self.attempt_state,
            self.attempt_resolution,
            self.attempt_response_sha256,
            self.attempt_as_of,
            self.dispatch_event_id,
            self.dispatch_event_sha256,
            self.dispatch_at,
            self.replay_run_id,
            self.replay_manifest_sha256,
            self.replay_input_sha256,
            self.replay_semantic_sha256,
            self.replay_tape_sha256,
            self.replay_started_at,
            self.replay_completed_at,
            self.replay_coverage_start,
            self.replay_coverage_end,
            self.replay_batch_count,
            self.final_batch_id,
            self.final_batch_sha256,
            self.simulation_result_id,
            self.simulation_result_sha256,
            self.simulation_outcome,
            self.simulation_session_sha256,
            self.simulation_model_sha256,
            self.risk_execution_caps_sha256,
            self.result_completed_at,
            self.order_submission_sha256,
            self.order_state_sha256,
            self.order_status,
            self.order_as_of,
            self.accepted_order_event_id,
            self.accepted_order_event_sha256,
            self.final_order_event_id,
            self.final_order_event_sha256,
            self.final_broker_sequence,
        )

    def _validate(self) -> None:
        for text_value, field_name in (
            (self.horizon_id, "horizon ID"),
            (self.horizon_reference, "horizon reference"),
            (self.reservation_id, "reservation ID"),
            (self.parent_decision_id, "parent decision ID"),
            (self.authorization_id, "authorization ID"),
            (self.attempt_id, "attempt ID"),
            (self.order_id, "order ID"),
            (self.client_order_id, "client order ID"),
            (self.broker_order_id, "broker order ID"),
            (self.intent_id, "intent ID"),
            (self.dispatch_event_id, "dispatch event ID"),
            (self.replay_run_id, "replay run ID"),
            (self.final_batch_id, "final batch ID"),
            (self.simulation_result_id, "simulation result ID"),
            (self.accepted_order_event_id, "accepted order event ID"),
            (self.final_order_event_id, "final order event ID"),
        ):
            _require_text(text_value, field_name)
        for digest, field_name in (
            (self.horizon_source_sha256, "horizon source digest"),
            (self.intent_payload_sha256, "intent payload digest"),
            (self.reservation_sha256, "reservation digest"),
            (self.authorization_sha256, "authorization digest"),
            (self.attempt_sha256, "attempt digest"),
            (self.attempt_response_sha256, "attempt response digest"),
            (self.dispatch_event_sha256, "dispatch event digest"),
            (self.replay_manifest_sha256, "replay manifest digest"),
            (self.replay_input_sha256, "replay input digest"),
            (self.replay_semantic_sha256, "replay result digest"),
            (self.replay_tape_sha256, "replay tape digest"),
            (self.final_batch_sha256, "final batch digest"),
            (self.simulation_result_sha256, "simulation result digest"),
            (self.simulation_session_sha256, "simulation session digest"),
            (self.simulation_model_sha256, "simulation model digest"),
            (self.risk_execution_caps_sha256, "risk execution caps digest"),
            (self.order_submission_sha256, "order submission digest"),
            (self.order_state_sha256, "order state digest"),
            (self.accepted_order_event_sha256, "accepted order event digest"),
            (self.final_order_event_sha256, "final order event digest"),
            (self.semantic_sha256, "simulation horizon semantic digest"),
        ):
            _require_sha256(digest, field_name)
        for timestamp, field_name in (
            (self.horizon_at, "horizon_at"),
            (self.attempt_as_of, "attempt_as_of"),
            (self.dispatch_at, "dispatch_at"),
            (self.replay_started_at, "replay_started_at"),
            (self.replay_completed_at, "replay_completed_at"),
            (self.replay_coverage_start, "replay_coverage_start"),
            (self.replay_coverage_end, "replay_coverage_end"),
            (self.result_completed_at, "result_completed_at"),
            (self.order_as_of, "order_as_of"),
        ):
            _require_utc(timestamp, field_name)
        if self.replay_completed_at < self.replay_started_at:
            raise SimulationHorizonError("replay completion precedes replay start")
        if self.replay_coverage_end < self.replay_coverage_start:
            raise SimulationHorizonError("replay coverage end precedes its start")
        if type(self.replay_batch_count) is not int or self.replay_batch_count <= 0:
            raise SimulationHorizonError("replay batch count must be positive")
        if type(self.final_broker_sequence) is not int or self.final_broker_sequence <= 0:
            raise SimulationHorizonError("final broker sequence must be positive")
        if (
            type(self.attempt_state) is not SubmissionAttemptState
            or self.attempt_state is not SubmissionAttemptState.CONFIRMED
        ):
            raise SimulationHorizonError(
                "simulation horizon requires a confirmed known accepted submission attempt"
            )
        if self.attempt_resolution is not None:
            raise SimulationHorizonError("confirmed attempt cannot carry a resolution")
        if type(self.simulation_outcome) is not SimulatedBrokerOutcome:
            raise SimulationHorizonError("simulation outcome is unsupported")
        if type(self.order_status) is not CanonicalOrderStatus:
            raise SimulationHorizonError("canonical order status is unsupported")
        expected_horizon_at = max(
            self.replay_completed_at,
            self.result_completed_at,
            self.attempt_as_of,
            self.order_as_of,
        )
        if self.horizon_at != expected_horizon_at:
            raise SimulationHorizonConflict(
                "simulation horizon time is not derived from its complete evidence"
            )
        expected_reference = canonical_id(
            "simulation-horizon-reference",
            self.replay_run_id,
            self.simulation_result_id,
            self.attempt_id,
            self.final_order_event_id,
        )
        if self.horizon_reference != expected_reference:
            raise SimulationHorizonConflict("simulation horizon reference is not canonical")
        expected_source = _source_sha256(
            manifest_sha256=self.replay_manifest_sha256,
            replay_semantic_sha256=self.replay_semantic_sha256,
            replay_tape_sha256=self.replay_tape_sha256,
            final_batch_sha256=self.final_batch_sha256,
            simulation_result_sha256=self.simulation_result_sha256,
            order_submission_sha256=self.order_submission_sha256,
            order_state_sha256=self.order_state_sha256,
            final_order_event_sha256=self.final_order_event_sha256,
        )
        if self.horizon_source_sha256 != expected_source:
            raise SimulationHorizonConflict("simulation horizon source digest is not canonical")
        expected_semantic_sha256 = _sha256(self._semantic_material())
        if self.semantic_sha256 != expected_semantic_sha256:
            raise SimulationHorizonConflict("simulation horizon semantic digest is inconsistent")
        if self.horizon_id != canonical_id(
            "simulation-horizon-fact",
            expected_semantic_sha256,
        ):
            raise SimulationHorizonConflict("simulation horizon ID is not content addressed")


def _validate_replay_and_manifest(
    replay: ReplayResult,
    manifest: ReplayRunManifest,
) -> None:
    if type(replay.batches) is not tuple or not replay.batches:
        raise SimulationHorizonError("simulation horizon requires a non-empty replay")
    _require_utc(replay.started_at, "replay started_at")
    _require_utc(replay.completed_at, "replay completed_at")
    if replay.completed_at < replay.started_at:
        raise SimulationHorizonError("replay completion cannot precede its start")
    if any(not batch.complete for batch in replay.batches):
        raise SimulationHorizonError(
            "simulation horizon requires every replay batch to be complete"
        )
    if replay.skipped_batch_ids:
        raise SimulationHorizonConflict(
            "complete simulation horizon cannot contain skipped replay batches"
        )
    plan = manifest.plan
    frontiers = tuple(batch.watermark.event_time_through for batch in replay.batches)
    if frontiers != tuple(sorted(set(frontiers))):
        raise SimulationHorizonConflict(
            "replay horizon frontiers must be unique and strictly increasing"
        )
    if (
        len(replay.batches) != plan.watermark_count
        or frontiers[0] != plan.coverage_start
        or frontiers[-1] != plan.coverage_end
    ):
        raise SimulationHorizonConflict(
            "replay batches do not exactly cover the manifest plan endpoints"
        )
    expected_instrument_ids = tuple(
        sorted(
            {
                instrument_id
                for batch in replay.batches
                for instrument_id in batch.watermark.expected_instrument_ids
            }
        )
    )
    if expected_instrument_ids != plan.expected_instrument_ids:
        raise SimulationHorizonConflict(
            "replay watermark instruments do not match the manifest plan"
        )
    for batch in replay.batches:
        try:
            batch._validate()
        except ValueError as error:
            raise SimulationHorizonError("replay contains a malformed market batch") from error
        watermark = batch.watermark
        if (
            watermark.closed_at - watermark.event_time_through != plan.decision_lag
            or watermark.revision_policy is not plan.revision_policy
            or watermark.missing_data_policy is not plan.missing_data_policy
            or watermark.late_event_policy is not plan.late_event_policy
        ):
            raise SimulationHorizonConflict(
                "replay watermark policy does not match the manifest plan"
            )
    if _watermarks_sha256(replay) != plan.watermarks_sha256:
        raise SimulationHorizonConflict("replay watermark digest does not match the manifest plan")
    if replay.completed_at != replay.batches[-1].as_of:
        raise SimulationHorizonConflict(
            "replay completion does not equal its final sealed batch availability"
        )
    try:
        expected_manifest = ReplayRunManifest.from_replay_result(
            dataset=manifest.dataset,
            plan=manifest.plan,
            engine=manifest.engine,
            runtime=manifest.runtime,
            result=replay,
            source_tape_sha256=manifest.dataset.source_tape_sha256,
        )
    except ValueError as error:
        raise SimulationHorizonError(
            "replay cannot reproduce a canonical completed manifest"
        ) from error
    if manifest != expected_manifest:
        raise SimulationHorizonConflict("replay manifest does not exactly bind the supplied replay")


def _validate_reservation_attempt_and_result(
    *,
    result: SimulatedBrokerResult,
    reservation: BatchRiskReservation,
    authorization: BatchRiskAuthorization,
    attempt: CanonicalSubmissionAttempt,
    manifest: ReplayRunManifest,
) -> None:
    try:
        canonical_attempt = reduce_submission_attempt(
            attempt.preparation,
            attempt.events,
        )
    except ValueError as error:
        raise SimulationHorizonError("submission attempt is not canonical") from error
    if canonical_attempt != attempt:
        raise SimulationHorizonConflict(
            "submission attempt projection disagrees with its append-only evidence"
        )
    if attempt.state is not SubmissionAttemptState.CONFIRMED:
        raise SimulationHorizonError(
            "simulation horizon requires a confirmed known accepted submission attempt"
        )
    matching_authorizations = tuple(
        item for item in reservation.authorizations if item.decision_id == authorization.decision_id
    )
    if matching_authorizations != (authorization,):
        raise SimulationHorizonConflict(
            "authorization is not the exact child of the supplied reservation"
        )
    preparation = attempt.preparation
    decision = preparation.risk_decision
    embedded_authorizations = tuple(
        item for item in decision.authorizations if item.decision_id == authorization.decision_id
    )
    if (
        decision.reservation != reservation
        or embedded_authorizations != (authorization,)
        or preparation.reservation_id != reservation.reservation_id
        or preparation.parent_decision_id != reservation.parent_decision_id
        or preparation.authorization_id != authorization.decision_id
    ):
        raise SimulationHorizonConflict(
            "reservation and authorization do not bind the submission attempt"
        )
    try:
        result.__post_init__()
    except ValueError as error:
        raise SimulationHorizonError("simulated broker result is not canonical") from error
    submission = result.submission
    intent = preparation.intent
    expected_request = create_conservative_simulation_request(
        intent=intent,
        manifest=manifest,
        session=result.session,
        model=result.model,
    )
    if preparation.request != expected_request:
        raise SimulationHorizonConflict(
            "submission request is not the exact conservative simulator request"
        )
    if (
        submission.submission_attempt_id != attempt.attempt_id
        or submission.order_id != attempt.order_id
        or submission.client_order_id != preparation.client_order_id
        or submission.risk_decision_id != authorization.decision_id
        or submission.intent != intent
        or submission.intent_payload_sha256 != preparation.intent_payload_sha256
    ):
        raise SimulationHorizonConflict(
            "simulated submission does not exactly bind the attempt and authorization"
        )
    if (
        authorization.intent_id != intent.intent_id
        or authorization.intent_payload_hash != preparation.intent_payload_sha256
        or authorization.instrument_id != intent.instrument_id
        or authorization.symbol != intent.symbol
        or authorization.side is not intent.side
        or authorization.quantity != intent.quantity
        or authorization.reference_price != intent.reference_price
    ):
        raise SimulationHorizonConflict(
            "risk authorization does not exactly bind the simulated intent"
        )
    expected_caps = SimulatedRiskExecutionCaps(
        authorization_decision_id=authorization.decision_id,
        session_sha256=authorization.session_sha256,
        currency=authorization.currency,
        maximum_execution_price=authorization.maximum_execution_price,
        maximum_cash_requirement=authorization.maximum_cash_requirement,
    )
    if result.risk_execution_caps != expected_caps:
        raise SimulationHorizonConflict(
            "simulated execution caps do not equal the authorization caps"
        )
    dispatch_events = tuple(
        event for event in attempt.events if event.state is SubmissionAttemptState.IN_FLIGHT
    )
    if len(dispatch_events) != 1:
        raise SimulationHorizonConflict("known accepted attempt lacks one exact dispatch event")
    dispatch_event = dispatch_events[0]
    accepted_event = result.broker_events[0]
    if (
        accepted_event.kind is not BrokerOrderEventKind.ACCEPTED
        or attempt.broker_order_id != accepted_event.broker_order_id
        or result.order_state.broker_order_id != accepted_event.broker_order_id
    ):
        raise SimulationHorizonConflict(
            "known accepted attempt disagrees with simulated broker acceptance"
        )
    if attempt.response_sha256 != result.semantic_sha256:
        raise SimulationHorizonConflict(
            "known accepted attempt response does not bind the simulated result"
        )
    if submission.submitted_at < dispatch_event.recorded_at:
        raise SimulationHorizonError("simulated submission predates its durable dispatch event")
    if attempt.as_of < accepted_event.received_at:
        raise SimulationHorizonError("known acceptance attempt predates the simulated acceptance")


def create_simulation_horizon_fact(
    *,
    result: SimulatedBrokerResult,
    replay: ReplayResult,
    manifest: ReplayRunManifest,
    reservation: BatchRiskReservation,
    authorization: BatchRiskAuthorization,
    attempt: CanonicalSubmissionAttempt,
) -> SimulationHorizonFact:
    """Derive one release-ready horizon proof without caller-supplied hashes or times."""

    for input_value, expected_type, field_name in (
        (result, SimulatedBrokerResult, "simulated broker result"),
        (replay, ReplayResult, "replay result"),
        (manifest, ReplayRunManifest, "replay run manifest"),
        (reservation, BatchRiskReservation, "batch risk reservation"),
        (authorization, BatchRiskAuthorization, "batch risk authorization"),
        (attempt, CanonicalSubmissionAttempt, "submission attempt"),
    ):
        if type(input_value) is not expected_type:
            raise SimulationHorizonError(f"{field_name} must be an exact immutable value")
    _validate_replay_and_manifest(replay, manifest)
    if (
        result.session.calendar_version != manifest.dataset.calendar_version
        or result.session.calendar_sha256 != manifest.dataset.calendar_sha256
    ):
        raise SimulationHorizonConflict(
            "simulator session does not match the replay manifest's pinned calendar"
        )
    if result.market_batches != replay.batches:
        raise SimulationHorizonConflict(
            "simulated market batches must equal the complete replay batches exactly"
        )
    if manifest.plan.coverage_end < result.activation_at:
        raise SimulationHorizonError("replay coverage ends before the simulated order activation")
    if result.completed_at != replay.completed_at:
        raise SimulationHorizonConflict(
            "simulation completion does not equal the sealed replay completion"
        )
    _validate_reservation_attempt_and_result(
        result=result,
        reservation=reservation,
        authorization=authorization,
        attempt=attempt,
        manifest=manifest,
    )

    preparation = attempt.preparation
    dispatch_event = next(
        event for event in attempt.events if event.state is SubmissionAttemptState.IN_FLIGHT
    )
    accepted_event = result.broker_events[0]
    final_order_event = result.broker_events[-1]
    final_batch = replay.batches[-1]
    execution_caps = result.risk_execution_caps
    assert execution_caps is not None
    horizon_at = max(
        replay.completed_at,
        result.completed_at,
        attempt.as_of,
        result.order_state.as_of,
    )
    horizon_reference = canonical_id(
        "simulation-horizon-reference",
        manifest.run_id,
        result.result_id,
        attempt.attempt_id,
        final_order_event.event_id,
    )
    horizon_source_sha256 = _source_sha256(
        manifest_sha256=manifest.manifest_sha256,
        replay_semantic_sha256=replay.semantic_sha256,
        replay_tape_sha256=replay.tape_sha256,
        final_batch_sha256=final_batch.semantic_sha256,
        simulation_result_sha256=result.semantic_sha256,
        order_submission_sha256=result.submission.semantic_sha256,
        order_state_sha256=result.order_state.semantic_sha256,
        final_order_event_sha256=final_order_event.semantic_sha256,
    )
    values: tuple[tuple[str, object], ...] = (
        ("horizon_reference", horizon_reference),
        ("horizon_source_sha256", horizon_source_sha256),
        ("horizon_at", horizon_at),
        ("reservation_id", reservation.reservation_id),
        ("parent_decision_id", reservation.parent_decision_id),
        ("authorization_id", authorization.decision_id),
        ("attempt_id", attempt.attempt_id),
        ("order_id", attempt.order_id),
        ("client_order_id", preparation.client_order_id),
        ("broker_order_id", accepted_event.broker_order_id),
        ("intent_id", preparation.intent.intent_id),
        ("intent_payload_sha256", preparation.intent_payload_sha256),
        ("reservation_sha256", reservation.semantic_sha256),
        ("authorization_sha256", authorization.semantic_sha256),
        ("attempt_sha256", attempt.semantic_sha256),
        ("attempt_state", attempt.state),
        ("attempt_resolution", attempt.resolution),
        ("attempt_response_sha256", attempt.response_sha256),
        ("attempt_as_of", attempt.as_of),
        ("dispatch_event_id", dispatch_event.event_id),
        ("dispatch_event_sha256", dispatch_event.semantic_sha256),
        ("dispatch_at", dispatch_event.occurred_at),
        ("replay_run_id", manifest.run_id),
        ("replay_manifest_sha256", manifest.manifest_sha256),
        ("replay_input_sha256", manifest.input_sha256),
        ("replay_semantic_sha256", replay.semantic_sha256),
        ("replay_tape_sha256", replay.tape_sha256),
        ("replay_started_at", replay.started_at),
        ("replay_completed_at", replay.completed_at),
        ("replay_coverage_start", manifest.plan.coverage_start),
        ("replay_coverage_end", manifest.plan.coverage_end),
        ("replay_batch_count", len(replay.batches)),
        ("final_batch_id", final_batch.batch_id),
        ("final_batch_sha256", final_batch.semantic_sha256),
        ("simulation_result_id", result.result_id),
        ("simulation_result_sha256", result.semantic_sha256),
        ("simulation_outcome", result.outcome),
        ("simulation_session_sha256", result.session.semantic_sha256),
        ("simulation_model_sha256", result.model.semantic_sha256),
        ("risk_execution_caps_sha256", execution_caps.semantic_sha256),
        ("result_completed_at", result.completed_at),
        ("order_submission_sha256", result.submission.semantic_sha256),
        ("order_state_sha256", result.order_state.semantic_sha256),
        ("order_status", result.order_state.status),
        ("order_as_of", result.order_state.as_of),
        ("accepted_order_event_id", accepted_event.event_id),
        ("accepted_order_event_sha256", accepted_event.semantic_sha256),
        ("final_order_event_id", final_order_event.event_id),
        ("final_order_event_sha256", final_order_event.semantic_sha256),
        ("final_broker_sequence", final_order_event.broker_sequence),
    )
    fact = object.__new__(SimulationHorizonFact)
    for field_name, attribute_value in values:
        object.__setattr__(fact, field_name, attribute_value)
    semantic_sha256 = _sha256(fact._semantic_material())
    object.__setattr__(fact, "semantic_sha256", semantic_sha256)
    object.__setattr__(
        fact,
        "horizon_id",
        canonical_id("simulation-horizon-fact", semantic_sha256),
    )
    fact._validate()
    return fact
