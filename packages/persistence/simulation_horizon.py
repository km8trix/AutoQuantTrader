"""Durable, reducer-replayed simulation-horizon proof persistence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any, cast

import sqlalchemy as sa
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from packages.backtest.simulated_broker import (
    SIMULATED_BROKER_CONTRACT_VERSION,
    ConservativeSimulatedBroker,
    SimulatedBrokerError,
    SimulatedBrokerResult,
    SimulatedBrokerSession,
    SimulatedMarketOrderModel,
)
from packages.backtest.simulation_horizon import (
    SIMULATION_HORIZON_CONTRACT_VERSION,
    SimulationHorizonConflict,
    SimulationHorizonError,
    SimulationHorizonFact,
    create_simulation_horizon_fact,
)
from packages.domain.batch_risk import (
    BatchRiskAuthorization,
    BatchRiskFactConflict,
    BatchRiskReservation,
)
from packages.domain.canonical import canonical_decimal_text, canonical_persisted_decimal
from packages.domain.market_batch import (
    LateEventPolicy,
    MarketWatermark,
    MissingDataPolicy,
    ReplayRevisionPolicy,
)
from packages.domain.models import MarketEvent, OrderIntent, require_utc
from packages.domain.replay import REPLAY_CONTRACT_VERSION, ReplayResult, replay_market_events
from packages.domain.replay_manifest import ReplayRunManifest
from packages.domain.risk import intent_payload_hash
from packages.domain.submission_attempt import (
    CanonicalSubmissionAttempt,
    SubmissionAttemptState,
)
from packages.market_data.calendar import ExchangeSession, SessionKind
from packages.persistence import replay as replay_persistence
from packages.persistence.batch_risk import load_batch_risk_decision
from packages.persistence.immutable import (
    ImmutableFactConflict,
    as_aware_utc,
    insert_or_verify_atomic,
)
from packages.persistence.market_data import ManifestObjects
from packages.persistence.replay import verify_replay_dataset_catalog
from packages.persistence.schema import (
    phase2_authorization_consumptions,
    phase2_logical_orders,
    phase2_simulation_horizon_facts,
    phase2_submission_attempts,
    replay_run_manifests,
)
from packages.persistence.submission_attempt import (
    SubmissionAttemptPersistenceError,
    load_submission_attempt,
)

PHASE2_SIMULATION_HORIZON_PERSISTENCE_VERSION = "phase2-simulation-horizon-proof-v1"
MAX_SIMULATION_HORIZON_PAYLOAD_BYTES = 524_288


class SimulationHorizonPersistenceError(SimulationHorizonConflict):
    """A durable horizon proof is missing, corrupt, or conflicts with canonical facts."""


@dataclass(frozen=True, slots=True)
class _SimulationProofInputs:
    events: tuple[MarketEvent, ...]
    watermarks: tuple[MarketWatermark, ...]
    session: SimulatedBrokerSession
    model: SimulatedMarketOrderModel
    submitted_at: datetime


@dataclass(slots=True)
class _ReplayAuthorizationConsumer:
    authorization: BatchRiskAuthorization
    submitted_at: datetime
    consumed: bool = False

    def get(self, decision_id: str) -> BatchRiskAuthorization | None:
        if decision_id == self.authorization.decision_id:
            return self.authorization
        return None

    def consume(self, decision_id: str, intent: OrderIntent) -> datetime:
        if (
            self.consumed
            or decision_id != self.authorization.decision_id
            or intent.intent_id != self.authorization.intent_id
            or intent_payload_hash(intent) != self.authorization.intent_payload_hash
        ):
            raise SimulationHorizonPersistenceError(
                "persisted simulation authorization consumption is inconsistent"
            )
        self.consumed = True
        return self.submitted_at


def _require_text(value: object, field_name: str, *, maximum: int = 256) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise SimulationHorizonPersistenceError(
            f"persisted {field_name} must be supported non-empty trimmed text"
        )
    return value


def _require_sha256(value: object, field_name: str) -> str:
    digest = _require_text(value, field_name, maximum=64)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise SimulationHorizonPersistenceError(
            f"persisted {field_name} must be a lowercase SHA-256 digest"
        )
    return digest


def _require_int(value: object, field_name: str, *, allow_zero: bool = False) -> int:
    if type(value) is not int or value < (0 if allow_zero else 1):
        qualifier = "non-negative" if allow_zero else "positive"
        raise SimulationHorizonPersistenceError(
            f"persisted {field_name} must be a {qualifier} integer"
        )
    return value


def _datetime_text(value: datetime) -> str:
    require_utc(value, "canonical simulation-horizon datetime")
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _decode_datetime(value: object, field_name: str) -> datetime:
    raw = _require_text(value, field_name, maximum=40)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise SimulationHorizonPersistenceError(
            f"persisted {field_name} is not a canonical UTC datetime"
        ) from error
    if parsed.tzinfo is None:
        raise SimulationHorizonPersistenceError(
            f"persisted {field_name} is not a canonical UTC datetime"
        )
    result = parsed.astimezone(UTC)
    if raw != _datetime_text(result):
        raise SimulationHorizonPersistenceError(
            f"persisted {field_name} is not a canonical UTC datetime"
        )
    return result


def _require_datetime(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise SimulationHorizonPersistenceError(f"persisted {field_name} must be a datetime")
    result = as_aware_utc(value)
    try:
        require_utc(result, f"persisted {field_name}")
    except ValueError as error:
        raise SimulationHorizonPersistenceError(str(error)) from error
    return result


def _decimal_text(value: Decimal) -> str:
    try:
        return canonical_decimal_text(canonical_persisted_decimal(value, "horizon proof Decimal"))
    except (TypeError, ValueError) as error:
        raise SimulationHorizonPersistenceError(str(error)) from error


def _decode_decimal(value: object, field_name: str) -> Decimal:
    raw = _require_text(value, field_name, maximum=64)
    try:
        result = canonical_persisted_decimal(Decimal(raw), f"persisted {field_name}")
    except (InvalidOperation, ValueError) as error:
        raise SimulationHorizonPersistenceError(
            f"persisted {field_name} is not an exact database Decimal"
        ) from error
    if raw != canonical_decimal_text(result):
        raise SimulationHorizonPersistenceError(f"persisted {field_name} is not canonical")
    return result


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SimulationHorizonPersistenceError(
                "persisted simulation-horizon JSON contains a duplicate object key"
            )
        result[key] = value
    return result


def _json_text(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _decode_json(raw: object) -> object:
    if type(raw) is not str:
        raise SimulationHorizonPersistenceError(
            "persisted simulation-horizon payload must be JSON text"
        )
    if len(raw.encode("utf-8")) > MAX_SIMULATION_HORIZON_PAYLOAD_BYTES:
        raise SimulationHorizonPersistenceError(
            "persisted simulation-horizon payload exceeds its size limit"
        )
    try:
        value = json.loads(raw, object_pairs_hook=_strict_pairs)
    except SimulationHorizonPersistenceError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise SimulationHorizonPersistenceError(
            "persisted simulation-horizon payload is invalid JSON"
        ) from error
    if raw != _json_text(value):
        raise SimulationHorizonPersistenceError(
            "persisted simulation-horizon payload is not canonical JSON"
        )
    return value


def _object(value: object, field_name: str, keys: frozenset[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise SimulationHorizonPersistenceError(
            f"persisted {field_name} has an invalid object shape"
        )
    return cast(dict[str, Any], value)


_EVENT_KEYS = frozenset(
    {
        "available_at",
        "close_price",
        "event_id",
        "event_time",
        "instrument_id",
        "observation_id",
        "revision",
        "source",
        "source_sequence",
        "supersedes_event_revision_id",
        "symbol",
    }
)
_WATERMARK_KEYS = frozenset(
    {
        "closed_at",
        "event_time_through",
        "expected_instrument_ids",
        "late_event_policy",
        "missing_data_policy",
        "revision_policy",
        "watermark_id",
    }
)
_SESSION_KEYS = frozenset(
    {
        "calendar_id",
        "calendar_sha256",
        "calendar_version",
        "closes_at",
        "kind",
        "opens_at",
        "session_label",
        "venue",
    }
)
_MODEL_KEYS = frozenset(
    {
        "activation_latency_microseconds",
        "currency",
        "fee_per_share",
        "fixed_fee",
        "half_spread_per_share",
        "model_id",
        "model_version",
        "slippage_per_share",
    }
)
_PAYLOAD_KEYS = frozenset(
    {
        "horizon_semantic_sha256",
        "model",
        "persistence_version",
        "replay_contract_version",
        "replay_events",
        "replay_watermarks",
        "simulated_broker_contract_version",
        "simulation_horizon_contract_version",
        "session",
        "submitted_at",
    }
)


def _event_payload(event: MarketEvent) -> dict[str, object]:
    return {
        "available_at": _datetime_text(event.available_at),
        "close_price": _decimal_text(event.close_price),
        "event_id": event.event_id,
        "event_time": _datetime_text(event.event_time),
        "instrument_id": event.instrument_id,
        "observation_id": event.observation_id,
        "revision": event.revision,
        "source": event.source,
        "source_sequence": event.source_sequence,
        "supersedes_event_revision_id": event.supersedes_event_revision_id,
        "symbol": event.symbol,
    }


def _event_from_payload(value: object) -> MarketEvent:
    payload = _object(value, "simulation replay event", _EVENT_KEYS)
    source_sequence_raw = payload["source_sequence"]
    source_sequence = (
        None
        if source_sequence_raw is None
        else _require_int(source_sequence_raw, "event source sequence", allow_zero=True)
    )
    observation_raw = payload["observation_id"]
    supersedes_raw = payload["supersedes_event_revision_id"]
    try:
        event = MarketEvent(
            event_id=_require_text(payload["event_id"], "event ID", maximum=160),
            instrument_id=_require_text(
                payload["instrument_id"], "event instrument ID", maximum=64
            ),
            symbol=_require_text(payload["symbol"], "event symbol", maximum=32),
            event_time=_decode_datetime(payload["event_time"], "event time"),
            available_at=_decode_datetime(payload["available_at"], "event available_at"),
            close_price=_decode_decimal(payload["close_price"], "event close price"),
            source=_require_text(payload["source"], "event source", maximum=128),
            source_sequence=source_sequence,
            observation_id=(
                None
                if observation_raw is None
                else _require_text(observation_raw, "event observation ID", maximum=160)
            ),
            revision=_require_int(payload["revision"], "event revision"),
            supersedes_event_revision_id=(
                None
                if supersedes_raw is None
                else _require_text(
                    supersedes_raw,
                    "superseded event revision ID",
                    maximum=160,
                )
            ),
        )
    except SimulationHorizonPersistenceError:
        raise
    except (TypeError, ValueError) as error:
        raise SimulationHorizonPersistenceError(
            "persisted simulation replay event is malformed"
        ) from error
    if payload != _event_payload(event):
        raise SimulationHorizonPersistenceError(
            "persisted simulation replay event is not canonical"
        )
    return event


def _watermark_payload(watermark: MarketWatermark) -> dict[str, object]:
    return {
        "closed_at": _datetime_text(watermark.closed_at),
        "event_time_through": _datetime_text(watermark.event_time_through),
        "expected_instrument_ids": list(watermark.expected_instrument_ids),
        "late_event_policy": watermark.late_event_policy.value,
        "missing_data_policy": watermark.missing_data_policy.value,
        "revision_policy": watermark.revision_policy.value,
        "watermark_id": watermark.watermark_id,
    }


def _watermark_from_payload(value: object) -> MarketWatermark:
    payload = _object(value, "simulation replay watermark", _WATERMARK_KEYS)
    instrument_ids_raw = payload["expected_instrument_ids"]
    if type(instrument_ids_raw) is not list:
        raise SimulationHorizonPersistenceError(
            "persisted watermark instruments must be a JSON array"
        )
    try:
        watermark = MarketWatermark(
            watermark_id=_require_text(payload["watermark_id"], "watermark ID", maximum=160),
            event_time_through=_decode_datetime(
                payload["event_time_through"], "watermark event time"
            ),
            closed_at=_decode_datetime(payload["closed_at"], "watermark closed_at"),
            expected_instrument_ids=tuple(
                _require_text(item, "watermark instrument ID", maximum=64)
                for item in instrument_ids_raw
            ),
            revision_policy=ReplayRevisionPolicy(
                _require_text(payload["revision_policy"], "watermark revision policy")
            ),
            missing_data_policy=MissingDataPolicy(
                _require_text(payload["missing_data_policy"], "watermark missing-data policy")
            ),
            late_event_policy=LateEventPolicy(
                _require_text(payload["late_event_policy"], "watermark late-event policy")
            ),
        )
    except SimulationHorizonPersistenceError:
        raise
    except (TypeError, ValueError) as error:
        raise SimulationHorizonPersistenceError(
            "persisted simulation replay watermark is malformed"
        ) from error
    if payload != _watermark_payload(watermark):
        raise SimulationHorizonPersistenceError(
            "persisted simulation replay watermark is not canonical"
        )
    return watermark


def _session_payload(session: SimulatedBrokerSession) -> dict[str, object]:
    return {
        "calendar_id": session.calendar_id,
        "calendar_sha256": session.calendar_sha256,
        "calendar_version": session.calendar_version,
        "closes_at": _datetime_text(session.session.closes_at),
        "kind": session.session.kind.value,
        "opens_at": _datetime_text(session.session.opens_at),
        "session_label": session.session.session_label.isoformat(),
        "venue": session.session.venue,
    }


def _session_from_payload(value: object) -> SimulatedBrokerSession:
    payload = _object(value, "simulation broker session", _SESSION_KEYS)
    label_raw = _require_text(payload["session_label"], "session label", maximum=10)
    try:
        label = date.fromisoformat(label_raw)
        if label.isoformat() != label_raw:
            raise ValueError("non-canonical date")
        session = SimulatedBrokerSession(
            calendar_id=_require_text(payload["calendar_id"], "calendar ID", maximum=128),
            calendar_version=_require_text(
                payload["calendar_version"], "calendar version", maximum=64
            ),
            calendar_sha256=_require_sha256(payload["calendar_sha256"], "calendar digest"),
            session=ExchangeSession(
                venue=_require_text(payload["venue"], "session venue", maximum=32),
                session_label=label,
                opens_at=_decode_datetime(payload["opens_at"], "session opens_at"),
                closes_at=_decode_datetime(payload["closes_at"], "session closes_at"),
                kind=SessionKind(_require_text(payload["kind"], "session kind", maximum=24)),
            ),
        )
    except SimulationHorizonPersistenceError:
        raise
    except (SimulatedBrokerError, TypeError, ValueError) as error:
        raise SimulationHorizonPersistenceError(
            "persisted simulation broker session is malformed"
        ) from error
    if payload != _session_payload(session):
        raise SimulationHorizonPersistenceError(
            "persisted simulation broker session is not canonical"
        )
    return session


def _latency_microseconds(value: timedelta) -> int:
    return value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds


def _model_payload(model: SimulatedMarketOrderModel) -> dict[str, object]:
    return {
        "activation_latency_microseconds": _latency_microseconds(model.activation_latency),
        "currency": model.currency,
        "fee_per_share": _decimal_text(model.fee_per_share),
        "fixed_fee": _decimal_text(model.fixed_fee),
        "half_spread_per_share": _decimal_text(model.half_spread_per_share),
        "model_id": model.model_id,
        "model_version": model.model_version,
        "slippage_per_share": _decimal_text(model.slippage_per_share),
    }


def _model_from_payload(value: object) -> SimulatedMarketOrderModel:
    payload = _object(value, "simulation broker model", _MODEL_KEYS)
    latency_microseconds = _require_int(
        payload["activation_latency_microseconds"],
        "model activation latency",
        allow_zero=True,
    )
    try:
        model = SimulatedMarketOrderModel(
            model_id=_require_text(payload["model_id"], "model ID", maximum=128),
            model_version=_require_text(payload["model_version"], "model version", maximum=64),
            activation_latency=timedelta(microseconds=latency_microseconds),
            half_spread_per_share=_decode_decimal(
                payload["half_spread_per_share"], "model half spread"
            ),
            slippage_per_share=_decode_decimal(payload["slippage_per_share"], "model slippage"),
            fixed_fee=_decode_decimal(payload["fixed_fee"], "model fixed fee"),
            fee_per_share=_decode_decimal(payload["fee_per_share"], "model per-share fee"),
            currency=_require_text(payload["currency"], "model currency", maximum=3),
        )
    except SimulationHorizonPersistenceError:
        raise
    except (OverflowError, SimulatedBrokerError, TypeError, ValueError) as error:
        raise SimulationHorizonPersistenceError(
            "persisted simulation broker model is malformed"
        ) from error
    if payload != _model_payload(model):
        raise SimulationHorizonPersistenceError(
            "persisted simulation broker model is not canonical"
        )
    return model


def _event_key(event: MarketEvent) -> tuple[object, ...]:
    return (
        event.event_time,
        event.instrument_id,
        event.source,
        event.observation_key,
        event.revision,
        event.event_id,
    )


def _watermark_key(watermark: MarketWatermark) -> tuple[object, ...]:
    return (watermark.event_time_through, watermark.closed_at, watermark.watermark_id)


def _proof_inputs(
    *,
    result: SimulatedBrokerResult,
    replay_events: tuple[MarketEvent, ...],
    replay_watermarks: tuple[MarketWatermark, ...],
) -> _SimulationProofInputs:
    if type(result) is not SimulatedBrokerResult:
        raise SimulationHorizonPersistenceError(
            "simulation horizon persistence requires an exact broker result"
        )
    if type(replay_events) is not tuple or any(
        type(event) is not MarketEvent for event in replay_events
    ):
        raise SimulationHorizonPersistenceError(
            "simulation horizon replay events must be exact immutable facts"
        )
    if type(replay_watermarks) is not tuple or any(
        type(watermark) is not MarketWatermark for watermark in replay_watermarks
    ):
        raise SimulationHorizonPersistenceError(
            "simulation horizon watermarks must be exact immutable facts"
        )
    if len({event.event_id for event in replay_events}) != len(replay_events):
        raise SimulationHorizonPersistenceError(
            "simulation horizon replay events must not contain duplicate identities"
        )
    if len({item.watermark_id for item in replay_watermarks}) != len(replay_watermarks):
        raise SimulationHorizonPersistenceError(
            "simulation horizon watermarks must not contain duplicate identities"
        )
    return _SimulationProofInputs(
        events=tuple(sorted(replay_events, key=_event_key)),
        watermarks=tuple(sorted(replay_watermarks, key=_watermark_key)),
        session=result.session,
        model=result.model,
        submitted_at=result.submission.submitted_at,
    )


def _payload_object(
    fact: SimulationHorizonFact,
    proof: _SimulationProofInputs,
) -> dict[str, object]:
    return {
        "horizon_semantic_sha256": fact.semantic_sha256,
        "model": _model_payload(proof.model),
        "persistence_version": PHASE2_SIMULATION_HORIZON_PERSISTENCE_VERSION,
        "replay_contract_version": REPLAY_CONTRACT_VERSION,
        "replay_events": [_event_payload(event) for event in proof.events],
        "replay_watermarks": [_watermark_payload(watermark) for watermark in proof.watermarks],
        "simulated_broker_contract_version": SIMULATED_BROKER_CONTRACT_VERSION,
        "simulation_horizon_contract_version": SIMULATION_HORIZON_CONTRACT_VERSION,
        "session": _session_payload(proof.session),
        "submitted_at": _datetime_text(proof.submitted_at),
    }


def _payload(fact: SimulationHorizonFact, proof: _SimulationProofInputs) -> str:
    payload = _json_text(_payload_object(fact, proof))
    if len(payload.encode("utf-8")) > MAX_SIMULATION_HORIZON_PAYLOAD_BYTES:
        raise SimulationHorizonPersistenceError(
            "simulation-horizon proof payload exceeds its durable size limit"
        )
    return payload


def _proof_from_payload(raw: object) -> tuple[_SimulationProofInputs, str]:
    payload = _object(_decode_json(raw), "simulation-horizon payload", _PAYLOAD_KEYS)
    if (
        payload["persistence_version"] != PHASE2_SIMULATION_HORIZON_PERSISTENCE_VERSION
        or payload["simulation_horizon_contract_version"] != SIMULATION_HORIZON_CONTRACT_VERSION
        or payload["simulated_broker_contract_version"] != SIMULATED_BROKER_CONTRACT_VERSION
        or payload["replay_contract_version"] != REPLAY_CONTRACT_VERSION
    ):
        raise SimulationHorizonPersistenceError(
            "persisted simulation-horizon proof uses an unsupported contract"
        )
    events_raw = payload["replay_events"]
    watermarks_raw = payload["replay_watermarks"]
    if type(events_raw) is not list or type(watermarks_raw) is not list:
        raise SimulationHorizonPersistenceError(
            "persisted simulation-horizon replay inputs must be JSON arrays"
        )
    events = tuple(_event_from_payload(item) for item in events_raw)
    watermarks = tuple(_watermark_from_payload(item) for item in watermarks_raw)
    if events != tuple(sorted(events, key=_event_key)) or len(
        {event.event_id for event in events}
    ) != len(events):
        raise SimulationHorizonPersistenceError(
            "persisted simulation-horizon events are not canonical and unique"
        )
    if watermarks != tuple(sorted(watermarks, key=_watermark_key)) or len(
        {item.watermark_id for item in watermarks}
    ) != len(watermarks):
        raise SimulationHorizonPersistenceError(
            "persisted simulation-horizon watermarks are not canonical and unique"
        )
    proof = _SimulationProofInputs(
        events=events,
        watermarks=watermarks,
        session=_session_from_payload(payload["session"]),
        model=_model_from_payload(payload["model"]),
        submitted_at=_decode_datetime(payload["submitted_at"], "broker submitted_at"),
    )
    return proof, _require_sha256(
        payload["horizon_semantic_sha256"],
        "horizon semantic digest",
    )


def _sealed_manifest(
    connection: Connection,
    run_id: str,
) -> tuple[ReplayRunManifest, ManifestObjects]:
    row = (
        connection.execute(
            sa.select(replay_run_manifests).where(replay_run_manifests.c.run_id == run_id)
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise SimulationHorizonPersistenceError(
            "simulation horizon lacks its sealed replay manifest"
        )
    try:
        manifest = replay_persistence._decode_row(row)
        catalog = verify_replay_dataset_catalog(
            connection,
            manifest.dataset,
            manifest.plan,
            shared_lock=True,
        )
    except (ImmutableFactConflict, TypeError, ValueError) as error:
        raise SimulationHorizonPersistenceError(
            "simulation horizon replay manifest is not durably authenticated"
        ) from error
    return manifest, catalog


def _verify_session_catalog_binding(
    proof: _SimulationProofInputs,
    manifest: ReplayRunManifest,
    catalog: ManifestObjects,
) -> None:
    session = proof.session
    exchange_session = session.session
    matching_sessions = tuple(
        item
        for item in catalog.calendar_sessions
        if item.session_label == exchange_session.session_label
    )
    expected_kind = (
        SessionKind.HALF_DAY
        if matching_sessions and matching_sessions[0].half_day
        else SessionKind.REGULAR
    )
    if (
        catalog.calendar_version != manifest.dataset.calendar_version
        or catalog.calendar_hash != manifest.dataset.calendar_sha256
        or session.calendar_id != catalog.calendar_name
        or session.calendar_version != manifest.dataset.calendar_version
        or session.calendar_sha256 != manifest.dataset.calendar_sha256
        or exchange_session.venue != catalog.calendar_name
        or len(matching_sessions) != 1
        or exchange_session.opens_at != matching_sessions[0].opens_at
        or exchange_session.closes_at != matching_sessions[0].closes_at
        or exchange_session.kind is not expected_kind
        or not (
            exchange_session.opens_at
            <= manifest.plan.coverage_start
            <= manifest.plan.coverage_end
            <= exchange_session.closes_at
        )
    ):
        raise SimulationHorizonPersistenceError(
            "simulation session conflicts with the pinned durable replay calendar"
        )


def _authorization(
    reservation: BatchRiskReservation,
    authorization_id: str,
) -> BatchRiskAuthorization:
    matches = tuple(
        authorization
        for authorization in reservation.authorizations
        if authorization.decision_id == authorization_id
    )
    if len(matches) != 1:
        raise SimulationHorizonPersistenceError(
            "simulation horizon lacks its exact reservation authorization"
        )
    return matches[0]


def _durable_context(
    connection: Connection,
    *,
    attempt_id: str,
    parent_decision_id: str,
    reservation_id: str,
    authorization_id: str,
) -> tuple[BatchRiskReservation, BatchRiskAuthorization, CanonicalSubmissionAttempt]:
    try:
        attempt = load_submission_attempt(connection, attempt_id)
        decision = load_batch_risk_decision(connection, parent_decision_id)
    except (BatchRiskFactConflict, SubmissionAttemptPersistenceError) as error:
        raise SimulationHorizonPersistenceError(
            "simulation horizon durable submission evidence is malformed"
        ) from error
    if attempt is None or decision is None or decision.reservation is None:
        raise SimulationHorizonPersistenceError(
            "simulation horizon durable submission evidence is incomplete"
        )
    reservation = decision.reservation
    authorization = _authorization(reservation, authorization_id)
    if (
        attempt.state is not SubmissionAttemptState.CONFIRMED
        or attempt.resolution is not None
        or attempt.parent_decision_id != parent_decision_id
        or attempt.preparation.reservation_id != reservation_id
        or attempt.preparation.authorization_id != authorization_id
        or reservation.reservation_id != reservation_id
    ):
        raise SimulationHorizonPersistenceError(
            "durable simulation horizon requires one exact CONFIRMED attempt binding"
        )
    return reservation, authorization, attempt


def _verify_submission_time_binding(
    connection: Connection,
    *,
    proof: _SimulationProofInputs,
    attempt: CanonicalSubmissionAttempt,
    authorization: BatchRiskAuthorization,
) -> None:
    row = (
        connection.execute(
            sa.select(
                phase2_logical_orders.c.order_id,
                phase2_logical_orders.c.submission_attempt_id.label("first_attempt_id"),
                phase2_logical_orders.c.authorization_id.label("order_authorization_id"),
                phase2_logical_orders.c.parent_decision_id,
                phase2_logical_orders.c.reservation_id,
                phase2_logical_orders.c.intent_id,
                phase2_logical_orders.c.intent_payload_sha256,
                phase2_logical_orders.c.client_order_id,
                phase2_logical_orders.c.submitted_at.label("first_prepared_at"),
                phase2_authorization_consumptions.c.authorization_id.label(
                    "consumption_authorization_id"
                ),
                phase2_authorization_consumptions.c.order_id.label("consumption_order_id"),
                phase2_authorization_consumptions.c.reservation_id.label(
                    "consumption_reservation_id"
                ),
                phase2_authorization_consumptions.c.intent_id.label("consumption_intent_id"),
                phase2_authorization_consumptions.c.intent_payload_sha256.label(
                    "consumption_intent_payload_sha256"
                ),
                phase2_authorization_consumptions.c.consumed_at,
            )
            .join(
                phase2_authorization_consumptions,
                phase2_authorization_consumptions.c.order_id == phase2_logical_orders.c.order_id,
            )
            .where(phase2_logical_orders.c.order_id == attempt.order_id)
        )
        .mappings()
        .one_or_none()
    )
    preparation = attempt.preparation
    if row is None:
        raise SimulationHorizonPersistenceError(
            "simulation horizon lacks its durable logical order and authorization consumption"
        )
    first_prepared_at = _require_datetime(
        row["first_prepared_at"],
        "logical-order first prepared_at",
    )
    consumed_at = _require_datetime(row["consumed_at"], "authorization consumed_at")
    stable_bindings = (
        (row["order_id"], attempt.order_id),
        (row["order_authorization_id"], authorization.decision_id),
        (row["parent_decision_id"], attempt.parent_decision_id),
        (row["reservation_id"], preparation.reservation_id),
        (row["intent_id"], preparation.intent.intent_id),
        (row["intent_payload_sha256"], preparation.intent_payload_sha256),
        (row["client_order_id"], preparation.client_order_id),
        (row["consumption_authorization_id"], authorization.decision_id),
        (row["consumption_order_id"], attempt.order_id),
        (row["consumption_reservation_id"], preparation.reservation_id),
        (row["consumption_intent_id"], preparation.intent.intent_id),
        (row["consumption_intent_payload_sha256"], preparation.intent_payload_sha256),
    )
    if (
        any(actual != expected for actual, expected in stable_bindings)
        or consumed_at != first_prepared_at
        or proof.submitted_at != preparation.prepared_at
    ):
        raise SimulationHorizonPersistenceError(
            "simulation submission conflicts with its durable attempt and authorization times"
        )

    attempt_ids = tuple(
        str(attempt_id)
        for attempt_id in connection.scalars(
            sa.select(phase2_submission_attempts.c.attempt_id)
            .where(
                phase2_submission_attempts.c.order_id == attempt.order_id,
                phase2_submission_attempts.c.parent_decision_id == attempt.parent_decision_id,
            )
            .order_by(
                phase2_submission_attempts.c.attempt_number,
                phase2_submission_attempts.c.attempt_id,
            )
        )
    )
    try:
        chain = tuple(load_submission_attempt(connection, attempt_id) for attempt_id in attempt_ids)
    except SubmissionAttemptPersistenceError as error:
        raise SimulationHorizonPersistenceError(
            "simulation retry chain contains malformed durable attempts"
        ) from error
    if any(item is None for item in chain):
        raise SimulationHorizonPersistenceError(
            "simulation retry chain contains a missing durable attempt"
        )
    durable_chain = cast(tuple[CanonicalSubmissionAttempt, ...], chain)
    expected_numbers = tuple(range(1, len(durable_chain) + 1))
    if (
        not durable_chain
        or tuple(item.attempt_number for item in durable_chain) != expected_numbers
        or durable_chain[-1] != attempt
        or durable_chain[0].attempt_id != row["first_attempt_id"]
        or durable_chain[0].preparation.prepared_at != first_prepared_at
    ):
        raise SimulationHorizonPersistenceError(
            "simulation retry chain does not preserve its exact first and current attempts"
        )
    for item in durable_chain:
        item_preparation = item.preparation
        if (
            item.order_id != attempt.order_id
            or item.parent_decision_id != attempt.parent_decision_id
            or item_preparation.reservation_id != preparation.reservation_id
            or item_preparation.authorization_id != authorization.decision_id
            or item_preparation.intent != preparation.intent
            or item_preparation.intent_payload_sha256 != preparation.intent_payload_sha256
            or item_preparation.client_order_id != preparation.client_order_id
        ):
            raise SimulationHorizonPersistenceError(
                "simulation retry chain changes stable order or authorization identity"
            )
    if any(not prior.may_resubmit for prior in durable_chain[:-1]):
        raise SimulationHorizonPersistenceError(
            "simulation retry chain lacks safe non-dispatch evidence for a prior attempt"
        )


def _derive_from_proof(
    *,
    proof: _SimulationProofInputs,
    manifest: ReplayRunManifest,
    reservation: BatchRiskReservation,
    authorization: BatchRiskAuthorization,
    attempt: CanonicalSubmissionAttempt,
) -> tuple[SimulationHorizonFact, ReplayResult, SimulatedBrokerResult]:
    try:
        replay = replay_market_events(events=proof.events, watermarks=proof.watermarks)
        consumer = _ReplayAuthorizationConsumer(
            authorization=authorization,
            submitted_at=proof.submitted_at,
        )
        result = ConservativeSimulatedBroker(
            risk_authorizations=consumer,
            model=proof.model,
            session=proof.session,
            market_batches=replay.batches,
        ).submit(
            attempt.preparation.intent,
            authorization.decision_id,
            attempt.attempt_id,
        )
        fact = create_simulation_horizon_fact(
            result=result,
            replay=replay,
            manifest=manifest,
            reservation=reservation,
            authorization=authorization,
            attempt=attempt,
        )
    except (SimulationHorizonError, SimulatedBrokerError, TypeError, ValueError) as error:
        raise SimulationHorizonPersistenceError(
            "persisted simulation-horizon proof cannot reproduce its canonical fact"
        ) from error
    return fact, replay, result


def immutable_simulation_horizon_values(
    fact: SimulationHorizonFact,
    proof: _SimulationProofInputs,
    *,
    recorded_at: datetime,
) -> dict[str, object]:
    """Return the complete immutable row for one reducer-replayable horizon fact."""

    if type(fact) is not SimulationHorizonFact:
        raise SimulationHorizonPersistenceError(
            "simulation-horizon persistence requires an exact proof-factory fact"
        )
    fact._validate()
    try:
        require_utc(recorded_at, "simulation-horizon recorded_at")
    except ValueError as error:
        raise SimulationHorizonPersistenceError(str(error)) from error
    if recorded_at < fact.horizon_at:
        raise SimulationHorizonPersistenceError(
            "simulation horizon cannot be recorded before its derived horizon"
        )
    return {
        "horizon_id": fact.horizon_id,
        "horizon_reference": fact.horizon_reference,
        "horizon_source_sha256": fact.horizon_source_sha256,
        "reservation_id": fact.reservation_id,
        "parent_decision_id": fact.parent_decision_id,
        "authorization_id": fact.authorization_id,
        "attempt_id": fact.attempt_id,
        "order_id": fact.order_id,
        "final_order_event_id": fact.final_order_event_id,
        "replay_run_id": fact.replay_run_id,
        "replay_manifest_sha256": fact.replay_manifest_sha256,
        "replay_event_count": len(proof.events),
        "replay_watermark_count": len(proof.watermarks),
        "simulation_result_id": fact.simulation_result_id,
        "horizon_at": fact.horizon_at,
        "recorded_at": recorded_at,
        "canonical_payload": _payload(fact, proof),
        "semantic_sha256": fact.semantic_sha256,
    }


def simulation_horizon_from_row(
    connection: Connection,
    row: RowMapping,
) -> SimulationHorizonFact:
    """Re-run every reducer, broker rule, and proof factory for one persisted row."""

    proof, payload_semantic_sha256 = _proof_from_payload(row["canonical_payload"])
    attempt_id = _require_text(row["attempt_id"], "horizon attempt ID", maximum=64)
    parent_decision_id = _require_text(
        row["parent_decision_id"], "horizon parent decision ID", maximum=64
    )
    reservation_id = _require_text(row["reservation_id"], "horizon reservation ID", maximum=64)
    authorization_id = _require_text(
        row["authorization_id"], "horizon authorization ID", maximum=64
    )
    reservation, authorization, attempt = _durable_context(
        connection,
        attempt_id=attempt_id,
        parent_decision_id=parent_decision_id,
        reservation_id=reservation_id,
        authorization_id=authorization_id,
    )
    manifest, catalog = _sealed_manifest(
        connection,
        _require_sha256(row["replay_run_id"], "horizon replay run ID"),
    )
    _verify_session_catalog_binding(proof, manifest, catalog)
    _verify_submission_time_binding(
        connection,
        proof=proof,
        attempt=attempt,
        authorization=authorization,
    )
    fact, replay, result = _derive_from_proof(
        proof=proof,
        manifest=manifest,
        reservation=reservation,
        authorization=authorization,
        attempt=attempt,
    )
    try:
        from packages.persistence.reservation_lifecycle import load_canonical_order_state

        order_state = load_canonical_order_state(connection, attempt.attempt_id)
    except (ImportError, SimulationHorizonError, TypeError, ValueError) as error:
        raise SimulationHorizonPersistenceError(
            "simulation horizon cannot reconstruct its durable order state"
        ) from error
    if order_state != result.order_state:
        raise SimulationHorizonPersistenceError(
            "simulation horizon result differs from the complete durable order history"
        )
    recorded_at = _require_datetime(row["recorded_at"], "horizon recorded_at")
    expected = immutable_simulation_horizon_values(fact, proof, recorded_at=recorded_at)
    persisted = dict(row)
    persisted["horizon_at"] = _require_datetime(row["horizon_at"], "horizon horizon_at")
    persisted["recorded_at"] = recorded_at
    if (
        fact.semantic_sha256 != payload_semantic_sha256
        or replay != replay_market_events(events=proof.events, watermarks=proof.watermarks)
        or result.semantic_sha256 != fact.simulation_result_sha256
        or any(persisted[field_name] != value for field_name, value in expected.items())
    ):
        raise SimulationHorizonPersistenceError(
            "persisted simulation-horizon row conflicts with its reconstructed fact"
        )
    return fact


def load_simulation_horizon_fact(
    connection: Connection,
    horizon_id: str,
) -> SimulationHorizonFact | None:
    """Strictly load one horizon by replaying its complete canonical proof."""

    row = (
        connection.execute(
            sa.select(phase2_simulation_horizon_facts).where(
                phase2_simulation_horizon_facts.c.horizon_id == horizon_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    return simulation_horizon_from_row(connection, row)


def persist_simulation_horizon_fact(
    connection: Connection,
    *,
    result: SimulatedBrokerResult,
    replay: ReplayResult,
    replay_events: tuple[MarketEvent, ...],
    replay_watermarks: tuple[MarketWatermark, ...],
    manifest: ReplayRunManifest,
    reservation: BatchRiskReservation,
    authorization: BatchRiskAuthorization,
    attempt: CanonicalSubmissionAttempt,
    recorded_at: datetime,
) -> tuple[SimulationHorizonFact, bool]:
    """Persist one fact only after rerunning its replay, broker, and proof factory."""

    for value, expected_type, field_name in (
        (replay, ReplayResult, "replay result"),
        (manifest, ReplayRunManifest, "replay run manifest"),
        (reservation, BatchRiskReservation, "risk reservation"),
        (authorization, BatchRiskAuthorization, "risk authorization"),
        (attempt, CanonicalSubmissionAttempt, "submission attempt"),
    ):
        if type(value) is not expected_type:
            raise SimulationHorizonPersistenceError(
                f"simulation-horizon {field_name} must be an exact immutable value"
            )
    proof = _proof_inputs(
        result=result,
        replay_events=replay_events,
        replay_watermarks=replay_watermarks,
    )
    sealed_manifest, catalog = _sealed_manifest(connection, manifest.run_id)
    if sealed_manifest != manifest:
        raise SimulationHorizonPersistenceError(
            "supplied replay manifest differs from its sealed durable row"
        )
    _verify_session_catalog_binding(proof, sealed_manifest, catalog)
    persisted_reservation, persisted_authorization, persisted_attempt = _durable_context(
        connection,
        attempt_id=attempt.attempt_id,
        parent_decision_id=reservation.parent_decision_id,
        reservation_id=reservation.reservation_id,
        authorization_id=authorization.decision_id,
    )
    if (
        persisted_reservation != reservation
        or persisted_authorization != authorization
        or persisted_attempt != attempt
    ):
        raise SimulationHorizonPersistenceError(
            "supplied horizon context differs from its durable exact facts"
        )
    _verify_submission_time_binding(
        connection,
        proof=proof,
        attempt=attempt,
        authorization=authorization,
    )
    fact, rebuilt_replay, rebuilt_result = _derive_from_proof(
        proof=proof,
        manifest=sealed_manifest,
        reservation=reservation,
        authorization=authorization,
        attempt=attempt,
    )
    if rebuilt_replay != replay or rebuilt_result != result:
        raise SimulationHorizonPersistenceError(
            "supplied simulation outputs differ from reducer-replayed proof inputs"
        )
    values = immutable_simulation_horizon_values(fact, proof, recorded_at=recorded_at)
    try:
        inserted = insert_or_verify_atomic(
            connection,
            phase2_simulation_horizon_facts,
            values,
        )
    except (ImmutableFactConflict, IntegrityError) as error:
        raise SimulationHorizonPersistenceError(
            "simulation-horizon fact conflicts with immutable SQL history"
        ) from error
    persisted = load_simulation_horizon_fact(connection, fact.horizon_id)
    if persisted != fact:
        raise SimulationHorizonPersistenceError(
            "simulation-horizon read-back changed its reconstructed semantics"
        )
    return fact, inserted


def verify_simulation_horizon_integrity(connection: Connection) -> None:
    """Strictly reconstruct every persisted simulation-horizon proof."""

    for horizon_id in connection.scalars(sa.select(phase2_simulation_horizon_facts.c.horizon_id)):
        if load_simulation_horizon_fact(connection, str(horizon_id)) is None:
            raise SimulationHorizonPersistenceError(
                "persisted simulation-horizon fact disappeared during verification"
            )
