"""Transactional persistence for bounded Phase 3 experiment governance."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import fields, is_dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import Enum
from itertools import pairwise
from types import MappingProxyType
from typing import Any, Literal, cast

import sqlalchemy as sa
from sqlalchemy import Connection, Engine
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import RowMapping

from packages.domain.canonical import canonical_decimal, canonical_json_bytes, canonical_json_text
from packages.domain.experiment_governance import (
    EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
    GOVERNED_SEGMENT_EVALUATION,
    NON_EXECUTABLE_DOMAIN_FIXTURE,
    AuditedHoldoutReveal,
    ExperimentAttempt,
    ExperimentAttemptEvent,
    ExperimentAttemptStatus,
    ExperimentGovernanceFamily,
    ExperimentGovernanceSnapshot,
    ExperimentSegmentEvidence,
    GovernedSegmentEvaluationReceipt,
    HoldoutRevealAuthorization,
    NonExecutableTerminalEvidence,
    StrategyConfigurationValidationReceipt,
    TestSegmentCommitment,
)
from packages.domain.experiment_registry import (
    EvaluationSegment,
    EvaluationSegmentKind,
    FrozenPromotionCriteria,
    PromotionComparison,
    PromotionCriterion,
    StrategyConfigurationRecord,
    StrategyVersionRecord,
)
from packages.domain.feature_target import CertifiedFeatureTargetReplay
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import (
    ImmutableFactConflict,
    as_aware_utc,
    insert_or_verify_atomic,
)
from packages.persistence.schema import (
    phase3_experiment_attempt_events,
    phase3_experiment_attempts,
    phase3_experiment_audit_events,
    phase3_experiment_families,
    phase3_experiment_tape_claims,
    phase3_experiment_tape_policies,
    phase3_holdout_reveals,
)

EXPERIMENT_GOVERNANCE_STORAGE_VERSION = "phase3-experiment-governance-storage-v1"
_SUPPORTED_DIALECTS = frozenset({"sqlite", "postgresql"})
_MutationAction = Literal["record_attempt", "transition_attempt", "reveal_holdout"]
_ALLOWED_TYPES: dict[str, type[object]] = {
    "AuditedHoldoutReveal": AuditedHoldoutReveal,
    "EvaluationSegment": EvaluationSegment,
    "ExperimentAttempt": ExperimentAttempt,
    "ExperimentAttemptEvent": ExperimentAttemptEvent,
    "ExperimentGovernanceFamily": ExperimentGovernanceFamily,
    "ExperimentSegmentEvidence": ExperimentSegmentEvidence,
    "FrozenPromotionCriteria": FrozenPromotionCriteria,
    "GovernedSegmentEvaluationReceipt": GovernedSegmentEvaluationReceipt,
    "HoldoutRevealAuthorization": HoldoutRevealAuthorization,
    "NonExecutableTerminalEvidence": NonExecutableTerminalEvidence,
    "PromotionCriterion": PromotionCriterion,
    "StrategyConfigurationRecord": StrategyConfigurationRecord,
    "StrategyConfigurationValidationReceipt": StrategyConfigurationValidationReceipt,
    "StrategyVersionRecord": StrategyVersionRecord,
    "TestSegmentCommitment": TestSegmentCommitment,
}
_ALLOWED_ENUM_TYPES: dict[str, type[Enum]] = {
    "EvaluationSegmentKind": EvaluationSegmentKind,
    "ExperimentAttemptStatus": ExperimentAttemptStatus,
    "PromotionComparison": PromotionComparison,
}


class ExperimentGovernanceError(RuntimeError):
    """Persisted experiment governance is unavailable or malformed."""


class ExperimentGovernanceConflict(ExperimentGovernanceError):
    """A command, immutable fact, or expected family head conflicts."""


class ExperimentGovernanceNotFound(ExperimentGovernanceError):
    """The requested experiment family does not exist."""


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _payload_sha256(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _tape_content_sha256(source_tape_sha256: str) -> str:
    return _sha256(
        (
            EXPERIMENT_GOVERNANCE_CONTRACT_VERSION,
            "sealed-test-replay-content",
            source_tape_sha256,
        )
    )


def _utc(value: object, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ExperimentGovernanceError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def _text(value: object, field_name: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ExperimentGovernanceError(f"{field_name} must be non-empty trimmed text")
    return value


def _encode(value: object) -> object:
    """Encode the closed experiment-registry object graph without executable tags."""

    if value is None or type(value) in {bool, int, str}:
        return value
    if isinstance(value, Decimal):
        canonical = canonical_decimal(value)
        decimal_tuple = canonical.as_tuple()
        return {
            "$decimal": [
                decimal_tuple.sign,
                list(decimal_tuple.digits),
                int(decimal_tuple.exponent),
            ]
        }
    if isinstance(value, datetime):
        resolved = _utc(value, "canonical datetime")
        return {"$datetime": resolved.isoformat(timespec="microseconds").replace("+00:00", "Z")}
    if isinstance(value, timedelta):
        microseconds = value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds
        return {"$timedelta_us": microseconds}
    if isinstance(value, Enum):
        enum_type = type(value)
        if _ALLOWED_ENUM_TYPES.get(enum_type.__qualname__) is not enum_type:
            raise ExperimentGovernanceError("governance evidence contains an unsupported enum")
        return {"$enum": enum_type.__qualname__, "value": value.value}
    if type(value) is tuple:
        return {"$tuple": [_encode(item) for item in value]}
    if isinstance(value, Mapping):
        entries = [(_encode(key), _encode(item)) for key, item in value.items()]
        entries.sort(key=lambda item: json.dumps(item[0], sort_keys=True, separators=(",", ":")))
        return {"$mapping": entries}
    if is_dataclass(value):
        value_type = type(value)
        if _ALLOWED_TYPES.get(value_type.__qualname__) is not value_type:
            raise ExperimentGovernanceError(
                f"governance evidence contains unsupported type {value_type.__qualname__}"
            )
        if value_type.__qualname__ == "StrategyConfigurationRecord":
            configuration = cast(Any, value)
            encoded_fields = {
                "strategy_version_sha256": _encode(configuration.strategy_version_sha256),
                "configuration_name": _encode(configuration.configuration_name),
                "parameters": _encode(configuration.parameters),
                "registered_at": _encode(configuration.registered_at),
                "registered_by": _encode(configuration.registered_by),
            }
        else:
            encoded_fields = {
                field.name: _encode(getattr(value, field.name))
                for field in fields(value)
                if field.init and not field.name.startswith("_")
            }
        return {"$type": value_type.__qualname__, "fields": encoded_fields}
    raise ExperimentGovernanceError(
        f"governance evidence contains unsupported type {type(value).__qualname__}"
    )


def _decode(value: object) -> object:
    if value is None or type(value) in {bool, int, str}:
        return value
    if type(value) is not dict:
        raise ExperimentGovernanceError("governance evidence has an unsupported JSON shape")
    node = cast(dict[str, object], value)
    if set(node) == {"$decimal"}:
        raw = node["$decimal"]
        if (
            type(raw) is not list
            or len(raw) != 3
            or type(raw[0]) is not int
            or type(raw[1]) is not list
            or any(type(digit) is not int for digit in raw[1])
            or type(raw[2]) is not int
        ):
            raise ExperimentGovernanceError("governance Decimal evidence is malformed")
        return Decimal((raw[0], tuple(cast(list[int], raw[1])), raw[2]))
    if set(node) == {"$datetime"}:
        raw = node["$datetime"]
        if type(raw) is not str or not raw.endswith("Z"):
            raise ExperimentGovernanceError("governance datetime evidence is malformed")
        return datetime.fromisoformat(raw[:-1] + "+00:00").astimezone(UTC)
    if set(node) == {"$timedelta_us"}:
        raw = node["$timedelta_us"]
        if type(raw) is not int:
            raise ExperimentGovernanceError("governance timedelta evidence is malformed")
        return timedelta(microseconds=raw)
    if set(node) == {"$enum", "value"}:
        name = node["$enum"]
        if type(name) is not str or "." in name:
            raise ExperimentGovernanceError("governance enum evidence is malformed")
        enum_type = _ALLOWED_ENUM_TYPES.get(name)
        if enum_type is None:
            raise ExperimentGovernanceError("governance enum type is unsupported")
        return enum_type(node["value"])
    if set(node) == {"$tuple"}:
        raw = node["$tuple"]
        if type(raw) is not list:
            raise ExperimentGovernanceError("governance tuple evidence is malformed")
        return tuple(_decode(item) for item in raw)
    if set(node) == {"$mapping"}:
        raw = node["$mapping"]
        if type(raw) is not list:
            raise ExperimentGovernanceError("governance mapping evidence is malformed")
        result: dict[object, object] = {}
        for item in raw:
            if type(item) is not list or len(item) != 2:
                raise ExperimentGovernanceError("governance mapping entry is malformed")
            key = _decode(item[0])
            if key in result:
                raise ExperimentGovernanceError("governance mapping keys are duplicated")
            result[key] = _decode(item[1])
        return MappingProxyType(result)
    if set(node) == {"$type", "fields"}:
        name = node["$type"]
        raw_fields = node["fields"]
        if type(name) is not str or "." in name or type(raw_fields) is not dict:
            raise ExperimentGovernanceError("governance type evidence is malformed")
        domain_type = _ALLOWED_TYPES.get(name)
        if domain_type is None:
            raise ExperimentGovernanceError("governance evidence type is unsupported")
        kwargs = {key: _decode(item) for key, item in cast(dict[str, object], raw_fields).items()}
        try:
            if name == "StrategyConfigurationValidationReceipt":
                expected = kwargs.pop("receipt_sha256")
                restore = cast(Any, StrategyConfigurationValidationReceipt._restore)
                return restore(
                    **kwargs,
                    expected_receipt_sha256=expected,
                )
            if name == "ExperimentSegmentEvidence":
                expected = kwargs.pop("evidence_sha256")
                restore = cast(Any, ExperimentSegmentEvidence._restore)
                return restore(
                    **kwargs,
                    expected_evidence_sha256=expected,
                )
            if name == "TestSegmentCommitment":
                expected = kwargs.pop("commitment_sha256")
                restore = cast(Any, TestSegmentCommitment._restore)
                return restore(
                    **kwargs,
                    expected_commitment_sha256=expected,
                )
            if name == "NonExecutableTerminalEvidence":
                evidence_kind = kwargs.pop("evidence_kind")
                if evidence_kind != NON_EXECUTABLE_DOMAIN_FIXTURE:
                    raise ExperimentGovernanceError("terminal evidence kind is unsupported")
                expected = kwargs.pop("evidence_sha256")
                restore = cast(Any, NonExecutableTerminalEvidence._restore)
                return restore(
                    **kwargs,
                    expected_evidence_sha256=expected,
                )
            if name == "GovernedSegmentEvaluationReceipt":
                evidence_kind = kwargs.pop("evidence_kind")
                if evidence_kind != GOVERNED_SEGMENT_EVALUATION:
                    raise ExperimentGovernanceError(
                        "segment evaluation evidence kind is unsupported"
                    )
                expected = kwargs.pop("receipt_sha256")
                restore = cast(Any, GovernedSegmentEvaluationReceipt._restore)
                return restore(
                    **kwargs,
                    expected_receipt_sha256=expected,
                )
            if name == "HoldoutRevealAuthorization":
                expected = kwargs.pop("authorization_sha256")
                restore = cast(Any, HoldoutRevealAuthorization._restore)
                return restore(
                    **kwargs,
                    expected_authorization_sha256=expected,
                )
            return domain_type(**kwargs)
        except (KeyError, TypeError, ValueError) as error:
            raise ExperimentGovernanceError(
                f"persisted {name} evidence violates its domain contract"
            ) from error
    raise ExperimentGovernanceError("governance evidence has unknown typed fields")


def _evidence_payload(value: object) -> str:
    return json.dumps(
        _encode(value),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _decode_payload(payload: object, expected_type_name: str) -> object:
    if type(payload) is not str:
        raise ExperimentGovernanceError("persisted governance evidence payload is malformed")
    try:
        value = _decode(json.loads(payload))
    except (json.JSONDecodeError, ArithmeticError, TypeError, ValueError) as error:
        if isinstance(error, ExperimentGovernanceError):
            raise
        raise ExperimentGovernanceError(
            "persisted governance evidence payload is malformed"
        ) from error
    if type(value).__qualname__ != expected_type_name or _evidence_payload(value) != payload:
        raise ExperimentGovernanceError(
            f"persisted {expected_type_name} evidence is not exact canonical evidence"
        )
    return value


@contextmanager
def _write_transaction(engine: Engine) -> Iterator[Connection]:
    with engine.connect() as connection:
        if connection.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()
            return
        if connection.dialect.name == "postgresql":
            with connection.begin():
                yield connection
            return
        raise ExperimentGovernanceError(
            f"experiment governance does not support SQL dialect {connection.dialect.name!r}"
        )


def _family_values(family: ExperimentGovernanceFamily) -> dict[str, Any]:
    evidence_payload = _evidence_payload(family)
    return {
        "family_id": family.family_id,
        "family_name": family.family_name,
        "owner_id": family.owner_id,
        "strategy_version_id": family.strategy_version.strategy_version_id,
        "dataset_replay_sha256": family.dataset_replay_sha256,
        "evaluation_plan_sha256": family.evaluation_plan_sha256,
        "promotion_criteria_sha256": family.promotion_criteria.semantic_sha256,
        "holdout_commitment_sha256": family.test_commitment.semantic_sha256,
        "holdout_content_commitment_sha256": (family.test_commitment.content_commitment_sha256),
        "created_at": family.created_at,
        "canonical_payload": family.canonical_json,
        "evidence_payload": evidence_payload,
        "evidence_sha256": _payload_sha256(evidence_payload),
        "semantic_sha256": family.semantic_sha256,
    }


def _family_tape_sources(
    family: ExperimentGovernanceFamily,
) -> tuple[tuple[EvaluationSegment, str, str], ...]:
    train, validation, test = family.segments
    return (
        (train, family.train_evidence.source_tape_sha256, "exploratory"),
        (
            validation,
            family.validation_evidence.source_tape_sha256,
            "exploratory",
        ),
        (test, family.test_commitment.source_tape_sha256, "holdout"),
    )


def _tape_policy_values(
    *,
    source_tape_sha256: str,
    usage_class: str,
    holdout_family_id: str | None,
) -> dict[str, Any]:
    tape_content_sha256 = _tape_content_sha256(source_tape_sha256)
    material = (
        EXPERIMENT_GOVERNANCE_STORAGE_VERSION,
        "source-tape-policy",
        tape_content_sha256,
        source_tape_sha256,
        usage_class,
        holdout_family_id,
    )
    semantic_sha256 = _sha256(material)
    return {
        "tape_content_sha256": tape_content_sha256,
        "source_tape_sha256": source_tape_sha256,
        "usage_class": usage_class,
        "holdout_family_id": holdout_family_id,
        "canonical_payload": canonical_json_text(material),
        "semantic_sha256": semantic_sha256,
    }


def _tape_claim_values(
    family: ExperimentGovernanceFamily,
    segment: EvaluationSegment,
    source_tape_sha256: str,
    usage_class: str,
) -> dict[str, Any]:
    tape_content_sha256 = _tape_content_sha256(source_tape_sha256)
    material = (
        EXPERIMENT_GOVERNANCE_STORAGE_VERSION,
        "source-tape-segment-claim",
        family.family_id,
        segment.kind.value,
        segment.semantic_sha256,
        source_tape_sha256,
        tape_content_sha256,
        usage_class,
    )
    claim_sha256 = _sha256(material)
    return {
        "claim_sha256": claim_sha256,
        "family_id": family.family_id,
        "segment_kind": segment.kind.value,
        "segment_sha256": segment.semantic_sha256,
        "source_tape_sha256": source_tape_sha256,
        "tape_content_sha256": tape_content_sha256,
        "usage_class": usage_class,
        "canonical_payload": canonical_json_text(material),
        "semantic_sha256": claim_sha256,
    }


def _family_tape_policy_values(
    family: ExperimentGovernanceFamily,
) -> tuple[dict[str, Any], ...]:
    values = (
        _tape_policy_values(
            source_tape_sha256=source_tape_sha256,
            usage_class=usage_class,
            holdout_family_id=(family.family_id if usage_class == "holdout" else None),
        )
        for _, source_tape_sha256, usage_class in _family_tape_sources(family)
    )
    return tuple(sorted(values, key=lambda value: cast(str, value["tape_content_sha256"])))


def _family_tape_claim_values(
    family: ExperimentGovernanceFamily,
) -> tuple[dict[str, Any], ...]:
    values = (
        _tape_claim_values(
            family,
            segment,
            source_tape_sha256,
            usage_class,
        )
        for segment, source_tape_sha256, usage_class in _family_tape_sources(family)
    )
    return tuple(
        sorted(
            values,
            key=lambda value: (
                cast(str, value["tape_content_sha256"]),
                cast(str, value["segment_kind"]),
            ),
        )
    )


def _attempt_values(attempt: ExperimentAttempt) -> dict[str, Any]:
    return {
        "attempt_id": attempt.attempt_id,
        "family_id": attempt.family_id,
        "sequence_number": attempt.sequence,
        "attempt_number": attempt.attempt_number,
        "configuration_sha256": attempt.configuration.semantic_sha256,
        "configuration_validation_sha256": (attempt.configuration_validation.semantic_sha256),
        "segment_kind": attempt.segment_kind.value,
        "segment_sha256": attempt.segment_sha256,
        "holdout_reveal_sha256": attempt.holdout_reveal_sha256,
        "requested_at": attempt.requested_at,
        "canonical_payload": _evidence_payload(attempt),
        "semantic_sha256": attempt.semantic_sha256,
    }


def _event_values(event: ExperimentAttemptEvent) -> dict[str, Any]:
    terminal = event.terminal_evidence
    terminal_payload = None if terminal is None else _evidence_payload(terminal)
    return {
        "event_sha256": event.event_sha256,
        "attempt_id": event.attempt_id,
        "family_id": event.family_id,
        "global_sequence_number": event.global_sequence_number,
        "attempt_sequence_number": event.attempt_sequence_number,
        "previous_entry_sha256": event.previous_entry_sha256,
        "status": event.status.value,
        "occurred_at": event.occurred_at,
        "actor_id": event.actor_id,
        "terminal_evidence_sha256": (None if terminal is None else terminal.semantic_sha256),
        "terminal_evidence_payload": terminal_payload,
        "canonical_payload": _evidence_payload(event),
        "semantic_sha256": event.semantic_sha256,
    }


def _reveal_values(reveal: AuditedHoldoutReveal) -> dict[str, Any]:
    authorization = reveal.authorization
    return {
        "reveal_id": reveal.reveal_sha256,
        "family_id": reveal.family_id,
        "holdout_commitment_sha256": authorization.holdout_commitment_sha256,
        "holdout_content_commitment_sha256": _tape_content_sha256(
            reveal.test_evidence.source_tape_sha256
        ),
        "global_sequence_number": reveal.global_sequence_number,
        "previous_entry_sha256": reveal.previous_entry_sha256,
        "promotion_criteria_sha256": authorization.promotion_criteria_sha256,
        "selected_configuration_sha256": authorization.selected_configuration_sha256,
        "pre_reveal_attempt_count": authorization.pre_reveal_attempt_count,
        "pre_reveal_attempts_sha256": authorization.pre_reveal_attempts_sha256,
        "pre_reveal_registry_sha256": authorization.pre_reveal_snapshot_sha256,
        "authorization_sha256": authorization.semantic_sha256,
        "revealed_at": reveal.revealed_at,
        "revealed_by": reveal.revealed_by,
        "access_reason": reveal.access_reason,
        "canonical_payload": _evidence_payload(reveal),
        "semantic_sha256": reveal.semantic_sha256,
    }


def _snapshot(
    family: ExperimentGovernanceFamily,
    attempts: tuple[ExperimentAttempt, ...],
    events: tuple[ExperimentAttemptEvent, ...],
    reveal: AuditedHoldoutReveal | None,
) -> ExperimentGovernanceSnapshot:
    try:
        return ExperimentGovernanceSnapshot(
            family=family,
            attempts=attempts,
            lifecycle_events=events,
            holdout_reveal=reveal,
        )
    except (TypeError, ValueError) as error:
        raise ExperimentGovernanceError(
            "persisted experiment governance violates its domain contract"
        ) from error


def _snapshot_sha256(snapshot: ExperimentGovernanceSnapshot) -> str:
    return snapshot.semantic_sha256


def _decode_family(row: RowMapping) -> ExperimentGovernanceFamily:
    family = cast(
        ExperimentGovernanceFamily,
        _decode_payload(row["evidence_payload"], "ExperimentGovernanceFamily"),
    )
    expected = _family_values(family)
    if any(row[key] != value for key, value in expected.items() if key != "created_at"):
        raise ExperimentGovernanceError(
            "persisted experiment family conflicts with its canonical evidence"
        )
    if as_aware_utc(cast(datetime, row["created_at"])) != expected["created_at"]:
        raise ExperimentGovernanceError(
            "persisted experiment family time conflicts with its canonical evidence"
        )
    return family


def _decode_attempt(row: RowMapping) -> ExperimentAttempt:
    attempt = cast(
        ExperimentAttempt,
        _decode_payload(row["canonical_payload"], "ExperimentAttempt"),
    )
    expected = _attempt_values(attempt)
    if any(row[key] != value for key, value in expected.items() if key != "requested_at"):
        raise ExperimentGovernanceError(
            "persisted experiment attempt conflicts with its canonical evidence"
        )
    if as_aware_utc(cast(datetime, row["requested_at"])) != expected["requested_at"]:
        raise ExperimentGovernanceError(
            "persisted experiment attempt time conflicts with its canonical evidence"
        )
    return attempt


def _decode_event(row: RowMapping) -> ExperimentAttemptEvent:
    event = cast(
        ExperimentAttemptEvent,
        _decode_payload(row["canonical_payload"], "ExperimentAttemptEvent"),
    )
    expected = _event_values(event)
    for key, value in expected.items():
        actual = row[key]
        if key == "occurred_at":
            actual = as_aware_utc(cast(datetime, actual))
        if actual != value:
            raise ExperimentGovernanceError(
                "persisted attempt event conflicts with its canonical evidence"
            )
    return event


def _decode_reveal(row: RowMapping) -> AuditedHoldoutReveal:
    reveal = cast(
        AuditedHoldoutReveal,
        _decode_payload(row["canonical_payload"], "AuditedHoldoutReveal"),
    )
    expected = _reveal_values(reveal)
    for key, value in expected.items():
        actual = row[key]
        if key == "revealed_at":
            actual = as_aware_utc(cast(datetime, actual))
        if actual != value:
            raise ExperimentGovernanceError(
                "persisted holdout reveal conflicts with its canonical evidence"
            )
    return reveal


def _verify_exact_row(
    row: RowMapping,
    expected: Mapping[str, Any],
    *,
    fact_name: str,
) -> None:
    if any(row[key] != value for key, value in expected.items()):
        raise ExperimentGovernanceError(
            f"persisted {fact_name} conflicts with its canonical evidence"
        )


def _verify_family_tape_claims(
    connection: Connection,
    family: ExperimentGovernanceFamily,
) -> None:
    expected_claims = _family_tape_claim_values(family)
    if len({claim["source_tape_sha256"] for claim in expected_claims}) != 3:
        raise ExperimentGovernanceError("experiment family must claim three distinct source tapes")
    expected_claims_by_id = {cast(str, claim["claim_sha256"]): claim for claim in expected_claims}
    claim_rows = tuple(
        connection.execute(
            sa.select(phase3_experiment_tape_claims).where(
                phase3_experiment_tape_claims.c.family_id == family.family_id
            )
        ).mappings()
    )
    if len(claim_rows) != 3 or {row["claim_sha256"] for row in claim_rows} != set(
        expected_claims_by_id
    ):
        raise ExperimentGovernanceError(
            "persisted experiment family does not have exactly three tape claims"
        )
    for row in claim_rows:
        _verify_exact_row(
            row,
            expected_claims_by_id[cast(str, row["claim_sha256"])],
            fact_name="experiment tape claim",
        )

    expected_policies = _family_tape_policy_values(family)
    expected_policies_by_id = {
        cast(str, policy["tape_content_sha256"]): policy for policy in expected_policies
    }
    policy_rows = tuple(
        connection.execute(
            sa.select(phase3_experiment_tape_policies).where(
                phase3_experiment_tape_policies.c.tape_content_sha256.in_(
                    tuple(expected_policies_by_id)
                )
            )
        ).mappings()
    )
    if len(policy_rows) != 3 or {row["tape_content_sha256"] for row in policy_rows} != set(
        expected_policies_by_id
    ):
        raise ExperimentGovernanceError(
            "persisted experiment family does not have exact tape-isolation policies"
        )
    for row in policy_rows:
        _verify_exact_row(
            row,
            expected_policies_by_id[cast(str, row["tape_content_sha256"])],
            fact_name="experiment tape-isolation policy",
        )


def _reconstruct_snapshots(
    family: ExperimentGovernanceFamily,
    attempts: tuple[ExperimentAttempt, ...],
    events: tuple[ExperimentAttemptEvent, ...],
    reveal: AuditedHoldoutReveal | None,
) -> tuple[ExperimentGovernanceSnapshot, ...]:
    snapshots = [_snapshot(family, (), (), None)]
    attempts_by_id = {attempt.attempt_id: attempt for attempt in attempts}
    included_attempts: list[ExperimentAttempt] = []
    included_events: list[ExperimentAttemptEvent] = []
    included_reveal: AuditedHoldoutReveal | None = None
    entries: list[tuple[int, ExperimentAttemptEvent | AuditedHoldoutReveal]] = [
        (event.global_sequence_number, event) for event in events
    ]
    if reveal is not None:
        entries.append((reveal.global_sequence_number, reveal))
    entries.sort(key=lambda item: item[0])
    for _, entry in entries:
        if type(entry) is ExperimentAttemptEvent:
            attempt = attempts_by_id.get(entry.attempt_id)
            if attempt is None:
                raise ExperimentGovernanceError(
                    "persisted lifecycle event belongs to an unknown attempt"
                )
            if attempt not in included_attempts:
                included_attempts.append(attempt)
            included_events.append(entry)
        else:
            if included_reveal is not None:
                raise ExperimentGovernanceError(
                    "persisted family contains multiple holdout reveals"
                )
            included_reveal = cast(AuditedHoldoutReveal, entry)
        snapshots.append(
            _snapshot(
                family,
                tuple(included_attempts),
                tuple(included_events),
                included_reveal,
            )
        )
    if tuple(included_attempts) != attempts:
        raise ExperimentGovernanceError(
            "persisted experiment attempts are missing queued lifecycle evidence"
        )
    return tuple(snapshots)


def _load_snapshot_history(
    connection: Connection,
    family_id: str,
    *,
    lock: bool = False,
) -> tuple[ExperimentGovernanceSnapshot, ...]:
    statement = sa.select(phase3_experiment_families).where(
        phase3_experiment_families.c.family_id == family_id
    )
    if lock and connection.dialect.name == "postgresql":
        statement = statement.with_for_update()
    family_row = connection.execute(statement).mappings().one_or_none()
    if family_row is None:
        raise ExperimentGovernanceNotFound(f"unknown experiment family {family_id!r}")
    family = _decode_family(family_row)
    _verify_family_tape_claims(connection, family)
    attempt_rows = tuple(
        connection.execute(
            sa.select(phase3_experiment_attempts)
            .where(phase3_experiment_attempts.c.family_id == family_id)
            .order_by(phase3_experiment_attempts.c.sequence_number)
        ).mappings()
    )
    event_rows = tuple(
        connection.execute(
            sa.select(phase3_experiment_attempt_events)
            .where(phase3_experiment_attempt_events.c.family_id == family_id)
            .order_by(phase3_experiment_attempt_events.c.global_sequence_number)
        ).mappings()
    )
    attempts = tuple(_decode_attempt(row) for row in attempt_rows)
    events = tuple(_decode_event(row) for row in event_rows)
    reveal_row = (
        connection.execute(
            sa.select(phase3_holdout_reveals).where(phase3_holdout_reveals.c.family_id == family_id)
        )
        .mappings()
        .one_or_none()
    )
    reveal = None if reveal_row is None else _decode_reveal(reveal_row)
    return _reconstruct_snapshots(family, attempts, events, reveal)


def _load_snapshot(
    connection: Connection,
    family_id: str,
    *,
    lock: bool = False,
) -> ExperimentGovernanceSnapshot:
    return _load_snapshot_history(connection, family_id, lock=lock)[-1]


def _load_snapshot_result(
    connection: Connection,
    family_id: str,
    result_registry_sha256: str,
) -> ExperimentGovernanceSnapshot:
    for snapshot in _load_snapshot_history(connection, family_id):
        if snapshot.semantic_sha256 == result_registry_sha256:
            return snapshot
    raise ExperimentGovernanceError(
        "audited experiment command result is absent from durable history"
    )


def _audit_material(
    *,
    action: str,
    family_id: str,
    actor_id: str,
    idempotency_key: str,
    request_sha256: str,
    expected_registry_sha256: str,
    result_registry_sha256: str,
    resource_sha256: str,
    occurred_at: datetime,
) -> tuple[object, ...]:
    return (
        EXPERIMENT_GOVERNANCE_STORAGE_VERSION,
        "audit",
        action,
        family_id,
        actor_id,
        idempotency_key,
        request_sha256,
        expected_registry_sha256,
        result_registry_sha256,
        resource_sha256,
        occurred_at,
    )


def _registration_request_sha256(family: ExperimentGovernanceFamily) -> str:
    evidence_payload = _evidence_payload(family)
    return _sha256(
        (
            EXPERIMENT_GOVERNANCE_STORAGE_VERSION,
            "register_family_request",
            _payload_sha256(evidence_payload),
        )
    )


def _mutation_request_sha256(snapshot: ExperimentGovernanceSnapshot) -> str:
    return _sha256(
        (
            EXPERIMENT_GOVERNANCE_STORAGE_VERSION,
            "mutation_request",
            snapshot.family_id,
            snapshot.semantic_sha256,
        )
    )


def _insert_audit_if_absent(
    connection: Connection,
    values: Mapping[str, Any],
) -> bool:
    if connection.dialect.name == "postgresql":
        statement = (
            postgresql_insert(phase3_experiment_audit_events)
            .values(**dict(values))
            .on_conflict_do_nothing()
            .returning(sa.literal(True))
        )
    else:
        statement = (
            sqlite_insert(phase3_experiment_audit_events)
            .values(**dict(values))
            .on_conflict_do_nothing()
            .returning(sa.literal(True))
        )
    return connection.execute(statement).scalar_one_or_none() is not None


def _record_audit(
    connection: Connection,
    *,
    action: str,
    family_id: str,
    actor_id: str,
    idempotency_key: str,
    request_sha256: str,
    expected_registry_sha256: str,
    result_registry_sha256: str,
    resource_sha256: str,
    occurred_at: datetime,
) -> bool:
    material = _audit_material(
        action=action,
        family_id=family_id,
        actor_id=actor_id,
        idempotency_key=idempotency_key,
        request_sha256=request_sha256,
        expected_registry_sha256=expected_registry_sha256,
        result_registry_sha256=result_registry_sha256,
        resource_sha256=resource_sha256,
        occurred_at=occurred_at,
    )
    digest = _sha256(material)
    values = {
        "audit_sha256": digest,
        "family_id": family_id,
        "action": action,
        "actor_id": actor_id,
        "idempotency_key": idempotency_key,
        "request_sha256": request_sha256,
        "expected_registry_sha256": expected_registry_sha256,
        "result_registry_sha256": result_registry_sha256,
        "resource_sha256": resource_sha256,
        "occurred_at": occurred_at,
        "canonical_payload": canonical_json_text(material),
        "semantic_sha256": digest,
    }
    if _insert_audit_if_absent(connection, values):
        return True
    winner = (
        connection.execute(
            sa.select(phase3_experiment_audit_events).where(
                phase3_experiment_audit_events.c.actor_id == actor_id,
                phase3_experiment_audit_events.c.idempotency_key == idempotency_key,
            )
        )
        .mappings()
        .one()
    )
    retry_fields = (
        "family_id",
        "action",
        "actor_id",
        "idempotency_key",
        "request_sha256",
        "expected_registry_sha256",
        "result_registry_sha256",
        "resource_sha256",
    )
    if any(winner[key] != values[key] for key in retry_fields) or as_aware_utc(
        cast(datetime, winner["occurred_at"])
    ) != _utc(occurred_at, "audit time"):
        raise ExperimentGovernanceConflict(
            "idempotency key was already used for a different experiment command"
        )
    return False


def _validate_idempotency(value: str) -> str:
    if (
        type(value) is not str
        or not 8 <= len(value) <= 128
        or not value[0].isalnum()
        or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
            for character in value
        )
    ):
        raise ExperimentGovernanceError("idempotency key has an unsupported shape")
    return value


def _persist_delta(
    connection: Connection,
    current: ExperimentGovernanceSnapshot,
    proposed: ExperimentGovernanceSnapshot,
) -> tuple[str, str, str, datetime]:
    if current.family != proposed.family:
        raise ExperimentGovernanceConflict("experiment mutation cannot replace its family")
    old_attempts = current.attempts
    new_attempts = proposed.attempts
    old_events = current.lifecycle_events
    new_events = proposed.lifecycle_events
    old_reveal = current.holdout_reveal
    new_reveal = proposed.holdout_reveal
    resource: ExperimentAttempt | ExperimentAttemptEvent | AuditedHoldoutReveal
    if (
        new_attempts[: len(old_attempts)] != old_attempts
        or new_events[: len(old_events)] != old_events
    ):
        raise ExperimentGovernanceConflict("experiment mutation must append exact evidence")
    if len(new_events) == len(old_events) + 1 and len(new_attempts) == len(old_attempts) + 1:
        action = "record_attempt"
        resource = new_attempts[-1]
        command_actor = resource.requested_by
        command_time = resource.requested_at
        insert_or_verify_atomic(
            connection,
            phase3_experiment_attempts,
            _attempt_values(resource),
        )
        insert_or_verify_atomic(
            connection,
            phase3_experiment_attempt_events,
            _event_values(new_events[-1]),
        )
    elif len(new_events) == len(old_events) + 1 and new_attempts == old_attempts:
        action = "transition_attempt"
        resource = new_events[-1]
        command_actor = resource.actor_id
        command_time = resource.occurred_at
        insert_or_verify_atomic(
            connection,
            phase3_experiment_attempt_events,
            _event_values(resource),
        )
    elif (
        new_events == old_events
        and new_attempts == old_attempts
        and old_reveal is None
        and new_reveal is not None
    ):
        action = "reveal_holdout"
        resource = new_reveal
        command_actor = resource.revealed_by
        command_time = resource.revealed_at
        insert_or_verify_atomic(
            connection,
            phase3_holdout_reveals,
            _reveal_values(new_reveal),
        )
    else:
        raise ExperimentGovernanceConflict(
            "experiment mutation must add one attempt, transition, or reveal"
        )
    return action, resource.semantic_sha256, command_actor, command_time


def _verify_audit_row(row: RowMapping) -> None:
    material = _audit_material(
        action=_text(row["action"], "audit action"),
        family_id=_text(row["family_id"], "audit family"),
        actor_id=_text(row["actor_id"], "audit actor"),
        idempotency_key=_text(row["idempotency_key"], "audit idempotency key"),
        request_sha256=_text(row["request_sha256"], "audit request digest"),
        expected_registry_sha256=_text(
            row["expected_registry_sha256"],
            "audit expected registry digest",
        ),
        result_registry_sha256=_text(
            row["result_registry_sha256"],
            "audit result registry digest",
        ),
        resource_sha256=_text(row["resource_sha256"], "audit resource digest"),
        occurred_at=as_aware_utc(cast(datetime, row["occurred_at"])),
    )
    digest = _sha256(material)
    if (
        row["canonical_payload"] != canonical_json_text(material)
        or row["audit_sha256"] != digest
        or row["semantic_sha256"] != digest
    ):
        raise ExperimentGovernanceError(
            "persisted experiment audit conflicts with its canonical evidence"
        )


def _audit_delta(
    previous: ExperimentGovernanceSnapshot,
    result: ExperimentGovernanceSnapshot,
) -> tuple[str, str, str, datetime]:
    if (
        result.attempts[:-1] == previous.attempts
        and len(result.attempts) == len(previous.attempts) + 1
        and result.lifecycle_events[:-1] == previous.lifecycle_events
        and len(result.lifecycle_events) == len(previous.lifecycle_events) + 1
        and result.holdout_reveal == previous.holdout_reveal
    ):
        attempt = result.attempts[-1]
        return (
            "record_attempt",
            attempt.semantic_sha256,
            attempt.requested_by,
            attempt.requested_at,
        )
    if (
        result.attempts == previous.attempts
        and result.lifecycle_events[:-1] == previous.lifecycle_events
        and len(result.lifecycle_events) == len(previous.lifecycle_events) + 1
        and result.holdout_reveal == previous.holdout_reveal
    ):
        event = result.lifecycle_events[-1]
        return (
            "transition_attempt",
            event.semantic_sha256,
            event.actor_id,
            event.occurred_at,
        )
    if (
        result.attempts == previous.attempts
        and result.lifecycle_events == previous.lifecycle_events
        and previous.holdout_reveal is None
        and result.holdout_reveal is not None
    ):
        reveal = result.holdout_reveal
        return (
            "reveal_holdout",
            reveal.semantic_sha256,
            reveal.revealed_by,
            reveal.revealed_at,
        )
    raise ExperimentGovernanceError(
        "persisted experiment history has an unauditable state transition"
    )


def _require_exact_mutation(
    previous: ExperimentGovernanceSnapshot,
    result: ExperimentGovernanceSnapshot,
    *,
    expected_action: _MutationAction,
    certification: CertifiedFeatureTargetReplay | None,
) -> tuple[_MutationAction, str, str, datetime]:
    try:
        action, resource_sha256, actor_id, occurred_at = _audit_delta(previous, result)
    except ExperimentGovernanceError as error:
        raise ExperimentGovernanceConflict(
            "experiment mutation must add one attempt, transition, or reveal"
        ) from error
    if action != expected_action:
        raise ExperimentGovernanceConflict(
            f"experiment {expected_action} command cannot persist a different mutation"
        )
    if action != "transition_attempt":
        if certification is not None:
            raise ExperimentGovernanceConflict(
                "only a completed attempt transition may supply target certification"
            )
        return action, resource_sha256, actor_id, occurred_at

    event = result.lifecycle_events[-1]
    if event.status is not ExperimentAttemptStatus.COMPLETED:
        if certification is not None:
            raise ExperimentGovernanceConflict(
                "non-completed attempt transition cannot supply target certification"
            )
        return action, resource_sha256, actor_id, occurred_at
    if type(certification) is not CertifiedFeatureTargetReplay:
        raise ExperimentGovernanceConflict(
            "completed attempt persistence requires exact target certification"
        )
    try:
        reconstructed = previous.complete_attempt(
            event.attempt_id,
            certification,
            completed_at=event.occurred_at,
            actor_id=event.actor_id,
        )
    except (TypeError, ValueError) as error:
        raise ExperimentGovernanceConflict(
            "completed attempt evidence does not match its exact target certification"
        ) from error
    if reconstructed != result:
        raise ExperimentGovernanceConflict(
            "completed attempt evidence does not match its exact target certification"
        )
    return action, resource_sha256, actor_id, occurred_at


def _verify_audits(
    connection: Connection,
    history: tuple[ExperimentGovernanceSnapshot, ...],
) -> None:
    family = history[0].family
    rows = tuple(
        connection.execute(
            sa.select(phase3_experiment_audit_events).where(
                phase3_experiment_audit_events.c.family_id == family.family_id
            )
        ).mappings()
    )
    for row in rows:
        _verify_audit_row(row)
    if len(rows) != len(history):
        raise ExperimentGovernanceError(
            "persisted experiment history does not have exact audit coverage"
        )
    registration_rows = tuple(row for row in rows if row["action"] == "register_family")
    if len(registration_rows) != 1:
        raise ExperimentGovernanceError(
            "persisted experiment family requires exactly one registration audit"
        )
    initial = history[0]
    registration = registration_rows[0]
    if (
        registration["resource_sha256"] != family.family_id
        or registration["request_sha256"] != _registration_request_sha256(family)
        or registration["expected_registry_sha256"] != initial.semantic_sha256
        or registration["result_registry_sha256"] != initial.semantic_sha256
    ):
        raise ExperimentGovernanceError(
            "persisted experiment registration audit changed its exact result"
        )
    mutation_rows = tuple(row for row in rows if row["action"] != "register_family")
    rows_by_result: dict[str, RowMapping] = {}
    for row in mutation_rows:
        result_sha256 = _text(
            row["result_registry_sha256"],
            "audit result registry digest",
        )
        if result_sha256 in rows_by_result:
            raise ExperimentGovernanceError(
                "persisted experiment result has duplicate command audits"
            )
        rows_by_result[result_sha256] = row
    for previous, result in pairwise(history):
        matched_row = rows_by_result.get(result.semantic_sha256)
        if matched_row is not None:
            del rows_by_result[result.semantic_sha256]
        action, resource_sha256, actor_id, occurred_at = _audit_delta(previous, result)
        if (
            matched_row is None
            or matched_row["action"] != action
            or matched_row["resource_sha256"] != resource_sha256
            or matched_row["request_sha256"] != _mutation_request_sha256(result)
            or matched_row["expected_registry_sha256"] != previous.semantic_sha256
            or matched_row["actor_id"] != actor_id
            or as_aware_utc(cast(datetime, matched_row["occurred_at"])) != occurred_at
        ):
            raise ExperimentGovernanceError(
                "persisted experiment command audit breaks registry history"
            )
    if rows_by_result:
        raise ExperimentGovernanceError(
            "persisted experiment audit references an unknown registry result"
        )


def _verify_global_tape_inventory(
    connection: Connection,
    families: tuple[ExperimentGovernanceFamily, ...],
) -> None:
    expected_claims: dict[str, Mapping[str, Any]] = {}
    expected_policies: dict[str, Mapping[str, Any]] = {}
    for family in families:
        for claim in _family_tape_claim_values(family):
            claim_sha256 = cast(str, claim["claim_sha256"])
            if claim_sha256 in expected_claims:
                raise ExperimentGovernanceError(
                    "persisted experiment families have duplicate tape-claim identities"
                )
            expected_claims[claim_sha256] = claim
        for policy in _family_tape_policy_values(family):
            tape_content_sha256 = cast(str, policy["tape_content_sha256"])
            existing = expected_policies.get(tape_content_sha256)
            if existing is not None and existing != policy:
                raise ExperimentGovernanceError(
                    "persisted experiment families violate global tape-role isolation"
                )
            expected_policies[tape_content_sha256] = policy

    claim_rows = tuple(connection.execute(sa.select(phase3_experiment_tape_claims)).mappings())
    claim_rows_by_id = {cast(str, row["claim_sha256"]): row for row in claim_rows}
    if len(claim_rows_by_id) != len(claim_rows) or set(claim_rows_by_id) != set(expected_claims):
        raise ExperimentGovernanceError(
            "persisted experiment tape claims contain missing or orphan facts"
        )
    for claim_sha256, expected in expected_claims.items():
        _verify_exact_row(
            claim_rows_by_id[claim_sha256],
            expected,
            fact_name="experiment tape claim",
        )

    policy_rows = tuple(connection.execute(sa.select(phase3_experiment_tape_policies)).mappings())
    policy_rows_by_id = {cast(str, row["tape_content_sha256"]): row for row in policy_rows}
    if len(policy_rows_by_id) != len(policy_rows) or set(policy_rows_by_id) != set(
        expected_policies
    ):
        raise ExperimentGovernanceError(
            "persisted tape-isolation policies contain missing or orphan facts"
        )
    for tape_content_sha256, expected in expected_policies.items():
        _verify_exact_row(
            policy_rows_by_id[tape_content_sha256],
            expected,
            fact_name="experiment tape-isolation policy",
        )


def _verify_experiment_governance_integrity(connection: Connection) -> None:
    family_ids = tuple(
        connection.scalars(
            sa.select(phase3_experiment_families.c.family_id).order_by(
                phase3_experiment_families.c.family_id
            )
        )
    )
    families: list[ExperimentGovernanceFamily] = []
    for family_id in family_ids:
        if type(family_id) is not str:
            raise ExperimentGovernanceError("persisted experiment family ID is malformed")
        history = _load_snapshot_history(connection, family_id)
        _verify_audits(connection, history)
        families.append(history[0].family)
    _verify_global_tape_inventory(connection, tuple(families))


class SqlExperimentGovernance:
    """Own durable experiment-family registration, mutation, and query."""

    __slots__ = ("_engine",)

    def __init__(self, engine: Engine) -> None:
        if not isinstance(engine, Engine):
            raise ExperimentGovernanceError("experiment governance requires a SQLAlchemy engine")
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise ExperimentGovernanceError(
                f"experiment governance does not support SQL dialect {engine.dialect.name!r}"
            )
        self._engine = engine

    def register_family(
        self,
        family: ExperimentGovernanceFamily,
        *,
        actor_id: str,
        idempotency_key: str,
        registered_at: datetime,
    ) -> ExperimentGovernanceSnapshot:
        try:
            snapshot = ExperimentGovernanceSnapshot.empty(family)
        except (TypeError, ValueError) as error:
            raise ExperimentGovernanceError("family registration is invalid") from error
        family_values = _family_values(family)
        family_id = family.family_id
        request_sha256 = _registration_request_sha256(family)
        occurred_at = _utc(registered_at, "family registration time")
        actor = _text(actor_id, "family registration actor")
        key = _validate_idempotency(idempotency_key)
        try:
            with _write_transaction(self._engine) as connection:
                insert_or_verify_atomic(
                    connection,
                    phase3_experiment_families,
                    family_values,
                )
                for policy_values in _family_tape_policy_values(family):
                    insert_or_verify_atomic(
                        connection,
                        phase3_experiment_tape_policies,
                        policy_values,
                    )
                for claim_values in _family_tape_claim_values(family):
                    insert_or_verify_atomic(
                        connection,
                        phase3_experiment_tape_claims,
                        claim_values,
                    )
                snapshot_sha256 = _snapshot_sha256(snapshot)
                _record_audit(
                    connection,
                    action="register_family",
                    family_id=family_id,
                    actor_id=actor,
                    idempotency_key=key,
                    request_sha256=request_sha256,
                    expected_registry_sha256=snapshot_sha256,
                    result_registry_sha256=snapshot_sha256,
                    resource_sha256=family_id,
                    occurred_at=occurred_at,
                )
                history = _load_snapshot_history(connection, family_id)
                _verify_audits(connection, history)
                return _load_snapshot_result(
                    connection,
                    family_id,
                    snapshot.semantic_sha256,
                )
        except ImmutableFactConflict as error:
            raise ExperimentGovernanceConflict(str(error)) from error

    def _persist(
        self,
        proposed: ExperimentGovernanceSnapshot,
        *,
        expected_action: _MutationAction,
        expected_registry_sha256: str,
        actor_id: str,
        idempotency_key: str,
        occurred_at: datetime,
        certification: CertifiedFeatureTargetReplay | None = None,
    ) -> ExperimentGovernanceSnapshot:
        if type(proposed) is not ExperimentGovernanceSnapshot:
            raise ExperimentGovernanceError(
                "experiment mutation requires an exact governance snapshot"
            )
        family_id = proposed.family_id
        request_sha256 = _mutation_request_sha256(proposed)
        actor = _text(actor_id, "experiment command actor")
        key = _validate_idempotency(idempotency_key)
        command_time = _utc(occurred_at, "experiment command time")
        try:
            with _write_transaction(self._engine) as connection:
                history = _load_snapshot_history(connection, family_id, lock=True)
                _verify_audits(connection, history)
                current = history[-1]
                existing = (
                    connection.execute(
                        sa.select(phase3_experiment_audit_events).where(
                            phase3_experiment_audit_events.c.actor_id == actor,
                            phase3_experiment_audit_events.c.idempotency_key == key,
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if existing is not None:
                    if (
                        existing["family_id"] != family_id
                        or existing["action"] != expected_action
                        or existing["request_sha256"] != request_sha256
                        or existing["expected_registry_sha256"] != expected_registry_sha256
                        or as_aware_utc(cast(datetime, existing["occurred_at"])) != command_time
                    ):
                        raise ExperimentGovernanceConflict(
                            "idempotency key was already used for a different experiment command"
                        )
                    _verify_audit_row(existing)
                    result = _load_snapshot_result(
                        connection,
                        family_id,
                        cast(str, existing["result_registry_sha256"]),
                    )
                    if result != proposed:
                        raise ExperimentGovernanceConflict(
                            "idempotent experiment retry changed its exact result"
                        )
                    previous = _load_snapshot_result(
                        connection,
                        family_id,
                        cast(str, existing["expected_registry_sha256"]),
                    )
                    _require_exact_mutation(
                        previous,
                        result,
                        expected_action=expected_action,
                        certification=certification,
                    )
                    return result
                if _snapshot_sha256(current) != expected_registry_sha256:
                    raise ExperimentGovernanceConflict(
                        "experiment family head changed concurrently"
                    )
                exact_mutation = _require_exact_mutation(
                    current,
                    proposed,
                    expected_action=expected_action,
                    certification=certification,
                )
                (
                    action,
                    resource_sha256,
                    exact_actor,
                    exact_command_time,
                ) = _persist_delta(connection, current, proposed)
                if (
                    action,
                    resource_sha256,
                    exact_actor,
                    exact_command_time,
                ) != exact_mutation:
                    raise ExperimentGovernanceConflict(
                        "experiment mutation changed while being persisted"
                    )
                if actor != exact_actor or command_time != exact_command_time:
                    raise ExperimentGovernanceConflict(
                        "experiment audit actor/time must match the exact appended fact"
                    )
                reconstructed = _load_snapshot(connection, family_id)
                if reconstructed != proposed:
                    raise ExperimentGovernanceConflict(
                        "persisted experiment mutation changed its domain evidence"
                    )
                _record_audit(
                    connection,
                    action=action,
                    family_id=family_id,
                    actor_id=actor,
                    idempotency_key=key,
                    request_sha256=request_sha256,
                    expected_registry_sha256=expected_registry_sha256,
                    result_registry_sha256=_snapshot_sha256(reconstructed),
                    resource_sha256=resource_sha256,
                    occurred_at=command_time,
                )
                _verify_audits(
                    connection,
                    _load_snapshot_history(connection, family_id),
                )
                return reconstructed
        except ImmutableFactConflict as error:
            raise ExperimentGovernanceConflict(str(error)) from error

    def record_attempt(
        self,
        proposed: ExperimentGovernanceSnapshot,
        *,
        expected_registry_sha256: str,
        actor_id: str,
        idempotency_key: str,
        occurred_at: datetime,
    ) -> ExperimentGovernanceSnapshot:
        return self._persist(
            proposed,
            expected_action="record_attempt",
            expected_registry_sha256=expected_registry_sha256,
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            occurred_at=occurred_at,
        )

    def transition_attempt(
        self,
        proposed: ExperimentGovernanceSnapshot,
        *,
        expected_registry_sha256: str,
        actor_id: str,
        idempotency_key: str,
        occurred_at: datetime,
        certification: CertifiedFeatureTargetReplay | None = None,
    ) -> ExperimentGovernanceSnapshot:
        return self._persist(
            proposed,
            expected_action="transition_attempt",
            expected_registry_sha256=expected_registry_sha256,
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            occurred_at=occurred_at,
            certification=certification,
        )

    def reveal_holdout(
        self,
        proposed: ExperimentGovernanceSnapshot,
        *,
        expected_registry_sha256: str,
        actor_id: str,
        idempotency_key: str,
        occurred_at: datetime,
    ) -> ExperimentGovernanceSnapshot:
        return self._persist(
            proposed,
            expected_action="reveal_holdout",
            expected_registry_sha256=expected_registry_sha256,
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            occurred_at=occurred_at,
        )

    def get(self, family_id: str) -> ExperimentGovernanceSnapshot:
        with _repeatable_read_transaction(self._engine) as connection:
            history = _load_snapshot_history(connection, family_id)
            _verify_audits(connection, history)
            return history[-1]

    def families(self, *, limit: int = 100) -> tuple[ExperimentGovernanceSnapshot, ...]:
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ExperimentGovernanceError("family query limit must be between 1 and 500")
        with _repeatable_read_transaction(self._engine) as connection:
            family_ids = tuple(
                connection.scalars(
                    sa.select(phase3_experiment_families.c.family_id)
                    .order_by(
                        phase3_experiment_families.c.created_at.desc(),
                        phase3_experiment_families.c.family_id,
                    )
                    .limit(limit)
                )
            )
            snapshots: list[ExperimentGovernanceSnapshot] = []
            for family_id in family_ids:
                history = _load_snapshot_history(connection, family_id)
                _verify_audits(connection, history)
                snapshots.append(history[-1])
            return tuple(snapshots)


__all__ = [
    "ExperimentGovernanceConflict",
    "ExperimentGovernanceError",
    "ExperimentGovernanceNotFound",
    "SqlExperimentGovernance",
]
