"""Pure operator statement data, never authentication or resolution authority.

Every operation consumes a complete native snapshot and fresh original values.
Declared head references, human metadata and evidence hashes prove no ownership,
durable membership, currentness, retained evidence or truth of the claim.
"""

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.identifiers import canonical_id
from packages.domain.operational_control import (
    OPERATIONAL_CONTROL_POLICY_SHA256,
    OperationalControlActor,
    OperationalControlActorKind,
    OperationalControlBlockingEvent,
    OperationalControlError,
    OperationalControlIncidentDisposition,
    OperationalControlState,
    _require_idempotency_key,
    _require_sha256,
    _require_text,
    _require_utc,
)

OPERATOR_STATEMENT_DATA_VERSION = "operational-control-operator-statement/1"
_ERROR = "OPERATIONAL_CONTROL_OPERATOR_STATEMENT_INVALID"
_FIELDS = (
    "scope_id",
    "control_transition_id",
    "control_transition_sha256",
    "control_sequence_number",
    "control_state",
    "control_state_epoch_id",
    "blocking_event",
    "actor",
    "resolution_claim",
    "authentication_checked_at",
    "attested_at",
    "idempotency_key",
)

type _Values = tuple[
    str,
    str,
    str,
    int,
    OperationalControlState,
    str,
    OperationalControlBlockingEvent,
    OperationalControlActor,
    OperationalControlIncidentDisposition,
    datetime,
    datetime,
    str,
]


@dataclass(frozen=True, slots=True, kw_only=True, eq=False, repr=False)
class OperationalControlOperatorStatement:
    scope_id: str
    control_transition_id: str
    control_transition_sha256: str
    control_sequence_number: int
    control_state: OperationalControlState
    control_state_epoch_id: str
    blocking_event: OperationalControlBlockingEvent
    actor: OperationalControlActor
    resolution_claim: OperationalControlIncidentDisposition
    authentication_checked_at: datetime
    attested_at: datetime
    idempotency_key: str

    def __post_init__(self) -> None:
        values = _validated_values(self)
        for name, value in zip(_FIELDS, values, strict=True):
            object.__setattr__(self, name, value)

    @property
    def statement_id(self) -> str:
        return _statement_id(_validated_values(self))

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(_semantic_material(_validated_values(self)))

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(_semantic_material(_validated_values(self)))
        ).hexdigest()


def _non_running_state(value: object) -> bool:
    return type(value) is OperationalControlState and any(
        value is member
        for member in (
            OperationalControlState.PAUSED,
            OperationalControlState.DRAINING,
            OperationalControlState.FLATTENING,
            OperationalControlState.HALTED,
        )
    )


def _validated_values(value: object) -> _Values:
    if type(value) is not OperationalControlOperatorStatement:
        raise OperationalControlError(_ERROR)
    scope = value.scope_id
    head_id = value.control_transition_id
    head_sha = value.control_transition_sha256
    sequence = value.control_sequence_number
    state = value.control_state
    epoch = value.control_state_epoch_id
    blocker = value.blocking_event
    actor = value.actor
    claim = value.resolution_claim
    auth_check = value.authentication_checked_at
    attested = value.attested_at
    key = value.idempotency_key
    if (
        type(blocker) is not OperationalControlBlockingEvent
        or type(actor) is not OperationalControlActor
        or type(claim) is not OperationalControlIncidentDisposition
    ):
        raise OperationalControlError(_ERROR)
    blocker_values = (
        blocker.scope_id,
        blocker.sequence_number,
        blocker.command_id,
        blocker.command_sha256,
        blocker.state,
        blocker.occurred_at,
    )
    actor_values = (actor.actor_id, actor.kind, actor.authority_sha256, actor.authenticated_at)
    claim_values = (
        claim.event_id,
        claim.event_sha256,
        claim.resolution_code,
        claim.resolution_evidence_sha256,
        claim.resolved_at,
    )
    # Admit all leaves before any original validator, constructor or canonical call.
    if (
        any(
            type(item) is not str
            for item in (
                scope,
                head_id,
                head_sha,
                epoch,
                key,
                blocker_values[0],
                blocker_values[2],
                blocker_values[3],
                actor_values[0],
                actor_values[2],
                *claim_values[:4],
            )
        )
        or type(sequence) is not int
        or type(blocker_values[1]) is not int
        or not _non_running_state(state)
        or not _non_running_state(blocker_values[4])
        or type(actor_values[1]) is not OperationalControlActorKind
        or actor_values[1] is not OperationalControlActorKind.HUMAN
        or any(
            type(instant) is not datetime or instant.tzinfo is not UTC
            for instant in (
                blocker_values[5],
                actor_values[3],
                claim_values[4],
                auth_check,
                attested,
            )
        )
    ):
        raise OperationalControlError(_ERROR)
    _require_text(scope, "operator statement scope ID")
    _require_text(head_id, "operator statement control transition ID")
    _require_sha256(head_sha, "operator statement control transition SHA-256")
    _require_text(epoch, "operator statement control state epoch ID")
    _require_idempotency_key(key, "operator statement idempotency key")
    _require_utc(auth_check, "operator statement authentication checked_at")
    _require_utc(attested, "operator statement attested_at")
    fresh_blocker = OperationalControlBlockingEvent(*blocker_values)
    fresh_actor = OperationalControlActor(*actor_values)
    fresh_claim = OperationalControlIncidentDisposition(*claim_values)
    authenticated = actor_values[3]
    if (
        sequence <= 0
        or blocker_values[0] != scope
        or blocker_values[1] > sequence
        or claim_values[0] != fresh_blocker.event_id
        or claim_values[1] != fresh_blocker.semantic_sha256
        or not (blocker_values[5] <= claim_values[4] <= attested)
        or authenticated is None
        or not (authenticated <= auth_check <= attested)
    ):
        raise OperationalControlError(_ERROR)
    return (
        scope,
        head_id,
        head_sha,
        sequence,
        state,
        epoch,
        fresh_blocker,
        fresh_actor,
        fresh_claim,
        auth_check,
        attested,
        key,
    )


def _statement_id(values: _Values) -> str:
    return canonical_id(
        "operational-control-operator-statement",
        OPERATOR_STATEMENT_DATA_VERSION,
        OPERATIONAL_CONTROL_POLICY_SHA256,
        values[0],
        OperationalControlActorKind.HUMAN,
        values[7].actor_id,
        values[11],
    )


def _semantic_material(values: _Values) -> tuple[object, ...]:
    return (
        OPERATOR_STATEMENT_DATA_VERSION,
        "operator_statement",
        OPERATIONAL_CONTROL_POLICY_SHA256,
        _statement_id(values),
        *values[:6],
        values[6].semantic_sha256,
        values[7].semantic_sha256,
        values[8].semantic_sha256,
        values[9],
        values[10],
        values[11],
    )


def copy_operational_control_operator_statement(
    value: OperationalControlOperatorStatement,
) -> OperationalControlOperatorStatement:
    """Revalidate and copy declared data; never authenticate or grant authority."""
    values = _validated_values(value)
    return OperationalControlOperatorStatement(
        scope_id=values[0],
        control_transition_id=values[1],
        control_transition_sha256=values[2],
        control_sequence_number=values[3],
        control_state=values[4],
        control_state_epoch_id=values[5],
        blocking_event=values[6],
        actor=values[7],
        resolution_claim=values[8],
        authentication_checked_at=values[9],
        attested_at=values[10],
        idempotency_key=values[11],
    )
