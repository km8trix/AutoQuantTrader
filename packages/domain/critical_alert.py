"""Pure immutable contracts for durable critical-alert delivery."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.identifiers import canonical_id

CRITICAL_ALERT_CONTRACT_VERSION = "phase5d-critical-alert-v1"

CRITICAL_ALERT_LOCAL_DURABILITY_MICROSECONDS = 1_000_000
CRITICAL_ALERT_PRIMARY_DEADLINE_MICROSECONDS = 15_000_000
CRITICAL_ALERT_ESCALATION_DEADLINE_MICROSECONDS = 30_000_000
MAX_CRITICAL_ALERT_ATTEMPTS = 1_024
MAX_CRITICAL_ALERT_SCAN_PAGE = 256

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")


class CriticalAlertError(ValueError):
    """Critical-alert evidence is malformed or cannot be interpreted safely."""


class CriticalAlertConflict(CriticalAlertError):
    """An immutable identity or append-only history conflicts."""


class CriticalAlertRoute(StrEnum):
    PRIMARY = "primary"
    ESCALATION = "escalation"


class CriticalAlertDeliveryOutcome(StrEnum):
    CONFIRMED = "confirmed"
    TIMEOUT = "timeout"
    ERROR = "error"


class CriticalAlertDeliveryState(StrEnum):
    CONFIRMED = "confirmed"
    TIMEOUT = "timeout"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CriticalAlertIncidentScanCursor:
    """Stable resume position for a bounded durable incident scan."""

    recorded_at: datetime
    incident_id: str

    def __post_init__(self) -> None:
        _require_utc(self.recorded_at, "critical-alert scan cursor recorded_at")
        _require_text(self.incident_id, "critical-alert scan cursor incident ID")

    @property
    def sort_key(self) -> tuple[datetime, str]:
        return self.recorded_at, self.incident_id


@dataclass(frozen=True, slots=True)
class CriticalAlertIncidentScanPage:
    """Authenticated active incidents from one bounded durable scan segment."""

    incidents: tuple[CriticalAlertIncident, ...]
    scanned_count: int
    resume_after: CriticalAlertIncidentScanCursor | None

    def __post_init__(self) -> None:
        if type(self.incidents) is not tuple:
            raise CriticalAlertError("critical-alert scan incidents must be an exact tuple")
        if (
            type(self.scanned_count) is not int
            or not 0 <= self.scanned_count <= MAX_CRITICAL_ALERT_SCAN_PAGE
            or len(self.incidents) > self.scanned_count
        ):
            raise CriticalAlertError("critical-alert scan count exceeds its bounded range")
        previous_key: tuple[datetime, str] | None = None
        for incident in self.incidents:
            if type(incident) is not CriticalAlertIncident:
                raise CriticalAlertError("critical-alert scan contains a noncanonical incident")
            key = (incident.recorded_at, incident.incident_id)
            if previous_key is not None and key <= previous_key:
                raise CriticalAlertError("critical-alert scan incidents must be strictly ordered")
            previous_key = key
        if self.resume_after is not None:
            if type(self.resume_after) is not CriticalAlertIncidentScanCursor:
                raise CriticalAlertError("critical-alert scan resume cursor must be exact")
            if self.scanned_count == 0:
                raise CriticalAlertError("empty critical-alert scan cannot require a resume cursor")
            if previous_key is not None and previous_key > self.resume_after.sort_key:
                raise CriticalAlertError(
                    "critical-alert scan resume cursor precedes an active incident"
                )


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(value: str, field_name: str, *, maximum: int = 128) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise CriticalAlertError(f"{field_name} must be a non-empty, trimmed string")
    if len(value) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise CriticalAlertError(f"{field_name} contains unsupported text")


def _require_idempotency_key(value: str, field_name: str) -> None:
    if type(value) is not str or _IDEMPOTENCY_KEY.fullmatch(value) is None:
        raise CriticalAlertError(f"{field_name} must contain 8-128 safe visible characters")


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise CriticalAlertError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise CriticalAlertError(f"{field_name} must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise CriticalAlertError(f"{field_name} must be UTC")


def _timedelta_microseconds(value: timedelta) -> int:
    return (value.days * 86_400 + value.seconds) * 1_000_000 + value.microseconds


def _deadline(recorded_at: datetime, microseconds: int) -> datetime:
    try:
        return recorded_at + timedelta(microseconds=microseconds)
    except OverflowError as error:
        raise CriticalAlertError("critical-alert deadline exceeds datetime range") from error


@dataclass(frozen=True, slots=True)
class CriticalAlertIncident:
    """One source-idempotent critical fact, without raw or secret material."""

    scope_id: str
    source_id: str
    idempotency_key: str
    alert_code: str
    evidence_sha256: str
    detected_at: datetime
    recorded_at: datetime
    correlation_sha256: str

    def __post_init__(self) -> None:
        for value, field_name in (
            (self.scope_id, "critical-alert scope ID"),
            (self.source_id, "critical-alert source ID"),
            (self.alert_code, "critical-alert code"),
        ):
            _require_text(value, field_name)
        _require_idempotency_key(
            self.idempotency_key,
            "critical-alert idempotency key",
        )
        _require_sha256(self.evidence_sha256, "critical-alert evidence_sha256")
        _require_sha256(
            self.correlation_sha256,
            "critical-alert correlation_sha256",
        )
        _require_utc(self.detected_at, "critical-alert detected_at")
        _require_utc(self.recorded_at, "critical-alert recorded_at")
        if self.recorded_at < self.detected_at:
            raise CriticalAlertError("critical-alert recording cannot precede detection")
        _ = self.escalation_deadline

    @property
    def incident_id(self) -> str:
        return canonical_id(
            "critical-alert-incident",
            self.scope_id,
            self.source_id,
            self.idempotency_key,
        )

    @property
    def local_durability_delay_microseconds(self) -> int:
        return _timedelta_microseconds(self.recorded_at - self.detected_at)

    @property
    def local_durability_milestone_met(self) -> bool:
        return (
            self.local_durability_delay_microseconds <= CRITICAL_ALERT_LOCAL_DURABILITY_MICROSECONDS
        )

    @property
    def primary_deadline(self) -> datetime:
        return _deadline(
            self.recorded_at,
            CRITICAL_ALERT_PRIMARY_DEADLINE_MICROSECONDS,
        )

    @property
    def escalation_deadline(self) -> datetime:
        return _deadline(
            self.recorded_at,
            CRITICAL_ALERT_ESCALATION_DEADLINE_MICROSECONDS,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                CRITICAL_ALERT_CONTRACT_VERSION,
                "incident",
                self.scope_id,
                self.source_id,
                self.idempotency_key,
                self.alert_code,
                self.evidence_sha256,
                self.detected_at,
                self.recorded_at,
                self.correlation_sha256,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json.encode()).hexdigest()

    @property
    def requested_control_state(self) -> None:
        return None

    @property
    def broker_action_authorized(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class CriticalAlertDeliveryCommand:
    """Idempotent intent to claim one provider delivery attempt."""

    incident_id: str
    incident_sha256: str
    route: CriticalAlertRoute
    provider_id: str
    idempotency_key: str
    request_sha256: str
    requested_at: datetime

    def __post_init__(self) -> None:
        _require_text(self.incident_id, "critical-alert command incident ID")
        _require_sha256(
            self.incident_sha256,
            "critical-alert command incident_sha256",
        )
        if type(self.route) is not CriticalAlertRoute:
            raise CriticalAlertError("critical-alert delivery route is unsupported")
        _require_text(self.provider_id, "critical-alert delivery provider ID")
        _require_idempotency_key(
            self.idempotency_key,
            "critical-alert delivery idempotency key",
        )
        _require_sha256(
            self.request_sha256,
            "critical-alert delivery request_sha256",
        )
        _require_utc(self.requested_at, "critical-alert delivery requested_at")

    @property
    def attempt_id(self) -> str:
        return canonical_id(
            "critical-alert-delivery-attempt",
            self.incident_id,
            self.provider_id,
            self.idempotency_key,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                CRITICAL_ALERT_CONTRACT_VERSION,
                "delivery_command",
                self.incident_id,
                self.incident_sha256,
                self.route,
                self.provider_id,
                self.idempotency_key,
                self.request_sha256,
                self.requested_at,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class CriticalAlertDeliveryAttempt:
    """One immutable single-use claim in an incident-local attempt chain."""

    incident_id: str
    incident_sha256: str
    sequence_number: int
    previous_attempt_id: str | None
    previous_attempt_sha256: str | None
    route: CriticalAlertRoute
    provider_id: str
    idempotency_key: str
    request_sha256: str
    requested_at: datetime
    claimed_at: datetime
    command_sha256: str

    def __post_init__(self) -> None:
        _require_text(self.incident_id, "critical-alert attempt incident ID")
        _require_sha256(
            self.incident_sha256,
            "critical-alert attempt incident_sha256",
        )
        if type(self.sequence_number) is not int or not (
            1 <= self.sequence_number <= MAX_CRITICAL_ALERT_ATTEMPTS
        ):
            raise CriticalAlertError("critical-alert delivery sequence exceeds its bounded range")
        if self.sequence_number == 1:
            if self.previous_attempt_id is not None or self.previous_attempt_sha256 is not None:
                raise CriticalAlertError("first critical-alert attempt cannot have a predecessor")
        else:
            if self.previous_attempt_id is None:
                raise CriticalAlertError("later critical-alert attempt requires a predecessor ID")
            _require_text(
                self.previous_attempt_id,
                "critical-alert previous attempt ID",
            )
            if self.previous_attempt_sha256 is None:
                raise CriticalAlertError(
                    "later critical-alert attempt requires a predecessor digest"
                )
            _require_sha256(
                self.previous_attempt_sha256,
                "critical-alert previous attempt_sha256",
            )
        if type(self.route) is not CriticalAlertRoute:
            raise CriticalAlertError("critical-alert attempt route is unsupported")
        _require_text(self.provider_id, "critical-alert attempt provider ID")
        _require_idempotency_key(
            self.idempotency_key,
            "critical-alert attempt idempotency key",
        )
        _require_sha256(
            self.request_sha256,
            "critical-alert attempt request_sha256",
        )
        _require_utc(self.requested_at, "critical-alert attempt requested_at")
        _require_utc(self.claimed_at, "critical-alert attempt claimed_at")
        if self.claimed_at < self.requested_at:
            raise CriticalAlertError("critical-alert attempt claim cannot predate its request")
        _require_sha256(
            self.command_sha256,
            "critical-alert attempt command_sha256",
        )

    @property
    def attempt_id(self) -> str:
        return canonical_id(
            "critical-alert-delivery-attempt",
            self.incident_id,
            self.provider_id,
            self.idempotency_key,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                CRITICAL_ALERT_CONTRACT_VERSION,
                "delivery_attempt",
                self.incident_id,
                self.incident_sha256,
                self.sequence_number,
                self.previous_attempt_id,
                self.previous_attempt_sha256,
                self.route,
                self.provider_id,
                self.idempotency_key,
                self.request_sha256,
                self.requested_at,
                self.claimed_at,
                self.command_sha256,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class CriticalAlertDeliveryResult:
    """One immutable terminal observation for an already claimed attempt."""

    incident_id: str
    incident_sha256: str
    attempt_id: str
    attempt_sha256: str
    outcome: CriticalAlertDeliveryOutcome
    completed_at: datetime
    elapsed_microseconds: int
    provider_receipt_sha256: str | None
    failure_code: str | None

    def __post_init__(self) -> None:
        _require_text(self.incident_id, "critical-alert result incident ID")
        _require_sha256(
            self.incident_sha256,
            "critical-alert result incident_sha256",
        )
        _require_text(self.attempt_id, "critical-alert result attempt ID")
        _require_sha256(
            self.attempt_sha256,
            "critical-alert result attempt_sha256",
        )
        if type(self.outcome) is not CriticalAlertDeliveryOutcome:
            raise CriticalAlertError("critical-alert delivery outcome is unsupported")
        _require_utc(self.completed_at, "critical-alert delivery completed_at")
        if type(self.elapsed_microseconds) is not int or self.elapsed_microseconds < 0:
            raise CriticalAlertError(
                "critical-alert delivery elapsed_microseconds must be non-negative"
            )
        if self.outcome is CriticalAlertDeliveryOutcome.CONFIRMED:
            if self.provider_receipt_sha256 is None or self.failure_code is not None:
                raise CriticalAlertError(
                    "confirmed critical-alert delivery requires only a receipt digest"
                )
            _require_sha256(
                self.provider_receipt_sha256,
                "critical-alert provider receipt_sha256",
            )
        else:
            if self.provider_receipt_sha256 is not None or self.failure_code is None:
                raise CriticalAlertError(
                    "failed critical-alert delivery requires only a failure code"
                )
            _require_text(
                self.failure_code,
                "critical-alert delivery failure code",
            )

    @property
    def result_id(self) -> str:
        return canonical_id(
            "critical-alert-delivery-result",
            self.attempt_id,
        )

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(
            (
                CRITICAL_ALERT_CONTRACT_VERSION,
                "delivery_result",
                self.incident_id,
                self.incident_sha256,
                self.attempt_id,
                self.attempt_sha256,
                self.outcome,
                self.completed_at,
                self.elapsed_microseconds,
                self.provider_receipt_sha256,
                self.failure_code,
            )
        )

    @property
    def semantic_sha256(self) -> str:
        return hashlib.sha256(self.canonical_json.encode()).hexdigest()

    @property
    def confirmed(self) -> bool:
        return self.outcome is CriticalAlertDeliveryOutcome.CONFIRMED

    @property
    def requested_control_state(self) -> None:
        return None

    @property
    def broker_action_authorized(self) -> bool:
        return False


def create_critical_alert_incident(
    *,
    scope_id: str,
    source_id: str,
    idempotency_key: str,
    alert_code: str,
    evidence_sha256: str,
    detected_at: datetime,
    recorded_at: datetime,
    correlation_sha256: str,
) -> CriticalAlertIncident:
    return CriticalAlertIncident(
        scope_id=scope_id,
        source_id=source_id,
        idempotency_key=idempotency_key,
        alert_code=alert_code,
        evidence_sha256=evidence_sha256,
        detected_at=detected_at,
        recorded_at=recorded_at,
        correlation_sha256=correlation_sha256,
    )


def append_critical_alert_delivery_attempt(
    *,
    incident: CriticalAlertIncident,
    command: CriticalAlertDeliveryCommand,
    claimed_at: datetime,
    previous: CriticalAlertDeliveryAttempt | None,
) -> CriticalAlertDeliveryAttempt:
    if type(incident) is not CriticalAlertIncident:
        raise CriticalAlertError("critical-alert attempt requires an exact incident")
    if type(command) is not CriticalAlertDeliveryCommand:
        raise CriticalAlertError("critical-alert attempt requires an exact delivery command")
    if (
        command.incident_id != incident.incident_id
        or command.incident_sha256 != incident.semantic_sha256
    ):
        raise CriticalAlertConflict("critical-alert command crosses incident identities")
    if command.requested_at < incident.recorded_at:
        raise CriticalAlertConflict(
            "critical-alert delivery request predates durable incident creation"
        )
    _require_utc(claimed_at, "critical-alert attempt claimed_at")
    if previous is None:
        sequence_number = 1
        previous_attempt_id = None
        previous_attempt_sha256 = None
    else:
        if type(previous) is not CriticalAlertDeliveryAttempt:
            raise CriticalAlertError("critical-alert predecessor must be an exact delivery attempt")
        if (
            previous.incident_id != incident.incident_id
            or previous.incident_sha256 != incident.semantic_sha256
        ):
            raise CriticalAlertConflict("critical-alert predecessor crosses incident identities")
        if command.requested_at < previous.requested_at:
            raise CriticalAlertConflict("critical-alert attempt request time moved backwards")
        if claimed_at < previous.claimed_at:
            raise CriticalAlertConflict("critical-alert attempt claim time moved backwards")
        sequence_number = previous.sequence_number + 1
        previous_attempt_id = previous.attempt_id
        previous_attempt_sha256 = previous.semantic_sha256
    return CriticalAlertDeliveryAttempt(
        incident_id=incident.incident_id,
        incident_sha256=incident.semantic_sha256,
        sequence_number=sequence_number,
        previous_attempt_id=previous_attempt_id,
        previous_attempt_sha256=previous_attempt_sha256,
        route=command.route,
        provider_id=command.provider_id,
        idempotency_key=command.idempotency_key,
        request_sha256=command.request_sha256,
        requested_at=command.requested_at,
        claimed_at=claimed_at,
        command_sha256=command.semantic_sha256,
    )


def record_critical_alert_delivery_result(
    *,
    incident: CriticalAlertIncident,
    attempt: CriticalAlertDeliveryAttempt,
    outcome: CriticalAlertDeliveryOutcome,
    completed_at: datetime,
    elapsed_microseconds: int,
    provider_receipt_sha256: str | None = None,
    failure_code: str | None = None,
) -> CriticalAlertDeliveryResult:
    if type(incident) is not CriticalAlertIncident:
        raise CriticalAlertError("critical-alert result requires an exact incident")
    if type(attempt) is not CriticalAlertDeliveryAttempt:
        raise CriticalAlertError("critical-alert result requires an exact attempt")
    if (
        attempt.incident_id != incident.incident_id
        or attempt.incident_sha256 != incident.semantic_sha256
    ):
        raise CriticalAlertConflict("critical-alert result attempt crosses incident identities")
    _require_utc(completed_at, "critical-alert delivery completed_at")
    if completed_at < attempt.claimed_at:
        raise CriticalAlertConflict("critical-alert delivery completion predates its claim")
    return CriticalAlertDeliveryResult(
        incident_id=incident.incident_id,
        incident_sha256=incident.semantic_sha256,
        attempt_id=attempt.attempt_id,
        attempt_sha256=attempt.semantic_sha256,
        outcome=outcome,
        completed_at=completed_at,
        elapsed_microseconds=elapsed_microseconds,
        provider_receipt_sha256=provider_receipt_sha256,
        failure_code=failure_code,
    )


def critical_alert_delivery_deadline(
    incident: CriticalAlertIncident,
    route: CriticalAlertRoute,
) -> datetime:
    if type(incident) is not CriticalAlertIncident:
        raise CriticalAlertError("critical-alert deadline requires an exact incident")
    if route is CriticalAlertRoute.PRIMARY:
        return incident.primary_deadline
    if route is CriticalAlertRoute.ESCALATION:
        return incident.escalation_deadline
    raise CriticalAlertError("critical-alert deadline route is unsupported")


def critical_alert_delivery_milestone_met(
    *,
    incident: CriticalAlertIncident,
    attempt: CriticalAlertDeliveryAttempt,
    result: CriticalAlertDeliveryResult,
) -> bool:
    if (
        type(incident) is not CriticalAlertIncident
        or type(attempt) is not CriticalAlertDeliveryAttempt
        or type(result) is not CriticalAlertDeliveryResult
    ):
        raise CriticalAlertError("critical-alert milestone requires exact immutable facts")
    if (
        attempt.incident_id != incident.incident_id
        or attempt.incident_sha256 != incident.semantic_sha256
        or result.incident_id != incident.incident_id
        or result.incident_sha256 != incident.semantic_sha256
        or result.attempt_id != attempt.attempt_id
        or result.attempt_sha256 != attempt.semantic_sha256
    ):
        raise CriticalAlertConflict("critical-alert milestone facts cross immutable identities")
    deadline = critical_alert_delivery_deadline(incident, attempt.route)
    deadline_microseconds = _timedelta_microseconds(deadline - incident.recorded_at)
    return (
        result.outcome is CriticalAlertDeliveryOutcome.CONFIRMED
        and result.completed_at < deadline
        and result.elapsed_microseconds < deadline_microseconds
    )


def validate_critical_alert_delivery_history(
    *,
    incident: CriticalAlertIncident,
    attempts: tuple[CriticalAlertDeliveryAttempt, ...],
    results: tuple[CriticalAlertDeliveryResult, ...],
) -> None:
    if type(attempts) is not tuple or type(results) is not tuple:
        raise CriticalAlertError("critical-alert history must use immutable tuples")
    if len(attempts) > MAX_CRITICAL_ALERT_ATTEMPTS:
        raise CriticalAlertError("critical-alert attempt history exceeds its bound")
    previous: CriticalAlertDeliveryAttempt | None = None
    seen_attempt_ids: set[str] = set()
    seen_delivery_keys: set[tuple[str, str]] = set()
    for expected_sequence, attempt in enumerate(attempts, start=1):
        if type(attempt) is not CriticalAlertDeliveryAttempt:
            raise CriticalAlertError("critical-alert history contains a noncanonical attempt")
        if (
            attempt.incident_id != incident.incident_id
            or attempt.incident_sha256 != incident.semantic_sha256
            or attempt.sequence_number != expected_sequence
        ):
            raise CriticalAlertConflict(
                "critical-alert attempt history is not gap-free and incident-bound"
            )
        command = CriticalAlertDeliveryCommand(
            incident_id=attempt.incident_id,
            incident_sha256=attempt.incident_sha256,
            route=attempt.route,
            provider_id=attempt.provider_id,
            idempotency_key=attempt.idempotency_key,
            request_sha256=attempt.request_sha256,
            requested_at=attempt.requested_at,
        )
        if command.semantic_sha256 != attempt.command_sha256:
            raise CriticalAlertConflict("critical-alert attempt command digest is invalid")
        expected_previous = (
            (None, None) if previous is None else (previous.attempt_id, previous.semantic_sha256)
        )
        if (
            attempt.previous_attempt_id,
            attempt.previous_attempt_sha256,
        ) != expected_previous:
            raise CriticalAlertConflict("critical-alert attempt predecessor chain is invalid")
        if attempt.attempt_id in seen_attempt_ids:
            raise CriticalAlertConflict("critical-alert attempt identity is repeated")
        delivery_key = (attempt.provider_id, attempt.idempotency_key)
        if delivery_key in seen_delivery_keys:
            raise CriticalAlertConflict("critical-alert provider idempotency key is repeated")
        seen_attempt_ids.add(attempt.attempt_id)
        seen_delivery_keys.add(delivery_key)
        previous = attempt

    by_attempt_id = {attempt.attempt_id: attempt for attempt in attempts}
    seen_result_attempt_ids: set[str] = set()
    for result in results:
        if type(result) is not CriticalAlertDeliveryResult:
            raise CriticalAlertError("critical-alert history contains a noncanonical result")
        linked_attempt = by_attempt_id.get(result.attempt_id)
        if linked_attempt is None:
            raise CriticalAlertConflict("critical-alert result has no attempt in its history")
        if result.attempt_id in seen_result_attempt_ids:
            raise CriticalAlertConflict("critical-alert attempt has multiple terminal results")
        if (
            result.incident_id != incident.incident_id
            or result.incident_sha256 != incident.semantic_sha256
            or result.attempt_sha256 != linked_attempt.semantic_sha256
            or result.completed_at < linked_attempt.claimed_at
        ):
            raise CriticalAlertConflict(
                "critical-alert result conflicts with its immutable attempt"
            )
        seen_result_attempt_ids.add(result.attempt_id)
