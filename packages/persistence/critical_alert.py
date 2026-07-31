"""Durable append-only critical-alert incidents and delivery evidence."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from packages.domain.clock import Clock
from packages.domain.critical_alert import (
    MAX_CRITICAL_ALERT_SCAN_PAGE,
    CriticalAlertConflict,
    CriticalAlertDeliveryAttempt,
    CriticalAlertDeliveryCommand,
    CriticalAlertDeliveryOutcome,
    CriticalAlertDeliveryResult,
    CriticalAlertError,
    CriticalAlertIncident,
    CriticalAlertIncidentScanCursor,
    CriticalAlertIncidentScanPage,
    CriticalAlertRoute,
    append_critical_alert_delivery_attempt,
    critical_alert_delivery_milestone_met,
    validate_critical_alert_delivery_history,
)
from packages.persistence.account_coordinator import _write_transaction
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import as_aware_utc
from packages.persistence.schema import (
    phase5_critical_alert_delivery_attempts,
    phase5_critical_alert_delivery_results,
    phase5_critical_alert_incidents,
)

CriticalAlertRow = Mapping[str, object] | RowMapping
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})


@dataclass(frozen=True, slots=True)
class CriticalAlertHistory:
    incident: CriticalAlertIncident
    attempts: tuple[CriticalAlertDeliveryAttempt, ...]
    results: tuple[CriticalAlertDeliveryResult, ...]


def _required_text(row: CriticalAlertRow, field_name: str) -> str:
    value = row[field_name]
    if type(value) is not str:
        raise CriticalAlertError(f"persisted critical-alert {field_name} must be a string")
    return value


def _optional_text(row: CriticalAlertRow, field_name: str) -> str | None:
    value = row[field_name]
    if value is None:
        return None
    if type(value) is not str:
        raise CriticalAlertError(f"persisted critical-alert {field_name} must be a string or null")
    return value


def _required_integer(row: CriticalAlertRow, field_name: str) -> int:
    value = row[field_name]
    if type(value) is not int:
        raise CriticalAlertError(f"persisted critical-alert {field_name} must be an integer")
    return value


def _required_datetime(row: CriticalAlertRow, field_name: str) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise CriticalAlertError(f"persisted critical-alert {field_name} must be a datetime")
    return as_aware_utc(value)


def critical_alert_incident_values(
    incident: CriticalAlertIncident,
) -> dict[str, object]:
    if type(incident) is not CriticalAlertIncident:
        raise CriticalAlertError("critical-alert persistence requires an exact incident")
    return {
        "incident_id": incident.incident_id,
        "scope_id": incident.scope_id,
        "source_id": incident.source_id,
        "idempotency_key": incident.idempotency_key,
        "alert_code": incident.alert_code,
        "evidence_sha256": incident.evidence_sha256,
        "detected_at": incident.detected_at,
        "recorded_at": incident.recorded_at,
        "correlation_sha256": incident.correlation_sha256,
        "canonical_payload": incident.canonical_json,
        "semantic_sha256": incident.semantic_sha256,
    }


def critical_alert_incident_from_row(row: CriticalAlertRow) -> CriticalAlertIncident:
    try:
        incident = CriticalAlertIncident(
            scope_id=_required_text(row, "scope_id"),
            source_id=_required_text(row, "source_id"),
            idempotency_key=_required_text(row, "idempotency_key"),
            alert_code=_required_text(row, "alert_code"),
            evidence_sha256=_required_text(row, "evidence_sha256"),
            detected_at=_required_datetime(row, "detected_at"),
            recorded_at=_required_datetime(row, "recorded_at"),
            correlation_sha256=_required_text(row, "correlation_sha256"),
        )
        expected = critical_alert_incident_values(incident)
        for field_name in (
            "incident_id",
            "canonical_payload",
            "semantic_sha256",
        ):
            if row[field_name] != expected[field_name]:
                raise CriticalAlertConflict(
                    f"persisted critical-alert incident {field_name} conflicts"
                )
        return incident
    except CriticalAlertError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise CriticalAlertError("persisted critical-alert incident is malformed") from error


def critical_alert_attempt_values(
    attempt: CriticalAlertDeliveryAttempt,
) -> dict[str, object]:
    if type(attempt) is not CriticalAlertDeliveryAttempt:
        raise CriticalAlertError("critical-alert persistence requires an exact attempt")
    return {
        "attempt_id": attempt.attempt_id,
        "incident_id": attempt.incident_id,
        "incident_sha256": attempt.incident_sha256,
        "sequence_number": attempt.sequence_number,
        "previous_attempt_id": attempt.previous_attempt_id,
        "previous_attempt_sha256": attempt.previous_attempt_sha256,
        "route": attempt.route.value,
        "provider_id": attempt.provider_id,
        "idempotency_key": attempt.idempotency_key,
        "request_sha256": attempt.request_sha256,
        "requested_at": attempt.requested_at,
        "claimed_at": attempt.claimed_at,
        "command_sha256": attempt.command_sha256,
        "canonical_payload": attempt.canonical_json,
        "semantic_sha256": attempt.semantic_sha256,
    }


def critical_alert_attempt_from_row(
    row: CriticalAlertRow,
) -> CriticalAlertDeliveryAttempt:
    try:
        attempt = CriticalAlertDeliveryAttempt(
            incident_id=_required_text(row, "incident_id"),
            incident_sha256=_required_text(row, "incident_sha256"),
            sequence_number=_required_integer(row, "sequence_number"),
            previous_attempt_id=_optional_text(row, "previous_attempt_id"),
            previous_attempt_sha256=_optional_text(
                row,
                "previous_attempt_sha256",
            ),
            route=CriticalAlertRoute(_required_text(row, "route")),
            provider_id=_required_text(row, "provider_id"),
            idempotency_key=_required_text(row, "idempotency_key"),
            request_sha256=_required_text(row, "request_sha256"),
            requested_at=_required_datetime(row, "requested_at"),
            claimed_at=_required_datetime(row, "claimed_at"),
            command_sha256=_required_text(row, "command_sha256"),
        )
        expected = critical_alert_attempt_values(attempt)
        for field_name in (
            "attempt_id",
            "canonical_payload",
            "semantic_sha256",
        ):
            if row[field_name] != expected[field_name]:
                raise CriticalAlertConflict(
                    f"persisted critical-alert attempt {field_name} conflicts"
                )
        return attempt
    except CriticalAlertError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise CriticalAlertError("persisted critical-alert attempt is malformed") from error


def critical_alert_result_values(
    result: CriticalAlertDeliveryResult,
) -> dict[str, object]:
    if type(result) is not CriticalAlertDeliveryResult:
        raise CriticalAlertError("critical-alert persistence requires an exact delivery result")
    return {
        "result_id": result.result_id,
        "incident_id": result.incident_id,
        "incident_sha256": result.incident_sha256,
        "attempt_id": result.attempt_id,
        "attempt_sha256": result.attempt_sha256,
        "outcome": result.outcome.value,
        "completed_at": result.completed_at,
        "elapsed_microseconds": result.elapsed_microseconds,
        "provider_receipt_sha256": result.provider_receipt_sha256,
        "failure_code": result.failure_code,
        "canonical_payload": result.canonical_json,
        "semantic_sha256": result.semantic_sha256,
    }


def critical_alert_result_from_row(
    row: CriticalAlertRow,
) -> CriticalAlertDeliveryResult:
    try:
        result = CriticalAlertDeliveryResult(
            incident_id=_required_text(row, "incident_id"),
            incident_sha256=_required_text(row, "incident_sha256"),
            attempt_id=_required_text(row, "attempt_id"),
            attempt_sha256=_required_text(row, "attempt_sha256"),
            outcome=CriticalAlertDeliveryOutcome(_required_text(row, "outcome")),
            completed_at=_required_datetime(row, "completed_at"),
            elapsed_microseconds=_required_integer(row, "elapsed_microseconds"),
            provider_receipt_sha256=_optional_text(
                row,
                "provider_receipt_sha256",
            ),
            failure_code=_optional_text(row, "failure_code"),
        )
        expected = critical_alert_result_values(result)
        for field_name in (
            "result_id",
            "canonical_payload",
            "semantic_sha256",
        ):
            if row[field_name] != expected[field_name]:
                raise CriticalAlertConflict(
                    f"persisted critical-alert result {field_name} conflicts"
                )
        return result
    except CriticalAlertError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise CriticalAlertError("persisted critical-alert delivery result is malformed") from error


def _incident_statement(
    incident_id: str,
    *,
    for_update: bool,
) -> sa.Select[tuple[object, ...]]:
    statement = sa.select(phase5_critical_alert_incidents).where(
        phase5_critical_alert_incidents.c.incident_id == incident_id
    )
    if for_update:
        statement = statement.with_for_update()
    return statement


def _load_incident(
    connection: Connection,
    incident_id: str,
    *,
    for_update: bool = False,
) -> CriticalAlertIncident | None:
    row = (
        connection.execute(_incident_statement(incident_id, for_update=for_update))
        .mappings()
        .one_or_none()
    )
    return None if row is None else critical_alert_incident_from_row(row)


def _load_attempts(
    connection: Connection,
    incident_id: str,
) -> tuple[CriticalAlertDeliveryAttempt, ...]:
    rows = connection.execute(
        sa.select(phase5_critical_alert_delivery_attempts)
        .where(phase5_critical_alert_delivery_attempts.c.incident_id == incident_id)
        .order_by(
            phase5_critical_alert_delivery_attempts.c.sequence_number,
        )
    ).mappings()
    return tuple(critical_alert_attempt_from_row(row) for row in rows)


def _load_results(
    connection: Connection,
    incident_id: str,
) -> tuple[CriticalAlertDeliveryResult, ...]:
    rows = connection.execute(
        sa.select(phase5_critical_alert_delivery_results)
        .where(phase5_critical_alert_delivery_results.c.incident_id == incident_id)
        .order_by(
            phase5_critical_alert_delivery_results.c.completed_at,
            phase5_critical_alert_delivery_results.c.result_id,
        )
    ).mappings()
    return tuple(critical_alert_result_from_row(row) for row in rows)


def _load_history(
    connection: Connection,
    incident_id: str,
    *,
    for_update: bool = False,
) -> CriticalAlertHistory:
    incident = _load_incident(
        connection,
        incident_id,
        for_update=for_update,
    )
    if incident is None:
        raise CriticalAlertError(f"critical-alert incident {incident_id!r} does not exist")
    attempts = _load_attempts(connection, incident_id)
    results = _load_results(connection, incident_id)
    validate_critical_alert_delivery_history(
        incident=incident,
        attempts=attempts,
        results=results,
    )
    return CriticalAlertHistory(
        incident=incident,
        attempts=attempts,
        results=results,
    )


def load_critical_alert_history_in_transaction(
    connection: Connection,
    incident_id: str,
    *,
    for_update: bool = False,
) -> CriticalAlertHistory:
    """Authenticate one complete incident history in a caller-owned transaction."""

    if not isinstance(connection, Connection) or not connection.in_transaction():
        raise CriticalAlertError(
            "transactional critical-alert history load requires an active Connection"
        )
    if connection.dialect.name not in _SUPPORTED_DIALECTS:
        raise CriticalAlertError(
            "transactional critical-alert history load does not support "
            f"{connection.dialect.name!r}"
        )
    if type(incident_id) is not str or not incident_id or incident_id != incident_id.strip():
        raise CriticalAlertError(
            "transactional critical-alert incident ID must be non-empty and trimmed"
        )
    if type(for_update) is not bool:
        raise CriticalAlertError("transactional critical-alert history lock flag must be boolean")
    return _load_history(
        connection,
        incident_id,
        for_update=for_update,
    )


def _require_trusted_time(value: datetime) -> None:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise CriticalAlertError("critical-alert repository clock must return UTC")


def _verify_critical_alert_integrity(connection: Connection) -> None:
    incident_rows = connection.execute(
        sa.select(phase5_critical_alert_incidents).order_by(
            phase5_critical_alert_incidents.c.incident_id
        )
    ).mappings()
    incidents = tuple(critical_alert_incident_from_row(row) for row in incident_rows)
    attempt_rows = connection.execute(
        sa.select(phase5_critical_alert_delivery_attempts).order_by(
            phase5_critical_alert_delivery_attempts.c.incident_id,
            phase5_critical_alert_delivery_attempts.c.sequence_number,
        )
    ).mappings()
    attempts = tuple(critical_alert_attempt_from_row(row) for row in attempt_rows)
    result_rows = connection.execute(
        sa.select(phase5_critical_alert_delivery_results).order_by(
            phase5_critical_alert_delivery_results.c.incident_id,
            phase5_critical_alert_delivery_results.c.completed_at,
            phase5_critical_alert_delivery_results.c.result_id,
        )
    ).mappings()
    results = tuple(critical_alert_result_from_row(row) for row in result_rows)

    incident_ids = {incident.incident_id for incident in incidents}
    if any(attempt.incident_id not in incident_ids for attempt in attempts):
        raise CriticalAlertConflict(
            "critical-alert persistence contains an orphan delivery attempt"
        )
    if any(result.incident_id not in incident_ids for result in results):
        raise CriticalAlertConflict("critical-alert persistence contains an orphan delivery result")
    for incident in incidents:
        validate_critical_alert_delivery_history(
            incident=incident,
            attempts=tuple(
                attempt for attempt in attempts if attempt.incident_id == incident.incident_id
            ),
            results=tuple(
                result for result in results if result.incident_id == incident.incident_id
            ),
        )


def verify_critical_alert_integrity(engine: Engine) -> None:
    """Authenticate every incident, append-only chain, and terminal result."""

    if not isinstance(engine, Engine):
        raise CriticalAlertError("critical-alert integrity verification requires an Engine")
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise CriticalAlertError(
            f"critical-alert persistence does not support {engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_critical_alert_integrity(connection)


def record_critical_alert_incident_in_transaction(
    connection: Connection,
    incident: CriticalAlertIncident,
    *,
    recorded_at: datetime,
) -> CriticalAlertIncident:
    """Record one incident inside a caller-owned effect transaction."""

    if not isinstance(connection, Connection) or not connection.in_transaction():
        raise CriticalAlertError(
            "transactional critical-alert recording requires an active Connection"
        )
    if connection.dialect.name not in _SUPPORTED_DIALECTS:
        raise CriticalAlertError(
            f"transactional critical-alert recording does not support {connection.dialect.name!r}"
        )
    if type(incident) is not CriticalAlertIncident:
        raise CriticalAlertError(
            "transactional critical-alert recording requires an exact incident"
        )
    _require_trusted_time(recorded_at)
    existing_row = (
        connection.execute(
            sa.select(phase5_critical_alert_incidents).where(
                phase5_critical_alert_incidents.c.scope_id == incident.scope_id,
                phase5_critical_alert_incidents.c.source_id == incident.source_id,
                phase5_critical_alert_incidents.c.idempotency_key == incident.idempotency_key,
            )
        )
        .mappings()
        .one_or_none()
    )
    if existing_row is not None:
        existing = critical_alert_incident_from_row(existing_row)
        if existing != incident:
            raise CriticalAlertConflict("critical-alert incident idempotency key conflicts")
        return existing
    if recorded_at != incident.recorded_at:
        raise CriticalAlertConflict("critical-alert incident is not bound to repository time")
    try:
        connection.execute(
            sa.insert(phase5_critical_alert_incidents).values(
                **critical_alert_incident_values(incident)
            )
        )
    except IntegrityError as error:
        raise CriticalAlertConflict(
            "critical-alert incident conflicts with durable history"
        ) from error
    persisted = _load_incident(connection, incident.incident_id)
    if persisted != incident:
        raise CriticalAlertError("critical-alert incident failed exact SQL readback")
    return persisted


class SqlCriticalAlertRepository:
    """Persist source-idempotent incidents and single-use delivery attempts."""

    __slots__ = ("_clock", "_engine")

    def __init__(self, *, engine: Engine, clock: Clock) -> None:
        if not isinstance(engine, Engine):
            raise CriticalAlertError("critical-alert repository requires an Engine")
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise CriticalAlertError(
                f"critical-alert persistence does not support {engine.dialect.name!r}"
            )
        if not callable(getattr(clock, "now", None)):
            raise CriticalAlertError("critical-alert repository requires a trusted clock")
        self._engine = engine
        self._clock = clock

    @property
    def runtime_store_identity(self) -> int:
        """Return the positive process-local identity of the durable store."""

        return id(self._engine)

    def record_incident(
        self,
        incident: CriticalAlertIncident,
    ) -> CriticalAlertIncident:
        if type(incident) is not CriticalAlertIncident:
            raise CriticalAlertError("critical-alert recording requires an exact incident")
        with _write_transaction(self._engine) as connection:
            recorded_at = self._clock.now()
            _require_trusted_time(recorded_at)
            return record_critical_alert_incident_in_transaction(
                connection,
                incident,
                recorded_at=recorded_at,
            )

    def load_incident(self, incident_id: str) -> CriticalAlertIncident:
        with _repeatable_read_transaction(self._engine) as connection:
            incident = _load_incident(connection, incident_id)
            if incident is None:
                raise CriticalAlertError(f"critical-alert incident {incident_id!r} does not exist")
            return incident

    def scan_active_incidents(
        self,
        *,
        as_of: datetime,
        after: CriticalAlertIncidentScanCursor | None,
        limit: int,
    ) -> CriticalAlertIncidentScanPage:
        """Return one cursor-bounded page with no in-budget confirmation.

        The SQL segment is limited before histories are decoded.  A caller must
        resume from ``resume_after`` until it is absent; this prevents a prefix
        of already delivered incidents from starving later active work.
        """

        _require_trusted_time(as_of)
        if after is not None and type(after) is not CriticalAlertIncidentScanCursor:
            raise CriticalAlertError("critical-alert scan cursor must be exact")
        if after is not None and after.recorded_at > as_of:
            raise CriticalAlertError("critical-alert scan cursor is later than as_of")
        if type(limit) is not int or not 1 <= limit <= MAX_CRITICAL_ALERT_SCAN_PAGE:
            raise CriticalAlertError("critical-alert scan limit exceeds its bounded range")

        with _repeatable_read_transaction(self._engine) as connection:
            statement = sa.select(phase5_critical_alert_incidents).where(
                phase5_critical_alert_incidents.c.recorded_at <= as_of
            )
            if after is not None:
                statement = statement.where(
                    sa.or_(
                        phase5_critical_alert_incidents.c.recorded_at > after.recorded_at,
                        sa.and_(
                            phase5_critical_alert_incidents.c.recorded_at == after.recorded_at,
                            phase5_critical_alert_incidents.c.incident_id > after.incident_id,
                        ),
                    )
                )
            rows = tuple(
                connection.execute(
                    statement.order_by(
                        phase5_critical_alert_incidents.c.recorded_at,
                        phase5_critical_alert_incidents.c.incident_id,
                    ).limit(limit + 1)
                ).mappings()
            )
            scanned_rows = rows[:limit]
            active: list[CriticalAlertIncident] = []
            for row in scanned_rows:
                incident = critical_alert_incident_from_row(row)
                attempts = _load_attempts(connection, incident.incident_id)
                results = _load_results(connection, incident.incident_id)
                validate_critical_alert_delivery_history(
                    incident=incident,
                    attempts=attempts,
                    results=results,
                )
                result_by_attempt = {result.attempt_id: result for result in results}
                delivered = any(
                    critical_alert_delivery_milestone_met(
                        incident=incident,
                        attempt=attempt,
                        result=result,
                    )
                    for attempt in attempts
                    if (result := result_by_attempt.get(attempt.attempt_id)) is not None
                )
                if not delivered:
                    active.append(incident)

            resume_after: CriticalAlertIncidentScanCursor | None = None
            if len(rows) > limit:
                last = critical_alert_incident_from_row(scanned_rows[-1])
                resume_after = CriticalAlertIncidentScanCursor(
                    recorded_at=last.recorded_at,
                    incident_id=last.incident_id,
                )
            return CriticalAlertIncidentScanPage(
                incidents=tuple(active),
                scanned_count=len(scanned_rows),
                resume_after=resume_after,
            )

    def find_delivery_attempt(
        self,
        *,
        incident_id: str,
        provider_id: str,
        idempotency_key: str,
    ) -> CriticalAlertDeliveryAttempt | None:
        history = self._history(incident_id)
        for attempt in history.attempts:
            if attempt.provider_id == provider_id and attempt.idempotency_key == idempotency_key:
                return attempt
        return None

    def claim_delivery_attempt(
        self,
        command: CriticalAlertDeliveryCommand,
    ) -> tuple[CriticalAlertDeliveryAttempt, bool]:
        if type(command) is not CriticalAlertDeliveryCommand:
            raise CriticalAlertError("critical-alert claim requires an exact delivery command")
        with _write_transaction(self._engine) as connection:
            history = _load_history(
                connection,
                command.incident_id,
                for_update=True,
            )
            if command.incident_sha256 != history.incident.semantic_sha256:
                raise CriticalAlertConflict("critical-alert command has the wrong incident digest")
            for existing in history.attempts:
                if (
                    existing.provider_id == command.provider_id
                    and existing.idempotency_key == command.idempotency_key
                ):
                    if (
                        existing.attempt_id != command.attempt_id
                        or existing.route is not command.route
                        or existing.request_sha256 != command.request_sha256
                    ):
                        raise CriticalAlertConflict(
                            "critical-alert delivery idempotency key conflicts"
                        )
                    # requested_at records the winning claim. A concurrent loser
                    # may have sampled trusted time later, but the provider request
                    # identity is unchanged and must converge on the same attempt.
                    return existing, False
            claimed_at = self._clock.now()
            _require_trusted_time(claimed_at)
            previous = history.attempts[-1] if history.attempts else None
            attempt = append_critical_alert_delivery_attempt(
                incident=history.incident,
                command=command,
                claimed_at=claimed_at,
                previous=previous,
            )
            try:
                connection.execute(
                    sa.insert(phase5_critical_alert_delivery_attempts).values(
                        **critical_alert_attempt_values(attempt)
                    )
                )
            except IntegrityError as error:
                raise CriticalAlertConflict(
                    "critical-alert delivery attempt conflicts with durable history"
                ) from error
            return attempt, True

    def load_delivery_result(
        self,
        attempt_id: str,
    ) -> CriticalAlertDeliveryResult | None:
        with _repeatable_read_transaction(self._engine) as connection:
            attempt_row = (
                connection.execute(
                    sa.select(phase5_critical_alert_delivery_attempts).where(
                        phase5_critical_alert_delivery_attempts.c.attempt_id == attempt_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if attempt_row is None:
                raise CriticalAlertError(f"critical-alert attempt {attempt_id!r} does not exist")
            attempt = critical_alert_attempt_from_row(attempt_row)
            history = _load_history(connection, attempt.incident_id)
            return next(
                (result for result in history.results if result.attempt_id == attempt_id),
                None,
            )

    def load_delivery_history(
        self,
        incident_id: str,
    ) -> tuple[
        tuple[CriticalAlertDeliveryAttempt, ...],
        tuple[CriticalAlertDeliveryResult, ...],
    ]:
        history = self._history(incident_id)
        return history.attempts, history.results

    def record_delivery_result(
        self,
        result: CriticalAlertDeliveryResult,
    ) -> CriticalAlertDeliveryResult:
        if type(result) is not CriticalAlertDeliveryResult:
            raise CriticalAlertError("critical-alert result recording requires an exact result")
        with _write_transaction(self._engine) as connection:
            history = _load_history(
                connection,
                result.incident_id,
                for_update=True,
            )
            attempt = next(
                (item for item in history.attempts if item.attempt_id == result.attempt_id),
                None,
            )
            if attempt is None:
                raise CriticalAlertConflict("critical-alert result has no durable attempt")
            existing = next(
                (item for item in history.results if item.attempt_id == result.attempt_id),
                None,
            )
            if existing is not None:
                if existing != result:
                    raise CriticalAlertConflict("critical-alert attempt result conflicts")
                return existing
            validate_critical_alert_delivery_history(
                incident=history.incident,
                attempts=history.attempts,
                results=(*history.results, result),
            )
            observed_at = self._clock.now()
            _require_trusted_time(observed_at)
            if result.completed_at > observed_at:
                raise CriticalAlertConflict(
                    "critical-alert result completion is in the repository future"
                )
            try:
                connection.execute(
                    sa.insert(phase5_critical_alert_delivery_results).values(
                        **critical_alert_result_values(result)
                    )
                )
            except IntegrityError as error:
                raise CriticalAlertConflict(
                    "critical-alert delivery result conflicts with durable history"
                ) from error
            return result

    def _history(self, incident_id: str) -> CriticalAlertHistory:
        with _repeatable_read_transaction(self._engine) as connection:
            return _load_history(connection, incident_id)
