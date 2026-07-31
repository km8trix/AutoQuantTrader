"""Atomic local critical-alert failure receipts and operational-control trips."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError

from packages.application.critical_alert_supervisor import (
    CriticalAlertRouteBinding,
    CriticalAlertRoutePlan,
    CriticalAlertSupervisorDisposition,
    CriticalAlertSupervisorEvidence,
    CriticalAlertSupervisorReason,
)
from packages.application.critical_alert_supervisor_failure_control import (
    CRITICAL_ALERT_FAILURE_CONTROL_POLICY_SHA256,
    CRITICAL_ALERT_FAILURE_CONTROL_SYSTEM_ACTOR_ID,
    CriticalAlertFailureControlError,
    CriticalAlertFailureControlReceipt,
    bind_critical_alert_failure_control_receipt,
)
from packages.domain.account_coordinator import AccountCoordinatorError
from packages.domain.clock import Clock
from packages.domain.critical_alert import CriticalAlertError, CriticalAlertRoute
from packages.domain.operational_control import (
    OperationalControlActorKind,
    OperationalControlError,
)
from packages.persistence.account_coordinator import (
    _write_transaction,
    lock_account_capacity_serialization,
)
from packages.persistence.critical_alert import (
    CriticalAlertHistory,
    load_critical_alert_history_in_transaction,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import (
    ImmutableFactConflict,
    as_aware_utc,
    assert_immutable,
)
from packages.persistence.operational_control import (
    _critical_alert_failure_control_append_authority,
    apply_operational_control_command_in_transaction,
    load_operational_control_head_in_transaction,
    load_operational_control_transition_in_transaction,
)
from packages.persistence.schema import (
    phase5_critical_alert_failure_control_receipts,
    phase5_operational_control_transitions,
)

CriticalAlertFailureControlRow = Mapping[str, object] | RowMapping
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})


class CriticalAlertFailureControlPersistenceError(RuntimeError):
    """The durable failure-control composition is unavailable or corrupt."""


class CriticalAlertFailureControlPersistenceConflict(CriticalAlertFailureControlPersistenceError):
    """An immutable source identity is reused with changed semantics."""


def _required_text(row: CriticalAlertFailureControlRow, field_name: str) -> str:
    value = row[field_name]
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise CriticalAlertFailureControlPersistenceConflict(
            f"persisted critical-alert failure-control {field_name} must be non-empty trimmed text"
        )
    return value


def _optional_text(
    row: CriticalAlertFailureControlRow,
    field_name: str,
) -> str | None:
    return None if row[field_name] is None else _required_text(row, field_name)


def _required_bool(row: CriticalAlertFailureControlRow, field_name: str) -> bool:
    value = row[field_name]
    if type(value) is not bool:
        raise CriticalAlertFailureControlPersistenceConflict(
            f"persisted critical-alert failure-control {field_name} must be an exact boolean"
        )
    return value


def _required_datetime(
    row: CriticalAlertFailureControlRow,
    field_name: str,
) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise CriticalAlertFailureControlPersistenceConflict(
            f"persisted critical-alert failure-control {field_name} must be a datetime"
        )
    return as_aware_utc(value)


def _require_account_id(value: str) -> None:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > 64
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise CriticalAlertFailureControlPersistenceError(
            "critical-alert failure-control account ID must be bounded, non-empty trimmed text"
        )


def _require_sha256(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CriticalAlertFailureControlPersistenceError(
            f"{field_name} must be a lowercase SHA-256 digest"
        )


def _require_utc(value: datetime, field_name: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise CriticalAlertFailureControlPersistenceError(f"{field_name} must be UTC")
    return value


def _route_plan_from_row(
    row: CriticalAlertFailureControlRow,
) -> CriticalAlertRoutePlan:
    route_plan = CriticalAlertRoutePlan(
        plan_id=_required_text(row, "route_plan_id"),
        plan_version=_required_text(row, "route_plan_version"),
        primary=CriticalAlertRouteBinding(
            route=CriticalAlertRoute.PRIMARY,
            provider_id=_required_text(row, "primary_provider_id"),
            destination_sha256=_required_text(
                row,
                "primary_destination_sha256",
            ),
            recipient_set_sha256=_required_text(
                row,
                "primary_recipient_set_sha256",
            ),
        ),
        escalation=CriticalAlertRouteBinding(
            route=CriticalAlertRoute.ESCALATION,
            provider_id=_required_text(row, "escalation_provider_id"),
            destination_sha256=_required_text(
                row,
                "escalation_destination_sha256",
            ),
            recipient_set_sha256=_required_text(
                row,
                "escalation_recipient_set_sha256",
            ),
        ),
    )
    if route_plan.semantic_sha256 != _required_text(row, "route_plan_sha256"):
        raise CriticalAlertFailureControlPersistenceConflict(
            "persisted critical-alert failure-control route-plan digest conflicts"
        )
    return route_plan


def _evidence_from_row(
    row: CriticalAlertFailureControlRow,
) -> CriticalAlertSupervisorEvidence:
    try:
        evidence = CriticalAlertSupervisorEvidence(
            incident_id=_required_text(row, "incident_id"),
            incident_sha256=_required_text(row, "incident_sha256"),
            route_plan_sha256=_required_text(row, "route_plan_sha256"),
            disposition=CriticalAlertSupervisorDisposition(
                _required_text(row, "supervisor_disposition")
            ),
            reason=CriticalAlertSupervisorReason(_required_text(row, "supervisor_reason")),
            observed_at=_required_datetime(row, "observed_at"),
            selected_route=CriticalAlertRoute(_required_text(row, "selected_route")),
            attempt_id=_required_text(row, "attempt_id"),
            attempt_sha256=_required_text(row, "attempt_sha256"),
            result_id=_optional_text(row, "result_id"),
            result_sha256=_optional_text(row, "result_sha256"),
            wait_until=None,
            provider_called=_required_bool(row, "provider_called"),
            unresolved_claim=_required_bool(row, "unresolved_claim"),
        )
    except ValueError as error:
        raise CriticalAlertFailureControlPersistenceConflict(
            "persisted critical-alert failure-control evidence contains an unsupported enum"
        ) from error
    if evidence.semantic_sha256 != _required_text(
        row,
        "supervisor_evidence_sha256",
    ):
        raise CriticalAlertFailureControlPersistenceConflict(
            "persisted critical-alert failure-control supervisor digest conflicts"
        )
    return evidence


def critical_alert_failure_control_receipt_values(
    receipt: CriticalAlertFailureControlReceipt,
) -> dict[str, object]:
    """Flatten an authenticated receipt into immutable SQL values."""

    if type(receipt) is not CriticalAlertFailureControlReceipt:
        raise CriticalAlertFailureControlPersistenceError(
            "critical-alert failure-control persistence requires an exact receipt"
        )
    receipt.__post_init__()
    plan = receipt.route_plan
    evidence = receipt.evidence
    return {
        "receipt_id": receipt.receipt_id,
        "account_id": receipt.incident.scope_id,
        "incident_id": receipt.incident.incident_id,
        "incident_sha256": receipt.incident.semantic_sha256,
        "route_plan_id": plan.plan_id,
        "route_plan_version": plan.plan_version,
        "route_plan_sha256": plan.semantic_sha256,
        "primary_provider_id": plan.primary.provider_id,
        "primary_destination_sha256": plan.primary.destination_sha256,
        "primary_recipient_set_sha256": plan.primary.recipient_set_sha256,
        "escalation_provider_id": plan.escalation.provider_id,
        "escalation_destination_sha256": plan.escalation.destination_sha256,
        "escalation_recipient_set_sha256": plan.escalation.recipient_set_sha256,
        "supervisor_evidence_sha256": evidence.semantic_sha256,
        "supervisor_disposition": evidence.disposition.value,
        "supervisor_reason": evidence.reason.value,
        "observed_at": evidence.observed_at,
        "selected_route": evidence.selected_route.value,
        "attempt_id": evidence.attempt_id,
        "attempt_sha256": evidence.attempt_sha256,
        "result_id": evidence.result_id,
        "result_sha256": evidence.result_sha256,
        "provider_called": evidence.provider_called,
        "unresolved_claim": evidence.unresolved_claim,
        "actor_authority_sha256": receipt.command.actor.authority_sha256,
        "control_policy_sha256": CRITICAL_ALERT_FAILURE_CONTROL_POLICY_SHA256,
        "control_command_id": receipt.command.command_id,
        "control_command_sha256": receipt.command.semantic_sha256,
        "pre_control_transition_id": receipt.pre_control.transition_id,
        "pre_control_transition_sha256": receipt.pre_control.semantic_sha256,
        "pre_control_state": receipt.pre_control.effective_state.value,
        "final_control_transition_id": receipt.final_control.transition_id,
        "final_control_transition_sha256": receipt.final_control.semantic_sha256,
        "final_control_state": receipt.final_control.effective_state.value,
        "bound_at": receipt.bound_at,
        "canonical_payload": receipt.canonical_json,
        "semantic_sha256": receipt.semantic_sha256,
    }


def _receipt_statement(
    incident_id: str,
    *,
    for_update: bool,
) -> sa.Select[tuple[object, ...]]:
    statement = sa.select(phase5_critical_alert_failure_control_receipts).where(
        phase5_critical_alert_failure_control_receipts.c.incident_id == incident_id
    )
    return statement.with_for_update() if for_update else statement


def _receipt_from_row(
    connection: Connection,
    row: CriticalAlertFailureControlRow,
    *,
    history: CriticalAlertHistory | None = None,
) -> CriticalAlertFailureControlReceipt:
    try:
        incident_id = _required_text(row, "incident_id")
        durable_history = (
            load_critical_alert_history_in_transaction(connection, incident_id)
            if history is None
            else history
        )
        if durable_history.incident.incident_id != incident_id:
            raise CriticalAlertFailureControlPersistenceConflict(
                "persisted critical-alert failure-control history identity conflicts"
            )
        plan = _route_plan_from_row(row)
        evidence = _evidence_from_row(row)
        account_id = _required_text(row, "account_id")
        pre_control = load_operational_control_transition_in_transaction(
            connection,
            account_id,
            _required_text(row, "pre_control_transition_id"),
        )
        final_control = load_operational_control_transition_in_transaction(
            connection,
            account_id,
            _required_text(row, "final_control_transition_id"),
        )
        if pre_control is None or final_control is None:
            raise CriticalAlertFailureControlPersistenceConflict(
                "persisted critical-alert failure-control receipt references "
                "missing control history"
            )
        receipt = bind_critical_alert_failure_control_receipt(
            incident=durable_history.incident,
            route_plan=plan,
            attempts=durable_history.attempts,
            results=durable_history.results,
            evidence=evidence,
            pre_control=pre_control,
            actor_authority_sha256=_required_text(row, "actor_authority_sha256"),
            bound_at=_required_datetime(row, "bound_at"),
        )
        if receipt.final_control != final_control:
            raise CriticalAlertFailureControlPersistenceConflict(
                "persisted critical-alert failure-control final transition conflicts"
            )
        try:
            assert_immutable(
                phase5_critical_alert_failure_control_receipts,
                receipt.receipt_id,
                row,
                critical_alert_failure_control_receipt_values(receipt),
            )
        except ImmutableFactConflict as error:
            raise CriticalAlertFailureControlPersistenceConflict(
                "persisted critical-alert failure-control receipt conflicts"
            ) from error
        return receipt
    except CriticalAlertFailureControlPersistenceError:
        raise
    except (
        CriticalAlertError,
        CriticalAlertFailureControlError,
        OperationalControlError,
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise CriticalAlertFailureControlPersistenceError(
            "persisted critical-alert failure-control receipt is malformed"
        ) from error


def load_critical_alert_failure_control_receipt_in_transaction(
    connection: Connection,
    incident_id: str,
    *,
    for_update: bool = False,
) -> CriticalAlertFailureControlReceipt | None:
    """Authenticate one receipt inside the caller-owned transaction."""

    if not isinstance(connection, Connection) or not connection.in_transaction():
        raise CriticalAlertFailureControlPersistenceError(
            "transactional failure-control load requires an active Connection"
        )
    if connection.dialect.name not in _SUPPORTED_DIALECTS:
        raise CriticalAlertFailureControlPersistenceError(
            "transactional failure-control load uses an unsupported SQL dialect"
        )
    if type(incident_id) is not str or not incident_id or incident_id != incident_id.strip():
        raise CriticalAlertFailureControlPersistenceError(
            "failure-control incident ID must be non-empty trimmed text"
        )
    if type(for_update) is not bool:
        raise CriticalAlertFailureControlPersistenceError(
            "failure-control lock flag must be boolean"
        )
    row = (
        connection.execute(_receipt_statement(incident_id, for_update=for_update))
        .mappings()
        .one_or_none()
    )
    return None if row is None else _receipt_from_row(connection, row)


def bind_critical_alert_failure_control_in_transaction(
    connection: Connection,
    *,
    account_id: str,
    route_plan: CriticalAlertRoutePlan,
    evidence: CriticalAlertSupervisorEvidence,
    actor_authority_sha256: str,
    bound_at: datetime,
) -> CriticalAlertFailureControlReceipt:
    """Atomically append a severity-preserving trip and its source receipt."""

    if not isinstance(connection, Connection) or not connection.in_transaction():
        raise CriticalAlertFailureControlPersistenceError(
            "failure-control binding requires an active transaction"
        )
    if connection.dialect.name not in _SUPPORTED_DIALECTS:
        raise CriticalAlertFailureControlPersistenceError(
            "failure-control binding uses an unsupported SQL dialect"
        )
    _require_account_id(account_id)
    if type(route_plan) is not CriticalAlertRoutePlan:
        raise CriticalAlertFailureControlPersistenceError(
            "failure-control binding requires an injected exact route plan"
        )
    if type(evidence) is not CriticalAlertSupervisorEvidence:
        raise CriticalAlertFailureControlPersistenceError(
            "failure-control binding requires exact supervisor evidence"
        )
    route_plan.__post_init__()
    evidence.__post_init__()
    _require_sha256(actor_authority_sha256, "failure-control actor authority_sha256")
    bound_at = _require_utc(bound_at, "failure-control bound_at")
    try:
        lock_account_capacity_serialization(connection, account_id)
        existing_row = (
            connection.execute(_receipt_statement(evidence.incident_id, for_update=True))
            .mappings()
            .one_or_none()
        )
        if existing_row is not None:
            existing = _receipt_from_row(connection, existing_row)
            if (
                existing.incident.scope_id != account_id
                or existing.route_plan != route_plan
                or existing.evidence != evidence
                or existing.command.actor.authority_sha256 != actor_authority_sha256
            ):
                raise CriticalAlertFailureControlPersistenceConflict(
                    "critical-alert failure-control source identity conflicts"
                )
            return existing
        history = load_critical_alert_history_in_transaction(
            connection,
            evidence.incident_id,
            for_update=True,
        )
        if history.incident.scope_id != account_id:
            raise CriticalAlertFailureControlPersistenceConflict(
                "failure-control incident crosses account scope"
            )
        pre_control = load_operational_control_head_in_transaction(
            connection,
            account_id,
        )
        if pre_control is None:
            raise CriticalAlertFailureControlPersistenceError(
                "failure-control binding requires durable operational-control state"
            )
        receipt = bind_critical_alert_failure_control_receipt(
            incident=history.incident,
            route_plan=route_plan,
            attempts=history.attempts,
            results=history.results,
            evidence=evidence,
            pre_control=pre_control,
            actor_authority_sha256=actor_authority_sha256,
            bound_at=bound_at,
        )
        append_authority = _critical_alert_failure_control_append_authority(
            connection,
            receipt,
        )
        final_control = apply_operational_control_command_in_transaction(
            connection,
            receipt.command,
            decided_at=bound_at,
            _critical_alert_failure_control_authority=append_authority,
        )
        if final_control != receipt.final_control:
            raise CriticalAlertFailureControlPersistenceConflict(
                "failure-control transition changed during atomic binding"
            )
        try:
            connection.execute(
                sa.insert(phase5_critical_alert_failure_control_receipts).values(
                    **critical_alert_failure_control_receipt_values(receipt)
                )
            )
        except IntegrityError as error:
            raise CriticalAlertFailureControlPersistenceConflict(
                "failure-control receipt conflicts with durable history"
            ) from error
        persisted_row = (
            connection.execute(_receipt_statement(evidence.incident_id, for_update=False))
            .mappings()
            .one()
        )
        persisted = _receipt_from_row(connection, persisted_row, history=history)
        if persisted != receipt:
            raise CriticalAlertFailureControlPersistenceError(
                "failure-control binding failed exact SQL readback"
            )
        return persisted
    except CriticalAlertFailureControlPersistenceError:
        raise
    except (
        AccountCoordinatorError,
        CriticalAlertError,
        CriticalAlertFailureControlError,
        OperationalControlError,
    ) as error:
        raise CriticalAlertFailureControlPersistenceError(str(error)) from error


def _verify_critical_alert_failure_control_integrity(
    connection: Connection,
) -> None:
    """Authenticate receipts and reject unreceipted reserved commands."""

    if not isinstance(connection, Connection) or not connection.in_transaction():
        raise CriticalAlertFailureControlPersistenceError(
            "failure-control verification requires an active Connection"
        )
    if connection.dialect.name not in _SUPPORTED_DIALECTS:
        raise CriticalAlertFailureControlPersistenceError(
            "failure-control verification uses an unsupported SQL dialect"
        )
    rows = (
        connection.execute(
            sa.select(phase5_critical_alert_failure_control_receipts).order_by(
                phase5_critical_alert_failure_control_receipts.c.account_id,
                phase5_critical_alert_failure_control_receipts.c.bound_at,
                phase5_critical_alert_failure_control_receipts.c.receipt_id,
            )
        )
        .mappings()
        .all()
    )
    receipt_command_ids = {_receipt_from_row(connection, row).command.command_id for row in rows}
    if len(receipt_command_ids) != len(rows):
        raise CriticalAlertFailureControlPersistenceConflict(
            "failure-control command has duplicate receipts"
        )
    reserved_command_ids = {
        str(value)
        for value in connection.scalars(
            sa.select(phase5_operational_control_transitions.c.command_id).where(
                phase5_operational_control_transitions.c.actor_kind
                == OperationalControlActorKind.SYSTEM.value,
                phase5_operational_control_transitions.c.actor_id
                == CRITICAL_ALERT_FAILURE_CONTROL_SYSTEM_ACTOR_ID,
            )
        )
    }
    if reserved_command_ids != receipt_command_ids:
        raise CriticalAlertFailureControlPersistenceConflict(
            "failure-control reserved command/receipt set conflicts"
        )


def verify_critical_alert_failure_control_integrity(engine: Engine) -> None:
    """Authenticate all failure-control receipts in one stable snapshot."""

    if not isinstance(engine, Engine):
        raise CriticalAlertFailureControlPersistenceError(
            "failure-control verification requires an Engine"
        )
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise CriticalAlertFailureControlPersistenceError(
            f"failure-control verification does not support {engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_critical_alert_failure_control_integrity(connection)


class SqlCriticalAlertFailureControlRepository:
    """Local, deliberately unwired supervisor-failure/control composition."""

    __slots__ = ("_actor_authority_sha256", "_clock", "_engine", "_route_plan")

    def __init__(
        self,
        *,
        engine: Engine,
        clock: Clock,
        route_plan: CriticalAlertRoutePlan,
        actor_authority_sha256: str,
    ) -> None:
        if not isinstance(engine, Engine):
            raise CriticalAlertFailureControlPersistenceError(
                "failure-control repository requires an Engine"
            )
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise CriticalAlertFailureControlPersistenceError(
                f"failure-control repository does not support {engine.dialect.name!r}"
            )
        if not callable(getattr(clock, "now", None)):
            raise CriticalAlertFailureControlPersistenceError(
                "failure-control repository requires an injected trusted clock"
            )
        if type(route_plan) is not CriticalAlertRoutePlan:
            raise CriticalAlertFailureControlPersistenceError(
                "failure-control repository requires an injected exact route plan"
            )
        try:
            route_plan.__post_init__()
        except CriticalAlertError as error:
            raise CriticalAlertFailureControlPersistenceError(
                "failure-control route plan is invalid"
            ) from error
        _require_sha256(actor_authority_sha256, "failure-control actor authority_sha256")
        self._engine = engine
        self._clock = clock
        self._route_plan = route_plan
        self._actor_authority_sha256 = actor_authority_sha256

    @property
    def runtime_store_identity(self) -> int:
        """Return the positive process-local identity of the durable store."""

        return id(self._engine)

    @property
    def route_plan_sha256(self) -> str:
        """Expose only the exact opaque route-plan identity used by the binder."""

        return self._route_plan.semantic_sha256

    @property
    def failure_control_policy_sha256(self) -> str:
        """Expose the fixed local 0032 policy identity, never its authority."""

        return CRITICAL_ALERT_FAILURE_CONTROL_POLICY_SHA256

    def bind(
        self,
        *,
        account_id: str,
        evidence: CriticalAlertSupervisorEvidence,
    ) -> CriticalAlertFailureControlReceipt:
        """Return an exact retry or append the trip and receipt atomically."""

        _require_account_id(account_id)
        if type(evidence) is not CriticalAlertSupervisorEvidence:
            raise CriticalAlertFailureControlPersistenceError(
                "failure-control binding requires exact supervisor evidence"
            )
        evidence.__post_init__()
        with _write_transaction(self._engine) as connection:
            lock_account_capacity_serialization(connection, account_id)
            existing = load_critical_alert_failure_control_receipt_in_transaction(
                connection,
                evidence.incident_id,
                for_update=True,
            )
            if existing is not None:
                if (
                    existing.incident.scope_id != account_id
                    or existing.route_plan != self._route_plan
                    or existing.evidence != evidence
                    or existing.command.actor.authority_sha256 != self._actor_authority_sha256
                ):
                    raise CriticalAlertFailureControlPersistenceConflict(
                        "critical-alert failure-control source identity conflicts"
                    )
                return existing
            return bind_critical_alert_failure_control_in_transaction(
                connection,
                account_id=account_id,
                route_plan=self._route_plan,
                evidence=evidence,
                actor_authority_sha256=self._actor_authority_sha256,
                bound_at=_require_utc(
                    self._clock.now(),
                    "failure-control trusted clock instant",
                ),
            )

    def load(
        self,
        incident_id: str,
    ) -> CriticalAlertFailureControlReceipt | None:
        with _repeatable_read_transaction(self._engine) as connection:
            return load_critical_alert_failure_control_receipt_in_transaction(
                connection,
                incident_id,
            )

    def history(
        self,
        account_id: str,
    ) -> tuple[CriticalAlertFailureControlReceipt, ...]:
        _require_account_id(account_id)
        with _repeatable_read_transaction(self._engine) as connection:
            rows = (
                connection.execute(
                    sa.select(phase5_critical_alert_failure_control_receipts)
                    .where(
                        phase5_critical_alert_failure_control_receipts.c.account_id == account_id
                    )
                    .order_by(
                        phase5_critical_alert_failure_control_receipts.c.bound_at,
                        phase5_critical_alert_failure_control_receipts.c.receipt_id,
                    )
                )
                .mappings()
                .all()
            )
            return tuple(_receipt_from_row(connection, row) for row in rows)

    def verify_integrity(self) -> None:
        verify_critical_alert_failure_control_integrity(self._engine)


__all__ = [
    "CriticalAlertFailureControlPersistenceConflict",
    "CriticalAlertFailureControlPersistenceError",
    "SqlCriticalAlertFailureControlRepository",
    "_verify_critical_alert_failure_control_integrity",
    "bind_critical_alert_failure_control_in_transaction",
    "critical_alert_failure_control_receipt_values",
    "load_critical_alert_failure_control_receipt_in_transaction",
    "verify_critical_alert_failure_control_integrity",
]
