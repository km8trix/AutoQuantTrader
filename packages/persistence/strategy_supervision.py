"""Durable, fenced strategy-supervision observations and breaker transitions."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountFence,
    AccountFenceReceipt,
)
from packages.domain.canonical import canonical_json_bytes
from packages.domain.clock import Clock
from packages.domain.critical_alert import CriticalAlertError, CriticalAlertIncident
from packages.domain.operational_control import (
    OperationalControlError,
    OperationalControlTransition,
)
from packages.domain.strategy_supervision import (
    StrategyInvocation,
    StrategyProtocolResponse,
    StrategyRuntimeBinding,
    StrategySupervisionError,
    StrategySupervisionOutcome,
    StrategySupervisionResult,
)
from packages.domain.strategy_supervision_alert import (
    strategy_supervision_critical_alert,
)
from packages.domain.strategy_supervision_control import (
    strategy_supervision_trip_command,
)
from packages.persistence.account_coordinator import (
    _write_transaction,
    account_lease_from_row,
)
from packages.persistence.critical_alert import (
    critical_alert_incident_from_row,
    record_critical_alert_incident_in_transaction,
)
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.immutable import as_aware_utc
from packages.persistence.operational_control import (
    apply_operational_control_command_in_transaction,
    load_operational_control_head_in_transaction,
    load_operational_control_transition_in_transaction,
)
from packages.persistence.schema import (
    phase2_account_leases,
    phase5_critical_alert_incidents,
    phase5_strategy_supervision_results,
)

STRATEGY_SUPERVISION_PERSISTENCE_CONTRACT_VERSION = "phase5c-strategy-supervision-persistence-v1"

StrategySupervisionRow = Mapping[str, object] | RowMapping
_SUPPORTED_DIALECTS = frozenset({"postgresql", "sqlite"})


class StrategySupervisionPersistenceError(RuntimeError):
    """Persisted strategy-supervision evidence is malformed or unavailable."""


class StrategySupervisionPersistenceConflict(StrategySupervisionPersistenceError):
    """An immutable invocation identity conflicts with durable evidence."""


class SqlAccountFenceValidator(Protocol):
    """Narrow coordinator surface required for an atomic durable observation."""

    def revalidate_in_transaction(
        self,
        connection: Connection,
        fence: AccountFence,
        *,
        checked_at: datetime,
    ) -> AccountFenceReceipt: ...


class _StrategySupervisionLifecycleWriteAuthority:
    """Unforgeable-by-convention token for the claim-owning repository path."""

    __slots__ = ()


_STRATEGY_SUPERVISION_LIFECYCLE_WRITE_AUTHORITY = _StrategySupervisionLifecycleWriteAuthority()
_STRATEGY_INVOCATION_LIFECYCLE_TABLES = (
    "phase5_strategy_invocation_claims",
    "phase5_strategy_invocation_finalizations",
)


def _strategy_invocation_lifecycle_schema_active(connection: Connection) -> bool:
    try:
        inspector = sa.inspect(connection)
        return any(
            inspector.has_table(table_name) for table_name in _STRATEGY_INVOCATION_LIFECYCLE_TABLES
        )
    except SQLAlchemyError as error:
        raise StrategySupervisionPersistenceError(
            "strategy-supervision lifecycle schema state is unavailable"
        ) from error


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_sha256(value: str, field_name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise StrategySupervisionPersistenceError(
            f"{field_name} must be a lowercase SHA-256 digest"
        )


def _require_utc(value: datetime, field_name: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise StrategySupervisionPersistenceError(f"{field_name} must be UTC")
    return value


def _utc_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc_text(value: object, field_name: str) -> datetime:
    if type(value) is not str:
        raise StrategySupervisionPersistenceError(f"{field_name} must be UTC text")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise StrategySupervisionPersistenceError(f"{field_name} is not exact UTC text") from error
    if _utc_text(parsed) != value:
        raise StrategySupervisionPersistenceError(f"{field_name} is not canonical UTC text")
    return parsed


def _plain_json_text(value: object) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, RecursionError) as error:
        raise StrategySupervisionPersistenceError(
            "strategy-supervision payload is not JSON encodable"
        ) from error


def _decode_object(payload: object, field_name: str) -> dict[str, object]:
    if type(payload) is not str:
        raise StrategySupervisionPersistenceError(
            f"persisted strategy-supervision {field_name} must be text"
        )
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, ValueError, RecursionError) as error:
        raise StrategySupervisionPersistenceError(
            f"persisted strategy-supervision {field_name} is not JSON"
        ) from error
    if type(value) is not dict or _plain_json_text(value) != payload:
        raise StrategySupervisionPersistenceError(
            f"persisted strategy-supervision {field_name} is not canonical"
        )
    return value


def _exact_keys(
    value: Mapping[str, object],
    expected: frozenset[str],
    field_name: str,
) -> None:
    if frozenset(value) != expected:
        raise StrategySupervisionPersistenceError(
            f"persisted strategy-supervision {field_name} has unsupported fields"
        )


def _text(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise StrategySupervisionPersistenceError(
            f"persisted strategy-supervision {field_name} must be text"
        )
    return value


def _integer(value: object, field_name: str) -> int:
    if type(value) is not int:
        raise StrategySupervisionPersistenceError(
            f"persisted strategy-supervision {field_name} must be an integer"
        )
    return value


def _boolean(value: object, field_name: str) -> bool:
    if type(value) is not bool:
        raise StrategySupervisionPersistenceError(
            f"persisted strategy-supervision {field_name} must be a boolean"
        )
    return value


def _optional_integer(value: object, field_name: str) -> int | None:
    if value is None:
        return None
    return _integer(value, field_name)


def _invocation_payload(invocation: StrategyInvocation) -> str:
    return _plain_json_text(
        {
            "control_scope_id": invocation.control_scope_id,
            "environment": invocation.environment,
            "input_state_sha256": invocation.input_state_sha256,
            "market_batch_as_of": _utc_text(invocation.market_batch_as_of),
            "market_batch_id": invocation.market_batch_id,
            "market_batch_sha256": invocation.market_batch_sha256,
            "protocol_version": invocation.protocol_version,
            "requested_at": _utc_text(invocation.requested_at),
            "runtime": {
                "artifact_sha256": invocation.runtime.artifact_sha256,
                "launch_spec_sha256": invocation.runtime.launch_spec_sha256,
                "runtime_id": invocation.runtime.runtime_id,
                "runtime_version": invocation.runtime.runtime_version,
            },
            "strategy_configuration_sha256": (invocation.strategy_configuration_sha256),
            "strategy_id": invocation.strategy_id,
            "strategy_version": invocation.strategy_version,
        }
    )


_INVOCATION_KEYS = frozenset(
    {
        "control_scope_id",
        "environment",
        "input_state_sha256",
        "market_batch_as_of",
        "market_batch_id",
        "market_batch_sha256",
        "protocol_version",
        "requested_at",
        "runtime",
        "strategy_configuration_sha256",
        "strategy_id",
        "strategy_version",
    }
)
_RUNTIME_KEYS = frozenset(
    {
        "artifact_sha256",
        "launch_spec_sha256",
        "runtime_id",
        "runtime_version",
    }
)


def _invocation_from_payload(payload: object) -> StrategyInvocation:
    value = _decode_object(payload, "invocation payload")
    _exact_keys(value, _INVOCATION_KEYS, "invocation payload")
    runtime_value = value["runtime"]
    if type(runtime_value) is not dict:
        raise StrategySupervisionPersistenceError(
            "persisted strategy-supervision runtime payload must be an object"
        )
    _exact_keys(runtime_value, _RUNTIME_KEYS, "runtime payload")
    try:
        invocation = StrategyInvocation(
            control_scope_id=_text(value["control_scope_id"], "control scope ID"),
            environment=_text(value["environment"], "environment"),
            market_batch_id=_text(value["market_batch_id"], "market batch ID"),
            market_batch_sha256=_text(
                value["market_batch_sha256"],
                "market_batch_sha256",
            ),
            market_batch_as_of=_parse_utc_text(
                value["market_batch_as_of"],
                "market_batch_as_of",
            ),
            strategy_id=_text(value["strategy_id"], "strategy ID"),
            strategy_version=_text(
                value["strategy_version"],
                "strategy version",
            ),
            strategy_configuration_sha256=_text(
                value["strategy_configuration_sha256"],
                "strategy_configuration_sha256",
            ),
            input_state_sha256=_text(
                value["input_state_sha256"],
                "input_state_sha256",
            ),
            runtime=StrategyRuntimeBinding(
                runtime_id=_text(runtime_value["runtime_id"], "runtime ID"),
                runtime_version=_text(
                    runtime_value["runtime_version"],
                    "runtime version",
                ),
                artifact_sha256=_text(
                    runtime_value["artifact_sha256"],
                    "runtime artifact_sha256",
                ),
                launch_spec_sha256=_text(
                    runtime_value["launch_spec_sha256"],
                    "runtime launch_spec_sha256",
                ),
            ),
            requested_at=_parse_utc_text(value["requested_at"], "requested_at"),
            protocol_version=_text(
                value["protocol_version"],
                "protocol version",
            ),
        )
    except StrategySupervisionError as error:
        raise StrategySupervisionPersistenceError(str(error)) from error
    if _invocation_payload(invocation) != payload:
        raise StrategySupervisionPersistenceConflict(
            "persisted strategy invocation payload conflicts"
        )
    return invocation


def _response_payload(response: StrategyProtocolResponse) -> dict[str, object]:
    return {
        "invocation_id": response.invocation_id,
        "invocation_sha256": response.invocation_sha256,
        "protocol_version": response.protocol_version,
        "result_json": response.result_json,
        "result_sha256": response.result_sha256,
    }


def _result_payload(result: StrategySupervisionResult) -> str:
    return _plain_json_text(
        {
            "completed_at": _utc_text(result.completed_at),
            "detail_code": result.detail_code,
            "elapsed_microseconds": result.elapsed_microseconds,
            "exit_code": result.exit_code,
            "invocation_id": result.invocation_id,
            "invocation_sha256": result.invocation_sha256,
            "outcome": result.outcome.value,
            "process_started": result.process_started,
            "response": (None if result.response is None else _response_payload(result.response)),
            "started_at": _utc_text(result.started_at),
            "stderr_bytes": result.stderr_bytes,
            "stderr_sha256": result.stderr_sha256,
            "stdout_bytes": result.stdout_bytes,
            "stdout_sha256": result.stdout_sha256,
        }
    )


_RESULT_KEYS = frozenset(
    {
        "completed_at",
        "detail_code",
        "elapsed_microseconds",
        "exit_code",
        "invocation_id",
        "invocation_sha256",
        "outcome",
        "process_started",
        "response",
        "started_at",
        "stderr_bytes",
        "stderr_sha256",
        "stdout_bytes",
        "stdout_sha256",
    }
)
_RESPONSE_KEYS = frozenset(
    {
        "invocation_id",
        "invocation_sha256",
        "protocol_version",
        "result_json",
        "result_sha256",
    }
)


def _result_from_payload(payload: object) -> StrategySupervisionResult:
    value = _decode_object(payload, "result payload")
    _exact_keys(value, _RESULT_KEYS, "result payload")
    response_value = value["response"]
    response: StrategyProtocolResponse | None
    if response_value is None:
        response = None
    else:
        if type(response_value) is not dict:
            raise StrategySupervisionPersistenceError(
                "persisted strategy-supervision response payload must be an object"
            )
        _exact_keys(response_value, _RESPONSE_KEYS, "response payload")
        try:
            response = StrategyProtocolResponse(
                invocation_id=_text(
                    response_value["invocation_id"],
                    "response invocation ID",
                ),
                invocation_sha256=_text(
                    response_value["invocation_sha256"],
                    "response invocation_sha256",
                ),
                protocol_version=_text(
                    response_value["protocol_version"],
                    "response protocol version",
                ),
                result_json=_text(
                    response_value["result_json"],
                    "response result JSON",
                ),
                result_sha256=_text(
                    response_value["result_sha256"],
                    "response result_sha256",
                ),
            )
        except StrategySupervisionError as error:
            raise StrategySupervisionPersistenceError(str(error)) from error
    try:
        result = StrategySupervisionResult(
            invocation_id=_text(value["invocation_id"], "result invocation ID"),
            invocation_sha256=_text(
                value["invocation_sha256"],
                "result invocation_sha256",
            ),
            outcome=StrategySupervisionOutcome(_text(value["outcome"], "result outcome")),
            started_at=_parse_utc_text(value["started_at"], "result started_at"),
            completed_at=_parse_utc_text(
                value["completed_at"],
                "result completed_at",
            ),
            elapsed_microseconds=_integer(
                value["elapsed_microseconds"],
                "result elapsed_microseconds",
            ),
            process_started=_boolean(
                value["process_started"],
                "result process_started",
            ),
            exit_code=_optional_integer(value["exit_code"], "result exit_code"),
            stdout_bytes=_integer(value["stdout_bytes"], "result stdout bytes"),
            stdout_sha256=_text(
                value["stdout_sha256"],
                "result stdout_sha256",
            ),
            stderr_bytes=_integer(value["stderr_bytes"], "result stderr bytes"),
            stderr_sha256=_text(
                value["stderr_sha256"],
                "result stderr_sha256",
            ),
            detail_code=_text(value["detail_code"], "result detail code"),
            response=response,
        )
    except (StrategySupervisionError, ValueError) as error:
        raise StrategySupervisionPersistenceError(str(error)) from error
    if _result_payload(result) != payload:
        raise StrategySupervisionPersistenceConflict("persisted strategy result payload conflicts")
    return result


@dataclass(frozen=True, slots=True)
class StrategySupervisionRecord:
    """One result bound to its fence and atomic operational-control effect."""

    invocation: StrategyInvocation
    result: StrategySupervisionResult
    fence: AccountFence
    lease_sha256: str
    pre_control: OperationalControlTransition
    final_control: OperationalControlTransition
    critical_alert_incident: CriticalAlertIncident | None
    recorded_at: datetime

    def __post_init__(self) -> None:
        if type(self.invocation) is not StrategyInvocation:
            raise StrategySupervisionPersistenceError(
                "strategy-supervision record requires an exact invocation"
            )
        if type(self.result) is not StrategySupervisionResult:
            raise StrategySupervisionPersistenceError(
                "strategy-supervision record requires an exact result"
            )
        if type(self.fence) is not AccountFence:
            raise StrategySupervisionPersistenceError(
                "strategy-supervision record requires an exact fence"
            )
        if (
            type(self.pre_control) is not OperationalControlTransition
            or type(self.final_control) is not OperationalControlTransition
        ):
            raise StrategySupervisionPersistenceError(
                "strategy-supervision record requires exact control transitions"
            )
        self.invocation.__post_init__()
        self.result.__post_init__()
        self.fence.__post_init__()
        self.pre_control.__post_init__()
        self.final_control.__post_init__()
        _require_sha256(self.lease_sha256, "strategy-supervision lease_sha256")
        _require_utc(self.recorded_at, "strategy-supervision recorded_at")
        if self.result.completed_at > self.recorded_at:
            raise StrategySupervisionPersistenceConflict(
                "strategy-supervision result cannot be recorded before completion"
            )
        if (
            self.result.invocation_id != self.invocation.invocation_id
            or self.result.invocation_sha256 != self.invocation.semantic_sha256
        ):
            raise StrategySupervisionPersistenceConflict(
                "strategy-supervision result crosses invocation identity"
            )
        account_id = self.invocation.control_scope_id
        if (
            self.fence.account_id != account_id
            or self.pre_control.scope_id != account_id
            or self.final_control.scope_id != account_id
        ):
            raise StrategySupervisionPersistenceConflict(
                "strategy-supervision account bindings conflict"
            )
        command = strategy_supervision_trip_command(self.invocation, self.result)
        if command is None:
            if self.final_control != self.pre_control or self.critical_alert_incident is not None:
                raise StrategySupervisionPersistenceConflict(
                    "completed strategy result cannot change control or create an alert"
                )
        else:
            if (
                self.final_control.sequence_number != self.pre_control.sequence_number + 1
                or self.final_control.previous_transition_sha256 != self.pre_control.semantic_sha256
                or self.final_control.command_id != command.command_id
                or self.final_control.command_sha256 != command.semantic_sha256
            ):
                raise StrategySupervisionPersistenceConflict(
                    "failed strategy result lacks its adjacent PAUSED breaker transition"
                )
            expected_incident = strategy_supervision_critical_alert(
                invocation=self.invocation,
                result=self.result,
                control_transition=self.final_control,
                recorded_at=self.recorded_at,
            )
            if (
                type(self.critical_alert_incident) is not CriticalAlertIncident
                or self.critical_alert_incident != expected_incident
            ):
                raise StrategySupervisionPersistenceConflict(
                    "failed strategy result lacks its exact critical-alert incident"
                )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(
            (
                STRATEGY_SUPERVISION_PERSISTENCE_CONTRACT_VERSION,
                self.invocation.semantic_sha256,
                self.result.semantic_sha256,
                self.fence.semantic_sha256,
                self.lease_sha256,
                self.pre_control.semantic_sha256,
                self.final_control.semantic_sha256,
                (
                    None
                    if self.critical_alert_incident is None
                    else self.critical_alert_incident.semantic_sha256
                ),
                self.recorded_at,
            )
        )


def _record_values(record: StrategySupervisionRecord) -> dict[str, object]:
    response = record.result.response
    return {
        "invocation_id": record.invocation.invocation_id,
        "account_id": record.invocation.control_scope_id,
        "invocation_sha256": record.invocation.semantic_sha256,
        "environment": record.invocation.environment,
        "market_batch_id": record.invocation.market_batch_id,
        "market_batch_sha256": record.invocation.market_batch_sha256,
        "strategy_id": record.invocation.strategy_id,
        "strategy_version": record.invocation.strategy_version,
        "strategy_configuration_sha256": (record.invocation.strategy_configuration_sha256),
        "runtime_sha256": record.invocation.runtime.semantic_sha256,
        "outcome": record.result.outcome.value,
        "started_at": record.result.started_at,
        "completed_at": record.result.completed_at,
        "elapsed_microseconds": record.result.elapsed_microseconds,
        "process_started": record.result.process_started,
        "exit_code": record.result.exit_code,
        "stdout_bytes": record.result.stdout_bytes,
        "stdout_sha256": record.result.stdout_sha256,
        "stderr_bytes": record.result.stderr_bytes,
        "stderr_sha256": record.result.stderr_sha256,
        "detail_code": record.result.detail_code,
        "response_sha256": (None if response is None else response.semantic_sha256),
        "response_result_sha256": (None if response is None else response.result_sha256),
        "response_result_json": (None if response is None else response.result_json),
        "fencing_generation": record.fence.fencing_generation,
        "lease_sha256": record.lease_sha256,
        "fence_sha256": record.fence.semantic_sha256,
        "pre_control_transition_id": record.pre_control.transition_id,
        "pre_control_transition_sha256": record.pre_control.semantic_sha256,
        "final_control_transition_id": record.final_control.transition_id,
        "final_control_transition_sha256": record.final_control.semantic_sha256,
        "critical_alert_incident_id": (
            None
            if record.critical_alert_incident is None
            else record.critical_alert_incident.incident_id
        ),
        "critical_alert_incident_sha256": (
            None
            if record.critical_alert_incident is None
            else record.critical_alert_incident.semantic_sha256
        ),
        "recorded_at": record.recorded_at,
        "invocation_payload": _invocation_payload(record.invocation),
        "result_payload": _result_payload(record.result),
        "semantic_sha256": record.semantic_sha256,
    }


def _required_text(row: StrategySupervisionRow, field_name: str) -> str:
    return _text(row[field_name], field_name)


def _required_integer(row: StrategySupervisionRow, field_name: str) -> int:
    return _integer(row[field_name], field_name)


def _required_bool(row: StrategySupervisionRow, field_name: str) -> bool:
    return _boolean(row[field_name], field_name)


def _required_datetime(
    row: StrategySupervisionRow,
    field_name: str,
) -> datetime:
    value = row[field_name]
    if not isinstance(value, datetime):
        raise StrategySupervisionPersistenceError(
            f"persisted strategy-supervision {field_name} must be a datetime"
        )
    return as_aware_utc(value)


def _record_from_row(
    connection: Connection,
    row: StrategySupervisionRow,
) -> StrategySupervisionRecord:
    try:
        invocation = _invocation_from_payload(row["invocation_payload"])
        result = _result_from_payload(row["result_payload"])
        lease_row = (
            connection.execute(
                sa.select(phase2_account_leases).where(
                    phase2_account_leases.c.account_id == _required_text(row, "account_id"),
                    phase2_account_leases.c.fencing_generation
                    == _required_integer(row, "fencing_generation"),
                    phase2_account_leases.c.lease_sha256 == _required_text(row, "lease_sha256"),
                )
            )
            .mappings()
            .one_or_none()
        )
        if lease_row is None:
            raise StrategySupervisionPersistenceConflict(
                "strategy-supervision record references a missing lease"
            )
        lease = account_lease_from_row(lease_row)
        pre_control = load_operational_control_transition_in_transaction(
            connection,
            invocation.control_scope_id,
            _required_text(row, "pre_control_transition_id"),
        )
        final_control = load_operational_control_transition_in_transaction(
            connection,
            invocation.control_scope_id,
            _required_text(row, "final_control_transition_id"),
        )
        if pre_control is None or final_control is None:
            raise StrategySupervisionPersistenceConflict(
                "strategy-supervision record references missing control history"
            )
        incident_id_value = row["critical_alert_incident_id"]
        incident: CriticalAlertIncident | None
        if incident_id_value is None:
            incident = None
        else:
            incident_id = _text(
                incident_id_value,
                "critical-alert incident ID",
            )
            incident_row = (
                connection.execute(
                    sa.select(phase5_critical_alert_incidents).where(
                        phase5_critical_alert_incidents.c.incident_id == incident_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if incident_row is None:
                raise StrategySupervisionPersistenceConflict(
                    "strategy-supervision record references a missing alert"
                )
            incident = critical_alert_incident_from_row(incident_row)
        record = StrategySupervisionRecord(
            invocation=invocation,
            result=result,
            fence=lease.fence,
            lease_sha256=lease.semantic_sha256,
            pre_control=pre_control,
            final_control=final_control,
            critical_alert_incident=incident,
            recorded_at=_required_datetime(row, "recorded_at"),
        )
        expected = _record_values(record)
        for field_name, expected_value in expected.items():
            observed = row[field_name]
            if field_name in {"started_at", "completed_at", "recorded_at"}:
                if not isinstance(observed, datetime):
                    raise StrategySupervisionPersistenceConflict(
                        f"persisted strategy-supervision {field_name} conflicts"
                    )
                observed = as_aware_utc(observed)
            if observed != expected_value:
                raise StrategySupervisionPersistenceConflict(
                    f"persisted strategy-supervision {field_name} conflicts"
                )
        return record
    except StrategySupervisionPersistenceError:
        raise
    except (
        AccountCoordinatorError,
        CriticalAlertError,
        KeyError,
        OperationalControlError,
        StrategySupervisionError,
        TypeError,
        ValueError,
    ) as error:
        raise StrategySupervisionPersistenceError(
            "persisted strategy-supervision record is malformed"
        ) from error


def _record_statement(
    invocation_id: str,
    *,
    for_update: bool,
) -> sa.Select[tuple[object, ...]]:
    statement = sa.select(phase5_strategy_supervision_results).where(
        phase5_strategy_supervision_results.c.invocation_id == invocation_id
    )
    if for_update:
        statement = statement.with_for_update()
    return statement


def _validate_receipt(
    receipt: AccountFenceReceipt,
    *,
    fence: AccountFence,
    recorded_at: datetime,
) -> None:
    if type(receipt) is not AccountFenceReceipt:
        raise StrategySupervisionPersistenceError(
            "strategy-supervision fence validator returned a noncanonical receipt"
        )
    receipt._validate()
    if receipt.fence != fence or receipt.validated_at != recorded_at:
        raise StrategySupervisionPersistenceConflict("strategy-supervision fence receipt conflicts")


def record_strategy_supervision_in_transaction(
    connection: Connection,
    *,
    coordinator: SqlAccountFenceValidator,
    invocation: StrategyInvocation,
    result: StrategySupervisionResult,
    fence: AccountFence,
    recorded_at: datetime,
    lifecycle_authority: _StrategySupervisionLifecycleWriteAuthority | None = None,
) -> StrategySupervisionRecord:
    """Atomically append one result, breaker transition, and critical incident.

    This is the transaction-scoped seam used by the durable pre-run invocation
    lifecycle.  It deliberately retains all validation and exact-readback
    behavior of :meth:`SqlStrategySupervisionRepository.record`.
    """

    if not isinstance(connection, Connection) or not connection.in_transaction():
        raise StrategySupervisionPersistenceError(
            "strategy-supervision append requires an active SQL transaction"
        )
    if connection.dialect.name not in _SUPPORTED_DIALECTS:
        raise StrategySupervisionPersistenceError(
            "strategy-supervision append uses an unsupported SQL dialect"
        )
    if (
        _strategy_invocation_lifecycle_schema_active(connection)
        and lifecycle_authority is not _STRATEGY_SUPERVISION_LIFECYCLE_WRITE_AUTHORITY
    ):
        raise StrategySupervisionPersistenceConflict(
            "direct strategy-supervision writes are disabled by the invocation lifecycle"
        )
    if not callable(getattr(coordinator, "revalidate_in_transaction", None)):
        raise StrategySupervisionPersistenceError(
            "strategy-supervision append requires a SQL fence validator"
        )
    if type(invocation) is not StrategyInvocation:
        raise StrategySupervisionPersistenceError(
            "strategy-supervision append requires an exact invocation"
        )
    if type(result) is not StrategySupervisionResult:
        raise StrategySupervisionPersistenceError(
            "strategy-supervision append requires an exact result"
        )
    if type(fence) is not AccountFence:
        raise StrategySupervisionPersistenceError(
            "strategy-supervision append requires an exact fence"
        )
    invocation.__post_init__()
    result.__post_init__()
    fence.__post_init__()
    recorded_at = _require_utc(
        recorded_at,
        "strategy-supervision recorded_at",
    )
    if (
        invocation.control_scope_id != fence.account_id
        or result.invocation_id != invocation.invocation_id
        or result.invocation_sha256 != invocation.semantic_sha256
    ):
        raise StrategySupervisionPersistenceConflict(
            "strategy-supervision append bindings conflict"
        )
    if recorded_at < result.completed_at:
        raise StrategySupervisionPersistenceConflict(
            "strategy-supervision clock predates result completion"
        )
    try:
        receipt = coordinator.revalidate_in_transaction(
            connection,
            fence,
            checked_at=recorded_at,
        )
        _validate_receipt(
            receipt,
            fence=fence,
            recorded_at=recorded_at,
        )
        existing_row = (
            connection.execute(
                _record_statement(
                    invocation.invocation_id,
                    for_update=True,
                )
            )
            .mappings()
            .one_or_none()
        )
        if existing_row is not None:
            existing = _record_from_row(connection, existing_row)
            if (
                existing.invocation != invocation
                or existing.result != result
                or existing.fence != fence
            ):
                raise StrategySupervisionPersistenceConflict(
                    "strategy-supervision invocation identity conflicts"
                )
            return existing
        pre_control = load_operational_control_head_in_transaction(
            connection,
            invocation.control_scope_id,
        )
        if pre_control is None:
            raise StrategySupervisionPersistenceError(
                "strategy-supervision append requires operational-control state"
            )
        command = strategy_supervision_trip_command(invocation, result)
        final_control = (
            pre_control
            if command is None
            else apply_operational_control_command_in_transaction(
                connection,
                command,
                decided_at=recorded_at,
            )
        )
        incident = strategy_supervision_critical_alert(
            invocation=invocation,
            result=result,
            control_transition=final_control,
            recorded_at=recorded_at,
        )
        if incident is not None:
            incident = record_critical_alert_incident_in_transaction(
                connection,
                incident,
                recorded_at=recorded_at,
            )
        record = StrategySupervisionRecord(
            invocation=invocation,
            result=result,
            fence=fence,
            lease_sha256=receipt.lease_sha256,
            pre_control=pre_control,
            final_control=final_control,
            critical_alert_incident=incident,
            recorded_at=recorded_at,
        )
        try:
            connection.execute(
                sa.insert(phase5_strategy_supervision_results).values(**_record_values(record))
            )
        except IntegrityError as error:
            raise StrategySupervisionPersistenceConflict(
                "strategy-supervision append conflicts with durable history"
            ) from error
        persisted_row = (
            connection.execute(
                _record_statement(
                    invocation.invocation_id,
                    for_update=False,
                )
            )
            .mappings()
            .one()
        )
        persisted = _record_from_row(connection, persisted_row)
        if persisted != record:
            raise StrategySupervisionPersistenceError(
                "strategy-supervision append failed exact SQL readback"
            )
        return persisted
    except StrategySupervisionPersistenceError:
        raise
    except (
        AccountCoordinatorError,
        CriticalAlertError,
        OperationalControlError,
        StrategySupervisionError,
    ) as error:
        raise StrategySupervisionPersistenceError(str(error)) from error


class SqlStrategySupervisionRepository:
    """Commit each child result and any PAUSED trip as one fenced transaction."""

    __slots__ = ("_clock", "_coordinator", "_engine")

    def __init__(
        self,
        *,
        engine: Engine,
        coordinator: SqlAccountFenceValidator,
        clock: Clock,
    ) -> None:
        if not isinstance(engine, Engine):
            raise StrategySupervisionPersistenceError(
                "strategy-supervision repository requires an Engine"
            )
        if engine.dialect.name not in _SUPPORTED_DIALECTS:
            raise StrategySupervisionPersistenceError(
                f"strategy-supervision repository does not support dialect {engine.dialect.name!r}"
            )
        if not callable(getattr(coordinator, "revalidate_in_transaction", None)):
            raise StrategySupervisionPersistenceError(
                "strategy-supervision repository requires a SQL fence validator"
            )
        if not callable(getattr(clock, "now", None)):
            raise StrategySupervisionPersistenceError(
                "strategy-supervision repository requires a trusted clock"
            )
        self._engine = engine
        self._coordinator = coordinator
        self._clock = clock

    def _trusted_now(self) -> datetime:
        return _require_utc(
            self._clock.now(),
            "strategy-supervision trusted clock instant",
        )

    def record(
        self,
        invocation: StrategyInvocation,
        result: StrategySupervisionResult,
        fence: AccountFence,
    ) -> StrategySupervisionRecord:
        """Record one exact result; failures atomically append their PAUSED trip."""

        recorded_at = self._trusted_now()
        with _write_transaction(self._engine) as connection:
            return record_strategy_supervision_in_transaction(
                connection,
                coordinator=self._coordinator,
                invocation=invocation,
                result=result,
                fence=fence,
                recorded_at=recorded_at,
            )

    def load(self, invocation_id: str) -> StrategySupervisionRecord | None:
        """Load one result through its authenticated lease and control histories."""

        if (
            type(invocation_id) is not str
            or not invocation_id
            or invocation_id != invocation_id.strip()
        ):
            raise StrategySupervisionPersistenceError(
                "strategy-supervision invocation ID must be non-empty trimmed text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            row = (
                connection.execute(_record_statement(invocation_id, for_update=False))
                .mappings()
                .one_or_none()
            )
            return None if row is None else _record_from_row(connection, row)

    def history(self, account_id: str) -> tuple[StrategySupervisionRecord, ...]:
        """Load all account results in deterministic completion order."""

        if type(account_id) is not str or not account_id or account_id != account_id.strip():
            raise StrategySupervisionPersistenceError(
                "strategy-supervision account ID must be non-empty trimmed text"
            )
        with _repeatable_read_transaction(self._engine) as connection:
            rows = (
                connection.execute(
                    sa.select(phase5_strategy_supervision_results)
                    .where(phase5_strategy_supervision_results.c.account_id == account_id)
                    .order_by(
                        phase5_strategy_supervision_results.c.completed_at,
                        phase5_strategy_supervision_results.c.invocation_id,
                    )
                )
                .mappings()
                .all()
            )
            return tuple(_record_from_row(connection, row) for row in rows)

    def verify_integrity(self) -> None:
        """Authenticate every durable strategy-supervision record."""

        verify_strategy_supervision_integrity(self._engine)


def _verify_strategy_supervision_integrity(connection: Connection) -> None:
    """Authenticate all rows on the caller's stable transaction snapshot."""

    if not isinstance(connection, Connection):
        raise StrategySupervisionPersistenceError(
            "strategy-supervision verification requires a Connection"
        )
    if connection.dialect.name not in _SUPPORTED_DIALECTS:
        raise StrategySupervisionPersistenceError(
            "strategy-supervision verification does not support "
            f"dialect {connection.dialect.name!r}"
        )
    rows = (
        connection.execute(
            sa.select(phase5_strategy_supervision_results).order_by(
                phase5_strategy_supervision_results.c.account_id,
                phase5_strategy_supervision_results.c.completed_at,
                phase5_strategy_supervision_results.c.invocation_id,
            )
        )
        .mappings()
        .all()
    )
    for row in rows:
        _record_from_row(connection, row)


def verify_strategy_supervision_integrity(engine: Engine) -> None:
    """Authenticate every durable strategy-supervision record in one snapshot."""

    if not isinstance(engine, Engine):
        raise StrategySupervisionPersistenceError(
            "strategy-supervision verification requires an Engine"
        )
    if engine.dialect.name not in _SUPPORTED_DIALECTS:
        raise StrategySupervisionPersistenceError(
            f"strategy-supervision verification does not support dialect {engine.dialect.name!r}"
        )
    with _repeatable_read_transaction(engine) as connection:
        _verify_strategy_supervision_integrity(connection)
