"""Bind one independently pinned Alpaca paper account without trading authority.

This owner-operated command performs exactly one approved, authenticated
``GET /v2/account`` through the fixed Phase 4G runtime.  It never submits,
replaces, or cancels an order; never initializes or changes operational
control; and never retries automatically.  The exact bounded account response
is retained in the durable raw-ingress journal before decoding.

An explicitly authorized recovery mode permits one second account ``GET`` only
from the exact released generation-one raw-only checkpoint.  Its atomic
conditional acquisition can create generation two only and preserves every
fact from the first attempt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, NoReturn
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import Engine

from packages.adapters.broker.alpaca_paper import (
    ALPACA_PAPER_ADAPTER_ID,
    ALPACA_PAPER_ADAPTER_VERSION,
    ALPACA_PAPER_TRADING_BASE_URL,
)
from packages.adapters.broker.alpaca_paper_account_assets import (
    AlpacaAccountObservationOutcome,
    create_alpaca_account_observation_description,
    decode_alpaca_account_observation_response,
)
from packages.adapters.broker.alpaca_paper_account_runtime import (
    ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE,
    ALPACA_PAPER_ACCOUNT_RUNTIME_CONTRACT_VERSION,
    AlpacaPaperAuthenticatedAccountBinding,
    AlpacaPaperCredentialReference,
    create_alpaca_paper_credential_envelope,
    observe_authenticated_alpaca_paper_account,
)
from packages.adapters.broker.alpaca_paper_budget import (
    ALPACA_PAPER_REQUEST_BUDGET_POLICY,
    AlpacaPaperBudgetOperation,
)
from packages.adapters.broker.alpaca_paper_ingress import (
    ALPACA_PAPER_ACCOUNT_INGRESS_CHANNEL,
    ALPACA_PAPER_ACCOUNT_INGRESS_OPERATION,
)
from packages.domain.account_coordinator import AccountLeasePolicy
from packages.domain.broker_request_budget import BrokerRequestPurpose
from packages.domain.canonical import canonical_json_bytes
from packages.domain.clock import SystemClock
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
    account_lease_from_row,
    account_lease_release_from_row,
)
from packages.persistence.alpaca_paper_account_binding import (
    SqlAlpacaPaperAccountBindingRepository,
    verify_alpaca_paper_account_binding_integrity,
)
from packages.persistence.broker_ingress import (
    SqlBrokerIngressRepository,
    broker_ingress_receipt_from_row,
    verify_broker_ingress_integrity,
)
from packages.persistence.broker_request_budget import (
    SqlBrokerRequestBudgetRepository,
    broker_request_permit_from_row,
    verify_broker_request_budget_integrity,
)
from packages.persistence.database import verify_operational_schema
from packages.persistence.operational_control import (
    verify_operational_control_integrity,
)
from packages.persistence.schema import (
    phase2_account_lease_heads,
    phase2_account_lease_releases,
    phase2_account_leases,
    phase4_alpaca_paper_account_binding_heads,
    phase4_alpaca_paper_account_bindings,
    phase4_broker_ingress_heads,
    phase4_broker_ingress_receipts,
    phase4_broker_request_heads,
    phase4_broker_request_permits,
    phase5_operational_control_completions,
    phase5_operational_control_heads,
    phase5_operational_control_transitions,
)
from scripts.credential_env import load_owner_only_environment
from scripts.verify_local_paper_smoke_preflight import (
    create_bounded_supabase_runtime_engine,
    validate_supabase_session_database_url,
)

_ENVIRONMENT_VARIABLES = (
    "AQT_DATABASE_URL",
    "ALPACA_PAPER_API_KEY",
    "ALPACA_PAPER_API_SECRET",
    "ALPACA_PAPER_BASE_URL",
    "AQT_PAPER_ACCOUNT_ID",
    "AQT_PAPER_PROVIDER_ACCOUNT_ID",
    "AQT_PAPER_BROKER_SECRET_REF",
    "AQT_PAPER_BROKER_SECRET_VERSION",
)
_MAXIMUM_ENVIRONMENT_BYTES = 128 * 1024
_RESOLVER_ID = "owner-dotenv-alpaca-paper"
_RESOLVER_VERSION = "1.0.0"
_LEASE_POLICY = AccountLeasePolicy(
    policy_id="local-alpaca-paper-account-binding",
    policy_version="1.0.0",
    lease_ttl=timedelta(minutes=1),
    maximum_in_flight_duration=timedelta(seconds=15),
    takeover_safety_interval=timedelta(seconds=30),
)
_CONTROL_TABLES = (
    phase5_operational_control_transitions,
    phase5_operational_control_heads,
    phase5_operational_control_completions,
)
_ACCOUNT_STATE_TABLES = (
    phase2_account_lease_heads,
    phase2_account_leases,
    phase2_account_lease_releases,
    phase4_broker_request_permits,
    phase4_broker_request_heads,
    phase4_broker_ingress_receipts,
    phase4_broker_ingress_heads,
    phase4_alpaca_paper_account_bindings,
    phase4_alpaca_paper_account_binding_heads,
)
_EXPECTED_COMPLETED_STATE_COUNTS = {str(table.name): 1 for table in _ACCOUNT_STATE_TABLES}
_EXPECTED_ACQUIRED_STATE_COUNTS = {
    str(table.name): (1 if table in {phase2_account_lease_heads, phase2_account_leases} else 0)
    for table in _ACCOUNT_STATE_TABLES
}
_EXPECTED_RECOVERY_BASELINE_STATE_COUNTS = {
    str(phase2_account_lease_heads.name): 1,
    str(phase2_account_leases.name): 1,
    str(phase2_account_lease_releases.name): 1,
    str(phase4_broker_request_permits.name): 1,
    str(phase4_broker_request_heads.name): 1,
    str(phase4_broker_ingress_receipts.name): 1,
    str(phase4_broker_ingress_heads.name): 1,
    str(phase4_alpaca_paper_account_bindings.name): 0,
    str(phase4_alpaca_paper_account_binding_heads.name): 0,
}
_EXPECTED_RECOVERY_ACQUIRED_STATE_COUNTS = {
    **_EXPECTED_RECOVERY_BASELINE_STATE_COUNTS,
    str(phase2_account_leases.name): 2,
}
_EXPECTED_RECOVERY_COMPLETED_STATE_COUNTS = {
    str(phase2_account_lease_heads.name): 1,
    str(phase2_account_leases.name): 2,
    str(phase2_account_lease_releases.name): 2,
    str(phase4_broker_request_permits.name): 2,
    str(phase4_broker_request_heads.name): 1,
    str(phase4_broker_ingress_receipts.name): 2,
    str(phase4_broker_ingress_heads.name): 1,
    str(phase4_alpaca_paper_account_bindings.name): 1,
    str(phase4_alpaca_paper_account_binding_heads.name): 1,
}
type AccountObserver = Callable[..., AlpacaPaperAuthenticatedAccountBinding]
type EngineFactory = Callable[[str], Engine]


class PaperAccountBindingCommandError(RuntimeError):
    """A bounded public reason for rejecting or failing one binding attempt."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        raise PaperAccountBindingCommandError("command_arguments_invalid")


class _OwnerEnvironmentCredentialResolver:
    """One-use, reference-bound resolver with redacted representations."""

    __slots__ = ("_api_key_id", "_reference", "_secret_key", "_used")

    resolver_id = _RESOLVER_ID
    resolver_version = _RESOLVER_VERSION

    def __init__(
        self,
        *,
        reference: AlpacaPaperCredentialReference,
        api_key_id: str,
        secret_key: str,
    ) -> None:
        if type(reference) is not AlpacaPaperCredentialReference:
            raise PaperAccountBindingCommandError("credential_reference_invalid")
        _validate_secret_value(api_key_id)
        _validate_secret_value(secret_key)
        self._reference = reference
        self._api_key_id: str | None = api_key_id
        self._secret_key: str | None = secret_key
        self._used = False

    def _resolve_for_account_observation(
        self,
        reference: AlpacaPaperCredentialReference,
    ) -> object:
        if self._used:
            raise PaperAccountBindingCommandError("credential_resolution_replay_rejected")
        if type(reference) is not AlpacaPaperCredentialReference or reference != self._reference:
            raise PaperAccountBindingCommandError("credential_reference_mismatch")
        self._used = True
        api_key_id = self._api_key_id
        secret_key = self._secret_key
        self._api_key_id = None
        self._secret_key = None
        if api_key_id is None or secret_key is None:
            raise PaperAccountBindingCommandError("credential_material_unavailable")
        return create_alpaca_paper_credential_envelope(
            api_key_id=api_key_id,
            secret_key=secret_key,
        )

    @property
    def consumed(self) -> bool:
        return self._used

    @property
    def credential_values_present(self) -> bool:
        return self._api_key_id is not None or self._secret_key is not None

    def close(self) -> None:
        self._api_key_id = None
        self._secret_key = None
        self._used = True

    def __repr__(self) -> str:
        return f"_OwnerEnvironmentCredentialResolver(<redacted>, consumed={self._used})"

    def __str__(self) -> str:
        return "<redacted owner Alpaca paper credential resolver>"


@dataclass(frozen=True, slots=True)
class _BindingEnvironment:
    database_url: str = field(repr=False)
    reference: AlpacaPaperCredentialReference
    credential_resolver: _OwnerEnvironmentCredentialResolver = field(
        repr=False,
        compare=False,
    )


@dataclass(frozen=True, slots=True)
class _ControlSnapshot:
    semantic_sha256: str
    account_row_count: int
    global_running_head_count: int


@dataclass(frozen=True, slots=True)
class _RecoveryCheckpoint:
    control_before: _ControlSnapshot
    prior_lease_sha256: str
    prior_release_id: str
    prior_permit_id: str
    prior_permit_sha256: str
    prior_ingress_receipt_id: str
    prior_ingress_receipt_sha256: str


@dataclass(frozen=True, slots=True)
class PaperAccountBindingResult:
    """Secret-free, non-authorizing result of exact durable readback."""

    operation_id: str
    binding_id: str
    binding_sha256: str
    provider_account_id_sha256: str
    sequence_number: int
    qualified_at: str

    @property
    def public_payload(self) -> dict[str, object]:
        return {
            "account_binding_established": True,
            "automatic_rearm_authorized": False,
            "binding_id": self.binding_id,
            "binding_sha256": self.binding_sha256,
            "broker_action_authorized": False,
            "control_state_changed": False,
            "exact_provider_pin_match": True,
            "live_trading_authorized": False,
            "mode": "owner_operated_alpaca_paper_account_binding",
            "new_exposure_authorized": False,
            "operation_id": self.operation_id,
            "paper_startup_ready": False,
            "provider_account_id_sha256": self.provider_account_id_sha256,
            "qualified_at": self.qualified_at,
            "raw_account_response_retained": True,
            "sequence_number": self.sequence_number,
            "status": "paper_account_bound_non_authorizing",
            "submission_authorized": False,
            "trading_effect_authorized": False,
        }


def _validate_secret_value(value: object) -> None:
    if type(value) is not str:
        raise PaperAccountBindingCommandError("credential_material_invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        raise PaperAccountBindingCommandError("credential_material_invalid") from None
    if not encoded or len(encoded) > 512 or any(byte < 33 or byte > 126 for byte in encoded):
        raise PaperAccountBindingCommandError("credential_material_invalid")


def _required_environment_value(
    environment: Mapping[str, str],
    variable: str,
) -> str:
    value = environment.get(variable)
    if type(value) is not str or not value:
        raise PaperAccountBindingCommandError("binding_environment_incomplete")
    return value


def _load_binding_environment(path: Path) -> _BindingEnvironment:
    if not path.is_absolute():
        raise PaperAccountBindingCommandError("env_file_path_not_absolute")
    try:
        environment = load_owner_only_environment(
            path,
            variables=_ENVIRONMENT_VARIABLES,
            maximum_bytes=_MAXIMUM_ENVIRONMENT_BYTES,
            reject_duplicate_variables=True,
            reject_symlinked_parents=True,
            require_current_user_owner=True,
        )
    except (OSError, ValueError):
        raise PaperAccountBindingCommandError("owner_environment_invalid") from None

    database_url = _required_environment_value(environment, "AQT_DATABASE_URL")
    try:
        validate_supabase_session_database_url(database_url)
    except Exception:
        raise PaperAccountBindingCommandError("database_url_rejected") from None
    if (
        _required_environment_value(environment, "ALPACA_PAPER_BASE_URL")
        != ALPACA_PAPER_TRADING_BASE_URL
    ):
        raise PaperAccountBindingCommandError("alpaca_paper_base_url_rejected")

    try:
        reference = AlpacaPaperCredentialReference(
            account_id=_required_environment_value(
                environment,
                "AQT_PAPER_ACCOUNT_ID",
            ),
            expected_provider_account_id=_required_environment_value(
                environment,
                "AQT_PAPER_PROVIDER_ACCOUNT_ID",
            ),
            secret_ref=_required_environment_value(
                environment,
                "AQT_PAPER_BROKER_SECRET_REF",
            ),
            secret_version=_required_environment_value(
                environment,
                "AQT_PAPER_BROKER_SECRET_VERSION",
            ),
        )
        resolver = _OwnerEnvironmentCredentialResolver(
            reference=reference,
            api_key_id=_required_environment_value(
                environment,
                "ALPACA_PAPER_API_KEY",
            ),
            secret_key=_required_environment_value(
                environment,
                "ALPACA_PAPER_API_SECRET",
            ),
        )
    except PaperAccountBindingCommandError:
        raise
    except Exception:
        raise PaperAccountBindingCommandError("credential_reference_invalid") from None
    return _BindingEnvironment(
        database_url=database_url,
        reference=reference,
        credential_resolver=resolver,
    )


def _canonical_operation_id(value: str) -> str:
    if type(value) is not str:
        raise PaperAccountBindingCommandError("operation_id_invalid")
    try:
        parsed = UUID(value)
    except ValueError:
        raise PaperAccountBindingCommandError("operation_id_invalid") from None
    if str(parsed) != value:
        raise PaperAccountBindingCommandError("operation_id_invalid")
    return value


def _idempotency_keys(operation_id: str) -> tuple[str, str, str]:
    operation_id = _canonical_operation_id(operation_id)
    return (
        f"aqt.paper.account.request.{operation_id}",
        f"aqt.paper.account.delivery.{operation_id}",
        f"aqt-paper-account-binding-{operation_id}",
    )


def _client_tls_active(connection: sa.Connection) -> bool:
    try:
        driver_connection = getattr(connection.connection, "driver_connection", None)
        pg_connection = getattr(driver_connection, "pgconn", None)
        return getattr(pg_connection, "ssl_in_use", False) is True
    except TypeError:
        return False


def _account_state_counts(
    engine: Engine,
    account_id: str,
) -> dict[str, int]:
    counts: dict[str, int] = {}
    with engine.connect() as connection:
        for table in _ACCOUNT_STATE_TABLES:
            counts[str(table.name)] = int(
                connection.scalar(
                    sa.select(sa.func.count())
                    .select_from(table)
                    .where(table.c.account_id == account_id),
                )
                or 0
            )
    return counts


def _control_snapshot(engine: Engine, account_id: str) -> _ControlSnapshot:
    material: list[tuple[str, tuple[tuple[Any, ...], ...]]] = []
    row_count = 0
    with engine.connect() as connection:
        for table in _CONTROL_TABLES:
            primary_key_columns = tuple(table.primary_key.columns)
            statement = sa.select(table).where(table.c.account_id == account_id)
            if primary_key_columns:
                statement = statement.order_by(*primary_key_columns)
            rows = tuple(tuple(row) for row in connection.execute(statement).tuples())
            row_count += len(rows)
            material.append((str(table.name), rows))
        running_count = int(
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase5_operational_control_heads)
                .where(
                    phase5_operational_control_heads.c.effective_state == "running",
                ),
            )
            or 0
        )
    return _ControlSnapshot(
        semantic_sha256=hashlib.sha256(
            canonical_json_bytes(
                (
                    "owner-alpaca-paper-binding-control-snapshot-v1",
                    account_id,
                    tuple(material),
                ),
            ),
        ).hexdigest(),
        account_row_count=row_count,
        global_running_head_count=running_count,
    )


def _provider_alias_count(
    engine: Engine,
    provider_account_id: str,
) -> int:
    with engine.connect() as connection:
        return int(
            connection.scalar(
                sa.select(sa.func.count())
                .select_from(phase4_alpaca_paper_account_binding_heads)
                .where(
                    phase4_alpaca_paper_account_binding_heads.c.provider_id == "alpaca-paper",
                    phase4_alpaca_paper_account_binding_heads.c.environment == "paper",
                    phase4_alpaca_paper_account_binding_heads.c.expected_provider_account_id
                    == provider_account_id,
                ),
            )
            or 0
        )


def _recovery_demand_correlation_sha256(
    reference: AlpacaPaperCredentialReference,
    description_sha256: str,
) -> str:
    if (
        type(description_sha256) is not str
        or len(description_sha256) != 64
        or any(character not in "0123456789abcdef" for character in description_sha256)
    ):
        raise PaperAccountBindingCommandError("recovery_checkpoint_rejected")
    return hashlib.sha256(
        canonical_json_bytes(
            (
                ALPACA_PAPER_ACCOUNT_RUNTIME_CONTRACT_VERSION,
                "account_observation_correlation",
                reference.semantic_sha256,
                description_sha256,
            ),
        ),
    ).hexdigest()


def _verify_recovery_database_preconditions(
    engine: Engine,
    reference: AlpacaPaperCredentialReference,
    recovery_from_operation_id: str,
) -> _RecoveryCheckpoint:
    try:
        if engine.dialect.name != "postgresql":
            raise PaperAccountBindingCommandError("runtime_database_not_postgresql")
        verify_operational_schema(engine, require_phase_zero_facts=False)
        with engine.connect() as connection:
            if not _client_tls_active(connection):
                raise PaperAccountBindingCommandError("runtime_database_tls_inactive")
        verify_broker_request_budget_integrity(engine)
        verify_broker_ingress_integrity(engine)
        verify_alpaca_paper_account_binding_integrity(engine)
        verify_operational_control_integrity(engine)

        account_id = reference.account_id
        if _account_state_counts(engine, account_id) != _EXPECTED_RECOVERY_BASELINE_STATE_COUNTS:
            raise PaperAccountBindingCommandError("recovery_checkpoint_rejected")
        if _provider_alias_count(
            engine,
            reference.expected_provider_account_id,
        ):
            raise PaperAccountBindingCommandError("provider_account_alias_conflict")

        prior_request_key, prior_delivery_key, prior_owner_id = _idempotency_keys(
            recovery_from_operation_id,
        )
        with engine.connect() as connection:
            lease_row = (
                connection.execute(
                    sa.select(phase2_account_leases).where(
                        phase2_account_leases.c.account_id == account_id,
                    ),
                )
                .mappings()
                .one()
            )
            release_row = (
                connection.execute(
                    sa.select(phase2_account_lease_releases).where(
                        phase2_account_lease_releases.c.account_id == account_id,
                    ),
                )
                .mappings()
                .one()
            )
            lease_head = (
                connection.execute(
                    sa.select(phase2_account_lease_heads).where(
                        phase2_account_lease_heads.c.account_id == account_id,
                    ),
                )
                .mappings()
                .one()
            )
            permit_row = (
                connection.execute(
                    sa.select(phase4_broker_request_permits).where(
                        phase4_broker_request_permits.c.account_id == account_id,
                    ),
                )
                .mappings()
                .one()
            )
            request_head = (
                connection.execute(
                    sa.select(phase4_broker_request_heads).where(
                        phase4_broker_request_heads.c.account_id == account_id,
                    ),
                )
                .mappings()
                .one()
            )
            ingress_row = (
                connection.execute(
                    sa.select(phase4_broker_ingress_receipts).where(
                        phase4_broker_ingress_receipts.c.account_id == account_id,
                    ),
                )
                .mappings()
                .one()
            )
            ingress_head = (
                connection.execute(
                    sa.select(phase4_broker_ingress_heads).where(
                        phase4_broker_ingress_heads.c.account_id == account_id,
                    ),
                )
                .mappings()
                .one()
            )

        lease = account_lease_from_row(lease_row)
        release = account_lease_release_from_row(release_row)
        permit_record = broker_request_permit_from_row(permit_row)
        permit = permit_record.permit
        demand = permit_record.demand
        ingress_receipt = broker_ingress_receipt_from_row(ingress_row)
        delivery = ingress_receipt.delivery
        transport_status = delivery.transport_status
        provider_request_id = delivery.provider_request_id
        if transport_status != 200 or provider_request_id is None:
            raise PaperAccountBindingCommandError("recovery_checkpoint_rejected")
        recovered_observation = decode_alpaca_account_observation_response(
            create_alpaca_account_observation_description(
                account_id=account_id,
            ),
            http_status=transport_status,
            provider_request_id=provider_request_id,
            response_body=delivery.body,
            received_at=delivery.received_at,
        )

        if (
            lease.account_id != account_id
            or lease.owner_id != prior_owner_id
            or lease.fencing_generation != 1
            or lease.revision_number != 1
            or lease.previous_lease_sha256 is not None
            or lease.policy_sha256 != _LEASE_POLICY.semantic_sha256
            or release.fence != lease.fence
            or release.lease_sha256 != lease.semantic_sha256
            or release.policy_sha256 != _LEASE_POLICY.semantic_sha256
            or lease_head["last_fencing_generation"] != 1
            or lease_head["current_fencing_generation"] is not None
            or lease_head["current_lease_sha256"] is not None
            or lease_head["updated_at"] != release.released_at
        ):
            raise PaperAccountBindingCommandError("recovery_checkpoint_rejected")

        if (
            permit_record.policy != ALPACA_PAPER_REQUEST_BUDGET_POLICY
            or demand.account_id != account_id
            or demand.idempotency_key != prior_request_key
            or demand.operation != AlpacaPaperBudgetOperation.OBSERVE_ACCOUNT.value
            or demand.purpose is not BrokerRequestPurpose.RECONCILIATION
            or permit.sequence_number != 1
            or permit.previous_permit_sha256 is not None
            or request_head["last_sequence_number"] != 1
            or request_head["last_permit_sha256"] != permit.semantic_sha256
            or request_head["last_issued_at"] != permit.issued_at
        ):
            raise PaperAccountBindingCommandError("recovery_checkpoint_rejected")

        description_sha256 = delivery.correlation_sha256
        if (
            ingress_receipt.account_id != account_id
            or ingress_receipt.ingress_sequence != 1
            or ingress_receipt.previous_receipt_sha256 is not None
            or delivery.delivery_idempotency_key != prior_delivery_key
            or delivery.provider_id != ALPACA_PAPER_ADAPTER_ID
            or delivery.adapter_version != ALPACA_PAPER_ADAPTER_VERSION
            or delivery.environment != "paper"
            or delivery.channel != ALPACA_PAPER_ACCOUNT_INGRESS_CHANNEL
            or delivery.operation != ALPACA_PAPER_ACCOUNT_INGRESS_OPERATION
            or delivery.transport_status != 200
            or delivery.provider_request_id is None
            or delivery.media_type != ALPACA_PAPER_ACCOUNT_ACCEPT_MEDIA_TYPE
            or ingress_head["last_ingress_sequence"] != 1
            or ingress_head["last_receipt_sha256"] != ingress_receipt.semantic_sha256
            or description_sha256 is None
            or demand.correlation_sha256
            != _recovery_demand_correlation_sha256(
                reference,
                description_sha256,
            )
            or not (
                lease.acquired_at
                <= demand.requested_at
                <= permit.issued_at
                <= delivery.received_at
                <= delivery.recorded_at
                <= release.released_at
            )
            or delivery.received_at >= permit.expires_at
            or delivery.received_at >= lease.expires_at
            or release.released_at >= lease.expires_at
            or recovered_observation.outcome
            is not AlpacaAccountObservationOutcome.OBSERVED_USABLE_CANDIDATE
            or recovered_observation.provider_account_id != reference.expected_provider_account_id
        ):
            raise PaperAccountBindingCommandError("recovery_checkpoint_rejected")

        control = _control_snapshot(engine, account_id)
        if control.global_running_head_count != 0:
            raise PaperAccountBindingCommandError("running_control_rejected")
        return _RecoveryCheckpoint(
            control_before=control,
            prior_lease_sha256=lease.semantic_sha256,
            prior_release_id=release.release_id,
            prior_permit_id=permit.permit_id,
            prior_permit_sha256=permit.semantic_sha256,
            prior_ingress_receipt_id=ingress_receipt.receipt_id,
            prior_ingress_receipt_sha256=ingress_receipt.semantic_sha256,
        )
    except PaperAccountBindingCommandError:
        raise
    except Exception:
        raise PaperAccountBindingCommandError(
            "recovery_database_preflight_rejected",
        ) from None


def _verify_database_preconditions(
    engine: Engine,
    reference: AlpacaPaperCredentialReference,
) -> _ControlSnapshot:
    try:
        if engine.dialect.name != "postgresql":
            raise PaperAccountBindingCommandError("runtime_database_not_postgresql")
        verify_operational_schema(engine, require_phase_zero_facts=False)
        with engine.connect() as connection:
            if not _client_tls_active(connection):
                raise PaperAccountBindingCommandError("runtime_database_tls_inactive")
        verify_broker_request_budget_integrity(engine)
        verify_broker_ingress_integrity(engine)
        verify_alpaca_paper_account_binding_integrity(engine)
        verify_operational_control_integrity(engine)
        if any(_account_state_counts(engine, reference.account_id).values()):
            raise PaperAccountBindingCommandError("residual_account_state_rejected")
        if _provider_alias_count(
            engine,
            reference.expected_provider_account_id,
        ):
            raise PaperAccountBindingCommandError("provider_account_alias_conflict")
        control = _control_snapshot(engine, reference.account_id)
        if control.global_running_head_count != 0:
            raise PaperAccountBindingCommandError("running_control_rejected")
        return control
    except PaperAccountBindingCommandError:
        raise
    except Exception:
        raise PaperAccountBindingCommandError("database_preflight_rejected") from None


def _verify_under_lease_preconditions(
    *,
    engine: Engine,
    reference: AlpacaPaperCredentialReference,
    lease_generation: int,
    lease_revision: int,
    control_before: _ControlSnapshot,
) -> None:
    """Close the account-local preflight race after acquiring generation one."""

    try:
        if lease_generation != 1 or lease_revision != 1:
            raise PaperAccountBindingCommandError("concurrent_account_state_rejected")
        if _account_state_counts(engine, reference.account_id) != (_EXPECTED_ACQUIRED_STATE_COUNTS):
            raise PaperAccountBindingCommandError("concurrent_account_state_rejected")
        if _provider_alias_count(
            engine,
            reference.expected_provider_account_id,
        ):
            raise PaperAccountBindingCommandError("provider_account_alias_conflict")
        verify_operational_control_integrity(engine)
        if _control_snapshot(engine, reference.account_id) != control_before:
            raise PaperAccountBindingCommandError("operational_control_changed")
    except PaperAccountBindingCommandError:
        raise
    except Exception:
        raise PaperAccountBindingCommandError("under_lease_preflight_rejected") from None


def _verify_recovery_lease_state(
    *,
    engine: Engine,
    account_id: str,
    checkpoint: _RecoveryCheckpoint,
    recovery_owner_id: str,
    recovery_lease_is_current: bool,
) -> None:
    with engine.connect() as connection:
        lease_rows = (
            connection.execute(
                sa.select(phase2_account_leases)
                .where(phase2_account_leases.c.account_id == account_id)
                .order_by(
                    phase2_account_leases.c.fencing_generation,
                    phase2_account_leases.c.revision_number,
                ),
            )
            .mappings()
            .all()
        )
        release_rows = (
            connection.execute(
                sa.select(phase2_account_lease_releases)
                .where(phase2_account_lease_releases.c.account_id == account_id)
                .order_by(phase2_account_lease_releases.c.fencing_generation),
            )
            .mappings()
            .all()
        )
        lease_head = (
            connection.execute(
                sa.select(phase2_account_lease_heads).where(
                    phase2_account_lease_heads.c.account_id == account_id,
                ),
            )
            .mappings()
            .one()
        )

    expected_release_count = 1 if recovery_lease_is_current else 2
    if len(lease_rows) != 2 or len(release_rows) != expected_release_count:
        raise PaperAccountBindingCommandError("recovery_lease_state_invalid")
    prior_lease, recovery_lease = tuple(account_lease_from_row(row) for row in lease_rows)
    releases = tuple(account_lease_release_from_row(row) for row in release_rows)
    prior_release = releases[0]
    if (
        prior_lease.semantic_sha256 != checkpoint.prior_lease_sha256
        or prior_release.release_id != checkpoint.prior_release_id
        or prior_release.fence != prior_lease.fence
        or recovery_lease.account_id != account_id
        or recovery_lease.owner_id != recovery_owner_id
        or recovery_lease.fencing_generation != 2
        or recovery_lease.revision_number != 1
        or recovery_lease.previous_lease_sha256 is not None
        or recovery_lease.policy_sha256 != _LEASE_POLICY.semantic_sha256
        or recovery_lease.acquired_at < prior_release.released_at
        or lease_head["last_fencing_generation"] != 2
    ):
        raise PaperAccountBindingCommandError("recovery_lease_state_invalid")

    if recovery_lease_is_current:
        if (
            lease_head["current_fencing_generation"] != 2
            or lease_head["current_lease_sha256"] != recovery_lease.semantic_sha256
            or lease_head["updated_at"] != recovery_lease.heartbeat_at
        ):
            raise PaperAccountBindingCommandError("recovery_lease_state_invalid")
        return

    recovery_release = releases[1]
    if (
        recovery_release.fence != recovery_lease.fence
        or recovery_release.lease_sha256 != recovery_lease.semantic_sha256
        or recovery_release.policy_sha256 != _LEASE_POLICY.semantic_sha256
        or recovery_release.released_at < recovery_lease.acquired_at
        or lease_head["current_fencing_generation"] is not None
        or lease_head["current_lease_sha256"] is not None
        or lease_head["updated_at"] != recovery_release.released_at
    ):
        raise PaperAccountBindingCommandError("recovery_lease_state_invalid")


def _verify_recovery_under_lease_preconditions(
    *,
    engine: Engine,
    reference: AlpacaPaperCredentialReference,
    lease_generation: int,
    lease_revision: int,
    checkpoint: _RecoveryCheckpoint,
    recovery_owner_id: str,
) -> None:
    try:
        if lease_generation != 2 or lease_revision != 1:
            raise PaperAccountBindingCommandError("concurrent_account_state_rejected")
        if (
            _account_state_counts(engine, reference.account_id)
            != _EXPECTED_RECOVERY_ACQUIRED_STATE_COUNTS
        ):
            raise PaperAccountBindingCommandError("concurrent_account_state_rejected")
        _verify_recovery_lease_state(
            engine=engine,
            account_id=reference.account_id,
            checkpoint=checkpoint,
            recovery_owner_id=recovery_owner_id,
            recovery_lease_is_current=True,
        )
        verify_broker_request_budget_integrity(engine)
        verify_broker_ingress_integrity(engine)
        verify_alpaca_paper_account_binding_integrity(engine)
        if _provider_alias_count(
            engine,
            reference.expected_provider_account_id,
        ):
            raise PaperAccountBindingCommandError("provider_account_alias_conflict")
        verify_operational_control_integrity(engine)
        if _control_snapshot(engine, reference.account_id) != checkpoint.control_before:
            raise PaperAccountBindingCommandError("operational_control_changed")
    except PaperAccountBindingCommandError:
        raise
    except Exception:
        raise PaperAccountBindingCommandError(
            "recovery_under_lease_preflight_rejected",
        ) from None


def _verify_completed_binding(
    *,
    engine: Engine,
    account_id: str,
    binding: AlpacaPaperAuthenticatedAccountBinding,
    bindings: SqlAlpacaPaperAccountBindingRepository,
    budget: SqlBrokerRequestBudgetRepository,
    ingress: SqlBrokerIngressRepository,
    coordinator: SqlAccountCoordinator,
    clock: SystemClock,
    control_before: _ControlSnapshot,
) -> None:
    try:
        verify_operational_schema(engine, require_phase_zero_facts=False)
        verify_broker_request_budget_integrity(engine)
        verify_broker_ingress_integrity(engine)
        verify_alpaca_paper_account_binding_integrity(engine)
        verify_operational_control_integrity(engine)
        if coordinator.current() is not None:
            raise PaperAccountBindingCommandError("coordinator_release_not_durable")
        if _account_state_counts(engine, account_id) != _EXPECTED_COMPLETED_STATE_COUNTS:
            raise PaperAccountBindingCommandError("durable_state_delta_invalid")
        loaded = bindings.load(binding.binding_id)
        binding_history = bindings.history(account_id)
        budget_history = budget.history(account_id)
        ingress_history = ingress.history(account_id)
        if (
            loaded != binding
            or binding_history != (binding,)
            or len(budget_history) != 1
            or budget_history[0].permit_id != binding.permit_id
            or len(ingress_history) != 1
            or ingress_history[0].receipt_id != binding.ingress_receipt_id
        ):
            raise PaperAccountBindingCommandError("durable_binding_readback_invalid")
        identity = bindings.authenticate_terminal_identity(
            binding,
            checked_at=clock.now(),
        )
        if (
            identity.binding_id != binding.binding_id
            or identity.binding_sha256 != binding.semantic_sha256
            or identity.expected_provider_account_id != binding.expected_provider_account_id
        ):
            raise PaperAccountBindingCommandError("terminal_identity_invalid")
        control_after = _control_snapshot(engine, account_id)
        if control_after != control_before:
            raise PaperAccountBindingCommandError("operational_control_changed")
        if (
            binding.expected_provider_account_id != binding.observed_provider_account_id
            or not binding.raw_response_persisted
            or binding.submission_authorized
            or binding.trading_effect_authorized
            or binding.paper_startup_ready
        ):
            raise PaperAccountBindingCommandError("binding_authority_invariant_failed")
    except PaperAccountBindingCommandError:
        raise
    except Exception:
        raise PaperAccountBindingCommandError("durable_binding_verification_failed") from None


def _verify_completed_recovery_binding(
    *,
    engine: Engine,
    account_id: str,
    binding: AlpacaPaperAuthenticatedAccountBinding,
    bindings: SqlAlpacaPaperAccountBindingRepository,
    budget: SqlBrokerRequestBudgetRepository,
    ingress: SqlBrokerIngressRepository,
    coordinator: SqlAccountCoordinator,
    clock: SystemClock,
    checkpoint: _RecoveryCheckpoint,
    recovery_owner_id: str,
    request_idempotency_key: str,
    delivery_idempotency_key: str,
) -> None:
    try:
        verify_operational_schema(engine, require_phase_zero_facts=False)
        verify_broker_request_budget_integrity(engine)
        verify_broker_ingress_integrity(engine)
        verify_alpaca_paper_account_binding_integrity(engine)
        verify_operational_control_integrity(engine)
        if coordinator.current() is not None:
            raise PaperAccountBindingCommandError("coordinator_release_not_durable")
        if _account_state_counts(engine, account_id) != _EXPECTED_RECOVERY_COMPLETED_STATE_COUNTS:
            raise PaperAccountBindingCommandError("durable_state_delta_invalid")
        _verify_recovery_lease_state(
            engine=engine,
            account_id=account_id,
            checkpoint=checkpoint,
            recovery_owner_id=recovery_owner_id,
            recovery_lease_is_current=False,
        )

        loaded = bindings.load(binding.binding_id)
        binding_history = bindings.history(account_id)
        budget_history = budget.history(account_id)
        ingress_history = ingress.history(account_id)
        if (
            loaded != binding
            or binding.sequence_number != 1
            or binding.previous_binding_sha256 is not None
            or binding_history != (binding,)
            or len(budget_history) != 2
            or budget_history[0].sequence_number != 1
            or budget_history[0].permit_id != checkpoint.prior_permit_id
            or budget_history[0].semantic_sha256 != checkpoint.prior_permit_sha256
            or budget_history[1].sequence_number != 2
            or budget_history[1].previous_permit_sha256 != budget_history[0].semantic_sha256
            or budget_history[1].permit_id != binding.permit_id
            or len(ingress_history) != 2
            or ingress_history[0].ingress_sequence != 1
            or ingress_history[0].receipt_id != checkpoint.prior_ingress_receipt_id
            or ingress_history[0].semantic_sha256 != checkpoint.prior_ingress_receipt_sha256
            or ingress_history[1].ingress_sequence != 2
            or ingress_history[1].previous_receipt_sha256 != ingress_history[0].semantic_sha256
            or ingress_history[1].receipt_id != binding.ingress_receipt_id
            or ingress_history[1].delivery.delivery_idempotency_key != delivery_idempotency_key
        ):
            raise PaperAccountBindingCommandError("durable_binding_readback_invalid")

        with engine.connect() as connection:
            permit_row = (
                connection.execute(
                    sa.select(phase4_broker_request_permits).where(
                        phase4_broker_request_permits.c.permit_id == binding.permit_id,
                    ),
                )
                .mappings()
                .one()
            )
        permit_record = broker_request_permit_from_row(permit_row)
        if (
            permit_record.demand.idempotency_key != request_idempotency_key
            or permit_record.demand.operation != AlpacaPaperBudgetOperation.OBSERVE_ACCOUNT.value
            or permit_record.demand.purpose is not BrokerRequestPurpose.RECONCILIATION
            or permit_record.permit != budget_history[1]
        ):
            raise PaperAccountBindingCommandError("durable_binding_readback_invalid")

        identity = bindings.authenticate_terminal_identity(
            binding,
            checked_at=clock.now(),
        )
        if (
            identity.binding_id != binding.binding_id
            or identity.binding_sha256 != binding.semantic_sha256
            or identity.expected_provider_account_id != binding.expected_provider_account_id
        ):
            raise PaperAccountBindingCommandError("terminal_identity_invalid")
        if _control_snapshot(engine, account_id) != checkpoint.control_before:
            raise PaperAccountBindingCommandError("operational_control_changed")
        if (
            binding.expected_provider_account_id != binding.observed_provider_account_id
            or not binding.raw_response_persisted
            or binding.submission_authorized
            or binding.trading_effect_authorized
            or binding.paper_startup_ready
        ):
            raise PaperAccountBindingCommandError("binding_authority_invariant_failed")
    except PaperAccountBindingCommandError:
        raise
    except Exception:
        raise PaperAccountBindingCommandError(
            "durable_recovery_binding_verification_failed",
        ) from None


def execute_binding(
    configuration: _BindingEnvironment,
    operation_id: str,
    *,
    engine_factory: EngineFactory = create_bounded_supabase_runtime_engine,
    observer: AccountObserver = observe_authenticated_alpaca_paper_account,
) -> PaperAccountBindingResult:
    """Execute one no-retry account binding and authenticate its durable result."""

    if type(configuration) is not _BindingEnvironment:
        raise PaperAccountBindingCommandError("binding_configuration_invalid")
    engine: Engine | None = None
    try:
        operation_id = _canonical_operation_id(operation_id)
        if not callable(engine_factory) or not callable(observer):
            raise PaperAccountBindingCommandError("binding_composition_invalid")
        request_key, delivery_key, owner_id = _idempotency_keys(operation_id)
        try:
            candidate = engine_factory(configuration.database_url)
        except Exception:
            raise PaperAccountBindingCommandError("database_connection_failed") from None
        if not isinstance(candidate, Engine):
            raise PaperAccountBindingCommandError("database_engine_invalid")
        engine = candidate

        control_before = _verify_database_preconditions(
            engine,
            configuration.reference,
        )
        clock = SystemClock()
        authority = SqlAccountCoordinatorAuthority(
            engine=engine,
            policy=_LEASE_POLICY,
            clock=clock,
        )
        coordinator = SqlAccountCoordinator(
            account_id=configuration.reference.account_id,
            authority=authority,
        )
        budget = SqlBrokerRequestBudgetRepository(engine=engine, clock=clock)
        ingress = SqlBrokerIngressRepository(engine)
        bindings = SqlAlpacaPaperAccountBindingRepository(engine)

        try:
            lease = coordinator.acquire(owner_id)
        except Exception:
            raise PaperAccountBindingCommandError("coordinator_acquire_failed") from None

        binding: AlpacaPaperAuthenticatedAccountBinding | None = None
        observation_error: BaseException | None = None
        release_error: BaseException | None = None
        try:
            _verify_under_lease_preconditions(
                engine=engine,
                reference=configuration.reference,
                lease_generation=lease.fencing_generation,
                lease_revision=lease.revision_number,
                control_before=control_before,
            )
            candidate_binding = observer(
                reference=configuration.reference,
                description=create_alpaca_account_observation_description(
                    account_id=configuration.reference.account_id,
                ),
                credential_resolver=configuration.credential_resolver,
                budget=budget,
                coordinator=coordinator,
                fence=lease.fence,
                ingress_recorder=ingress,
                binding_recorder=bindings,
                clock=clock,
                request_idempotency_key=request_key,
                delivery_idempotency_key=delivery_key,
            )
            if type(candidate_binding) is not AlpacaPaperAuthenticatedAccountBinding:
                observation_error = PaperAccountBindingCommandError(
                    "account_observation_result_invalid",
                )
            else:
                binding = candidate_binding
        except BaseException as error:
            observation_error = error
        finally:
            try:
                coordinator.release(lease.fence)
            except BaseException as error:
                release_error = error
        if release_error is not None:
            raise PaperAccountBindingCommandError("coordinator_release_failed")
        if isinstance(observation_error, PaperAccountBindingCommandError):
            raise observation_error
        if observation_error is not None or binding is None:
            raise PaperAccountBindingCommandError("account_observation_failed")

        _verify_completed_binding(
            engine=engine,
            account_id=configuration.reference.account_id,
            binding=binding,
            bindings=bindings,
            budget=budget,
            ingress=ingress,
            coordinator=coordinator,
            clock=clock,
            control_before=control_before,
        )
        return PaperAccountBindingResult(
            operation_id=operation_id,
            binding_id=binding.binding_id,
            binding_sha256=binding.semantic_sha256,
            provider_account_id_sha256=hashlib.sha256(
                (
                    f"aqt-alpaca-paper-provider-account-v1:{binding.observed_provider_account_id}"
                ).encode("ascii"),
            ).hexdigest(),
            sequence_number=binding.sequence_number,
            qualified_at=binding.qualified_at.isoformat(),
        )
    finally:
        if type(configuration) is _BindingEnvironment:
            configuration.credential_resolver.close()
        if engine is not None:
            with suppress(Exception):
                engine.dispose()


def execute_recovery_binding(
    configuration: _BindingEnvironment,
    operation_id: str,
    recovery_from_operation_id: str,
    *,
    authorize_second_account_get: bool,
    engine_factory: EngineFactory = create_bounded_supabase_runtime_engine,
    observer: AccountObserver = observe_authenticated_alpaca_paper_account,
) -> PaperAccountBindingResult:
    """Execute one explicitly authorized second GET from one exact failed checkpoint."""

    if type(configuration) is not _BindingEnvironment:
        raise PaperAccountBindingCommandError("binding_configuration_invalid")
    engine: Engine | None = None
    try:
        operation_id = _canonical_operation_id(operation_id)
        recovery_from_operation_id = _canonical_operation_id(
            recovery_from_operation_id,
        )
        if type(authorize_second_account_get) is not bool or not authorize_second_account_get:
            raise PaperAccountBindingCommandError("second_account_get_not_authorized")
        if operation_id == recovery_from_operation_id:
            raise PaperAccountBindingCommandError("recovery_operation_id_conflict")
        if not callable(engine_factory) or not callable(observer):
            raise PaperAccountBindingCommandError("binding_composition_invalid")
        request_key, delivery_key, owner_id = _idempotency_keys(operation_id)
        try:
            candidate = engine_factory(configuration.database_url)
        except Exception:
            raise PaperAccountBindingCommandError("database_connection_failed") from None
        if not isinstance(candidate, Engine):
            raise PaperAccountBindingCommandError("database_engine_invalid")
        engine = candidate

        checkpoint = _verify_recovery_database_preconditions(
            engine,
            configuration.reference,
            recovery_from_operation_id,
        )
        clock = SystemClock()
        authority = SqlAccountCoordinatorAuthority(
            engine=engine,
            policy=_LEASE_POLICY,
            clock=clock,
        )
        coordinator = SqlAccountCoordinator(
            account_id=configuration.reference.account_id,
            authority=authority,
        )
        budget = SqlBrokerRequestBudgetRepository(engine=engine, clock=clock)
        ingress = SqlBrokerIngressRepository(engine)
        bindings = SqlAlpacaPaperAccountBindingRepository(engine)

        try:
            lease = coordinator.acquire_if_inactive_generation(
                owner_id,
                expected_last_fencing_generation=1,
            )
        except Exception:
            raise PaperAccountBindingCommandError("coordinator_acquire_failed") from None

        binding: AlpacaPaperAuthenticatedAccountBinding | None = None
        observation_error: BaseException | None = None
        release_error: BaseException | None = None
        try:
            _verify_recovery_under_lease_preconditions(
                engine=engine,
                reference=configuration.reference,
                lease_generation=lease.fencing_generation,
                lease_revision=lease.revision_number,
                checkpoint=checkpoint,
                recovery_owner_id=owner_id,
            )
            candidate_binding = observer(
                reference=configuration.reference,
                description=create_alpaca_account_observation_description(
                    account_id=configuration.reference.account_id,
                ),
                credential_resolver=configuration.credential_resolver,
                budget=budget,
                coordinator=coordinator,
                fence=lease.fence,
                ingress_recorder=ingress,
                binding_recorder=bindings,
                clock=clock,
                request_idempotency_key=request_key,
                delivery_idempotency_key=delivery_key,
            )
            if type(candidate_binding) is not AlpacaPaperAuthenticatedAccountBinding:
                observation_error = PaperAccountBindingCommandError(
                    "account_observation_result_invalid",
                )
            else:
                binding = candidate_binding
        except BaseException as error:
            observation_error = error
        finally:
            try:
                coordinator.release(lease.fence)
            except BaseException as error:
                release_error = error
        if release_error is not None:
            raise PaperAccountBindingCommandError("coordinator_release_failed")
        if isinstance(observation_error, PaperAccountBindingCommandError):
            raise observation_error
        if observation_error is not None or binding is None:
            raise PaperAccountBindingCommandError("account_observation_failed")

        _verify_completed_recovery_binding(
            engine=engine,
            account_id=configuration.reference.account_id,
            binding=binding,
            bindings=bindings,
            budget=budget,
            ingress=ingress,
            coordinator=coordinator,
            clock=clock,
            checkpoint=checkpoint,
            recovery_owner_id=owner_id,
            request_idempotency_key=request_key,
            delivery_idempotency_key=delivery_key,
        )
        return PaperAccountBindingResult(
            operation_id=operation_id,
            binding_id=binding.binding_id,
            binding_sha256=binding.semantic_sha256,
            provider_account_id_sha256=hashlib.sha256(
                (
                    f"aqt-alpaca-paper-provider-account-v1:{binding.observed_provider_account_id}"
                ).encode("ascii"),
            ).hexdigest(),
            sequence_number=binding.sequence_number,
            qualified_at=binding.qualified_at.isoformat(),
        )
    finally:
        if type(configuration) is _BindingEnvironment:
            configuration.credential_resolver.close()
        if engine is not None:
            with suppress(Exception):
                engine.dispose()


def _failure_payload(reason_code: str) -> dict[str, object]:
    return {
        "account_binding_established": "not_asserted",
        "automatic_rearm_authorized": False,
        "broker_action_authorized": False,
        "broker_request_outcome": "not_asserted",
        "control_state_changed": "not_asserted",
        "live_trading_authorized": False,
        "mode": "owner_operated_alpaca_paper_account_binding",
        "new_exposure_authorized": False,
        "paper_startup_ready": False,
        "raw_account_response_retained": "possible_after_permit_issuance",
        "reason": reason_code,
        "status": "paper_account_binding_not_completed",
        "submission_authorized": False,
        "trading_effect_authorized": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = _SafeArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-file",
        required=True,
        type=Path,
        help="absolute path to the owner-only dotenv file",
    )
    parser.add_argument(
        "--operation-id",
        required=True,
        help="canonical lowercase UUID for this one approved, no-retry attempt",
    )
    parser.add_argument(
        "--recovery-from-operation-id",
        help="canonical lowercase UUID of the exact retained generation-one checkpoint",
    )
    parser.add_argument(
        "--authorize-second-account-get",
        action="store_true",
        help="explicitly authorize one second GET for the exact recovery checkpoint",
    )
    try:
        arguments = parser.parse_args(argv)
        operation_id = _canonical_operation_id(arguments.operation_id)
        recovery_from_operation_id = arguments.recovery_from_operation_id
        authorize_second_account_get = arguments.authorize_second_account_get
        if (recovery_from_operation_id is None) == authorize_second_account_get:
            raise PaperAccountBindingCommandError("recovery_arguments_invalid")
        if recovery_from_operation_id is not None:
            recovery_from_operation_id = _canonical_operation_id(
                recovery_from_operation_id,
            )
            if recovery_from_operation_id == operation_id:
                raise PaperAccountBindingCommandError(
                    "recovery_operation_id_conflict",
                )
        configuration = _load_binding_environment(arguments.env_file)
        if recovery_from_operation_id is None:
            result = execute_binding(configuration, operation_id)
        else:
            result = execute_recovery_binding(
                configuration,
                operation_id,
                recovery_from_operation_id,
                authorize_second_account_get=authorize_second_account_get,
            )
    except PaperAccountBindingCommandError as error:
        print(json.dumps(_failure_payload(error.reason_code), sort_keys=True), flush=True)
        return 2
    except Exception:
        print(json.dumps(_failure_payload("binding_command_failed"), sort_keys=True), flush=True)
        return 2
    print(json.dumps(result.public_payload, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
