"""Bind one independently pinned Alpaca paper account without trading authority.

This owner-operated command performs exactly one approved, authenticated
``GET /v2/account`` through the fixed Phase 4G runtime.  It never submits,
replaces, or cancels an order; never initializes or changes operational
control; and never retries automatically.  The exact bounded account response
is retained in the durable raw-ingress journal before decoding.
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

from packages.adapters.broker.alpaca_paper import ALPACA_PAPER_TRADING_BASE_URL
from packages.adapters.broker.alpaca_paper_account_assets import (
    create_alpaca_account_observation_description,
)
from packages.adapters.broker.alpaca_paper_account_runtime import (
    AlpacaPaperAuthenticatedAccountBinding,
    AlpacaPaperCredentialReference,
    create_alpaca_paper_credential_envelope,
    observe_authenticated_alpaca_paper_account,
)
from packages.domain.account_coordinator import AccountLeasePolicy
from packages.domain.canonical import canonical_json_bytes
from packages.domain.clock import SystemClock
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.alpaca_paper_account_binding import (
    SqlAlpacaPaperAccountBindingRepository,
    verify_alpaca_paper_account_binding_integrity,
)
from packages.persistence.broker_ingress import (
    SqlBrokerIngressRepository,
    verify_broker_ingress_integrity,
)
from packages.persistence.broker_request_budget import (
    SqlBrokerRequestBudgetRepository,
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
    try:
        arguments = parser.parse_args(argv)
        operation_id = _canonical_operation_id(arguments.operation_id)
        configuration = _load_binding_environment(arguments.env_file)
        result = execute_binding(configuration, operation_id)
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
