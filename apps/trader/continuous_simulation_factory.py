"""Fixed offline restoration; reconstructed owners issue no new delivery authority."""

from __future__ import annotations

import json
import os
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Literal, TypeVar
from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.pool import NullPool

from apps.api.backtest_views import LocalOperatorSecurity
from apps.api.runtime_owner_authentication import LocalRuntimeOwnerAuthenticator
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.adapters.runtime_clock_evidence import RuntimeClockSampler
from packages.application import personal_codec as codec
from packages.application.continuous_account_transition import ContinuousAccountTransitionPreparer
from packages.application.continuous_process import ContinuousProcessRequest, _private_read
from packages.application.continuous_reconciliation import (
    ContinuousReconciliationTransitionResolver,
)
from packages.application.reference_strategy import ReferenceStrategy
from packages.application.venue_reconciliation import VenueReconciliationResolver
from packages.backtest.personal_accounting import PersonalAccounting
from packages.domain.account_coordinator import (
    AccountFence,
    AccountLease,
    AccountLeasePolicy,
    AccountLeaseRelease,
)
from packages.domain.continuous_engine_contracts import ContinuousEngineInputs
from packages.domain.continuous_persistence_contracts import (
    CONTINUOUS_COMMIT_SCHEMA,
    CONTINUOUS_REQUEST_SCHEMA,
    MAX_CONTINUOUS_OBJECT_BYTES,
    ContinuousAccountCommit,
    ContinuousAccountScope,
    ContinuousEvidenceRef,
)
from packages.domain.continuous_runtime_source_contracts import (
    RUNTIME_SOURCE_SCHEMA,
    ContinuousRuntimeSourceDescriptor,
)
from packages.domain.daily_runtime_contracts import RuntimeProducerMap
from packages.domain.forward_capture_contracts import CaptureEvidenceClass
from packages.domain.operational_control import OperationalControlState
from packages.domain.personal_contracts import ContractRecord, content_digest
from packages.domain.reconciliation_contracts import ReconciliationScope
from packages.domain.research_job_contracts import require_identifier
from packages.domain.runtime_operating_contracts import (
    CLOCK_SCHEMA,
    ClockProfile,
    RuntimeClockObservation,
)
from packages.domain.stateful_venue_contracts import VenueModel, VenueSourceReference
from packages.persistence.account_coordinator import (
    SqlAccountCoordinator,
    SqlAccountCoordinatorAuthority,
)
from packages.persistence.continuous_account import SqlContinuousAccount
from packages.persistence.continuous_attempt_outcome_sources import (
    SqlContinuousAttemptOutcomeSources,
)
from packages.persistence.continuous_attempt_publication import SqlContinuousAttemptPublication
from packages.persistence.continuous_composition import SqlContinuousCommitComposer
from packages.persistence.continuous_forward_sources import SqlContinuousForwardSources
from packages.persistence.continuous_integrity import SqlContinuousIntegrityReader
from packages.persistence.continuous_observed_hold_sources import SqlContinuousObservedHoldSources
from packages.persistence.continuous_reconciliation_publication import (
    SqlContinuousReconciliationPublication,
)
from packages.persistence.continuous_runtime_attempt_sources import (
    SqlContinuousRuntimeAttemptSources,
)
from packages.persistence.continuous_runtime_sources import SqlContinuousRuntimeSources
from packages.persistence.continuous_simulation_delivery import SqlContinuousSimulationDelivery
from packages.persistence.continuous_venue_sources import SqlContinuousVenueSources
from packages.persistence.daily_runtime_risk import SqlDailyRuntimeRisk
from packages.persistence.database import (
    EXPECTED_SCHEMA_REVISION,
    create_database_engine,
)
from packages.persistence.durable_journal import SqlDurableJournal
from packages.persistence.operational_control import SqlOperationalControlRepository
from packages.persistence.runtime_operating_evidence import SqlRuntimeOperatingEvidence
from packages.persistence.runtime_owner_associations import SqlRuntimeOwnerAssociations
from packages.persistence.runtime_owner_commands import SqlRuntimeOwnerCommands
from packages.persistence.runtime_owner_dependencies import SqlRuntimeOwnerDependencies
from packages.persistence.stateful_venue import SqlStatefulVenue
from packages.persistence.venue_reconciliation_capture import SqlVenueReconciliationCapture

if TYPE_CHECKING:
    from apps.trader.continuous_process_lifecycle import ContinuousWorkerLifecycle

R = TypeVar("R", bound=ContractRecord)
CONFIGURATION_SCHEMA = "continuous-offline-configuration/1"
PRODUCER_MAP_SCHEMA = "runtime-producer-map/1"


class ContinuousSimulationFactoryError(ValueError):
    """Static failure codes; private configuration paths and payloads stay private."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ContinuousSimulationConfiguration:
    schema_id: Literal["continuous-offline-configuration/1"]
    operation: Literal["restore", "integrity"]
    owner_id: str
    database_path: str
    artifact_root: str
    venue_database_path: str
    venue_artifact_root: str
    inputs: ContinuousEvidenceRef
    venue_model: ContinuousEvidenceRef
    producer_map: ContinuousEvidenceRef
    benchmark_instrument_id: str | None
    capture_evidence_class: CaptureEvidenceClass
    clock_profile: ClockProfile
    lease_policy_id: str
    lease_policy_version: str
    lease_ttl_microseconds: int
    maximum_in_flight_microseconds: int
    takeover_safety_microseconds: int

    def __post_init__(self) -> None:
        if (
            self.schema_id != CONFIGURATION_SCHEMA
            or self.operation not in ("restore", "integrity")
            or self.capture_evidence_class not in ("synthetic_fixture", "provider_https_read")
            or self.clock_profile not in ("host_unqualified", "explicit_simulation_time_model")
        ):
            raise ContinuousSimulationFactoryError("OFFLINE_CONFIGURATION_PROFILE_INVALID")
        require_identifier(self.owner_id, "offline worker owner")
        for value in (
            self.database_path,
            self.artifact_root,
            self.venue_database_path,
            self.venue_artifact_root,
        ):
            if (
                type(value) is not str
                or not Path(value).is_absolute()
                or any(part.startswith(".env") for part in Path(value).parts)
            ):
                raise ContinuousSimulationFactoryError("OFFLINE_PRIVATE_PATH_REQUIRED")
        for ref, schema in (
            (self.inputs, CONTINUOUS_REQUEST_SCHEMA),
            (self.venue_model, "venue-model/1"),
            (self.producer_map, PRODUCER_MAP_SCHEMA),
        ):
            if type(ref) is not ContinuousEvidenceRef or ref.schema_id != schema:
                raise ContinuousSimulationFactoryError("OFFLINE_CONFIGURATION_REFERENCE_INVALID")
            ref.__post_init__()
        if sum(ref.object_ref.byte_count for ref in self.references) > MAX_CONTINUOUS_OBJECT_BYTES:
            raise ContinuousSimulationFactoryError("OFFLINE_CONFIGURATION_OBJECT_BOUND")
        self.lease_policy()

    @property
    def references(self) -> tuple[ContinuousEvidenceRef, ...]:
        return self.inputs, self.venue_model, self.producer_map

    def lease_policy(self) -> AccountLeasePolicy:
        values = (
            self.lease_ttl_microseconds,
            self.maximum_in_flight_microseconds,
            self.takeover_safety_microseconds,
        )
        if any(type(value) is not int or not 0 < value <= 86_400_000_000 for value in values):
            raise ContinuousSimulationFactoryError("OFFLINE_LEASE_POLICY_INVALID")
        return AccountLeasePolicy(
            self.lease_policy_id,
            self.lease_policy_version,
            *(timedelta(microseconds=value) for value in values),
        )


def load_continuous_configuration(path: Path) -> ContinuousSimulationConfiguration:
    try:
        if (
            not isinstance(path, Path)
            or not path.is_absolute()
            or path.suffix != ".json"
            or any(part.startswith(".env") for part in path.parts)
        ):
            raise ValueError("configuration path")
        payload = _private_read(path, 64 * 1024)
        value = codec.decode_record(payload, ContinuousSimulationConfiguration)
        if codec.encode_record(value) != payload:
            raise ValueError("noncanonical")
        value.__post_init__()
        return value
    except Exception:
        raise ContinuousSimulationFactoryError("OFFLINE_CONFIGURATION_INVALID") from None


def _existing_private(path: str, *, directory: bool) -> Path:
    value = Path(path)
    resolved = value.resolve(strict=True)
    info = value.lstat()
    if (
        resolved != value
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
        or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        or (not directory and info.st_nlink != 1)
    ):
        raise ContinuousSimulationFactoryError("OFFLINE_EXISTING_PRIVATE_STORAGE_REQUIRED")
    return resolved


class _ActualClock:
    @staticmethod
    def now() -> datetime:
        return datetime.now(UTC)


class ContinuousSimulationFactory:
    """One actual acquired lease, fixed retained stores and historical-only auth."""

    def __init__(
        self,
        configuration: ContinuousSimulationConfiguration,
        *,
        account_id: str,
        stop_requested: Callable[[], bool],
        lifecycle: ContinuousWorkerLifecycle | None = None,
    ) -> None:
        self.configuration, self.stop_requested = configuration, stop_requested
        self.engine: Engine | None = None
        self.venue_engine: Engine | None = None
        self.lease: AccountLease | None = None
        try:
            if lifecycle is not None:
                from apps.trader.continuous_process_lifecycle import ContinuousWorkerLifecycle

                if type(lifecycle) is not ContinuousWorkerLifecycle:
                    raise ValueError("actual worker lifecycle required")
            if type(configuration) is not ContinuousSimulationConfiguration:
                raise ValueError("configuration type")
            configuration.__post_init__()
            self._original_configuration = codec.encode_record(configuration)
            self._check_stop()
            database = _existing_private(configuration.database_path, directory=False)
            venue_database = _existing_private(configuration.venue_database_path, directory=False)
            objects = _existing_private(configuration.artifact_root, directory=True)
            venue_objects = _existing_private(configuration.venue_artifact_root, directory=True)
            if database == venue_database or objects == venue_objects:
                raise ContinuousSimulationFactoryError("OFFLINE_INDEPENDENT_STORAGE_REQUIRED")
            self.artifacts = LocalResearchArtifactStore(objects)
            self.inputs = self._read(configuration.inputs, ContinuousEngineInputs)
            model = self._read(configuration.venue_model, VenueModel)
            producer_map = self._read(configuration.producer_map, RuntimeProducerMap)
            spec = self.inputs.spec
            if (
                account_id != spec.account_id
                or model.instruments != spec.instruments
                or (spec.source_mode == "recorded_as_observed")
                != (configuration.capture_evidence_class == "provider_https_read")
                or (
                    configuration.benchmark_instrument_id is not None
                    and dict(spec.instruments).get(configuration.benchmark_instrument_id) != "SPY"
                )
            ):
                raise ContinuousSimulationFactoryError("OFFLINE_RETAINED_CONFIGURATION_DIFFERS")
            self.scope = ContinuousAccountScope(
                spec.account_id, spec.account_binding_sha256, spec.deployment_id
            )
            # URI mode=rw refuses to create a replacement database if the file vanishes.
            url = sa.URL.create(
                "sqlite+pysqlite", database=database.as_uri(), query={"mode": "rw", "uri": "true"}
            )
            self.engine = create_database_engine(
                url.render_as_string(hide_password=True), research_sqlite_wal=True
            )
            with self.engine.connect() as connection:
                versions = tuple(
                    connection.scalars(sa.text("SELECT version_num FROM alembic_version"))
                )
            if versions != (EXPECTED_SCHEMA_REVISION,):
                raise ContinuousSimulationFactoryError("OFFLINE_EXISTING_SCHEMA_REQUIRED")
            self.clock = _ActualClock()
            self.controls = SqlOperationalControlRepository(engine=self.engine, clock=self.clock)
            self._require_halted()
            self.coordinator = SqlAccountCoordinator(
                account_id=account_id,
                authority=SqlAccountCoordinatorAuthority(
                    engine=self.engine, policy=configuration.lease_policy(), clock=self.clock
                ),
            )
            instance_nonce = uuid4().hex
            instance_owner = "offline-owner-" + content_digest(
                (configuration.owner_id, os.getpid(), instance_nonce)
            )
            self.lease = self.coordinator.acquire(instance_owner)
            if lifecycle is not None:
                lifecycle.acquired(
                    configuration=configuration,
                    scope=self.scope,
                    lease=self.lease,
                    instance_nonce=instance_nonce,
                    engine=self.engine,
                )
            self._check_stop()
            accounting = PersonalAccounting()
            strategy = ReferenceStrategy(
                reserve_fraction=spec.risk_policy.adverse_reserve_fraction,
                fee_per_share=spec.risk_policy.fee_per_share,
            )
            forward = SqlContinuousForwardSources(
                self.engine,
                artifacts=self.artifacts,
                codec=codec,
                evidence_class=configuration.capture_evidence_class,
            )
            epoch = f"offline-restore:{instance_nonce}:{os.getpid()}"
            sampler = (
                RuntimeClockSampler(scope=self.scope)
                if configuration.clock_profile == "host_unqualified"
                else RuntimeClockSampler.simulation_model(
                    scope=self.scope,
                    utc_now=self.clock.now,
                    monotonic_now_ns=time.monotonic_ns,
                    epoch_provider=lambda: epoch,
                )
            )
            operating = SqlRuntimeOperatingEvidence(
                self.engine,
                artifacts=self.artifacts,
                codec=codec,
                clock_sampler=sampler,
                journal=SqlDurableJournal(
                    self.engine, codec=codec, record_types={CLOCK_SCHEMA: RuntimeClockObservation}
                ),
            )
            self.runtime_sources = SqlContinuousRuntimeSources(
                self.engine,
                coordinator=self.coordinator,
                journal=SqlDurableJournal(
                    self.engine,
                    codec=codec,
                    record_types={RUNTIME_SOURCE_SCHEMA: ContinuousRuntimeSourceDescriptor},
                ),
                artifacts=self.artifacts,
                codec=codec,
                forward_sources=forward,
                operating=operating,
                accounting=accounting,
                strategy=strategy,
                venue_model=model,
                venue_reference=VenueSourceReference(
                    model.producer, model.semantic_sha256, configuration.venue_model.object_ref
                ),
                producer_map=producer_map,
                benchmark_instrument_id=configuration.benchmark_instrument_id,
                current_fence=lambda: self._fence(),
            )
            self.daily = SqlDailyRuntimeRisk(
                self.engine,
                coordinator=self.coordinator,
                codec=codec,
                producers=self.runtime_sources,
                accounting=accounting,
            )
            preparer = ContinuousAccountTransitionPreparer(
                accounting=accounting, strategy=strategy, runtime_evidence=self.runtime_sources
            )
            reconciliation_scope = ReconciliationScope(
                account_id,
                model.venue_id,
                "stateful_simulation",
                spec.account_binding_sha256,
                "stateful_simulation",
            )
            venue_sources = SqlContinuousVenueSources(
                self.engine,
                artifacts=self.artifacts,
                codec=codec,
                resolver=VenueReconciliationResolver(
                    transition_resolver=ContinuousReconciliationTransitionResolver(
                        accounting=accounting
                    )
                ),
                scope=reconciliation_scope,
                model=model,
            )
            composer = SqlContinuousCommitComposer(
                self.engine,
                daily=self.daily,
                coordinator=self.coordinator,
                forward_sources=forward,
                artifacts=self.artifacts,
                codec=codec,
                producer_history=self.runtime_sources,
                fence=self._fence(),
                benchmark_instrument_id=configuration.benchmark_instrument_id,
                venue_sources=venue_sources,
                accounting=accounting,
            )
            self.account = SqlContinuousAccount(
                self.engine,
                coordinator=self.coordinator,
                journal=SqlDurableJournal(
                    self.engine,
                    codec=codec,
                    record_types={CONTINUOUS_COMMIT_SCHEMA: ContinuousAccountCommit},
                ),
                artifacts=self.artifacts,
                codec=codec,
                preparer=preparer,
                composer=composer,
            )
            self.runtime_sources.bind_stores(accounts=self.account, daily=self.daily)
            publisher = SqlContinuousReconciliationPublication(
                self.engine,
                account=self.account,
                composer=composer,
                coordinator=self.coordinator,
                sources=venue_sources,
                artifacts=self.artifacts,
                codec=codec,
                accounting=accounting,
            )
            self.runtime_sources.bind_reconciliation(publisher)
            self.runtime_sources.bind_observed_hold_sources(
                SqlContinuousObservedHoldSources(
                    self.engine,
                    accounts=self.account,
                    preparer=preparer,
                    venue_sources=venue_sources,
                    daily=self.daily,
                    artifacts=self.artifacts,
                    codec=codec,
                )
            )
            attempts = SqlContinuousRuntimeAttemptSources(
                self.engine,
                accounts=self.account,
                preparer=preparer,
                daily=self.daily,
                runtime_sources=self.runtime_sources,
                artifacts=self.artifacts,
                codec=codec,
            )
            self.runtime_sources.bind_attempt_sources(attempts)
            # Historical outcome sources retain the exact original delivery/venue
            # graph. Reconstruction never issues a completed first-send token and
            # never initializes, captures or writes the independent venue.
            venue_url = sa.URL.create(
                "sqlite+pysqlite",
                database=venue_database.as_uri(),
                query={"mode": "ro", "uri": "true"},
            )
            self.venue_engine = sa.create_engine(
                venue_url, poolclass=NullPool, connect_args={"timeout": 0.1}
            )
            self.delivery = SqlContinuousSimulationDelivery(
                publisher=SqlContinuousAttemptPublication(account=self.account), sources=attempts
            )
            self.venue = SqlStatefulVenue(
                self.venue_engine,
                model=model,
                artifacts=LocalResearchArtifactStore(venue_objects),
                codec=codec,
                accounting=accounting,
                verified_sources=self.delivery,
            )
            self.delivery.bind_venue(self.venue)
            self.outcomes = SqlContinuousAttemptOutcomeSources(
                attempts=attempts,
                venue=self.venue,
                capture=SqlVenueReconciliationCapture(
                    self.engine, artifacts=self.artifacts, codec=codec, clock=self.clock.now
                ),
                venue_sources=SqlContinuousVenueSources(
                    self.engine,
                    artifacts=self.artifacts,
                    codec=codec,
                    resolver=venue_sources.resolver,
                    scope=ReconciliationScope(
                        model.account_id,
                        model.venue_id,
                        "stateful_simulation",
                        self.runtime_sources.venue_reference.semantic_sha256_ref,
                        "stateful_simulation",
                    ),
                    model=model,
                ),
            )
            attempts.bind_outcome_sources(self.outcomes)
            self.commands = SqlRuntimeOwnerCommands(
                self.engine,
                codec=codec,
                authenticator=LocalRuntimeOwnerAuthenticator(
                    LocalOperatorSecurity(
                        enabled=False,
                        transport_is_loopback_scoped=False,
                        operator_id=configuration.owner_id,
                        configured_secret="",
                    )
                ),
            )
            owners = SqlRuntimeOwnerDependencies(
                self.engine,
                accounts=self.account,
                daily=self.daily,
                publisher=publisher,
                commands=self.commands,
                artifacts=self.artifacts,
                codec=codec,
            )
            self.runtime_sources.bind_owner_dependencies(owners)
            self.integrity = SqlContinuousIntegrityReader(
                self.engine,
                scope=self.scope,
                reconciliation_scope=reconciliation_scope,
                account=self.account,
                daily=self.daily,
                publisher=publisher,
                associations=SqlRuntimeOwnerAssociations(owner_dependencies=owners),
                fence=self._fence(),
                journals=(
                    self.account.journal,
                    publisher.journal,
                    venue_sources.journal,
                    forward.journal,
                    self.runtime_sources.journal,
                    operating.journal,
                    self.commands.journal,
                    attempts.dispatch_journal,
                ),
            )
            self._check_stop()
        except Exception:
            self.close()
            raise ContinuousSimulationFactoryError(
                "OFFLINE_FACTORY_INITIALIZATION_FAILED"
            ) from None

    def _fence(self) -> AccountFence:
        if self.lease is None:
            raise ContinuousSimulationFactoryError("OFFLINE_ACTUAL_LEASE_REQUIRED")
        return self.lease.fence

    def _check_stop(self) -> None:
        if self.stop_requested():
            raise ContinuousSimulationFactoryError("OFFLINE_OPERATION_STOPPED")

    def _read(self, reference: ContinuousEvidenceRef, expected: type[R]) -> R:
        payload = self.artifacts.read(reference.object_ref, max_bytes=MAX_CONTINUOUS_OBJECT_BYTES)
        value = codec.decode_record(payload, expected)
        if (
            len(payload),
            sha256(payload).hexdigest(),
            value.semantic_sha256,
            codec.encode_record(value),
        ) != (
            reference.object_ref.byte_count,
            reference.object_ref.object_sha256,
            reference.semantic_sha256,
            payload,
        ):
            raise ContinuousSimulationFactoryError("OFFLINE_RETAINED_OBJECT_DIFFERS")
        return value

    def _require_halted(self) -> None:
        control = self.controls.load(self.inputs.spec.account_id)
        if control is None or control.effective_state is not OperationalControlState.HALTED:
            raise ContinuousSimulationFactoryError("OFFLINE_EXISTING_HALTED_CONTROL_REQUIRED")

    def execute(self, *, operation_id: str) -> bytes:
        try:
            require_identifier(operation_id, "offline operation")
            if codec.encode_record(self.configuration) != self._original_configuration:
                raise ContinuousSimulationFactoryError("OFFLINE_ORIGINAL_CONFIGURATION_CHANGED")
            self._check_stop()
            self._require_halted()
            assert self.engine is not None
            reader = self.integrity
            with reader.original_factory_read() as actual:
                self._check_stop()
                reader.require_original_factory_values()
                if actual is None or actual.checkpoint.inputs != self.inputs:
                    raise ContinuousSimulationFactoryError("OFFLINE_ACTUAL_BOOTSTRAP_REQUIRED")
                if (
                    not actual.checkpoint.state.cash_flows
                    or actual.checkpoint.state.cash_flows[0]
                    != self.runtime_sources.venue_model.initial_cash_flow
                ):
                    raise ContinuousSimulationFactoryError("OFFLINE_ORIGINAL_CONTRIBUTION_DIFFERS")
                current = reader.read_original_daily_for_factory()
                if current.assignment is None:
                    raise ContinuousSimulationFactoryError(
                        "OFFLINE_ORIGINAL_SIGNED_ASSIGNMENT_REQUIRED"
                    )
                self._require_halted()
                self._check_stop()
                self.coordinator.revalidate(self._fence())
                reader.require_original_factory_values()
                result = {
                    "schema": "continuous-offline-result/1",
                    "operation_id": operation_id,
                    "operation": self.configuration.operation,
                    "status": "integrity_verified"
                    if self.configuration.operation == "integrity"
                    else "restored",
                    "account_id": self.scope.account_id,
                    "sequence": actual.receipt.commit.sequence,
                    "commit_sha256": actual.receipt.commit.semantic_sha256,
                    "checkpoint_sha256": actual.checkpoint.semantic_sha256,
                    "assignment_generation": current.assignment.generation,
                    "assignment_sha256": current.assignment.semantic_sha256,
                }
                payload = (
                    json.dumps(result, sort_keys=True, separators=(",", ":")).encode("ascii")
                    + b"\n"
                )
                if len(payload) > 16 * 1024:
                    raise ContinuousSimulationFactoryError("OFFLINE_RESULT_BOUND")
            # The values above remain provisional through terminal validation
            # and cleanup. Stop can arrive during that work as well.
            self._check_stop()
            return payload
        except Exception:
            raise ContinuousSimulationFactoryError("OFFLINE_OPERATION_FAILED") from None

    def close(self) -> AccountLeaseRelease | None:
        try:
            if self.lease is not None:
                return self.coordinator.release(self.lease.fence)
            return None
        except Exception:
            raise ContinuousSimulationFactoryError("OFFLINE_LEASE_RELEASE_FAILED") from None
        finally:
            self.lease = None
            try:
                if self.venue_engine is not None:
                    self.venue_engine.dispose()
                    self.venue_engine = None
            finally:
                if self.engine is not None:
                    self.engine.dispose()
                    self.engine = None


def run_continuous_operation(
    request: ContinuousProcessRequest,
    *,
    stop_requested: Callable[[], bool],
    lifecycle: ContinuousWorkerLifecycle | None = None,
) -> bytes:
    try:
        if type(request) is not ContinuousProcessRequest:
            raise ValueError("request type")
        request.__post_init__()
        if stop_requested():
            raise ContinuousSimulationFactoryError("OFFLINE_OPERATION_STOPPED")
        configuration = load_continuous_configuration(request.configuration_path)
        if (
            request.objects
            and tuple(ref.object_ref for ref in configuration.references) != request.objects
        ):
            raise ContinuousSimulationFactoryError("OFFLINE_REQUEST_OBJECTS_DIFFER")
        factory = ContinuousSimulationFactory(
            configuration,
            account_id=request.account_id,
            stop_requested=stop_requested,
            lifecycle=lifecycle,
        )
        try:
            payload = factory.execute(operation_id=request.operation_id)
            if lifecycle is not None:
                lifecycle.begin_release(payload)
        except BaseException:
            factory.close()
            raise
        release = factory.close()
        if lifecycle is not None:
            if type(release) is not AccountLeaseRelease:
                raise ContinuousSimulationFactoryError("OFFLINE_ACTUAL_RELEASE_REQUIRED")
            lifecycle.completed(payload, release=release)
        return payload
    except Exception:
        raise ContinuousSimulationFactoryError("OFFLINE_OPERATION_FAILED") from None
