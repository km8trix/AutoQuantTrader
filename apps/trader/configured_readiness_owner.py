"""Compose one cold, HALTED synthetic readiness owner from explicit private paths.

Construction admits argument data only. The original owner thread loads existing
configuration, holds the instance guard, reconstructs the original factory and
performs full readiness checks. It owns the sole original close/release attempt;
no execution, initialization, migration, renewal, adoption or retry is supplied.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from threading import Event

from sqlalchemy import Engine

from apps.trader.continuous_readiness_owner import (
    ContinuousReadinessOwner,
    ReadinessOwnerLimits,
    _ReadinessRuntime,
)
from apps.trader.continuous_simulation_factory import (
    ContinuousSimulationConfiguration,
    ContinuousSimulationFactory,
    _existing_private,
    load_continuous_configuration,
)
from apps.trader.readiness_store_binding import _StoreIdentityValues, _validated_store_identity
from apps.trader.synthetic_session_genesis import _database_path
from packages.application import personal_codec
from packages.application.personal_runtime import LocalInstanceGuard
from packages.domain.account_coordinator import AccountLease, AccountLeaseRelease
from packages.domain.research_job_contracts import require_identifier

_EVENT_IS_SET = Event.is_set
_DEFAULT_LIMITS = ReadinessOwnerLimits()


def _argument_path(value: str) -> Path:
    # Pure lexical admission: no resolve/stat/open on the calling thread.
    if type(value) is not str:
        raise ValueError("CONFIGURED_READINESS_ARGUMENT_INVALID")
    path = Path(value)
    if not path.is_absolute() or any(part.startswith(".env") for part in path.parts):
        raise ValueError("CONFIGURED_READINESS_ARGUMENT_INVALID")
    return path


def _stopped(event: Event) -> bool:
    # No caller-supplied callback or overridden Event method is invoked.
    if type(event) is not Event:
        raise ValueError("CONFIGURED_READINESS_STOP_INVALID")
    observed = _EVENT_IS_SET(event)
    if type(observed) is not bool:
        raise ValueError("CONFIGURED_READINESS_STOP_INVALID")
    return observed


def _require_running(event: Event) -> None:
    if _stopped(event):
        raise ValueError("CONFIGURED_READINESS_STOPPED")


def _overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _preflight(configuration_path: Path, lock: Path) -> ContinuousSimulationConfiguration:
    # The same original private-path and profile predicates used by the offline
    # recovery boundary run here directly, without its process/request workflow.
    _existing_private(str(configuration_path), directory=False)
    _existing_private(str(lock.parent), directory=True)
    if lock.exists() or lock.is_symlink():
        _existing_private(str(lock), directory=False)
    configuration = load_continuous_configuration(configuration_path)
    if (
        type(configuration) is not ContinuousSimulationConfiguration
        or configuration.operation != "restore"
        or configuration.capture_evidence_class != "synthetic_fixture"
        or configuration.clock_profile != "explicit_simulation_time_model"
        or (
            configuration.lease_ttl_microseconds,
            configuration.maximum_in_flight_microseconds,
            configuration.takeover_safety_microseconds,
        )
        != (60_000_000, 5_000_000, 10_000_000)
    ):
        raise ValueError("CONFIGURED_READINESS_CONFIGURATION_INVALID")
    database = _existing_private(configuration.database_path, directory=False)
    venue_database = _existing_private(configuration.venue_database_path, directory=False)
    objects = _existing_private(configuration.artifact_root, directory=True)
    venue_objects = _existing_private(configuration.venue_artifact_root, directory=True)
    if database.samefile(venue_database) or _overlap(objects, venue_objects):
        raise ValueError("CONFIGURED_READINESS_CONFIGURATION_INVALID")
    protected = (configuration_path, database, venue_database, objects, venue_objects)
    if lock in protected or lock.is_relative_to(objects) or lock.is_relative_to(venue_objects):
        raise ValueError("CONFIGURED_READINESS_CONFIGURATION_INVALID")
    return configuration


@contextmanager
def _held_guard(path: Path) -> Iterator[LocalInstanceGuard]:
    guard = LocalInstanceGuard(path)
    guard.__enter__()
    primary: BaseException | None = None
    try:
        yield guard
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            if primary is None:
                guard.__exit__(None, None, None)
            else:
                guard.__exit__(type(primary), primary, primary.__traceback__)
        except BaseException as cleanup:
            if primary is not None:
                raise BaseExceptionGroup(
                    "configured readiness and guard cleanup failed", [primary, cleanup]
                ) from None
            raise


def _require_release(
    release: AccountLeaseRelease | None,
    lease: AccountLease | None,
    original_sha256: str | None,
) -> None:
    # close already disposed both engines. Do not reopen them to inspect a head,
    # replay an operation, or infer a release from a cleared factory field.
    if type(release) is not AccountLeaseRelease or type(lease) is not AccountLease:
        raise ValueError("CONFIGURED_READINESS_RELEASE_INVALID")
    release._validate()
    lease.__post_init__()
    if (
        lease.semantic_sha256 != original_sha256
        or release.fence != lease.fence
        or release.lease_sha256 != original_sha256
        or release.policy_sha256 != lease.policy_sha256
        or not lease.acquired_at <= release.released_at < lease.expires_at
    ):
        raise ValueError("CONFIGURED_READINESS_RELEASE_INVALID")


def _database_identity(path: str) -> tuple[str, int, int]:
    canonical = _existing_private(path, directory=False)
    observed = canonical.lstat()
    if (
        type(observed.st_dev) is not int
        or type(observed.st_ino) is not int
        or observed.st_dev < 0
        or observed.st_ino < 0
    ):
        raise ValueError("CONFIGURED_READINESS_STORE_IDENTITY_DIFFERS")
    return str(canonical), observed.st_dev, observed.st_ino


def _store_identity(
    factory: ContinuousSimulationFactory,
    runtime: _ReadinessRuntime,
    configuration: ContinuousSimulationConfiguration,
    *,
    account_id: str,
    baseline: tuple[str, int, int],
) -> _StoreIdentityValues:
    engine = factory.engine
    if (
        type(engine) is not Engine
        or runtime.reader.engine is not engine
        or runtime.reader.scope is not factory.scope
        or factory.scope.account_id != account_id
        or factory.configuration is not configuration
        or str(_database_path(engine)) != baseline[0]
        or _database_identity(configuration.database_path) != baseline
    ):
        raise ValueError("CONFIGURED_READINESS_STORE_IDENTITY_DIFFERS")
    payload = factory._original_configuration
    if type(payload) is not bytes or personal_codec.encode_record(configuration) != payload:
        raise ValueError("CONFIGURED_READINESS_STORE_IDENTITY_DIFFERS")
    scope = runtime.reader.scope
    identity = _validated_store_identity(
        (
            scope.account_id,
            scope.account_binding_sha256,
            scope.stream_id,
            *baseline,
            sha256(payload).hexdigest(),
        )
    )
    if (
        str(_database_path(engine)) != baseline[0]
        or _database_identity(configuration.database_path) != baseline
    ):
        raise ValueError("CONFIGURED_READINESS_STORE_IDENTITY_DIFFERS")
    return identity


def _configured_runtime_generator(
    *,
    configuration_file: Path,
    lock_path: Path,
    account_id: str,
    stop_event: Event,
) -> Iterator[_ReadinessRuntime]:
    _require_running(stop_event)
    configuration = _preflight(configuration_file, lock_path)
    _require_running(stop_event)
    with _held_guard(lock_path) as guard:
        _require_running(stop_event)
        # Observe the selected file before the factory opens any Engine;
        # a post-factory observation alone could adopt a one-way replacement.
        database_baseline = _database_identity(configuration.database_path)
        # A failed constructor already owns its partial cleanup, including
        # the explicit unknown-acquisition group. No returned object exists
        # to close again, inspect, adopt or use as guessed release authority.
        factory = ContinuousSimulationFactory(
            configuration,
            account_id=account_id,
            stop_requested=lambda: _stopped(stop_event),
        )
        lease = factory.lease
        original_sha256: str | None = None
        primary: BaseException | None = None
        try:
            if type(lease) is not AccountLease:
                raise ValueError("CONFIGURED_READINESS_ORIGINAL_LEASE_REQUIRED")
            lease.__post_init__()
            original_sha256 = lease.semantic_sha256
            venue_engine = factory.venue_engine
            if type(venue_engine) is not Engine:
                raise ValueError("CONFIGURED_READINESS_ORIGINAL_VENUE_REQUIRED")
            _require_running(stop_event)
            runtime = _ReadinessRuntime(
                reader=factory.integrity,
                lease=lease,
                guard=guard,
                venue=factory.venue,
                venue_engine=venue_engine,
                stop_event=stop_event,
            )
            identity = _store_identity(
                factory,
                runtime,
                configuration,
                account_id=account_id,
                baseline=database_baseline,
            )
            runtime._bind_store_identity(identity)
            if _database_identity(configuration.database_path) != database_baseline:
                raise ValueError("CONFIGURED_READINESS_STORE_IDENTITY_DIFFERS")
            _require_running(stop_event)
            yield runtime
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                release = factory.close()
                _require_release(release, lease, original_sha256)
            except BaseException as cleanup:
                if primary is not None:
                    raise BaseExceptionGroup(
                        "configured readiness and factory cleanup failed", [primary, cleanup]
                    ) from None
                raise


_CONFIGURED_RUNTIME_GENERATOR = _configured_runtime_generator


def create_configured_readiness_owner(
    *,
    configuration_path: str,
    account_id: str,
    instance_lock: str,
    limits: ReadinessOwnerLimits = _DEFAULT_LIMITS,
) -> ContinuousReadinessOwner:
    """Return an unstarted owner; perform no filesystem or clock I/O here."""
    configuration_file = _argument_path(configuration_path)
    lock_path = _argument_path(instance_lock)
    if configuration_file.suffix != ".json" or type(account_id) is not str:
        raise ValueError("CONFIGURED_READINESS_ARGUMENT_INVALID")
    require_identifier(account_id, "configured readiness account")
    if type(limits) is not ReadinessOwnerLimits:
        raise ValueError("CONFIGURED_READINESS_ARGUMENT_INVALID")
    limits.__post_init__()
    runtime_generator = _CONFIGURED_RUNTIME_GENERATOR
    if _configured_runtime_generator is not runtime_generator:
        raise RuntimeError("CONFIGURED_READINESS_RUNTIME_BINDING_CHANGED")

    @contextmanager
    def open_runtime(stop_event: Event) -> Iterator[_ReadinessRuntime]:
        if _configured_runtime_generator is not runtime_generator:
            raise RuntimeError("CONFIGURED_READINESS_RUNTIME_BINDING_CHANGED")
        yield from runtime_generator(
            configuration_file=configuration_file,
            lock_path=lock_path,
            account_id=account_id,
            stop_event=stop_event,
        )

    return ContinuousReadinessOwner(_open_runtime=open_runtime, limits=limits)
