"""Export selected synthetic state for the existing HALTED offline factory.

This same-process join retains only the original producer map. It returns a
configuration value, not a recovery result or an execution permission. The caller
owns private configuration-file publication and its current lease's release.
No stores, schema, permissions, authentication, assignments or leases are created.
"""

from datetime import timedelta
from hashlib import sha256
from pathlib import Path

from apps.trader.continuous_simulation_factory import (
    PRODUCER_MAP_SCHEMA,
    ContinuousSimulationConfiguration,
    _existing_private,
)
from apps.trader.synthetic_initial_selection import _require_owners
from apps.trader.synthetic_session_genesis import (
    SyntheticSessionGenesis,
    SyntheticSessionOwners,
    _database_path,
    _require_genesis_owner_graph,
)
from packages.adapters.research_artifacts_v2 import LocalResearchArtifactStore
from packages.application import personal_codec as codec
from packages.domain.account_coordinator import AccountLease, AccountLeasePolicy
from packages.domain.continuous_persistence_contracts import (
    MAX_CONTINUOUS_OBJECT_BYTES,
    ContinuousEvidenceRef,
)
from packages.domain.operational_control import OperationalControlState
from packages.domain.personal_contracts import content_digest
from packages.domain.research_job_contracts import ObjectRef, require_identifier
from packages.persistence.database import _repeatable_read_transaction
from packages.persistence.runtime_owner_associations import SqlRuntimeOwnerAssociations


def _require_paths(
    genesis: SyntheticSessionGenesis,
    *,
    database_path: Path,
    artifact_root: Path,
    venue_database_path: Path,
    venue_artifact_root: Path,
) -> None:
    paths = (database_path, artifact_root, venue_database_path, venue_artifact_root)
    if any(
        not isinstance(path, Path)
        or not path.is_absolute()
        or any(part.startswith(".env") for part in path.parts)
        for path in paths
    ):
        raise ValueError("EXPLICIT_PRIVATE_SYNTHETIC_STORAGE_REQUIRED")
    for path, directory in zip(paths, (False, True, False, True), strict=True):
        _existing_private(str(path), directory=directory)
    if database_path.samefile(venue_database_path) or artifact_root.samefile(venue_artifact_root):
        raise ValueError("INDEPENDENT_SYNTHETIC_STORAGE_REQUIRED")
    account_artifacts = genesis.runtime_sources.artifacts
    venue_artifacts = genesis.venue.artifacts
    if (
        not isinstance(account_artifacts, LocalResearchArtifactStore)
        or type(account_artifacts) is not LocalResearchArtifactStore
        or not isinstance(venue_artifacts, LocalResearchArtifactStore)
        or type(venue_artifacts) is not LocalResearchArtifactStore
    ):
        raise ValueError("ORIGINAL_SYNTHETIC_STORAGE_BINDINGS_REQUIRED")
    if (
        _database_path(genesis.account.engine) != database_path
        or _database_path(genesis.venue.journal._engine) != venue_database_path
        or account_artifacts._root != artifact_root
        or venue_artifacts._root != venue_artifact_root
    ):
        raise ValueError("ORIGINAL_SYNTHETIC_STORAGE_BINDINGS_REQUIRED")


def export_synthetic_offline_configuration(
    genesis: SyntheticSessionGenesis,
    *,
    owners: SyntheticSessionOwners,
    lease: AccountLease,
    owner_id: str,
    database_path: Path,
    artifact_root: Path,
    venue_database_path: Path,
    venue_artifact_root: Path,
) -> ContinuousSimulationConfiguration:
    """Describe one original selected account; preserve all later factory checks.

    Every path must already be canonical, private, independent and bound to the
    supplied original stores. Current C1, complete disabled B and its historical
    signed association are authenticated before retaining the producer map and
    rechecked afterward. Ordinary coordinator validation may update a watermark.
    A failed final check leaves the immutable map for inspection, not adoption.

    The caller must release its setup lease before the factory's first load.
    That factory uses a new actual-time recovery lease; historical modeled times
    remain unchanged. This value supplies no active-workflow clock bridge.
    """
    _require_genesis_owner_graph(genesis)
    paths = dict(
        database_path=database_path,
        artifact_root=artifact_root,
        venue_database_path=venue_database_path,
        venue_artifact_root=venue_artifact_root,
    )
    # Path rejection precedes even the coordinator's ordinary watermark update.
    _require_paths(genesis, **paths)
    require_identifier(owner_id, "synthetic offline owner")
    _require_owners(genesis, owners, lease)
    policy = owners.account.coordinator._authority.policy
    if (
        type(policy) is not AccountLeasePolicy
        or policy.lease_ttl != timedelta(seconds=60)
        or policy.maximum_in_flight_duration != timedelta(seconds=5)
        or policy.takeover_safety_interval != timedelta(seconds=10)
        or policy.semantic_sha256 != genesis.lease.policy_sha256
        or policy.semantic_sha256 != lease.policy_sha256
    ):
        raise ValueError("ORIGINAL_SYNTHETIC_LEASE_POLICY_REQUIRED")
    restored = owners.account.restore(genesis.scope)
    if (
        restored is None
        or restored.receipt != genesis.restored.receipt
        or restored.checkpoint != genesis.restored.checkpoint
    ):
        raise ValueError("OFFLINE_SYNTHETIC_ORIGINAL_C1_REQUIRED")
    owners.account.require_resolved(restored)
    current = owners.daily.resolve_snapshot(
        owners.daily.read_snapshot(account_id=genesis.scope.account_id, fence=lease.fence)
    )
    assignment = current.assignment
    spec = restored.checkpoint.inputs.spec
    if (
        assignment is None
        or current.assignment_rows != (assignment,)
        or assignment.account_id != genesis.scope.account_id
        or assignment.account_binding_sha256 != genesis.scope.account_binding_sha256
        or assignment.generation != 1
        or assignment.previous_assignment_sha256 is not None
        or assignment.enabled_for_new_exposure is not False
        or assignment.live_authorized is not False
        or assignment.policy != spec.risk_policy
        or assignment.strategy != spec.strategy
        or assignment.configuration_sha256 != content_digest(spec.strategy_configuration)
        or assignment.instrument_symbols != spec.instruments
        or assignment.producer_map_sha256 != owners.runtime.producer_map.semantic_sha256
        or current.admissions
        or current.obligations.bindings
        or current.attempts
        or current.attempt_envelopes
        or current.observed_groups
        or current.control != genesis.control
        or current.control is None
        or current.control.effective_state is not OperationalControlState.HALTED
    ):
        raise ValueError("OFFLINE_SYNTHETIC_DISABLED_INITIAL_SELECTION_REQUIRED")
    associations = SqlRuntimeOwnerAssociations(owner_dependencies=owners.owners)
    association = associations.read(genesis.scope, current=current, assignment_generation=1)
    associations.require_association(association)
    if (
        association.dependencies.previous != genesis.restored.receipt
        or association.dependencies.proposed != assignment
        or association.dependencies.previous_assignment_sha256 is not None
        or association.canonical.receipt != genesis.restored.receipt
        or association.checkpoint != genesis.restored.checkpoint
        or association.prefix.before_assignment is not None
        or association.prefix.after_assignment != assignment
        or association.reconciliation is not None
    ):
        raise ValueError("OFFLINE_SYNTHETIC_ORIGINAL_SELECTION_HISTORY_REQUIRED")
    inputs = genesis.restored.receipt.commit.request
    model = owners.runtime.venue_model
    venue = ContinuousEvidenceRef(
        "venue-model/1", owners.runtime.venue_reference.object_ref, model.semantic_sha256
    )
    artifacts = owners.runtime.artifacts
    for reference, value in ((inputs, restored.checkpoint.inputs), (venue, model)):
        if reference.semantic_sha256 != value.semantic_sha256 or artifacts.read(
            reference.object_ref, max_bytes=MAX_CONTINUOUS_OBJECT_BYTES
        ) != codec.encode_record(value):
            raise ValueError("OFFLINE_SYNTHETIC_ORIGINAL_OBJECT_DIFFERS")
    payload = codec.encode_record(owners.runtime.producer_map)
    # Derive the content-addressed locator before I/O so every original object
    # and configuration bound can reject without leaving a newly retained map.
    map_reference = ObjectRef(sha256(payload).hexdigest(), len(payload))
    result = ContinuousSimulationConfiguration(
        schema_id="continuous-offline-configuration/1",
        operation="restore",
        owner_id=owner_id,
        database_path=str(database_path),
        artifact_root=str(artifact_root),
        venue_database_path=str(venue_database_path),
        venue_artifact_root=str(venue_artifact_root),
        inputs=inputs,
        venue_model=venue,
        producer_map=ContinuousEvidenceRef(
            PRODUCER_MAP_SCHEMA, map_reference, owners.runtime.producer_map.semantic_sha256
        ),
        benchmark_instrument_id=owners.runtime.benchmark_instrument_id,
        capture_evidence_class=owners.runtime.forward_sources.evidence_class,
        clock_profile=owners.runtime.operating.clock_sampler.profile,
        lease_policy_id=policy.policy_id,
        lease_policy_version=policy.policy_version,
        lease_ttl_microseconds=60_000_000,
        maximum_in_flight_microseconds=5_000_000,
        takeover_safety_microseconds=10_000_000,
    )
    if len(codec.encode_record(result)) > 64 * 1024:
        raise ValueError("OFFLINE_SYNTHETIC_CONFIGURATION_BOUND")
    _require_owners(genesis, owners, lease)
    _require_paths(genesis, **paths)
    if artifacts.put(payload, max_bytes=MAX_CONTINUOUS_OBJECT_BYTES) != map_reference:
        raise ValueError("OFFLINE_SYNTHETIC_PRODUCER_MAP_REFERENCE_DIFFERS")
    with _repeatable_read_transaction(owners.account.engine) as connection:
        associations.recheck_in_transaction(connection, association)
        owners.account.recheck_in_transaction(connection, restored, require_current=True)
        owners.daily.recheck_snapshot_in_transaction(connection, current, fence=lease.fence)
    _require_owners(genesis, owners, lease)
    _require_paths(genesis, **paths)
    return result
