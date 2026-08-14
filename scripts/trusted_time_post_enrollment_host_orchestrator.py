"""Execute one exact approved post-enrollment trusted-time start.

This is the sole supported host composition for the Phase 6D post-enrollment
controller.  It accepts only a content-addressed approval artifact and the
dedicated owner-only runtime environment file.  Every mutable operation runs
under the topology issuer's single global flock and its one suspend-aware
choreography lease.  The executor grants no shutdown, readiness, exposure, or
trading authority.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Never


def _require_isolated_cli_source_runtime(
    *,
    expected_relative_path: Path,
    module_file: str = __file__,
) -> Path:
    """Require canonical source in an isolated, non-reusable Python runtime."""

    try:
        repository_root = Path.cwd()
        expected_source = repository_root / expected_relative_path
        actual_source = Path(os.path.abspath(module_file))
        source_metadata = expected_source.lstat()
        canonical_root = repository_root.resolve(strict=True)
        canonical_source = expected_source.resolve(strict=True)
        runtime_prefix = Path(sys.prefix).resolve(strict=True)
        base_prefix = Path(sys.base_prefix).resolve(strict=True)
        reusable_repository_venv = (canonical_root / ".venv").resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        raise RuntimeError("trusted-time post-enrollment CLI runtime attestation failed") from None
    if (
        repository_root != canonical_root
        or expected_source != canonical_source
        or actual_source != expected_source
        or not stat.S_ISREG(source_metadata.st_mode)
        or source_metadata.st_nlink != 1
        or sys.flags.isolated != 1
        or sys.flags.dont_write_bytecode != 1
        or sys.pycache_prefix != "/dev/null"
        or runtime_prefix in (base_prefix, reusable_repository_venv)
        or runtime_prefix.is_relative_to(reusable_repository_venv)
    ):
        raise RuntimeError("trusted-time post-enrollment CLI runtime attestation failed")
    for raw_path in sys.path:
        if not raw_path:
            continue
        try:
            candidate = Path(raw_path).resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            raise RuntimeError(
                "trusted-time post-enrollment CLI runtime attestation failed"
            ) from None
        if candidate == reusable_repository_venv or candidate.is_relative_to(
            reusable_repository_venv
        ):
            raise RuntimeError("trusted-time post-enrollment CLI runtime attestation failed")
    sys.path.insert(0, os.fspath(canonical_root))
    return canonical_root


def _require_repository_first_party_sources(repository_root: Path) -> None:
    """Require loaded first-party modules to be the exact reviewed sources."""

    for module_name, module in tuple(sys.modules.items()):
        if module_name.split(".", 1)[0] not in {"apps", "packages", "scripts"}:
            continue
        origin = getattr(module, "__file__", None)
        if type(origin) is not str:
            raise RuntimeError("trusted-time first-party source attestation failed")
        module_path = repository_root.joinpath(*module_name.split("."))
        expected_sources = {
            module_path.with_suffix(".py"),
            module_path / "__init__.py",
        }
        try:
            lexical_origin = Path(os.path.abspath(origin))
            canonical_origin = lexical_origin.resolve(strict=True)
            source_metadata = lexical_origin.lstat()
        except (OSError, RuntimeError, ValueError):
            raise RuntimeError("trusted-time first-party source attestation failed") from None
        if (
            lexical_origin != canonical_origin
            or lexical_origin not in expected_sources
            or lexical_origin.suffix != ".py"
            or "__pycache__" in lexical_origin.parts
            or not stat.S_ISREG(source_metadata.st_mode)
            or source_metadata.st_nlink != 1
        ):
            raise RuntimeError("trusted-time first-party source attestation failed")


_CLI_REPOSITORY_ROOT = (
    _require_isolated_cli_source_runtime(
        expected_relative_path=Path("scripts/trusted_time_post_enrollment_host_orchestrator.py")
    )
    if __name__ == "__main__"
    else None
)

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from apps.trusted_time_supervisor.config import (  # noqa: E402
    MAXIMUM_CHRONY_CONFIG_BYTES,
    MAXIMUM_DATABASE_CA_BYTES,
    decode_trusted_time_authority,
)
from apps.trusted_time_supervisor.head_anchor_config import (  # noqa: E402
    decode_trusted_time_head_anchor_auth_secret,
    decode_trusted_time_head_anchor_authority,
)
from packages.adapters.trusted_time.ed25519_anchor import (  # noqa: E402
    Ed25519TrustedTimeAnchorVerifier,
)
from packages.domain.trusted_time_enrollment_evidence import (  # noqa: E402
    TrustedTimeFirstEnrollmentIdentities,
    trusted_time_first_enrollment_identity_sha256,
)
from packages.domain.trusted_time_post_enrollment_start import (  # noqa: E402
    TrustedTimePostEnrollmentStartApproval,
)
from scripts.start_trusted_time_supervisor import (  # noqa: E402
    DATABASE_SECRET_ROOT,
    LocalDockerDaemonIdentity,
    MaterializedDatabaseSecret,
    MaterializedHeadAnchorInputs,
    TrustedTimeApprovedLaunch,
    TrustedTimeRuntimeConfiguration,
    _current_git_revision,
    _MaterializedRuntimeInputOwner,
    _minimal_docker_environment,
    _require_same_local_daemon,
    _validate_runtime_compose_payload,
    load_trusted_time_runtime_configuration,
    materialize_database_secret,
    materialize_trusted_time_head_anchor_inputs,
    qualify_local_docker_daemon,
    validate_materialized_database_secret,
    validate_materialized_trusted_time_head_anchor_inputs,
)
from scripts.start_trusted_time_supervisor import (  # noqa: E402
    ROOT as LAUNCHER_ROOT,
)
from scripts.trusted_time_post_enrollment_action_topology_fence import (  # noqa: E402
    prepare_post_enrollment_start_leased_claimed_action_topology_fence,
)
from scripts.trusted_time_post_enrollment_active_controller import (  # noqa: E402
    TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired,
    run_post_enrollment_start_active_controller,
)
from scripts.trusted_time_post_enrollment_active_controller_admission import (  # noqa: E402
    prepare_post_enrollment_start_active_controller_admission,
)
from scripts.trusted_time_post_enrollment_claimed_fence import (  # noqa: E402
    TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired,
    prepare_post_enrollment_start_leased_claimed_pre_release_fence,
)
from scripts.trusted_time_post_enrollment_controller_outcome import (  # noqa: E402
    RetainedTrustedTimePostEnrollmentStartControllerOutcome,
    TrustedTimePostEnrollmentStartControllerOutcomeStatus,
    revalidate_retained_post_enrollment_start_controller_outcome,
)
from scripts.trusted_time_post_enrollment_execution_admission import (  # noqa: E402
    DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
    LoadedTrustedTimePostEnrollmentExecutionApproval,
    _consume_post_enrollment_execution_admission,
    load_post_enrollment_execution_approval,
    reserve_post_enrollment_execution_attempt,
)
from scripts.trusted_time_post_enrollment_outcome import (  # noqa: E402
    RetainedTrustedTimePostEnrollmentStartOutcome,
    TrustedTimePostEnrollmentStartRecoveryOutcomeRetained,
    retain_post_enrollment_start_recovery_required_outcome,
    revalidate_retained_post_enrollment_start_outcome,
)
from scripts.trusted_time_post_enrollment_sequence_one_reauthentication import (  # noqa: E402
    TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer,
    prepare_trusted_time_post_enrollment_sequence_one_reauthentication_issuer,
)
from scripts.trusted_time_post_enrollment_sequence_two_verifier import (  # noqa: E402
    TrustedTimePostEnrollmentStartSequenceTwoReadOnlyConfiguration,
    TrustedTimePostEnrollmentStartSequenceTwoVerifier,
    prepare_trusted_time_post_enrollment_start_sequence_two_verifier,
)
from scripts.trusted_time_post_enrollment_topology_fence import (  # noqa: E402
    bind_post_enrollment_start_pre_claim_topology_fence,
)
from scripts.trusted_time_post_enrollment_topology_reader import (  # noqa: E402
    TrustedTimePostEnrollmentCreatedTopologyObservation,
    TrustedTimePostEnrollmentTopologyObservationIssuer,
    TrustedTimePostEnrollmentTopologyReaderError,
)
from scripts.verify_trusted_time_compose import (  # noqa: E402
    render_compose_model,
    validate_compose_model,
)
from scripts.verify_trusted_time_images import (  # noqa: E402
    DEFAULT_IMAGE_ADMISSION_ARTIFACT,
    IGNORED_ARTIFACT_ROOT,
    TrustedTimeImageAdmission,
    _head_reviewed_input_payload,
    verify_and_write_existing_image_admission,
)

ROOT = _CLI_REPOSITORY_ROOT or Path(__file__).resolve().parents[1]
if _CLI_REPOSITORY_ROOT is not None:
    _require_repository_first_party_sources(ROOT)
if ROOT != LAUNCHER_ROOT:
    raise RuntimeError("trusted-time post-enrollment source root is unavailable")

POST_ENROLLMENT_HOST_ORCHESTRATOR_CONTRACT_VERSION = (
    "phase6d-post-enrollment-start-host-orchestrator-v2"
)
POST_ENROLLMENT_HOST_ORCHESTRATOR_SERVICE = "trusted-time-post-enrollment-start-host-orchestrator"
POST_ENROLLMENT_HOST_ORCHESTRATOR_STATUS = "terminal_outcome_retained"

_CLOSED_AUTHORITY_FIELDS = (
    "active_controller_authorized",
    "alert_delivery_authorized",
    "arming_authorized",
    "authority_granted",
    "automatic_rearm_authorized",
    "automatic_resume_authorized",
    "broker_action_authorized",
    "claim_retention_authorized",
    "controller_execution_authorized",
    "database_secret_disclosed",
    "exposure_authorized",
    "live_trading_authorized",
    "new_exposure_authorized",
    "operational_control_authorized",
    "outcome_retention_authorized",
    "paper_trading_authorized",
    "persistent_start_authorized",
    "readiness_authorized",
    "rearm_authorized",
    "release_authorized",
    "retry_authorized",
    "runtime_start_authorized",
    "sequence_2_authorized",
    "shutdown_authorized",
    "source_start_authorized",
    "success_outcome_retention_authorized",
    "supervisor_start_authorized",
    "topology_mutation_authorized",
)


class TrustedTimePostEnrollmentHostOrchestratorRejected(RuntimeError):
    """The exact one-shot host execution could not be safely completed."""


@dataclass(frozen=True, slots=True)
class _RuntimeMaterials:
    database_url: str
    database_secret: MaterializedDatabaseSecret
    head_anchor_inputs: MaterializedHeadAnchorInputs
    sequence_two_configuration: TrustedTimePostEnrollmentStartSequenceTwoReadOnlyConfiguration

    @property
    def staged_paths(self) -> tuple[Path, Path, Path, Path]:
        return (
            self.database_secret.path,
            self.head_anchor_inputs.authority.path,
            self.head_anchor_inputs.auth_secret.path,
            self.head_anchor_inputs.signing_key.path,
        )


def _approved_launch(
    approval: TrustedTimePostEnrollmentStartApproval,
) -> TrustedTimeApprovedLaunch:
    if type(approval) is not TrustedTimePostEnrollmentStartApproval:
        raise TrustedTimePostEnrollmentHostOrchestratorRejected(
            "trusted-time post-enrollment approval is invalid"
        )
    approval.__post_init__()
    launch = approval.proposed_launch
    return TrustedTimeApprovedLaunch(
        git_revision=launch.git_revision,
        image_admission_sha256=launch.image_admission_sha256,
        source_image_id=launch.source_image_id,
        supervisor_image_id=launch.supervisor_image_id,
    )


def _read_reviewed_source_authority(revision: str) -> tuple[bytes, bytes, bytes]:
    try:
        authority_payload = _head_reviewed_input_payload(
            revision,
            "infra/trusted-time/source-authority.json",
        )
        chrony_payload = _head_reviewed_input_payload(
            revision,
            "infra/trusted-time/chrony.conf",
        )
        database_ca_payload = _head_reviewed_input_payload(
            revision,
            "packages/persistence/certs/supabase-prod-ca-2021.crt",
        )
        if (
            not authority_payload
            or not 1 <= len(chrony_payload) <= MAXIMUM_CHRONY_CONFIG_BYTES
            or not 1 <= len(database_ca_payload) <= MAXIMUM_DATABASE_CA_BYTES
        ):
            raise ValueError
    except BaseException:
        raise TrustedTimePostEnrollmentHostOrchestratorRejected(
            "trusted-time reviewed source authority is unavailable"
        ) from None
    return authority_payload, chrony_payload, database_ca_payload


def _build_read_only_configuration(
    *,
    approval: TrustedTimePostEnrollmentStartApproval,
    runtime: TrustedTimeRuntimeConfiguration,
) -> TrustedTimePostEnrollmentStartSequenceTwoReadOnlyConfiguration:
    if type(approval) is not TrustedTimePostEnrollmentStartApproval:
        raise TrustedTimePostEnrollmentHostOrchestratorRejected(
            "trusted-time post-enrollment approval is invalid"
        )
    approval.__post_init__()
    revision = approval.proposed_launch.git_revision
    source_authority, chrony_config, database_ca = _read_reviewed_source_authority(revision)
    deployment = decode_trusted_time_authority(
        source_authority,
        chrony_config_payload=chrony_config,
        database_ca_payload=database_ca,
    )
    authority = decode_trusted_time_head_anchor_authority(
        runtime.head_anchor_payloads.authority,
        database_url=runtime.database_url,
        expected_host_id=deployment.host_id,
        expected_source_authority_sha256=deployment.source_authority_sha256,
    )
    credentials = decode_trusted_time_head_anchor_auth_secret(
        runtime.head_anchor_payloads.auth_secret,
        authority=authority,
    )
    try:
        derived_public_key = (
            Ed25519PrivateKey.from_private_bytes(runtime.head_anchor_payloads.signing_key)
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )
        verifier = Ed25519TrustedTimeAnchorVerifier.from_public_key_bytes(
            signing_key_id=authority.signing_key_id,
            expected_signing_public_key_sha256=authority.signing_public_key_sha256,
            public_key_bytes=authority.signing_public_key_bytes,
        )
    except BaseException:
        raise TrustedTimePostEnrollmentHostOrchestratorRejected(
            "trusted-time signing identity is unavailable"
        ) from None
    if derived_public_key != authority.signing_public_key_bytes:
        raise TrustedTimePostEnrollmentHostOrchestratorRejected(
            "trusted-time signing identity is unavailable"
        )
    identities = approval.confirmed_enrollment.identities
    expected = TrustedTimeFirstEnrollmentIdentities(
        anchor_authority_sha256=authority.anchor_authority_sha256,
        anchor_project_identity_sha256=authority.anchor_project_identity_sha256,
        bucket_identity_sha256=trusted_time_first_enrollment_identity_sha256(
            kind="bucket", value=authority.bucket_name
        ),
        deployment_identity_sha256=authority.deployment_identity_sha256,
        host_identity_sha256=trusted_time_first_enrollment_identity_sha256(
            kind="host", value=authority.host_id
        ),
        principal_identity_sha256=trusted_time_first_enrollment_identity_sha256(
            kind="principal", value=authority.principal_id
        ),
        runtime_database_identity_sha256=authority.runtime_database_identity_sha256,
        signing_public_key_sha256=authority.signing_public_key_sha256,
        source_authority_sha256=authority.source_authority_sha256,
    )
    if expected != identities:
        raise TrustedTimePostEnrollmentHostOrchestratorRejected(
            "trusted-time read-only authority crosses confirmed enrollment"
        )
    return TrustedTimePostEnrollmentStartSequenceTwoReadOnlyConfiguration(
        authority=authority,
        credentials=credentials,
        verifier=verifier,
    )


def _materialize_runtime_inputs(
    *,
    approval: TrustedTimePostEnrollmentStartApproval,
    runtime_env_file: Path,
    owner: _MaterializedRuntimeInputOwner,
) -> _RuntimeMaterials:
    runtime = load_trusted_time_runtime_configuration(runtime_env_file)
    configuration = _build_read_only_configuration(approval=approval, runtime=runtime)
    database_secret = materialize_database_secret(
        runtime.database_url,
        root=DATABASE_SECRET_ROOT,
        ignored_root=IGNORED_ARTIFACT_ROOT,
        _owner=owner,
    )
    head_anchor_inputs = materialize_trusted_time_head_anchor_inputs(
        runtime.head_anchor_payloads,
        root=DATABASE_SECRET_ROOT,
        ignored_root=IGNORED_ARTIFACT_ROOT,
        _owner=owner,
    )
    validate_materialized_database_secret(database_secret)
    validate_materialized_trusted_time_head_anchor_inputs(head_anchor_inputs)
    return _RuntimeMaterials(
        database_url=runtime.database_url,
        database_secret=database_secret,
        head_anchor_inputs=head_anchor_inputs,
        sequence_two_configuration=configuration,
    )


def _validate_compose(
    *,
    approved_launch: TrustedTimeApprovedLaunch,
    daemon_identity: LocalDockerDaemonIdentity,
    docker_environment: dict[str, str],
    materials: _RuntimeMaterials,
) -> tuple[bytes, TrustedTimeImageAdmission]:
    if _current_git_revision() != approved_launch.git_revision:
        raise TrustedTimePostEnrollmentHostOrchestratorRejected(
            "trusted-time approved revision is unavailable"
        )
    _require_same_local_daemon(daemon_identity, environment=docker_environment)
    compose_payload = _validate_runtime_compose_payload(
        _head_reviewed_input_payload(
            approved_launch.git_revision,
            "infra/compose/trusted-time.compose.yaml",
        )
    )
    rendered = render_compose_model(
        source_image=approved_launch.source_image_id,
        supervisor_image=approved_launch.supervisor_image_id,
        database_secret_file=materials.database_secret.path,
        head_anchor_authority_file=materials.head_anchor_inputs.authority.path,
        head_anchor_auth_secret_file=materials.head_anchor_inputs.auth_secret.path,
        head_anchor_signing_key_secret_file=materials.head_anchor_inputs.signing_key.path,
        compose_payload=compose_payload,
        docker_environment=docker_environment,
    )
    validate_compose_model(
        rendered,
        expected_source_image=approved_launch.source_image_id,
        expected_supervisor_image=approved_launch.supervisor_image_id,
        expected_database_secret_file=materials.database_secret.path,
        expected_head_anchor_authority_file=materials.head_anchor_inputs.authority.path,
        expected_head_anchor_auth_secret_file=materials.head_anchor_inputs.auth_secret.path,
        expected_head_anchor_signing_key_secret_file=materials.head_anchor_inputs.signing_key.path,
    )
    validate_materialized_database_secret(materials.database_secret)
    validate_materialized_trusted_time_head_anchor_inputs(materials.head_anchor_inputs)
    try:
        image_witness = verify_and_write_existing_image_admission(
            DEFAULT_IMAGE_ADMISSION_ARTIFACT,
            approved_launch.source_image_id,
            approved_launch.supervisor_image_id,
            ignored_root=IGNORED_ARTIFACT_ROOT,
            docker_environment=docker_environment,
        )
    except BaseException:
        raise TrustedTimePostEnrollmentHostOrchestratorRejected(
            "trusted-time current image witness is unavailable"
        ) from None
    if image_witness.identities != approved_launch.identities:
        raise TrustedTimePostEnrollmentHostOrchestratorRejected(
            "trusted-time approved images are unavailable"
        )
    _require_same_local_daemon(daemon_identity, environment=docker_environment)
    # The isolated image probe is deliberately reversible and precedes the
    # permanent attempt slot.  Reopen the original named receipts afterwards so
    # a same-UID replacement cannot ride that probe into the prepared fence.
    validate_materialized_database_secret(materials.database_secret)
    validate_materialized_trusted_time_head_anchor_inputs(materials.head_anchor_inputs)
    return compose_payload, image_witness


def _retire_inputs(owner: _MaterializedRuntimeInputOwner, materials: _RuntimeMaterials) -> None:
    owner._retire_all_confirmed()
    if not owner._is_empty() or any(os.path.lexists(path) for path in materials.staged_paths):
        raise TrustedTimePostEnrollmentHostOrchestratorRejected(
            "trusted-time staged-input retirement is unconfirmed"
        )


def _run_post_enrollment_choreography(
    *,
    loaded_approval: LoadedTrustedTimePostEnrollmentExecutionApproval,
    image_witness: TrustedTimeImageAdmission,
    materials: _RuntimeMaterials,
    owner: _MaterializedRuntimeInputOwner,
    approved_launch: TrustedTimeApprovedLaunch,
    compose_payload: bytes,
    issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
) -> RetainedTrustedTimePostEnrollmentStartControllerOutcome:
    approval = loaded_approval.approval
    approval_artifact = loaded_approval.artifact_path
    staged_paths = materials.staged_paths

    def choreography(
        lease: object,
        recovery_retention_capability: object,
    ) -> RetainedTrustedTimePostEnrollmentStartControllerOutcome:
        created: TrustedTimePostEnrollmentCreatedTopologyObservation | None = None
        sequence_one: TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer | None = None
        sequence_two: TrustedTimePostEnrollmentStartSequenceTwoVerifier | None = None
        mutation_may_have_begun = False
        claim_boundary_may_have_begun = False
        controller_may_have_begun = False
        try:
            checkpoint = issuer._require_active_choreography_lease(lease)
            sequence_one = (
                prepare_trusted_time_post_enrollment_sequence_one_reauthentication_issuer(
                    database_url=materials.database_url,
                    authority=materials.sequence_two_configuration.authority,
                    credentials=materials.sequence_two_configuration.credentials,
                    verifier=materials.sequence_two_configuration.verifier,
                    topology_issuer=issuer,
                    choreography_lease=lease,
                    recovery_retention_capability=recovery_retention_capability,
                    action_deadline_monotonic_ns=checkpoint.deadline_monotonic_ns,
                    artifact_directory=DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
                    ignored_root=IGNORED_ARTIFACT_ROOT,
                )
            )
            prepared_creation = issuer._prepare_reviewed_topology_creation(
                approval=approval,
                approved_launch=approved_launch,
                compose_payload=compose_payload,
                expected_database_secret_file=staged_paths[0],
                expected_head_anchor_authority_file=staged_paths[1],
                expected_head_anchor_auth_secret_file=staged_paths[2],
                expected_head_anchor_signing_key_secret_file=staged_paths[3],
                database_secret_receipt=materials.database_secret,
                head_anchor_inputs_receipt=materials.head_anchor_inputs,
                _choreography_lease=lease,
            )
            admission = reserve_post_enrollment_execution_attempt(
                loaded_approval=loaded_approval,
                image_admission=image_witness,
                artifact_directory=DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
                ignored_root=IGNORED_ARTIFACT_ROOT,
            )
            if not _consume_post_enrollment_execution_admission(
                admission,
                approval_artifact=approval_artifact,
                artifact_directory=DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
                ignored_root=IGNORED_ARTIFACT_ROOT,
            ):
                raise TrustedTimePostEnrollmentHostOrchestratorRejected(
                    "trusted-time execution admission is unavailable"
                )
            mutation_may_have_begun = True
            created = issuer._execute_prepared_reviewed_topology_creation(
                prepared_creation,
                _choreography_lease=lease,
            )
            issuer._start_reviewed_source(
                created_observation=created,
                expected_database_secret_file=staged_paths[0],
                expected_head_anchor_authority_file=staged_paths[1],
                expected_head_anchor_auth_secret_file=staged_paths[2],
                expected_head_anchor_signing_key_secret_file=staged_paths[3],
                _choreography_lease=lease,
            )
            issuer._start_reviewed_supervisor(
                created_observation=created,
                expected_database_secret_file=staged_paths[0],
                expected_head_anchor_authority_file=staged_paths[1],
                expected_head_anchor_auth_secret_file=staged_paths[2],
                expected_head_anchor_signing_key_secret_file=staged_paths[3],
                _choreography_lease=lease,
            )
            _retire_inputs(owner, materials)
            ordinal_one = issuer.issue_staged_unreleased_snapshot(
                created_observation=created,
                approval=approval,
                approved_launch=approved_launch,
                expected_database_secret_file=staged_paths[0],
                expected_head_anchor_authority_file=staged_paths[1],
                expected_head_anchor_auth_secret_file=staged_paths[2],
                expected_head_anchor_signing_key_secret_file=staged_paths[3],
                _choreography_lease=lease,
            )
            pre_claim = bind_post_enrollment_start_pre_claim_topology_fence(
                created,
                ordinal_one,
            )
            claim_boundary_may_have_begun = True
            issuer._mark_reviewed_topology_claim_boundary(
                created_observation=created,
                _choreography_lease=lease,
            )
            claimed = prepare_post_enrollment_start_leased_claimed_pre_release_fence(
                approval=approval,
                expected_approval_sha256=approval.approval_sha256,
                approved_launch=approved_launch,
                created_observation=created,
                pre_claim_fence=pre_claim,
                topology_issuer=issuer,
                choreography_lease=lease,
                supervisor_container_id=created.snapshot.supervisor.container_id,
                reauthentication_issuer=sequence_one,
                expected_database_secret_file=staged_paths[0],
                expected_head_anchor_authority_file=staged_paths[1],
                expected_head_anchor_auth_secret_file=staged_paths[2],
                expected_head_anchor_signing_key_secret_file=staged_paths[3],
                artifact_directory=DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
                ignored_root=IGNORED_ARTIFACT_ROOT,
                recovery_retention_capability=recovery_retention_capability,
            )
            action = prepare_post_enrollment_start_leased_claimed_action_topology_fence(
                claimed_fence=claimed,
                topology_issuer=issuer,
                choreography_lease=lease,
                recovery_retention_capability=recovery_retention_capability,
                approved_launch=approved_launch,
                expected_database_secret_file=staged_paths[0],
                expected_head_anchor_authority_file=staged_paths[1],
                expected_head_anchor_auth_secret_file=staged_paths[2],
                expected_head_anchor_signing_key_secret_file=staged_paths[3],
                artifact_directory=DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
                ignored_root=IGNORED_ARTIFACT_ROOT,
            )
            controller_admission = prepare_post_enrollment_start_active_controller_admission(
                action_fence=action,
                topology_issuer=issuer,
                choreography_lease=lease,
                recovery_retention_capability=recovery_retention_capability,
                artifact_directory=DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
                ignored_root=IGNORED_ARTIFACT_ROOT,
            )
            sequence_two = prepare_trusted_time_post_enrollment_start_sequence_two_verifier(
                admission=controller_admission,
                topology_issuer=issuer,
                choreography_lease=lease,
                recovery_retention_capability=recovery_retention_capability,
                action_deadline_monotonic_ns=checkpoint.deadline_monotonic_ns,
                database_url=materials.database_url,
                configuration=materials.sequence_two_configuration,
                artifact_directory=DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
                ignored_root=IGNORED_ARTIFACT_ROOT,
            )
            controller_may_have_begun = True
            controller_result = run_post_enrollment_start_active_controller(
                admission=controller_admission,
                topology_issuer=issuer,
                choreography_lease=lease,
                recovery_retention_capability=recovery_retention_capability,
                sequence_two_verifier=sequence_two,
                expected_database_secret_file=staged_paths[0],
                expected_head_anchor_authority_file=staged_paths[1],
                expected_head_anchor_auth_secret_file=staged_paths[2],
                expected_head_anchor_signing_key_secret_file=staged_paths[3],
                artifact_directory=DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
                ignored_root=IGNORED_ARTIFACT_ROOT,
            )
            return controller_result
        except BaseException as primary_error:
            if (
                controller_may_have_begun
                or claim_boundary_may_have_begun
                or isinstance(
                    primary_error,
                    TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired,
                )
            ):
                adopted_terminal: object | None = None
                try:
                    adopted_terminal = issuer._adopt_registered_confirmed_terminal_outcome(
                        lease,
                        recovery_retention_capability,
                        artifact_directory=DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
                        ignored_root=IGNORED_ARTIFACT_ROOT,
                    )
                except TrustedTimePostEnrollmentTopologyReaderError:
                    adopted_terminal = None
                if (
                    type(adopted_terminal)
                    is RetainedTrustedTimePostEnrollmentStartControllerOutcome
                ):
                    if (
                        adopted_terminal.status
                        is TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED
                    ):
                        return adopted_terminal
                    raise TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired(
                        adopted_terminal
                    ) from primary_error
                if type(adopted_terminal) is RetainedTrustedTimePostEnrollmentStartOutcome:
                    raise TrustedTimePostEnrollmentStartRecoveryOutcomeRetained(
                        adopted_terminal
                    ) from primary_error
                if adopted_terminal is not None:
                    raise TrustedTimePostEnrollmentHostOrchestratorRejected(
                        "trusted-time terminal outcome handoff is unconfirmed"
                    ) from primary_error
                if isinstance(
                    primary_error,
                    (
                        TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired,
                        TrustedTimePostEnrollmentStartRecoveryOutcomeRetained,
                    ),
                ):
                    raise TrustedTimePostEnrollmentHostOrchestratorRejected(
                        "trusted-time terminal outcome handoff is unconfirmed"
                    ) from primary_error
                try:
                    recovery_is_armed = issuer._recovery_outcome_retention_is_armed(
                        lease,
                        recovery_retention_capability,
                        artifact_directory=DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
                        ignored_root=IGNORED_ARTIFACT_ROOT,
                    )
                except BaseException as classification_error:
                    raise TrustedTimePostEnrollmentHostOrchestratorRejected(
                        "trusted-time recovery state classification is unavailable"
                    ) from classification_error
                if recovery_is_armed:
                    retain_post_enrollment_start_recovery_required_outcome(
                        topology_issuer=issuer,
                        recovery_retention_capability=recovery_retention_capability,
                        artifact_directory=DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
                        ignored_root=IGNORED_ARTIFACT_ROOT,
                    )
                    raise AssertionError(
                        "trusted-time recovery retention unexpectedly returned"
                    ) from None
                raise
            if mutation_may_have_begun:
                try:
                    issuer._teardown_reviewed_topology_before_claim(
                        approval=approval,
                        approved_launch=approved_launch,
                        compose_payload=compose_payload,
                        expected_database_secret_file=staged_paths[0],
                        expected_head_anchor_authority_file=staged_paths[1],
                        expected_head_anchor_auth_secret_file=staged_paths[2],
                        expected_head_anchor_signing_key_secret_file=staged_paths[3],
                        created_observation=created,
                        _choreography_lease=lease,
                    )
                except BaseException as teardown_error:
                    raise TrustedTimePostEnrollmentHostOrchestratorRejected(
                        "trusted-time pre-claim topology teardown is unconfirmed"
                    ) from teardown_error
            raise
        finally:
            # Both helpers are close-once.  Staging/controller normally close
            # them first; these calls cover every pre-CALL and CALL/STORE edge.
            # Pre-claim teardown remains above this cleanup because closing an
            # unused sequence-one issuer deliberately poisons the choreography.
            cleanup_error: BaseException | None = None
            if sequence_one is not None:
                try:
                    sequence_one.close()
                except BaseException as error:
                    cleanup_error = error
            if sequence_two is not None:
                try:
                    sequence_two.abort()
                except BaseException as error:
                    cleanup_error = error
            if cleanup_error is not None:
                raise TrustedTimePostEnrollmentHostOrchestratorRejected(
                    "trusted-time verification resource cleanup is unconfirmed"
                ) from cleanup_error

    result = issuer._run_exclusive_choreography_with_recovery_retention(choreography)
    if type(result) is not RetainedTrustedTimePostEnrollmentStartControllerOutcome:
        raise TrustedTimePostEnrollmentHostOrchestratorRejected(
            "trusted-time controller terminal outcome is unavailable"
        )
    return result


def _execute_under_issuer(
    *,
    loaded_approval: LoadedTrustedTimePostEnrollmentExecutionApproval,
    runtime_env_file: Path,
    issuer: TrustedTimePostEnrollmentTopologyObservationIssuer,
    daemon_identity: LocalDockerDaemonIdentity,
    docker_environment: dict[str, str],
) -> RetainedTrustedTimePostEnrollmentStartControllerOutcome:
    approval = loaded_approval.approval
    owner = _MaterializedRuntimeInputOwner()
    try:
        materials = _materialize_runtime_inputs(
            approval=approval,
            runtime_env_file=runtime_env_file,
            owner=owner,
        )
        approved_launch = _approved_launch(approval)
        compose_payload, image_witness = _validate_compose(
            approved_launch=approved_launch,
            daemon_identity=daemon_identity,
            docker_environment=docker_environment,
            materials=materials,
        )
        return _run_post_enrollment_choreography(
            loaded_approval=loaded_approval,
            image_witness=image_witness,
            materials=materials,
            owner=owner,
            approved_launch=approved_launch,
            compose_payload=compose_payload,
            issuer=issuer,
        )
    finally:
        try:
            owner._retire_all_confirmed()
        except BaseException as cleanup_error:
            raise TrustedTimePostEnrollmentHostOrchestratorRejected(
                "trusted-time staged-input cleanup is unconfirmed"
            ) from cleanup_error


def run_approved_post_enrollment_start_once(
    *,
    approval_artifact: Path,
    runtime_env_file: Path,
) -> RetainedTrustedTimePostEnrollmentStartControllerOutcome:
    """Consume one disk approval and retain exactly one terminal controller outcome."""

    if _CLI_REPOSITORY_ROOT is None:
        raise TrustedTimePostEnrollmentHostOrchestratorRejected(
            "trusted-time post-enrollment execution is available only through the isolated CLI"
        )
    _require_repository_first_party_sources(_CLI_REPOSITORY_ROOT)
    loaded_approval = load_post_enrollment_execution_approval(
        approval_artifact=approval_artifact,
        artifact_directory=DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
        ignored_root=IGNORED_ARTIFACT_ROOT,
    )
    approval = loaded_approval.approval
    approved_launch = _approved_launch(approval)
    docker_environment = _minimal_docker_environment()
    daemon_identity = qualify_local_docker_daemon(environment=docker_environment)
    issuer: TrustedTimePostEnrollmentTopologyObservationIssuer | None = None
    try:
        issuer = TrustedTimePostEnrollmentTopologyObservationIssuer.open(
            expected_daemon_identity=daemon_identity,
            docker_environment=docker_environment,
        )
        _require_same_local_daemon(daemon_identity, environment=docker_environment)
        if _current_git_revision() != approved_launch.git_revision:
            raise TrustedTimePostEnrollmentHostOrchestratorRejected(
                "trusted-time approved revision is unavailable"
            )
        return _execute_under_issuer(
            loaded_approval=loaded_approval,
            runtime_env_file=runtime_env_file,
            issuer=issuer,
            daemon_identity=daemon_identity,
            docker_environment=docker_environment,
        )
    finally:
        if issuer is not None:
            try:
                issuer.close()
            except BaseException as close_error:
                raise TrustedTimePostEnrollmentHostOrchestratorRejected(
                    "trusted-time topology issuer close is unconfirmed"
                ) from close_error


def _safe_terminal_payload(
    outcome: (
        RetainedTrustedTimePostEnrollmentStartControllerOutcome
        | RetainedTrustedTimePostEnrollmentStartOutcome
    ),
) -> dict[str, object]:
    if type(outcome) not in {
        RetainedTrustedTimePostEnrollmentStartControllerOutcome,
        RetainedTrustedTimePostEnrollmentStartOutcome,
    }:
        raise TrustedTimePostEnrollmentHostOrchestratorRejected(
            "trusted-time terminal outcome is invalid"
        )
    outcome.__post_init__()
    payload: dict[str, object] = {field: False for field in _CLOSED_AUTHORITY_FIELDS}
    payload.update(
        {
            "approval_sha256": outcome.approval_sha256,
            "contract_version": POST_ENROLLMENT_HOST_ORCHESTRATOR_CONTRACT_VERSION,
            "operation_id": outcome.operation_id,
            "orchestrator_status": POST_ENROLLMENT_HOST_ORCHESTRATOR_STATUS,
            "outcome_sha256": outcome.outcome_sha256,
            "reason": outcome.reason,
            "service": POST_ENROLLMENT_HOST_ORCHESTRATOR_SERVICE,
            "status": outcome.status,
        }
    )
    return payload


def _require_exact_terminal_outcome(
    approval: TrustedTimePostEnrollmentStartApproval,
    outcome: object,
) -> (
    RetainedTrustedTimePostEnrollmentStartControllerOutcome
    | RetainedTrustedTimePostEnrollmentStartOutcome
):
    """Require one durably revalidated terminal bound to the requested approval."""

    if type(approval) is not TrustedTimePostEnrollmentStartApproval:
        raise TrustedTimePostEnrollmentHostOrchestratorRejected(
            "trusted-time terminal approval is invalid"
        )
    approval.__post_init__()
    exact: (
        RetainedTrustedTimePostEnrollmentStartControllerOutcome
        | RetainedTrustedTimePostEnrollmentStartOutcome
    )
    if type(outcome) is RetainedTrustedTimePostEnrollmentStartControllerOutcome:
        exact = outcome
        valid = revalidate_retained_post_enrollment_start_controller_outcome(
            exact,
            artifact_directory=DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
            ignored_root=IGNORED_ARTIFACT_ROOT,
        )
    elif type(outcome) is RetainedTrustedTimePostEnrollmentStartOutcome:
        exact = outcome
        valid = revalidate_retained_post_enrollment_start_outcome(
            exact,
            artifact_directory=DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
            ignored_root=IGNORED_ARTIFACT_ROOT,
        )
    else:
        raise TrustedTimePostEnrollmentHostOrchestratorRejected(
            "trusted-time terminal outcome is invalid"
        )
    exact.__post_init__()
    if (
        not valid
        or exact.operation_id != approval.operation_id
        or exact.approval_sha256 != approval.approval_sha256
    ):
        raise TrustedTimePostEnrollmentHostOrchestratorRejected(
            "trusted-time terminal outcome crosses the requested approval"
        )
    return exact


def _terminal_exit_code(
    outcome: (
        RetainedTrustedTimePostEnrollmentStartControllerOutcome
        | RetainedTrustedTimePostEnrollmentStartOutcome
    ),
) -> int:
    if (
        type(outcome) is RetainedTrustedTimePostEnrollmentStartControllerOutcome
        and outcome.status is TrustedTimePostEnrollmentStartControllerOutcomeStatus.CONFIRMED
    ):
        return 0
    return 2


def _fatal_payload() -> dict[str, object]:
    payload: dict[str, object] = {field: False for field in _CLOSED_AUTHORITY_FIELDS}
    payload.update(
        {
            "contract_version": POST_ENROLLMENT_HOST_ORCHESTRATOR_CONTRACT_VERSION,
            "orchestrator_status": "retention_unconfirmed",
            "reason": "retention_unconfirmed_manual_recovery_required",
            "service": POST_ENROLLMENT_HOST_ORCHESTRATOR_SERVICE,
            "status": "fatal",
        }
    )
    return payload


def _parse_cli(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Execute one exact approved trusted-time post-enrollment start."
    )
    parser.add_argument("--approval-artifact", required=True, type=Path)
    parser.add_argument("--runtime-env-file", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> Never:
    """Run the single-use CLI and emit only canonical nonsecret terminal evidence."""

    arguments = _parse_cli(argv)
    try:
        approval = load_post_enrollment_execution_approval(
            approval_artifact=arguments.approval_artifact,
            artifact_directory=DEFAULT_TRUSTED_TIME_ARTIFACT_DIRECTORY,
            ignored_root=IGNORED_ARTIFACT_ROOT,
        ).approval
    except BaseException:
        print(json.dumps(_fatal_payload(), sort_keys=True))
        raise SystemExit(2) from None
    retained: (
        RetainedTrustedTimePostEnrollmentStartControllerOutcome
        | RetainedTrustedTimePostEnrollmentStartOutcome
    )
    try:
        retained = run_approved_post_enrollment_start_once(
            approval_artifact=arguments.approval_artifact,
            runtime_env_file=arguments.runtime_env_file,
        )
    except (
        TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired,
        TrustedTimePostEnrollmentStartRecoveryOutcomeRetained,
    ) as terminal:
        try:
            retained = _require_exact_terminal_outcome(
                approval,
                terminal.retained_outcome,
            )
        except BaseException:
            print(json.dumps(_fatal_payload(), sort_keys=True))
            raise SystemExit(2) from None
    except BaseException:
        print(json.dumps(_fatal_payload(), sort_keys=True))
        raise SystemExit(2) from None
    try:
        retained = _require_exact_terminal_outcome(approval, retained)
    except BaseException:
        print(json.dumps(_fatal_payload(), sort_keys=True))
        raise SystemExit(2) from None
    print(json.dumps(_safe_terminal_payload(retained), sort_keys=True))
    raise SystemExit(_terminal_exit_code(retained))


__all__ = [
    "POST_ENROLLMENT_HOST_ORCHESTRATOR_CONTRACT_VERSION",
    "POST_ENROLLMENT_HOST_ORCHESTRATOR_SERVICE",
    "POST_ENROLLMENT_HOST_ORCHESTRATOR_STATUS",
    "TrustedTimePostEnrollmentHostOrchestratorRejected",
    "run_approved_post_enrollment_start_once",
]


if __name__ == "__main__":
    main()
