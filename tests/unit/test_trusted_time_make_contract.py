from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _first_enrollment_assignments() -> tuple[str, ...]:
    digests = {
        "TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256": "b" * 64,
        "TRUSTED_TIME_APPROVED_UNENROLLED_ADMISSION_SHA256": "e" * 64,
        "TRUSTED_TIME_APPROVED_ANCHOR_AUTHORITY_SHA256": "f" * 64,
        "TRUSTED_TIME_APPROVED_DEPLOYMENT_IDENTITY_SHA256": "1" * 64,
        "TRUSTED_TIME_APPROVED_RUNTIME_DATABASE_IDENTITY_SHA256": "2" * 64,
        "TRUSTED_TIME_APPROVED_ANCHOR_PROJECT_IDENTITY_SHA256": "3" * 64,
        "TRUSTED_TIME_APPROVED_SOURCE_AUTHORITY_SHA256": "4" * 64,
        "TRUSTED_TIME_APPROVED_SIGNING_PUBLIC_KEY_SHA256": "5" * 64,
        "TRUSTED_TIME_APPROVED_HOST_IDENTITY_SHA256": "6" * 64,
        "TRUSTED_TIME_APPROVED_PRINCIPAL_IDENTITY_SHA256": "7" * 64,
        "TRUSTED_TIME_APPROVED_BUCKET_IDENTITY_SHA256": "8" * 64,
    }
    return (
        "TRUSTED_TIME_LAUNCH_ENV_FILE=/private/operator/trusted-time-launch.env",
        "TRUSTED_TIME_FIRST_ENROLLMENT_OPERATION_ID=123e4567-e89b-42d3-a456-426614174000",
        "TRUSTED_TIME_PRIOR_NEW_OPERATION_ID=223e4567-e89b-42d3-a456-426614174001",
        f"TRUSTED_TIME_PRIOR_NEW_CLAIM_SHA256={'9' * 64}",
        f"TRUSTED_TIME_APPROVED_GIT_REVISION={'a' * 40}",
        "TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID=sha256:" + "c" * 64,
        "TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID=sha256:" + "d" * 64,
        *(f"{name}={value}" for name, value in digests.items()),
    )


def test_trusted_time_python_launcher_is_isolated_and_cannot_be_overridden() -> None:
    completed = subprocess.run(
        (
            "make",
            "-n",
            "trusted-time-images",
            "TRUSTED_TIME_PYTHON=python",
        ),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert (
        "uv run --isolated --offline --locked --no-env-file "
        "python -I -B -X pycache_prefix=/dev/null"
    ) in completed.stdout
    assert "--no-sync" not in completed.stdout
    assert "--frozen" not in completed.stdout


def test_every_supported_trusted_time_python_target_uses_isolated_launcher() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    assert makefile.count("$(TRUSTED_TIME_PYTHON)") == 10
    for script in (
        "diagnose_trusted_time_runtime.py",
        "enroll_trusted_time_head_anchor.py",
        "inspect_trusted_time_qualification.py",
        "start_trusted_time_supervisor.py",
        "verify_trusted_time_compose.py",
        "verify_trusted_time_images.py",
    ):
        assert script in makefile


def test_post_enrollment_start_is_reachable_only_through_standalone_host_orchestrator() -> None:
    legacy_execution_contracts = (
        "phase6d-post-enrollment-start-execution-approval-v1",
        "phase6d-post-enrollment-start-execution-attempt-v1",
        "phase6d-post-enrollment-start-execution-admission-v1",
    )
    legacy_host_orchestrator_contract = "phase6d-post-enrollment-start-host-orchestrator-v1"
    execution_admission_api_names = (
        "trusted_time_post_enrollment_execution_admission",
        "phase6d-post-enrollment-start-execution-approval-v2",
        "phase6d-post-enrollment-start-execution-attempt-v2",
        "phase6d-post-enrollment-start-execution-admission-v2",
        ".post-enrollment-start-execution-attempt-slot",
        "LoadedTrustedTimePostEnrollmentExecutionApproval",
        "TrustedTimePostEnrollmentExecutionAdmission",
        "admit_post_enrollment_execution_attempt",
        "load_post_enrollment_execution_approval",
        "reserve_post_enrollment_execution_attempt",
        "retain_post_enrollment_execution_approval",
        "_consume_post_enrollment_execution_admission",
    )
    image_provenance_api_names = (
        "TrustedTimeImageAdmissionProvenance",
        "load_image_admission_provenance_artifact",
    )
    prepared_creation_api_names = (
        "_TrustedTimePostEnrollmentPreparedReviewedTopologyCreation",
        "_prepare_reviewed_topology_creation",
        "_execute_prepared_reviewed_topology_creation",
    )
    sequence_one_reauthentication_api_names = (
        "trusted_time_post_enrollment_sequence_one_reauthentication",
        "phase6d-post-enrollment-sequence-one-read-only-reauthentication-v1",
        "TrustedTimePostEnrollmentSequenceOneReauthenticationIssuer",
        "prepare_trusted_time_post_enrollment_sequence_one_reauthentication_issuer",
    )
    host_orchestrator_api_names = (
        "trusted_time_post_enrollment_host_orchestrator",
        "POST_ENROLLMENT_HOST_ORCHESTRATOR_CONTRACT_VERSION",
        "phase6d-post-enrollment-start-host-orchestrator-v2",
        "POST_ENROLLMENT_HOST_ORCHESTRATOR_STATUS",
        "terminal_outcome_retained",
        '"orchestrator_status"',
        "TrustedTimePostEnrollmentHostOrchestratorRejected",
        "run_approved_post_enrollment_start_once",
    )
    active_controller_api_names = (
        "trusted_time_post_enrollment_active_controller",
        "POST_ENROLLMENT_START_ACTIVE_CONTROLLER_CONTRACT_VERSION",
        "POST_ENROLLMENT_START_ACTIVE_CONTROLLER_STATUS",
        "phase6d-post-enrollment-start-active-controller-v1",
        "post_enrollment_start_confirmed",
        "TrustedTimePostEnrollmentStartActiveControllerRejected",
        "TrustedTimePostEnrollmentStartActiveControllerRecoveryRequired",
        "run_post_enrollment_start_active_controller",
    )
    active_controller_admission_api_names = (
        "trusted_time_post_enrollment_active_controller_admission",
        "POST_ENROLLMENT_START_ACTIVE_CONTROLLER_ADMISSION_CONTRACT_VERSION",
        "POST_ENROLLMENT_START_ACTIVE_CONTROLLER_ADMISSION_STATUS",
        "phase6d-post-enrollment-start-active-controller-admission-v1",
        "active_controller_admission_unqualified",
        "TrustedTimePostEnrollmentStartActiveControllerAdmission",
        "TrustedTimePostEnrollmentStartActiveControllerAdmissionRejected",
        "TrustedTimePostEnrollmentStartActiveControllerAdmissionRecoveryRequired",
        "prepare_post_enrollment_start_active_controller_admission",
        "_consume_active_controller_continuation",
        "active_controller_authorized",
        "controller_execution_authorized",
    )
    controller_outcome_api_names = (
        "trusted_time_post_enrollment_controller_outcome",
        "POST_ENROLLMENT_START_RETAINED_CONTROLLER_OUTCOME_CONTRACT_VERSION",
        "phase6d-post-enrollment-start-retained-controller-outcome-v1",
        "RetainedTrustedTimePostEnrollmentStartControllerOutcome",
        "TrustedTimePostEnrollmentStartControllerOutcomeEvidence",
        "load_retained_post_enrollment_start_controller_outcome",
        "retain_post_enrollment_start_controller_outcome",
        "revalidate_retained_post_enrollment_start_controller_outcome",
        ".post-enrollment-start-controller-outcome-slot",
        ".post-enrollment-start-controller-outcome-staging",
        ".post-enrollment-start-controller-outcome-commit-staging",
        ".post-enrollment-start-controller-outcome-committed",
    )
    persistent_topology_api_names = (
        "trusted_time_post_enrollment_persistent_topology",
        "POST_ENROLLMENT_PERSISTENT_TOPOLOGY_CONTRACT_VERSION",
        "POST_ENROLLMENT_PERSISTENT_TOPOLOGY_STATUS",
        "phase6d-post-enrollment-start-persistent-topology-snapshot-v1",
        "persistent_topology_snapshot_unqualified",
        "TrustedTimePostEnrollmentPersistentTopologySnapshot",
        "validate_post_enrollment_start_persistent_topology",
    )
    sequence_two_verifier_api_names = (
        "trusted_time_post_enrollment_sequence_two_verifier",
        "POST_ENROLLMENT_START_SEQUENCE_TWO_VERIFIER_CONTRACT_VERSION",
        "POST_ENROLLMENT_START_SEQUENCE_TWO_FIRST_VERIFICATION_RESERVE_NANOSECONDS",
        "POST_ENROLLMENT_START_SEQUENCE_TWO_SECOND_VERIFICATION_RESERVE_NANOSECONDS",
        "phase6d-post-enrollment-start-sequence-two-verifier-v1",
        "TrustedTimePostEnrollmentStartSequenceTwoReadOnlyConfiguration",
        "TrustedTimePostEnrollmentStartSequenceTwoVerificationRejected",
        "TrustedTimePostEnrollmentStartSequenceTwoVerifier",
        "prepare_trusted_time_post_enrollment_start_sequence_two_verifier",
    )
    action_topology_fence_api_names = (
        "trusted_time_post_enrollment_action_topology_fence",
        "POST_ENROLLMENT_START_CLAIMED_ACTION_TOPOLOGY_FENCE_CONTRACT_VERSION",
        "POST_ENROLLMENT_START_CLAIMED_ACTION_TOPOLOGY_FENCE_STATUS",
        "phase6d-post-enrollment-start-claimed-action-topology-fence-v1",
        "claimed_action_topology_fence_unqualified",
        "TrustedTimePostEnrollmentStartClaimedActionTopologyFence",
        "TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRejected",
        "TrustedTimePostEnrollmentStartClaimedActionTopologyFenceRecoveryRequired",
        "prepare_post_enrollment_start_leased_claimed_action_topology_fence",
        "POST_ENROLLMENT_FINAL_ACTION_TOPOLOGY_OBSERVATION_CONTRACT_VERSION",
        "POST_ENROLLMENT_FINAL_ACTION_TOPOLOGY_OBSERVATION_STATUS",
        "phase6d-post-enrollment-final-action-topology-observation-v1",
        "final_action_staged_unreleased_topology_observation_unqualified",
        "TrustedTimePostEnrollmentFinalActionTopologyObservation",
        "_consume_claimed_fence_action_choreography",
        "_consume_claimed_action_fence_controller_choreography",
        "_issue_claimed_final_action_topology_snapshot",
        "_require_armed_recovery_outcome_retention",
        "_require_unbound_recovery_retention_preparation",
        "_recovery_outcome_retention_is_armed",
        "_adopt_registered_confirmed_terminal_outcome",
    )
    recovery_outcome_api_names = (
        "trusted_time_post_enrollment_outcome",
        "phase6d-post-enrollment-start-retained-recovery-outcome-v1",
        '"recovery_required"',
        "retain_post_enrollment_start_recovery_required_outcome",
        "_TrustedTimePostEnrollmentRecoveryClaimBinder",
        "_TrustedTimePostEnrollmentRecoveryRetentionCapability",
        "_issue_recovery_retention_claim_binder",
        "_run_exclusive_choreography_with_recovery_retention",
        "_POST_ENROLLMENT_START_RECOVERY_RETENTION_DEADLINE_SECONDS",
        ".post-enrollment-start-recovery-outcome-staging",
    )
    claimed_fence_api_names = (
        "POST_ENROLLMENT_START_CLAIMED_PRE_RELEASE_TOPOLOGY_FENCE_CONTRACT_VERSION",
        "POST_ENROLLMENT_START_CLAIMED_PRE_RELEASE_TOPOLOGY_FENCE_STATUS",
        "phase6d-post-enrollment-start-claimed-pre-release-topology-fence-v1",
        "claimed_pre_release_topology_fence_unqualified",
        "TrustedTimePostEnrollmentStartClaimedPreReleaseTopologyFence",
        "TrustedTimePostEnrollmentStartClaimedFenceRejected",
        "TrustedTimePostEnrollmentStartClaimedFenceRecoveryRequired",
        "prepare_post_enrollment_start_claimed_pre_release_fence",
        "prepare_post_enrollment_start_leased_claimed_pre_release_fence",
    )
    topology_cursor_api_names = (
        "POST_ENROLLMENT_TOPOLOGY_OBSERVATION_CURSOR_CONTRACT_VERSION",
        "POST_ENROLLMENT_TOPOLOGY_OBSERVATION_CURSOR_STATUS",
        "phase6d-post-enrollment-topology-observation-cursor-v1",
        "topology_observation_cursor_unqualified",
        "TrustedTimePostEnrollmentTopologyObservationCursor",
        "issue_observation_cursor",
    )
    topology_fence_api_names = (
        "POST_ENROLLMENT_START_PRE_CLAIM_TOPOLOGY_FENCE_CONTRACT_VERSION",
        "POST_ENROLLMENT_START_PRE_CLAIM_TOPOLOGY_FENCE_STATUS",
        "POST_ENROLLMENT_START_PRE_RELEASE_TOPOLOGY_FENCE_CONTRACT_VERSION",
        "POST_ENROLLMENT_START_PRE_RELEASE_TOPOLOGY_FENCE_STATUS",
        "phase6d-post-enrollment-start-pre-claim-topology-fence-v1",
        "pre_claim_same_session_topology_fence_unqualified",
        "phase6d-post-enrollment-start-pre-release-topology-fence-v1",
        "pre_release_same_session_topology_fence_unqualified",
        "TrustedTimePostEnrollmentStartPreClaimTopologyFence",
        "TrustedTimePostEnrollmentStartPreReleaseTopologyFence",
        "TrustedTimePostEnrollmentStartTopologyFenceRejected",
        "bind_post_enrollment_start_pre_claim_topology_fence",
        "bind_post_enrollment_start_pre_release_topology_fence",
    )
    forbidden_names = (
        *legacy_execution_contracts,
        legacy_host_orchestrator_contract,
        *execution_admission_api_names,
        *image_provenance_api_names,
        *prepared_creation_api_names,
        *sequence_one_reauthentication_api_names,
        *host_orchestrator_api_names,
        "trusted_time_post_enrollment_topology",
        "validate_post_enrollment_start_created_topology",
        "trusted_time_post_enrollment_staged_topology",
        "validate_post_enrollment_start_staged_unreleased_topology",
        "trusted_time_post_enrollment_topology_reader",
        "phase6d-post-enrollment-topology-observation-reader-v2",
        "TrustedTimePostEnrollmentTopologyObservationIssuer",
        "TrustedTimePostEnrollmentCreatedTopologyObservation",
        "TrustedTimePostEnrollmentStagedTopologyObservation",
        *active_controller_api_names,
        *active_controller_admission_api_names,
        *action_topology_fence_api_names,
        "trusted_time_post_enrollment_claimed_fence",
        *claimed_fence_api_names,
        "_run_exclusive_choreography",
        "choreography_lease",
        "choreography_deadline",
        *recovery_outcome_api_names,
        *controller_outcome_api_names,
        *persistent_topology_api_names,
        *sequence_two_verifier_api_names,
        *topology_cursor_api_names,
        "trusted_time_post_enrollment_topology_fence",
        *topology_fence_api_names,
    )
    supported_surfaces = (
        ROOT / "Makefile",
        ROOT / "apps" / "api" / "main.py",
        ROOT / "apps" / "trader" / "main.py",
        ROOT / "apps" / "worker" / "main.py",
        *sorted((ROOT / "apps" / "trusted_time_supervisor").glob("*.py")),
        ROOT / "infra" / "compose" / "compose.yaml",
        ROOT / "infra" / "compose" / "trusted-time.compose.yaml",
        ROOT / "infra" / "compose" / "trusted-time.defaults.env",
        ROOT / "pyproject.toml",
        ROOT / "scripts" / "diagnose_trusted_time_runtime.py",
        ROOT / "scripts" / "enroll_trusted_time_head_anchor.py",
        ROOT / "scripts" / "generate_trusted_time_anchor_artifacts.py",
        ROOT / "scripts" / "inspect_trusted_time_qualification.py",
        ROOT / "scripts" / "migrate_phase6_trusted_time_head_anchors.py",
        ROOT / "scripts" / "migrate_phase6_trusted_time_uncertainty.py",
        ROOT / "scripts" / "prove_trusted_time_anchor_storage.py",
        ROOT / "scripts" / "provision_trusted_time_anchor_project.py",
        ROOT / "scripts" / "start_trusted_time_supervisor.py",
        ROOT / "scripts" / "verify_trusted_time_compose.py",
    )

    for path in supported_surfaces:
        payload = path.read_text(encoding="utf-8")
        for forbidden_name in forbidden_names:
            assert forbidden_name not in payload
        assert re.search(r"(?<![0-9A-Za-z_])recovery_required(?![0-9A-Za-z_])", payload) is None
        assert re.search(r"(?<![0-9A-Za-z])305(?:\.0)?(?![0-9A-Za-z])", payload) is None
        assert re.search(r"(?<![0-9A-Za-z])600(?:\.0)?(?![0-9A-Za-z])", payload) is None
        assert re.search(r"(?<![0-9A-Za-z])605(?:\.0)?(?![0-9A-Za-z])", payload) is None

    network_owned_sources = (
        ROOT / "scripts" / "trusted_time_post_enrollment_topology_reader.py",
        ROOT / "scripts" / "trusted_time_post_enrollment_active_controller.py",
        ROOT / "scripts" / "trusted_time_post_enrollment_persistent_topology.py",
    )
    for path in network_owned_sources:
        payload = path.read_text(encoding="utf-8")
        assert "COMPOSE_NETWORK_NAME" not in payload
        assert "post_enrollment_created_topology_network_name" in payload
    reader_payload = network_owned_sources[0].read_text(encoding="utf-8")
    assert "phase6d-post-enrollment-topology-observation-reader-v2" in reader_payload
    assert "phase6d-post-enrollment-topology-observation-reader-v1" not in reader_payload
    network_contract_docs = (
        ROOT / "docs" / "ARCHITECTURE.md",
        ROOT / "docs" / "IMPLEMENTATION_PLAN.md",
        ROOT / "docs" / "adr" / "0099-approval-bound-post-enrollment-start-and-graceful-stop.md",
        ROOT / "docs" / "runbooks" / "trusted-time-supervisor.md",
    )
    for path in network_contract_docs:
        payload = path.read_text(encoding="utf-8")
        normalized_payload = " ".join(payload.split())
        assert "issuer-session-derived network name" in normalized_payload
        assert "fixed legacy" in payload
        assert "phase6d-post-enrollment-topology-observation-reader-v1" not in payload
    assert all(
        "phase6d-post-enrollment-topology-observation-reader-v2" in path.read_text(encoding="utf-8")
        for path in network_contract_docs
    )

    staged_input_digest_environment = (
        "AQT_TRUSTED_TIME_EXPECTED_DATABASE_URL_SHA256",
        "AQT_TRUSTED_TIME_EXPECTED_HEAD_ANCHOR_AUTHORITY_SHA256",
        "AQT_TRUSTED_TIME_EXPECTED_HEAD_ANCHOR_AUTH_SECRET_SHA256",
        "AQT_TRUSTED_TIME_EXPECTED_HEAD_ANCHOR_SIGNING_KEY_SHA256",
    )
    supervisor_main = (ROOT / "apps" / "trusted_time_supervisor" / "main.py").read_text(
        encoding="utf-8"
    )
    supervisor_configuration = (ROOT / "apps" / "trusted_time_supervisor" / "config.py").read_text(
        encoding="utf-8"
    ) + (ROOT / "apps" / "trusted_time_supervisor" / "head_anchor_config.py").read_text(
        encoding="utf-8"
    )
    supervisor_start = (ROOT / "scripts" / "start_trusted_time_supervisor.py").read_text(
        encoding="utf-8"
    )
    for environment_name in staged_input_digest_environment:
        assert environment_name in supervisor_configuration
    assert "_EXPECTED_STAGED_INPUT_SHA256_ENVIRONMENT" in supervisor_main
    assert "POST_ENROLLMENT_STAGED_INPUT_SHA256_ENVIRONMENT" in supervisor_start
    assert "POST_ENROLLMENT_STAGED_INPUT_SHA256_ENVIRONMENT" in reader_payload
    assert "validate_exact_post_start_exited_supervisor_container" in reader_payload
    assert "_ReviewedCreatedTopologyRegistration" in reader_payload
    normalized_contract_docs = tuple(
        " ".join(path.read_text(encoding="utf-8").split()) for path in network_contract_docs
    )
    for normalized_payload in normalized_contract_docs:
        assert "four private expected SHA-256 bindings" in normalized_payload
        assert "exact bytes" in normalized_payload
        assert "before marker, readiness, or claim" in normalized_payload
        assert "private digests" in normalized_payload

    admission_cli = (ROOT / "scripts" / "verify_trusted_time_images.py").read_text(encoding="utf-8")
    assert '"scripts/trusted_time_post_enrollment_action_topology_fence.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_action_topology_fence") == 1
    assert '"scripts/trusted_time_post_enrollment_active_controller.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_active_controller") == 2
    assert '"scripts/trusted_time_post_enrollment_active_controller_admission.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_active_controller_admission") == 1
    assert '"scripts/trusted_time_post_enrollment_claimed_fence.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_claimed_fence") == 1
    assert '"scripts/trusted_time_post_enrollment_controller_outcome.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_controller_outcome") == 1
    assert '"scripts/trusted_time_post_enrollment_execution_admission.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_execution_admission") == 1
    assert '"scripts/trusted_time_post_enrollment_host_orchestrator.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_host_orchestrator") == 1
    assert '"scripts/trusted_time_post_enrollment_outcome.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_outcome") == 1
    assert '"scripts/trusted_time_post_enrollment_persistent_topology.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_persistent_topology") == 1
    assert (
        '"scripts/trusted_time_post_enrollment_sequence_one_reauthentication.py"' in admission_cli
    )
    assert admission_cli.count("trusted_time_post_enrollment_sequence_one_reauthentication") == 1
    assert '"scripts/trusted_time_post_enrollment_sequence_two_verifier.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_sequence_two_verifier") == 1
    assert '"scripts/trusted_time_post_enrollment_topology_fence.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_topology_fence") == 1
    for forbidden_name in (
        *legacy_execution_contracts,
        legacy_host_orchestrator_contract,
        *execution_admission_api_names[1:],
        *prepared_creation_api_names,
        *sequence_one_reauthentication_api_names[1:],
        *host_orchestrator_api_names[1:],
        *active_controller_api_names[1:],
        *active_controller_admission_api_names[1:],
        *action_topology_fence_api_names[1:],
        *recovery_outcome_api_names[1:],
        *controller_outcome_api_names[1:],
        *persistent_topology_api_names[1:],
        *sequence_two_verifier_api_names[1:],
        *claimed_fence_api_names,
        *topology_cursor_api_names,
        *topology_fence_api_names,
    ):
        assert forbidden_name not in admission_cli
    assert re.search(r"(?<![0-9A-Za-z_])recovery_required(?![0-9A-Za-z_])", admission_cli) is None
    assert re.search(r"(?<![0-9A-Za-z])305(?:\.0)?(?![0-9A-Za-z])", admission_cli) is None
    assert re.search(r"(?<![0-9A-Za-z])600(?:\.0)?(?![0-9A-Za-z])", admission_cli) is None
    assert re.search(r"(?<![0-9A-Za-z])605(?:\.0)?(?![0-9A-Za-z])", admission_cli) is None

    orchestrator = (
        ROOT / "scripts" / "trusted_time_post_enrollment_host_orchestrator.py"
    ).read_text(encoding="utf-8")
    for required_name in (
        execution_admission_api_names[0],
        "LoadedTrustedTimePostEnrollmentExecutionApproval",
        "load_post_enrollment_execution_approval",
        "reserve_post_enrollment_execution_attempt",
        "_consume_post_enrollment_execution_admission",
        "verify_and_write_existing_image_admission",
        "_prepare_reviewed_topology_creation",
        "_execute_prepared_reviewed_topology_creation",
        sequence_one_reauthentication_api_names[0],
        sequence_one_reauthentication_api_names[-1],
        "trusted_time_post_enrollment_topology_reader",
        host_orchestrator_api_names[2],
        active_controller_api_names[0],
        active_controller_admission_api_names[0],
        action_topology_fence_api_names[0],
        claimed_fence_api_names[-1],
        sequence_two_verifier_api_names[0],
        host_orchestrator_api_names[-1],
        'if __name__ == "__main__"',
    ):
        assert required_name in orchestrator
    assert orchestrator.count("_require_isolated_cli_source_runtime") == 2
    assert "expected_relative_path=Path" in orchestrator
    assert '"scripts/trusted_time_post_enrollment_host_orchestrator.py"' in orchestrator
    assert "sys.flags.isolated != 1" in orchestrator
    assert "sys.flags.dont_write_bytecode != 1" in orchestrator
    assert 'sys.pycache_prefix != "/dev/null"' in orchestrator
    assert orchestrator.count('"--approval-artifact"') == 1
    assert orchestrator.count('"--runtime-env-file"') == 1
    assert orchestrator.count("_recovery_outcome_retention_is_armed") == 1
    assert orchestrator.count("_adopt_registered_confirmed_terminal_outcome") == 1
    assert "admit_post_enrollment_execution_attempt" not in orchestrator
    assert legacy_host_orchestrator_contract not in orchestrator

    validation_start = orchestrator.index("def _validate_compose(")
    validation_end = orchestrator.index("\ndef _retire_inputs(", validation_start)
    validation_body = orchestrator[validation_start:validation_end]
    assert validation_body.index("render_compose_model(") < validation_body.index(
        "validate_compose_model("
    )
    assert validation_body.index("validate_materialized_database_secret(") < validation_body.index(
        "verify_and_write_existing_image_admission("
    )
    assert validation_body.index(
        "validate_materialized_trusted_time_head_anchor_inputs("
    ) < validation_body.index("verify_and_write_existing_image_admission(")

    execution_start = orchestrator.index("def _execute_under_issuer(")
    execution_end = orchestrator.index("\ndef run_approved_post_enrollment_start_once(")
    execution_body = orchestrator[execution_start:execution_end]
    assert (
        execution_body.index("_MaterializedRuntimeInputOwner()")
        < execution_body.index("_materialize_runtime_inputs(")
        < execution_body.index("_validate_compose(")
        < execution_body.index("_run_post_enrollment_choreography(")
    )

    run_start = execution_end + 1
    run_end = orchestrator.index("\ndef _safe_terminal_payload(", run_start)
    run_body = orchestrator[run_start:run_end]
    assert run_body.index(
        "TrustedTimePostEnrollmentTopologyObservationIssuer.open("
    ) < run_body.index("_execute_under_issuer(")

    choreography_start = orchestrator.index("    def choreography(")
    choreography_end = orchestrator.index(
        "    result = issuer._run_exclusive_choreography_with_recovery_retention(",
        choreography_start,
    )
    choreography_body = orchestrator[choreography_start:choreography_end]
    ordered_late_attempt_markers = (
        "prepare_trusted_time_post_enrollment_sequence_one_reauthentication_issuer(",
        "issuer._prepare_reviewed_topology_creation(",
        "reserve_post_enrollment_execution_attempt(",
        "_consume_post_enrollment_execution_admission(",
        "mutation_may_have_begun = True",
        "issuer._execute_prepared_reviewed_topology_creation(",
    )
    marker_offsets = tuple(
        choreography_body.index(marker) for marker in ordered_late_attempt_markers
    )
    assert marker_offsets == tuple(sorted(marker_offsets))

    execution_admission = (
        ROOT / "scripts" / "trusted_time_post_enrollment_execution_admission.py"
    ).read_text(encoding="utf-8")
    for contract in execution_admission_api_names[1:4]:
        assert contract in execution_admission
    for legacy_contract in legacy_execution_contracts:
        assert legacy_contract not in execution_admission
    reserve_signature = re.search(
        r"    def reserve\(\n(?P<parameters>.*?)\n    \) -> ",
        execution_admission,
        flags=re.DOTALL,
    )
    assert reserve_signature is not None
    reserve_parameters = reserve_signature.group("parameters")
    assert "loaded_approval:" in reserve_parameters
    assert "image_admission:" in reserve_parameters
    assert "approval_artifact:" not in reserve_parameters
    assert (
        "admit_post_enrollment_execution_attempt = reserve_post_enrollment_execution_attempt"
    ) in execution_admission
    assert '"retain_post_enrollment_execution_approval"' in execution_admission

    image_admission = (ROOT / "scripts" / "verify_trusted_time_images.py").read_text(
        encoding="utf-8"
    )
    for required_name in image_provenance_api_names:
        assert required_name in image_admission
    active_controller = (
        ROOT / "scripts" / "trusted_time_post_enrollment_active_controller.py"
    ).read_text(encoding="utf-8")
    assert active_controller.count("_adopt_registered_confirmed_terminal_outcome") == 1
    sequence_one = (
        ROOT / "scripts" / "trusted_time_post_enrollment_sequence_one_reauthentication.py"
    ).read_text(encoding="utf-8")
    assert sequence_one.count("_require_unbound_recovery_retention_preparation") == 2


def test_runtime_state_inspector_is_in_container_only_and_not_a_host_controller() -> None:
    command = "autoquant-trusted-time-post-enrollment-runtime-state"
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    marker_paths = (
        "/tmp/post-enrollment-start-sequence-two-deadline",
        "/tmp/.post-enrollment-start-sequence-two-deadline-staging",
        "/tmp/post-enrollment-start-release",
        "/tmp/.post-enrollment-start-release-staging",
        "/tmp/post-enrollment-start-sequence-two-ready",
        "/tmp/.post-enrollment-start-sequence-two-ready-staging",
    )

    assert pyproject.count(command) == 1
    for path in (
        ROOT / "Makefile",
        ROOT / "infra" / "compose" / "trusted-time.compose.yaml",
        ROOT / "scripts" / "start_trusted_time_supervisor.py",
        ROOT / "scripts" / "verify_trusted_time_compose.py",
    ):
        payload = path.read_text(encoding="utf-8")
        assert command not in payload
        for marker_path in marker_paths:
            assert marker_path not in payload


def test_runtime_diagnostic_make_target_emits_only_child_output(tmp_path: Path) -> None:
    fake_uv = tmp_path / "fake-uv"
    expected = '{"outcome_code":"test-only","status":"failed"}\n'
    fake_uv.write_text(
        f"#!/bin/sh\nprintf '%s\\n' '{expected.rstrip()}'\n",
        encoding="utf-8",
    )
    fake_uv.chmod(0o700)
    launch_path = "/private/operator/secret-launch-path.env"

    completed = subprocess.run(
        (
            "make",
            "trusted-time-runtime-diagnostic",
            f"UV={fake_uv}",
            f"TRUSTED_TIME_LAUNCH_ENV_FILE={launch_path}",
        ),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert completed.stdout == expected
    assert launch_path not in completed.stdout
    assert launch_path not in completed.stderr


def test_runtime_diagnostic_make_target_is_pinned_to_v5_contract() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    target = makefile.partition("\ntrusted-time-runtime-diagnostic:")[2].partition("\n\n")[0]
    diagnostic = (ROOT / "scripts" / "diagnose_trusted_time_runtime.py").read_text(encoding="utf-8")

    assert "scripts/diagnose_trusted_time_runtime.py" in target
    assert 'CONTRACT_VERSION = "phase6d-bounded-read-only-runtime-diagnostic-v5"' in diagnostic


def test_container_ci_uses_supported_isolated_trusted_time_entrypoints() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    marker = "\n  containers:\n"
    assert workflow.count(marker) == 1
    container_job = workflow.partition(marker)[2]

    setup = "uses: astral-sh/setup-uv@08807647e7069bb48b6ef5acd8ec9567f424441b"
    prewarm = "- name: Prepare locked isolated dependencies"
    compose_admission = "run: make trusted-time-compose-check"
    image_admission = "run: make trusted-time-images"

    assert setup in container_job
    assert 'python-version: "3.12"' in container_job
    assert 'version: "0.11.28"' in container_job
    assert prewarm in container_job
    assert (
        "uv run\n          --isolated\n          --locked\n          --no-env-file" in container_job
    )
    assert "pycache_prefix=/dev/null\n          -c\n          pass" in container_job
    assert compose_admission in container_job
    assert image_admission in container_job
    assert (
        container_job.index(setup)
        < container_job.index(prewarm)
        < container_job.index(compose_admission)
        < container_job.index(image_admission)
    )
    assert "python scripts/verify_trusted_time_compose.py" not in container_job
    assert "python -m scripts.verify_trusted_time_images --build" not in container_job


def test_unenrolled_admission_make_target_passes_exact_approval_tuple() -> None:
    revision = "a" * 40
    artifact_sha256 = "b" * 64
    source_id = "sha256:" + "c" * 64
    supervisor_id = "sha256:" + "d" * 64
    launch_env = "/private/operator/trusted-time-launch.env"
    completed = subprocess.run(
        (
            "make",
            "-n",
            "trusted-time-admit-unenrolled",
            f"TRUSTED_TIME_LAUNCH_ENV_FILE={launch_env}",
            f"TRUSTED_TIME_APPROVED_GIT_REVISION={revision}",
            f"TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256={artifact_sha256}",
            f"TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID={source_id}",
            f"TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID={supervisor_id}",
        ),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert f'--env-file "{launch_env}"' in completed.stdout
    assert f'--approved-git-revision "{revision}"' in completed.stdout
    assert f'--approved-image-admission-sha256 "{artifact_sha256}"' in completed.stdout
    assert f'--approved-source-image-id "{source_id}"' in completed.stdout
    assert f'--approved-supervisor-image-id "{supervisor_id}"' in completed.stdout
    assert "--expect-unenrolled-fail-closed" in completed.stdout
    assert "scripts/verify_trusted_time_images.py" not in completed.stdout


def test_persistent_start_make_target_passes_exact_approval_tuple_without_build() -> None:
    revision = "a" * 40
    artifact_sha256 = "b" * 64
    source_id = "sha256:" + "c" * 64
    supervisor_id = "sha256:" + "d" * 64
    launch_env = "/private/operator/trusted-time-launch.env"
    completed = subprocess.run(
        (
            "make",
            "-n",
            "trusted-time-start",
            f"TRUSTED_TIME_LAUNCH_ENV_FILE={launch_env}",
            f"TRUSTED_TIME_APPROVED_GIT_REVISION={revision}",
            f"TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256={artifact_sha256}",
            f"TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID={source_id}",
            f"TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID={supervisor_id}",
        ),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert f'--approved-git-revision "{revision}"' in completed.stdout
    assert f'--approved-image-admission-sha256 "{artifact_sha256}"' in completed.stdout
    assert f'--approved-source-image-id "{source_id}"' in completed.stdout
    assert f'--approved-supervisor-image-id "{supervisor_id}"' in completed.stdout
    assert "--expect-unenrolled-fail-closed" not in completed.stdout
    assert "scripts/verify_trusted_time_images.py" not in completed.stdout


def test_existing_image_readmission_target_passes_only_exact_immutable_ids() -> None:
    source_id = "sha256:" + "1" * 64
    supervisor_id = "sha256:" + "2" * 64
    artifact = "/private/operator/image-admission.json"
    completed = subprocess.run(
        (
            "make",
            "-n",
            "trusted-time-readmit-images",
            f"TRUSTED_TIME_IMAGE_ADMISSION_ARTIFACT={artifact}",
            f"TRUSTED_TIME_EXISTING_SOURCE_IMAGE_ID={source_id}",
            f"TRUSTED_TIME_EXISTING_SUPERVISOR_IMAGE_ID={supervisor_id}",
        ),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert "scripts/verify_trusted_time_images.py --admit-existing" in completed.stdout
    assert f'--artifact "{artifact}"' in completed.stdout
    assert f'"{source_id}"' in completed.stdout
    assert f'"{supervisor_id}"' in completed.stdout
    assert "--build" not in completed.stdout


@pytest.mark.parametrize(
    ("assignments", "required_name"),
    [
        ((), "TRUSTED_TIME_EXISTING_SOURCE_IMAGE_ID"),
        (
            ("TRUSTED_TIME_EXISTING_SOURCE_IMAGE_ID=sha256:" + "1" * 64,),
            "TRUSTED_TIME_EXISTING_SUPERVISOR_IMAGE_ID",
        ),
    ],
)
def test_existing_image_readmission_guards_reject_incomplete_pair_before_launcher(
    assignments: tuple[str, ...],
    required_name: str,
) -> None:
    completed = subprocess.run(
        ("make", "trusted-time-readmit-images", *assignments),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode != 0
    assert required_name in completed.stderr
    assert "scripts/verify_trusted_time_images.py" not in completed.stdout


@pytest.mark.parametrize(
    ("target", "recovery_expected"),
    [
        ("trusted-time-enroll-first", False),
        ("trusted-time-recover-first-enrollment", True),
    ],
)
def test_first_enrollment_targets_pass_every_exact_binding_and_separate_mode(
    target: str,
    recovery_expected: bool,
) -> None:
    assignments = _first_enrollment_assignments()
    completed = subprocess.run(
        ("make", "-n", target, *assignments),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert "scripts/enroll_trusted_time_head_anchor.py" in completed.stdout
    expected_flags = {
        "TRUSTED_TIME_FIRST_ENROLLMENT_OPERATION_ID": "--operation-id",
        "TRUSTED_TIME_APPROVED_GIT_REVISION": "--approved-git-revision",
        "TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256": ("--approved-image-admission-sha256"),
        "TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID": "--approved-source-image-id",
        "TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID": ("--approved-supervisor-image-id"),
        "TRUSTED_TIME_APPROVED_UNENROLLED_ADMISSION_SHA256": ("--unenrolled-admission-sha256"),
        "TRUSTED_TIME_APPROVED_ANCHOR_AUTHORITY_SHA256": ("--anchor-authority-sha256"),
        "TRUSTED_TIME_APPROVED_DEPLOYMENT_IDENTITY_SHA256": ("--deployment-identity-sha256"),
        "TRUSTED_TIME_APPROVED_RUNTIME_DATABASE_IDENTITY_SHA256": (
            "--runtime-database-identity-sha256"
        ),
        "TRUSTED_TIME_APPROVED_ANCHOR_PROJECT_IDENTITY_SHA256": (
            "--anchor-project-identity-sha256"
        ),
        "TRUSTED_TIME_APPROVED_SOURCE_AUTHORITY_SHA256": ("--source-authority-sha256"),
        "TRUSTED_TIME_APPROVED_SIGNING_PUBLIC_KEY_SHA256": ("--signing-public-key-sha256"),
        "TRUSTED_TIME_APPROVED_HOST_IDENTITY_SHA256": "--host-identity-sha256",
        "TRUSTED_TIME_APPROVED_PRINCIPAL_IDENTITY_SHA256": ("--principal-identity-sha256"),
        "TRUSTED_TIME_APPROVED_BUCKET_IDENTITY_SHA256": ("--bucket-identity-sha256"),
    }
    assignment_values = dict(item.split("=", 1) for item in assignments)
    for variable, flag in expected_flags.items():
        assert f'{flag} "{assignment_values[variable]}"' in completed.stdout
    assert ("--recover-pending" in completed.stdout) is recovery_expected
    assert ("--prior-new-operation-id" in completed.stdout) is recovery_expected
    assert ("--prior-new-claim-sha256" in completed.stdout) is recovery_expected
    assert "scripts/start_trusted_time_supervisor.py" not in completed.stdout


def test_first_enrollment_guard_rejects_missing_operation_id_before_launcher() -> None:
    completed = subprocess.run(
        (
            "make",
            "trusted-time-enroll-first",
            "TRUSTED_TIME_LAUNCH_ENV_FILE=/private/operator/trusted-time-launch.env",
        ),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode != 0
    assert "TRUSTED_TIME_FIRST_ENROLLMENT_OPERATION_ID" in completed.stderr
    assert "scripts/enroll_trusted_time_head_anchor.py" not in completed.stdout


def test_persistent_start_make_guard_rejects_incomplete_approval_before_launcher() -> None:
    completed = subprocess.run(
        (
            "make",
            "trusted-time-start",
            "TRUSTED_TIME_LAUNCH_ENV_FILE=/private/launch.env",
            f"TRUSTED_TIME_APPROVED_GIT_REVISION={'a' * 40}",
            f"TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256={'b' * 64}",
            f"TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID=sha256:{'c' * 64}",
        ),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode != 0
    assert "TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID" in completed.stderr
    assert "scripts/start_trusted_time_supervisor.py" not in completed.stdout


def test_stop_make_target_fails_closed_without_live_compose_files() -> None:
    completed = subprocess.run(
        ("make", "trusted-time-stop"),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode != 0
    assert "approval-blocked" in completed.stderr
    assert "docker compose" not in completed.stdout


def test_inspection_make_target_uses_separate_database_only_environment() -> None:
    inspect_env = "/private/operator/trusted-time-inspect.env"
    completed = subprocess.run(
        (
            "make",
            "-n",
            "trusted-time-inspect",
            f"TRUSTED_TIME_INSPECT_ENV_FILE={inspect_env}",
        ),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0
    assert f'--env-file "{inspect_env}"' in completed.stdout
    assert "TRUSTED_TIME_LAUNCH_ENV_FILE" not in completed.stdout


@pytest.mark.parametrize(
    ("assignments", "required_name"),
    [
        ((), "TRUSTED_TIME_LAUNCH_ENV_FILE"),
        (
            ("TRUSTED_TIME_LAUNCH_ENV_FILE=/private/launch.env",),
            "TRUSTED_TIME_APPROVED_GIT_REVISION",
        ),
        (
            (
                "TRUSTED_TIME_LAUNCH_ENV_FILE=/private/launch.env",
                f"TRUSTED_TIME_APPROVED_GIT_REVISION={'a' * 40}",
            ),
            "TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256",
        ),
        (
            (
                "TRUSTED_TIME_LAUNCH_ENV_FILE=/private/launch.env",
                f"TRUSTED_TIME_APPROVED_GIT_REVISION={'a' * 40}",
                f"TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256={'b' * 64}",
            ),
            "TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID",
        ),
        (
            (
                "TRUSTED_TIME_LAUNCH_ENV_FILE=/private/launch.env",
                f"TRUSTED_TIME_APPROVED_GIT_REVISION={'a' * 40}",
                f"TRUSTED_TIME_APPROVED_IMAGE_ADMISSION_SHA256={'b' * 64}",
                f"TRUSTED_TIME_APPROVED_SOURCE_IMAGE_ID=sha256:{'c' * 64}",
            ),
            "TRUSTED_TIME_APPROVED_SUPERVISOR_IMAGE_ID",
        ),
    ],
)
def test_unenrolled_admission_make_guards_execute_before_launcher(
    assignments: tuple[str, ...],
    required_name: str,
) -> None:
    completed = subprocess.run(
        ("make", "trusted-time-admit-unenrolled", *assignments),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode != 0
    assert required_name in completed.stderr
    assert "scripts/start_trusted_time_supervisor.py" not in completed.stdout


def test_inspection_make_guard_executes_before_inspector() -> None:
    completed = subprocess.run(
        ("make", "trusted-time-inspect"),
        cwd=ROOT,
        env={"LC_ALL": "C", "PATH": os.defpath},
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode != 0
    assert "TRUSTED_TIME_INSPECT_ENV_FILE" in completed.stderr
    assert "scripts/inspect_trusted_time_qualification.py" not in completed.stdout
