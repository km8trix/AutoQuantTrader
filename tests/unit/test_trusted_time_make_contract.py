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


def test_post_enrollment_topology_contracts_have_no_runtime_wiring() -> None:
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
        "trusted_time_post_enrollment_topology",
        "validate_post_enrollment_start_created_topology",
        "trusted_time_post_enrollment_staged_topology",
        "validate_post_enrollment_start_staged_unreleased_topology",
        "trusted_time_post_enrollment_topology_reader",
        "phase6d-post-enrollment-topology-observation-reader-v1",
        "TrustedTimePostEnrollmentTopologyObservationIssuer",
        "TrustedTimePostEnrollmentCreatedTopologyObservation",
        "TrustedTimePostEnrollmentStagedTopologyObservation",
        "trusted_time_post_enrollment_claimed_fence",
        *claimed_fence_api_names,
        "_run_exclusive_choreography",
        "choreography_lease",
        "choreography_deadline",
        *recovery_outcome_api_names,
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
        ROOT / "infra" / "compose" / "trusted-time.compose.yaml",
        ROOT / "pyproject.toml",
        ROOT / "scripts" / "diagnose_trusted_time_runtime.py",
        ROOT / "scripts" / "enroll_trusted_time_head_anchor.py",
        ROOT / "scripts" / "inspect_trusted_time_qualification.py",
        ROOT / "scripts" / "start_trusted_time_supervisor.py",
        ROOT / "scripts" / "verify_trusted_time_compose.py",
    )

    for path in supported_surfaces:
        payload = path.read_text(encoding="utf-8")
        for forbidden_name in forbidden_names:
            assert forbidden_name not in payload
        assert re.search(r"(?<![0-9A-Za-z_])recovery_required(?![0-9A-Za-z_])", payload) is None
        assert re.search(r"(?<![0-9A-Za-z])305(?:\.0)?(?![0-9A-Za-z])", payload) is None

    admission_cli = (ROOT / "scripts" / "verify_trusted_time_images.py").read_text(encoding="utf-8")
    assert '"scripts/trusted_time_post_enrollment_claimed_fence.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_claimed_fence") == 1
    assert '"scripts/trusted_time_post_enrollment_outcome.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_outcome") == 1
    assert '"scripts/trusted_time_post_enrollment_topology_fence.py"' in admission_cli
    assert admission_cli.count("trusted_time_post_enrollment_topology_fence") == 1
    for forbidden_name in (
        *recovery_outcome_api_names[1:],
        *claimed_fence_api_names,
        *topology_cursor_api_names,
        *topology_fence_api_names,
    ):
        assert forbidden_name not in admission_cli
    assert re.search(r"(?<![0-9A-Za-z_])recovery_required(?![0-9A-Za-z_])", admission_cli) is None
    assert re.search(r"(?<![0-9A-Za-z])305(?:\.0)?(?![0-9A-Za-z])", admission_cli) is None


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
