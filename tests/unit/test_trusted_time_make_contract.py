from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


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

    assert makefile.count("$(TRUSTED_TIME_PYTHON)") == 7
    for script in (
        "diagnose_trusted_time_runtime.py",
        "inspect_trusted_time_qualification.py",
        "start_trusted_time_supervisor.py",
        "verify_trusted_time_compose.py",
        "verify_trusted_time_images.py",
    ):
        assert script in makefile


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
