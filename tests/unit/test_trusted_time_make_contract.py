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

    assert makefile.count("$(TRUSTED_TIME_PYTHON)") == 6
    for script in (
        "inspect_trusted_time_qualification.py",
        "start_trusted_time_supervisor.py",
        "verify_trusted_time_compose.py",
        "verify_trusted_time_images.py",
    ):
        assert script in makefile


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
