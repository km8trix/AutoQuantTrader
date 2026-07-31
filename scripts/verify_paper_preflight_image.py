"""Verify that a production image is a non-root, fail-closed paper preflight."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from typing import cast

_IMAGE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")
_EXPECTED_USER = "10001:10001"
_EXPECTED_COMMAND = ["autoquant-trader", "--once"]
_RUNTIME_INPUT_PATHS = (
    "/workspace/strategy_artifacts/no_exposure_smoke_v1/strategy.py",
    "/workspace/strategy_artifacts/no_exposure_smoke_v1/manifest.json",
    "/workspace/apps/trader/main.py",
)
_NON_AUTHORIZING_FLAGS = (
    "automatic_rearm_authorized",
    "broker_action_authorized",
    "live_trading_authorized",
    "new_exposure_authorized",
    "public_inbound_authorized",
)


class PaperPreflightImageVerificationError(RuntimeError):
    """The image metadata or default process violates the production contract."""


def _mapping(value: object, label: str) -> dict[str, object]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise PaperPreflightImageVerificationError(f"{label} must be a JSON object")
    return cast(dict[str, object], value)


def validate_image_inspection(document: object) -> None:
    """Validate sanitized Docker inspection data without invoking Docker."""

    if type(document) is not list or len(document) != 1:
        raise PaperPreflightImageVerificationError(
            "Docker inspection must contain exactly one image"
        )
    image = _mapping(document[0], "Docker image")
    configuration = _mapping(image.get("Config"), "Docker image Config")

    if configuration.get("User") != _EXPECTED_USER:
        raise PaperPreflightImageVerificationError("production image user is not pinned")
    if configuration.get("ExposedPorts") is not None:
        raise PaperPreflightImageVerificationError("production image exposes an inbound port")
    if configuration.get("Entrypoint") is not None:
        raise PaperPreflightImageVerificationError("production image overrides its entrypoint")
    if configuration.get("Cmd") != _EXPECTED_COMMAND:
        raise PaperPreflightImageVerificationError("production image command is not pinned")

    environment = configuration.get("Env")
    if type(environment) is not list or any(type(item) is not str for item in environment):
        raise PaperPreflightImageVerificationError("production image environment is malformed")
    if "AQT_ENVIRONMENT=paper" not in environment:
        raise PaperPreflightImageVerificationError(
            "production image does not default to paper admission"
        )


def validate_preflight_result(*, return_code: int, stdout: str, stderr: str) -> None:
    """Validate the default container's public, fail-closed result."""

    if return_code != 2:
        raise PaperPreflightImageVerificationError(
            "paper preflight must exit 2 while external sources are unbound"
        )
    if stderr:
        raise PaperPreflightImageVerificationError("paper preflight wrote to stderr")
    try:
        document: object = json.loads(stdout)
    except json.JSONDecodeError:
        raise PaperPreflightImageVerificationError(
            "paper preflight output is not valid JSON"
        ) from None
    payload = _mapping(document, "paper preflight output")
    if (
        payload.get("requested_environment") != "paper"
        or payload.get("status") != "not_ready"
        or payload.get("smoke_deployable") is not False
        or payload.get("phase5_activation_ready") is not False
    ):
        raise PaperPreflightImageVerificationError(
            "paper preflight did not report an exact not-ready decision"
        )
    blockers = payload.get("smoke_blockers")
    if (
        type(blockers) is not list
        or not blockers
        or any(type(blocker) is not str for blocker in blockers)
    ):
        raise PaperPreflightImageVerificationError(
            "paper preflight did not report bounded smoke blockers"
        )
    for field_name in _NON_AUTHORIZING_FLAGS:
        if payload.get(field_name) is not False:
            raise PaperPreflightImageVerificationError(
                "paper preflight reported an authorizing flag"
            )


def validate_runtime_input_permissions(stdout: str) -> None:
    """Require root-owned runtime inputs with no group/other write bits."""

    records = stdout.splitlines()
    if len(records) != len(_RUNTIME_INPUT_PATHS):
        raise PaperPreflightImageVerificationError(
            "production runtime-input ownership output is incomplete"
        )
    for record in records:
        fields = record.split(":")
        if len(fields) != 3 or fields[:2] != ["0", "0"]:
            raise PaperPreflightImageVerificationError(
                "production runtime inputs are not root-owned"
            )
        try:
            mode = int(fields[2], 8)
        except ValueError:
            raise PaperPreflightImageVerificationError(
                "production runtime-input mode is malformed"
            ) from None
        if mode & 0o022:
            raise PaperPreflightImageVerificationError(
                "production runtime inputs are writable by the runtime identity"
            )


def _run_docker(*arguments: str, timeout_seconds: float) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ("docker", *arguments),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise PaperPreflightImageVerificationError("Docker verification command failed") from None


def verify_image(image_reference: str) -> None:
    """Inspect and execute one local image without exposing command output."""

    if type(image_reference) is not str or _IMAGE_REFERENCE.fullmatch(image_reference) is None:
        raise PaperPreflightImageVerificationError("image reference is invalid")

    inspected = _run_docker(
        "image",
        "inspect",
        image_reference,
        timeout_seconds=10.0,
    )
    if inspected.returncode != 0 or inspected.stderr:
        raise PaperPreflightImageVerificationError("Docker image inspection failed")
    try:
        inspection: object = json.loads(inspected.stdout)
    except json.JSONDecodeError:
        raise PaperPreflightImageVerificationError(
            "Docker image inspection returned invalid JSON"
        ) from None
    validate_image_inspection(inspection)

    permissions = _run_docker(
        "run",
        "--rm",
        "--entrypoint",
        "stat",
        image_reference,
        "--format=%u:%g:%a",
        *_RUNTIME_INPUT_PATHS,
        timeout_seconds=10.0,
    )
    if permissions.returncode != 0 or permissions.stderr:
        raise PaperPreflightImageVerificationError(
            "production runtime-input ownership inspection failed"
        )
    validate_runtime_input_permissions(permissions.stdout)

    executed = _run_docker(
        "run",
        "--rm",
        image_reference,
        timeout_seconds=30.0,
    )
    validate_preflight_result(
        return_code=executed.returncode,
        stdout=executed.stdout,
        stderr=executed.stderr,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", help="local production image reference")
    arguments = parser.parse_args()
    verify_image(arguments.image)
    print("paper preflight production image verified")


if __name__ == "__main__":
    main()
