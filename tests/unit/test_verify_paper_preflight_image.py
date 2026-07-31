from __future__ import annotations

import json
from typing import cast

import pytest

from scripts.verify_paper_preflight_image import (
    PaperPreflightImageVerificationError,
    validate_image_inspection,
    validate_preflight_result,
    validate_runtime_input_permissions,
)


def _inspection() -> list[dict[str, object]]:
    return [
        {
            "Config": {
                "Cmd": ["autoquant-trader", "--once"],
                "Entrypoint": None,
                "Env": [
                    "PATH=/opt/venv/bin:/usr/local/bin",
                    "AQT_ENVIRONMENT=paper",
                ],
                "ExposedPorts": None,
                "User": "10001:10001",
            }
        }
    ]


def _payload() -> dict[str, object]:
    return {
        "automatic_rearm_authorized": False,
        "broker_action_authorized": False,
        "live_trading_authorized": False,
        "new_exposure_authorized": False,
        "phase5_activation_ready": False,
        "public_inbound_authorized": False,
        "requested_environment": "paper",
        "smoke_blockers": ["database_secret_source_missing"],
        "smoke_deployable": False,
        "status": "not_ready",
    }


def test_image_inspection_accepts_exact_nonroot_outbound_only_contract() -> None:
    validate_image_inspection(_inspection())


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("User", "root"),
        ("ExposedPorts", {"8000/tcp": {}}),
        ("Entrypoint", ["/bin/sh"]),
        ("Cmd", ["autoquant-api"]),
        ("Env", ["PATH=/opt/venv/bin:/usr/local/bin"]),
    ],
)
def test_image_inspection_rejects_contract_drift(field_name: str, value: object) -> None:
    inspection = _inspection()
    configuration = cast(dict[str, object], inspection[0]["Config"])
    configuration[field_name] = value

    with pytest.raises(PaperPreflightImageVerificationError):
        validate_image_inspection(inspection)


def test_preflight_result_accepts_exact_non_authorizing_payload() -> None:
    validate_preflight_result(
        return_code=2,
        stdout=json.dumps(_payload()),
        stderr="",
    )


def test_runtime_input_permissions_accept_root_owned_nonwritable_files() -> None:
    validate_runtime_input_permissions("0:0:644\n0:0:444\n0:0:640\n")


@pytest.mark.parametrize(
    "permissions",
    (
        "10001:10001:644\n0:0:644\n0:0:644\n",
        "0:0:664\n0:0:644\n0:0:644\n",
        "0:0:644\n0:0:644\n",
        "0:0:invalid\n0:0:644\n0:0:644\n",
    ),
)
def test_runtime_input_permissions_reject_ownership_or_mode_drift(
    permissions: str,
) -> None:
    with pytest.raises(PaperPreflightImageVerificationError):
        validate_runtime_input_permissions(permissions)


@pytest.mark.parametrize(
    ("return_code", "mutated_field", "mutated_value", "stderr"),
    [
        (0, None, None, ""),
        (2, "status", "ready", ""),
        (2, "broker_action_authorized", True, ""),
        (2, "smoke_blockers", [], ""),
        (2, None, None, "unexpected diagnostic"),
    ],
)
def test_preflight_result_rejects_non_fail_closed_outcomes(
    return_code: int,
    mutated_field: str | None,
    mutated_value: object,
    stderr: str,
) -> None:
    payload = _payload()
    if mutated_field is not None:
        payload[mutated_field] = mutated_value

    with pytest.raises(PaperPreflightImageVerificationError):
        validate_preflight_result(
            return_code=return_code,
            stdout=json.dumps(payload),
            stderr=stderr,
        )
