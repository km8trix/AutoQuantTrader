"""Strict JSON boundary for deterministic market-data admission evidence."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from packages.market_data import (
    AdmissionEvidence,
    AdmissionReport,
    AdmissionSpecification,
    ApprovalDecision,
    EntitlementStatus,
    IndependentApproval,
    SourceKind,
    TechnicalCheckEvidence,
)

MAX_ADMISSION_INPUT_BYTES = 2 * 1024 * 1024


class AdmissionInputError(ValueError):
    """A JSON admission input is malformed, ambiguous, or outside the contract."""


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdmissionInputError(f"duplicate JSON field {key!r}")
        result[key] = value
    return result


def _load(path: Path) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise AdmissionInputError(f"cannot read admission input {path}") from error
    if len(payload) > MAX_ADMISSION_INPUT_BYTES:
        raise AdmissionInputError("admission input exceeds the 2 MiB limit")
    try:
        value: Any = json.loads(payload.decode("utf-8"), object_pairs_hook=_object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdmissionInputError(f"admission input {path} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise AdmissionInputError("admission input must be a JSON object")
    return value


def _strict_object(
    value: object,
    *,
    required: set[str],
    context: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise AdmissionInputError(f"{context} must be a JSON object")
    unknown = set(value) - required
    missing = required - set(value)
    if unknown or missing:
        details: list[str] = []
        if unknown:
            details.append(f"unknown fields: {', '.join(sorted(unknown))}")
        if missing:
            details.append(f"missing fields: {', '.join(sorted(missing))}")
        raise AdmissionInputError(f"{context} has {'; '.join(details)}")
    return value


def _string(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise AdmissionInputError(f"{field_name} must be a string")
    return value


def _optional_string(value: object, field_name: str) -> str | None:
    return None if value is None else _string(value, field_name)


def _boolean(value: object, field_name: str) -> bool:
    if type(value) is not bool:
        raise AdmissionInputError(f"{field_name} must be a boolean")
    return value


def _timestamp(value: object, field_name: str) -> datetime:
    raw = _string(value, field_name)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise AdmissionInputError(f"{field_name} must be an ISO-8601 timestamp") from error


def _string_tuple(value: object, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise AdmissionInputError(f"{field_name} must be an array of strings")
    return tuple(value)


def load_admission_specification(path: Path) -> AdmissionSpecification:
    row = _strict_object(
        _load(path),
        required={
            "calendar_version",
            "corporate_action_version",
            "frozen_at",
            "identifier_authority",
            "required_checks",
            "source_id",
            "specification_id",
            "universe_version",
        },
        context="admission specification",
    )
    try:
        return AdmissionSpecification(
            specification_id=_string(row["specification_id"], "specification_id"),
            source_id=_string(row["source_id"], "source_id"),
            identifier_authority=_string(
                row["identifier_authority"],
                "identifier_authority",
            ),
            universe_version=_string(row["universe_version"], "universe_version"),
            calendar_version=_string(row["calendar_version"], "calendar_version"),
            corporate_action_version=_string(
                row["corporate_action_version"],
                "corporate_action_version",
            ),
            required_checks=_string_tuple(row["required_checks"], "required_checks"),
            frozen_at=_timestamp(row["frozen_at"], "frozen_at"),
        )
    except ValueError as error:
        raise AdmissionInputError(str(error)) from error


def _technical_check(value: object, index: int) -> TechnicalCheckEvidence:
    row = _strict_object(
        value,
        required={"check_id", "checked_at", "evidence_digest", "passed"},
        context=f"technical_checks[{index}]",
    )
    try:
        return TechnicalCheckEvidence(
            check_id=_string(row["check_id"], "check_id"),
            passed=_boolean(row["passed"], "passed"),
            evidence_digest=_string(row["evidence_digest"], "evidence_digest"),
            checked_at=_timestamp(row["checked_at"], "checked_at"),
        )
    except ValueError as error:
        raise AdmissionInputError(str(error)) from error


def _approval(value: object) -> IndependentApproval | None:
    if value is None:
        return None
    row = _strict_object(
        value,
        required={"decision", "reviewed_at", "reviewer_id"},
        context="approval",
    )
    try:
        return IndependentApproval(
            reviewer_id=_string(row["reviewer_id"], "reviewer_id"),
            decision=ApprovalDecision(_string(row["decision"], "decision")),
            reviewed_at=_timestamp(row["reviewed_at"], "reviewed_at"),
        )
    except ValueError as error:
        raise AdmissionInputError(str(error)) from error


def load_admission_evidence(path: Path) -> AdmissionEvidence:
    row = _strict_object(
        _load(path),
        required={
            "approval",
            "calendar_version",
            "corporate_action_version",
            "entitlement_status",
            "evaluated_at",
            "executor_id",
            "identifier_authority",
            "licensed",
            "source_id",
            "source_kind",
            "technical_checks",
            "terms_digest",
            "universe_version",
        },
        context="admission evidence",
    )
    technical_rows = row["technical_checks"]
    if not isinstance(technical_rows, list):
        raise AdmissionInputError("technical_checks must be an array")
    try:
        return AdmissionEvidence(
            source_id=_string(row["source_id"], "source_id"),
            source_kind=SourceKind(_string(row["source_kind"], "source_kind")),
            licensed=_boolean(row["licensed"], "licensed"),
            entitlement_status=EntitlementStatus(
                _string(row["entitlement_status"], "entitlement_status")
            ),
            terms_digest=_optional_string(row["terms_digest"], "terms_digest"),
            identifier_authority=_optional_string(
                row["identifier_authority"],
                "identifier_authority",
            ),
            universe_version=_optional_string(row["universe_version"], "universe_version"),
            calendar_version=_optional_string(row["calendar_version"], "calendar_version"),
            corporate_action_version=_optional_string(
                row["corporate_action_version"],
                "corporate_action_version",
            ),
            technical_checks=tuple(
                _technical_check(value, index) for index, value in enumerate(technical_rows)
            ),
            executor_id=_string(row["executor_id"], "executor_id"),
            evaluated_at=_timestamp(row["evaluated_at"], "evaluated_at"),
            approval=_approval(row["approval"]),
        )
    except ValueError as error:
        raise AdmissionInputError(str(error)) from error


def admission_report_payload(report: AdmissionReport) -> dict[str, Any]:
    return {
        "checks": [
            {
                "check_id": check.check_id,
                "detail": check.detail,
                "evidence_digest": check.evidence_digest,
                "status": check.status.value,
            }
            for check in report.checks
        ],
        "evaluated_at": report.evaluated_at.isoformat().replace("+00:00", "Z"),
        "evidence_digest": report.evidence_digest,
        "report_digest": report.report_digest,
        "run_id": report.run_id,
        "source_id": report.source_id,
        "specification_id": report.specification_id,
        "status": report.status.value,
    }
