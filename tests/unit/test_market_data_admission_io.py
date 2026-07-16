from __future__ import annotations

import json
from pathlib import Path

import pytest

from packages.application.market_data_admission import (
    AdmissionInputError,
    admission_report_payload,
    load_admission_evidence,
    load_admission_specification,
)
from packages.market_data import AdmissionStatus, evaluate_admission


def write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def specification_payload() -> dict[str, object]:
    return {
        "specification_id": "reference-admission-v1",
        "source_id": "synthetic-source-v1",
        "identifier_authority": "synthetic-authority-v1",
        "universe_version": "synthetic-universe-v1",
        "calendar_version": "synthetic-calendar-v1",
        "corporate_action_version": "synthetic-actions-v1",
        "required_checks": ["causal_revisions", "calendar_edges"],
        "frozen_at": "2026-07-15T12:00:00Z",
    }


def evidence_payload() -> dict[str, object]:
    return {
        "source_id": "synthetic-source-v1",
        "source_kind": "synthetic_fixture",
        "licensed": False,
        "entitlement_status": "fixture_only",
        "terms_digest": "c" * 64,
        "identifier_authority": "synthetic-authority-v1",
        "universe_version": "synthetic-universe-v1",
        "calendar_version": "synthetic-calendar-v1",
        "corporate_action_version": "synthetic-actions-v1",
        "technical_checks": [
            {
                "check_id": "causal_revisions",
                "passed": True,
                "evidence_digest": "a" * 64,
                "checked_at": "2026-07-15T13:00:00Z",
            },
            {
                "check_id": "calendar_edges",
                "passed": True,
                "evidence_digest": "b" * 64,
                "checked_at": "2026-07-15T13:01:00Z",
            },
        ],
        "executor_id": "local-executor",
        "evaluated_at": "2026-07-15T14:00:00Z",
        "approval": None,
    }


def test_strict_json_inputs_produce_a_deterministic_blocked_report(tmp_path: Path) -> None:
    specification = load_admission_specification(
        write_json(tmp_path / "specification.json", specification_payload())
    )
    evidence = load_admission_evidence(write_json(tmp_path / "evidence.json", evidence_payload()))

    first = evaluate_admission(specification, evidence)
    second = evaluate_admission(specification, evidence)

    assert first == second
    assert first.status is AdmissionStatus.BLOCKED
    payload = admission_report_payload(first)
    assert payload["status"] == "blocked"
    assert payload["source_id"] == "synthetic-source-v1"
    assert len(str(payload["evidence_digest"])) == 64
    assert len(str(payload["report_digest"])) == 64


def test_json_boundary_rejects_duplicate_keys_before_field_validation(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text('{"source_id":"one","source_id":"two"}', encoding="utf-8")

    with pytest.raises(AdmissionInputError, match="duplicate JSON field 'source_id'"):
        load_admission_evidence(path)


def test_json_boundary_rejects_unknown_fields(tmp_path: Path) -> None:
    payload = specification_payload()
    payload["credential"] = "must-not-be-accepted"

    with pytest.raises(AdmissionInputError, match="unknown fields: credential"):
        load_admission_specification(write_json(tmp_path / "specification.json", payload))


def test_json_boundary_rejects_non_utc_evidence(tmp_path: Path) -> None:
    payload = evidence_payload()
    payload["evaluated_at"] = "2026-07-15T10:00:00-04:00"

    with pytest.raises(AdmissionInputError, match="evaluated_at must be stored in UTC"):
        load_admission_evidence(write_json(tmp_path / "evidence.json", payload))
