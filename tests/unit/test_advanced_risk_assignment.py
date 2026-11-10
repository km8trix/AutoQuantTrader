from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone

import pytest

from packages.domain.advanced_risk_assignment import (
    ADVANCED_RISK_ASSIGNMENT_CONTRACT_VERSION,
    AdvancedRiskAssignmentCommand,
    AdvancedRiskAssignmentConflict,
    AdvancedRiskAssignmentError,
    assign_advanced_risk_policy,
)

NOW = datetime(2026, 7, 28, 16, 0, tzinfo=UTC)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def command(**changes: object) -> AdvancedRiskAssignmentCommand:
    values: dict[str, object] = {
        "account_id": "paper-account",
        "environment": "paper",
        "idempotency_key": "assign-moderate-0001",
        "policy_id": "phase5b-moderate-paper-rth-etf-v1",
        "policy_sha256": digest("policy"),
        "actor_id": "owner",
        "actor_authority_sha256": digest("authority"),
        "actor_authenticated_at": NOW,
        "requested_at": NOW + timedelta(seconds=1),
        "approval_evidence_sha256": digest("approval"),
        "expected_assignment_sequence_number": 0,
        "expected_assignment_sha256": None,
    }
    values.update(changes)
    return AdvancedRiskAssignmentCommand(**values)  # type: ignore[arg-type]


def test_assignment_is_authenticated_gap_free_and_exact_retry_safe() -> None:
    first_command = command()
    first = assign_advanced_risk_policy(
        None,
        first_command,
        assigned_at=NOW + timedelta(seconds=2),
    )
    second_command = command(
        idempotency_key="assign-moderate-0002",
        requested_at=NOW + timedelta(seconds=3),
        policy_sha256=digest("policy-v2"),
        expected_assignment_sequence_number=first.sequence_number,
        expected_assignment_sha256=first.semantic_sha256,
    )
    second = assign_advanced_risk_policy(
        first,
        second_command,
        assigned_at=NOW + timedelta(seconds=4),
    )

    assert ADVANCED_RISK_ASSIGNMENT_CONTRACT_VERSION.endswith("-v1")
    assert first.sequence_number == 1
    assert first.previous_assignment_sha256 is None
    assert second.sequence_number == 2
    assert second.previous_assignment_sha256 == first.semantic_sha256
    assert (
        assign_advanced_risk_policy(
            second,
            second_command,
            assigned_at=NOW + timedelta(minutes=1),
        )
        is second
    )


def test_assignment_rejects_conflicting_retry_scope_and_unauthenticated_shape() -> None:
    first_command = command()
    first = assign_advanced_risk_policy(
        None,
        first_command,
        assigned_at=NOW + timedelta(seconds=2),
    )

    with pytest.raises(AdvancedRiskAssignmentConflict, match="conflicting semantics"):
        assign_advanced_risk_policy(
            first,
            replace(first_command, policy_sha256=digest("changed")),
            assigned_at=NOW + timedelta(seconds=3),
        )
    with pytest.raises(AdvancedRiskAssignmentConflict, match="scope"):
        assign_advanced_risk_policy(
            first,
            command(
                account_id="other-account",
                idempotency_key="assign-other-0001",
            ),
            assigned_at=NOW + timedelta(seconds=3),
        )
    with pytest.raises(AdvancedRiskAssignmentError, match="only to paper"):
        command(environment="live")
    with pytest.raises(AdvancedRiskAssignmentError, match="authentication"):
        command(actor_authenticated_at=NOW + timedelta(seconds=2))
    with pytest.raises(AdvancedRiskAssignmentError, match="UTC"):
        command(requested_at=(NOW + timedelta(seconds=1)).astimezone(timezone(timedelta(hours=1))))
    with pytest.raises(AdvancedRiskAssignmentError, match="cannot carry a digest"):
        command(expected_assignment_sha256=digest("unexpected-head"))
    with pytest.raises(AdvancedRiskAssignmentError, match="lowercase SHA-256"):
        command(
            expected_assignment_sequence_number=1,
            expected_assignment_sha256=None,
        )
    with pytest.raises(AdvancedRiskAssignmentConflict, match="expected head"):
        assign_advanced_risk_policy(
            first,
            command(
                idempotency_key="assign-stale-0001",
                expected_assignment_sequence_number=0,
                expected_assignment_sha256=None,
            ),
            assigned_at=NOW + timedelta(seconds=3),
        )


def test_assignment_digest_changes_with_authority_or_predecessor() -> None:
    first = assign_advanced_risk_policy(
        None,
        command(),
        assigned_at=NOW + timedelta(seconds=2),
    )
    changed_authority = assign_advanced_risk_policy(
        None,
        command(actor_authority_sha256=digest("other-authority")),
        assigned_at=NOW + timedelta(seconds=2),
    )

    assert first.semantic_sha256 != changed_authority.semantic_sha256
    assert len(first.assignment_id) == 36
    assert len(first.semantic_sha256) == 64
