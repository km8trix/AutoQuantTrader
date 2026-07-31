"""Authenticated, account-local assignment of an approved risk policy.

Policy approval fixes semantics; assignment is the separate durable act that
selects one approved policy for one account and environment.  This module is a
pure state transition.  Persistence callers must authenticate actor authority,
serialize on the account lease head, and retain the returned chain exactly.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.identifiers import canonical_id

ADVANCED_RISK_ASSIGNMENT_CONTRACT_VERSION = "phase5b-advanced-risk-assignment-v1"

_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AdvancedRiskAssignmentError(ValueError):
    """Assignment evidence is malformed or cannot be applied safely."""


class AdvancedRiskAssignmentConflict(AdvancedRiskAssignmentError):
    """An immutable assignment identity has conflicting semantics."""


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_text(value: str, field_name: str, *, maximum: int = 128) -> None:
    if type(value) is not str or not value or value != value.strip():
        raise AdvancedRiskAssignmentError(f"{field_name} must be non-empty trimmed text")
    if len(value) > maximum or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise AdvancedRiskAssignmentError(f"{field_name} contains unsupported text")


def _require_sha256(value: str, field_name: str) -> None:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AdvancedRiskAssignmentError(f"{field_name} must be a lowercase SHA-256 digest")


def _require_utc(value: datetime, field_name: str) -> None:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise AdvancedRiskAssignmentError(f"{field_name} must be UTC")


@dataclass(frozen=True, slots=True)
class AdvancedRiskAssignmentCommand:
    """One authenticated request to select an approved policy for an account."""

    account_id: str
    environment: str
    idempotency_key: str
    policy_id: str
    policy_sha256: str
    actor_id: str
    actor_authority_sha256: str
    actor_authenticated_at: datetime
    requested_at: datetime
    approval_evidence_sha256: str
    expected_assignment_sequence_number: int
    expected_assignment_sha256: str | None

    def __post_init__(self) -> None:
        for value, field_name, maximum in (
            (self.account_id, "assignment account ID", 64),
            (self.environment, "assignment environment", 32),
            (self.policy_id, "assignment policy ID", 128),
            (self.actor_id, "assignment actor ID", 128),
        ):
            _require_text(value, field_name, maximum=maximum)
        if (
            type(self.idempotency_key) is not str
            or _IDEMPOTENCY_KEY.fullmatch(self.idempotency_key) is None
        ):
            raise AdvancedRiskAssignmentError(
                "assignment idempotency key must contain 8-128 safe visible characters"
            )
        for value, field_name in (
            (self.policy_sha256, "assignment policy_sha256"),
            (self.actor_authority_sha256, "assignment actor_authority_sha256"),
            (self.approval_evidence_sha256, "assignment approval_evidence_sha256"),
        ):
            _require_sha256(value, field_name)
        _require_utc(self.actor_authenticated_at, "assignment actor_authenticated_at")
        _require_utc(self.requested_at, "assignment requested_at")
        if self.actor_authenticated_at > self.requested_at:
            raise AdvancedRiskAssignmentError("assignment cannot predate actor authentication")
        if (
            type(self.expected_assignment_sequence_number) is not int
            or self.expected_assignment_sequence_number < 0
        ):
            raise AdvancedRiskAssignmentError(
                "assignment expected head sequence must be non-negative"
            )
        if self.expected_assignment_sequence_number == 0:
            if self.expected_assignment_sha256 is not None:
                raise AdvancedRiskAssignmentError(
                    "initial assignment expected head cannot carry a digest"
                )
        else:
            _require_sha256(
                self.expected_assignment_sha256 or "",
                "assignment expected_assignment_sha256",
            )
        if self.environment != "paper":
            raise AdvancedRiskAssignmentError(
                "the Phase 5B approved policy may be assigned only to paper"
            )

    @property
    def command_id(self) -> str:
        return canonical_id(
            "advanced-risk-assignment-command",
            ADVANCED_RISK_ASSIGNMENT_CONTRACT_VERSION,
            self.account_id,
            self.actor_id,
            self.idempotency_key,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ADVANCED_RISK_ASSIGNMENT_CONTRACT_VERSION,
            "assignment_command",
            self.command_id,
            self.account_id,
            self.environment,
            self.idempotency_key,
            self.policy_id,
            self.policy_sha256,
            self.actor_id,
            self.actor_authority_sha256,
            self.actor_authenticated_at,
            self.requested_at,
            self.approval_evidence_sha256,
            self.expected_assignment_sequence_number,
            self.expected_assignment_sha256,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


@dataclass(frozen=True, slots=True)
class AdvancedRiskPolicyAssignment:
    """One immutable node in the gap-free account assignment chain."""

    assignment_id: str
    account_id: str
    environment: str
    sequence_number: int
    previous_assignment_sha256: str | None
    command_id: str
    command_sha256: str
    policy_id: str
    policy_sha256: str
    actor_id: str
    actor_authority_sha256: str
    actor_authenticated_at: datetime
    assigned_at: datetime

    def __post_init__(self) -> None:
        for value, field_name, maximum in (
            (self.assignment_id, "assignment ID", 36),
            (self.account_id, "assignment account ID", 64),
            (self.environment, "assignment environment", 32),
            (self.command_id, "assignment command ID", 36),
            (self.policy_id, "assignment policy ID", 128),
            (self.actor_id, "assignment actor ID", 128),
        ):
            _require_text(value, field_name, maximum=maximum)
        if len(self.assignment_id) != 36 or len(self.command_id) != 36:
            raise AdvancedRiskAssignmentError(
                "assignment and command IDs must be canonical UUID text"
            )
        if type(self.sequence_number) is not int or self.sequence_number <= 0:
            raise AdvancedRiskAssignmentError("assignment sequence number must be positive")
        for value, field_name in (
            (self.command_sha256, "assignment command_sha256"),
            (self.policy_sha256, "assignment policy_sha256"),
            (self.actor_authority_sha256, "assignment actor_authority_sha256"),
        ):
            _require_sha256(value, field_name)
        if self.previous_assignment_sha256 is None:
            if self.sequence_number != 1:
                raise AdvancedRiskAssignmentError(
                    "only the initial assignment may omit a predecessor"
                )
        else:
            _require_sha256(
                self.previous_assignment_sha256,
                "assignment previous_assignment_sha256",
            )
            if self.sequence_number == 1:
                raise AdvancedRiskAssignmentError("initial assignment cannot have a predecessor")
        _require_utc(self.actor_authenticated_at, "assignment actor_authenticated_at")
        _require_utc(self.assigned_at, "assignment assigned_at")
        if self.actor_authenticated_at > self.assigned_at:
            raise AdvancedRiskAssignmentError("assignment cannot predate actor authentication")
        if self.environment != "paper":
            raise AdvancedRiskAssignmentError(
                "the Phase 5B approved policy may be assigned only to paper"
            )

    def _semantic_material(self) -> tuple[object, ...]:
        return (
            ADVANCED_RISK_ASSIGNMENT_CONTRACT_VERSION,
            "policy_assignment",
            self.assignment_id,
            self.account_id,
            self.environment,
            self.sequence_number,
            self.previous_assignment_sha256,
            self.command_id,
            self.command_sha256,
            self.policy_id,
            self.policy_sha256,
            self.actor_id,
            self.actor_authority_sha256,
            self.actor_authenticated_at,
            self.assigned_at,
        )

    @property
    def semantic_sha256(self) -> str:
        return _sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


def assign_advanced_risk_policy(
    current: AdvancedRiskPolicyAssignment | None,
    command: AdvancedRiskAssignmentCommand,
    *,
    assigned_at: datetime,
) -> AdvancedRiskPolicyAssignment:
    """Apply an authenticated exact command to the account assignment chain."""

    if current is not None and type(current) is not AdvancedRiskPolicyAssignment:
        raise AdvancedRiskAssignmentError("current advanced-risk assignment must be exact")
    if type(command) is not AdvancedRiskAssignmentCommand:
        raise AdvancedRiskAssignmentError("advanced-risk assignment command must be exact")
    if current is not None:
        current.__post_init__()
    command.__post_init__()
    _require_utc(assigned_at, "assignment assigned_at")
    if assigned_at < command.requested_at:
        raise AdvancedRiskAssignmentError("assignment cannot be committed before it was requested")
    if current is not None:
        if current.account_id != command.account_id or current.environment != command.environment:
            raise AdvancedRiskAssignmentConflict(
                "assignment command scope conflicts with current head"
            )
        if current.command_id == command.command_id:
            if (
                current.command_sha256 != command.semantic_sha256
                or current.policy_id != command.policy_id
                or current.policy_sha256 != command.policy_sha256
            ):
                raise AdvancedRiskAssignmentConflict(
                    "assignment command identity has conflicting semantics"
                )
            return current

    expected_sequence_number = 0 if current is None else current.sequence_number
    expected_sha256 = None if current is None else current.semantic_sha256
    if (
        command.expected_assignment_sequence_number != expected_sequence_number
        or command.expected_assignment_sha256 != expected_sha256
    ):
        raise AdvancedRiskAssignmentConflict(
            "assignment command expected head conflicts with current head"
        )

    sequence_number = 1 if current is None else current.sequence_number + 1
    previous_sha256 = None if current is None else current.semantic_sha256
    assignment_id = canonical_id(
        "advanced-risk-policy-assignment",
        ADVANCED_RISK_ASSIGNMENT_CONTRACT_VERSION,
        command.command_id,
        command.semantic_sha256,
        sequence_number,
        previous_sha256,
    )
    return AdvancedRiskPolicyAssignment(
        assignment_id=assignment_id,
        account_id=command.account_id,
        environment=command.environment,
        sequence_number=sequence_number,
        previous_assignment_sha256=previous_sha256,
        command_id=command.command_id,
        command_sha256=command.semantic_sha256,
        policy_id=command.policy_id,
        policy_sha256=command.policy_sha256,
        actor_id=command.actor_id,
        actor_authority_sha256=command.actor_authority_sha256,
        actor_authenticated_at=command.actor_authenticated_at,
        assigned_at=assigned_at,
    )
